package main

import (
	"encoding/binary"
	"hash/crc32"
	"log"
	"net"
	"strconv"
	"time"
)

func (s *session) udpWriter() {
	defer s.close()
	buf := make([]byte, 65535)
	for {
		_ = s.udpConn.SetReadDeadline(time.Now().Add(time.Second))
		n, addr, err := s.udpConn.ReadFromUDP(buf)
		if err != nil {
			if time.Since(s.lastUDPUse) > time.Duration(s.client.cfg.udpTimeout)*time.Second {
				return
			}
			continue
		}
		if n < 10 {
			continue
		}
		s.udpClient = addr
		s.lastUDPUse = time.Now()
		atyp := buf[3]
		offset := 4
		var host string
		switch atyp {
		case 1:
			host = net.IP(buf[offset : offset+4]).String()
			offset += 4
		case 3:
			l := int(buf[offset])
			offset++
			host = string(buf[offset : offset+l])
			offset += l
		default:
			continue
		}
		port := int(binary.BigEndian.Uint16(buf[offset : offset+2]))
		offset += 2
		payload := append([]byte(nil), buf[offset:n]...)
		fragments := fragmentUDP(payload, s.client.cfg.udpFragSize)
		for idx, frag := range fragments {
			info := map[string][]byte{"CMD": []byte("FORWARD"), "MARK": []byte(s.mark), "IP": []byte(host), "PORT": []byte(strconv.Itoa(port)), "DATA": frag.data}
			if frag.meta != nil {
				info["UDPFRAG"] = frag.meta
			}
			if !s.forwardUDPFragment(info, idx+1, len(fragments)) {
				return
			}
		}
		s.recordTune(len(payload), 0, 0)
	}
}

func (s *session) forwardUDPFragment(info map[string][]byte, index, count int) bool {
	for retry := 0; retry <= s.client.cfg.maxRetry; retry++ {
		rinfo, err := s.client.request(info, 5*time.Second)
		if err == nil && string(rinfo["STATUS"]) == "OK" {
			return true
		}
		if err != nil {
			log.Printf("[UDP] FORWARD failed mark=%s fragment=%d/%d retry=%d/%d: %v", s.mark, index, count, retry, s.client.cfg.maxRetry, err)
		} else {
			log.Printf("[UDP] FORWARD failed mark=%s fragment=%d/%d retry=%d/%d: status=%s error=%s", s.mark, index, count, retry, s.client.cfg.maxRetry, rinfo["STATUS"], rinfo["ERROR"])
		}
		if retry < s.client.cfg.maxRetry {
			time.Sleep(s.client.cfg.writeInterval)
		}
	}
	log.Printf("[UDP] dropping session mark=%s after failed fragment %d/%d", s.mark, index, count)
	return false
}

func (s *session) udpReader() {
	s.classicReader()
}

type udpFrag struct {
	meta []byte
	data []byte
}

func fragmentUDP(data []byte, size int) []udpFrag {
	if size <= 0 || len(data) <= size {
		return []udpFrag{{data: data}}
	}
	count := (len(data) + size - 1) / size
	id := crc32.ChecksumIEEE(data) ^ uint32(time.Now().UnixNano())
	out := make([]udpFrag, 0, count)
	for i := 0; i < count; i++ {
		start := i * size
		end := start + size
		if end > len(data) {
			end = len(data)
		}
		meta := make([]byte, 12)
		binary.BigEndian.PutUint32(meta[0:4], id)
		binary.BigEndian.PutUint16(meta[4:6], uint16(i))
		binary.BigEndian.PutUint16(meta[6:8], uint16(count))
		binary.BigEndian.PutUint32(meta[8:12], uint32(len(data)))
		out = append(out, udpFrag{meta: meta, data: data[start:end]})
	}
	return out
}

func (s *session) reassembleUDP(data, meta []byte) []byte {
	if len(meta) == 0 {
		return data
	}
	if len(meta) != 12 {
		return nil
	}
	id := binary.BigEndian.Uint32(meta[0:4])
	idx := binary.BigEndian.Uint16(meta[4:6])
	count := int(binary.BigEndian.Uint16(meta[6:8]))
	total := binary.BigEndian.Uint32(meta[8:12])
	if count < 1 || int(idx) >= count || int(total) > s.client.cfg.udpMaxSize {
		return nil
	}
	entry := s.udpReasm[id]
	if entry == nil {
		entry = &udpReasmEntry{count: count, total: total, parts: map[uint16][]byte{}}
		s.udpReasm[id] = entry
	}
	entry.parts[idx] = append([]byte(nil), data...)
	if len(entry.parts) != entry.count {
		return nil
	}
	var out []byte
	for i := 0; i < entry.count; i++ {
		out = append(out, entry.parts[uint16(i)]...)
	}
	delete(s.udpReasm, id)
	if uint32(len(out)) != entry.total {
		return nil
	}
	return out
}
