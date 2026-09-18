package main

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
	"log"
	"net"
	"strconv"
	"time"
)

type socksUDPDatagram struct {
	host    string
	port    int
	payload []byte
}

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
		datagram, err := parseSocksUDPDatagram(buf[:n])
		if err != nil {
			log.Printf("[UDP] dropping malformed SOCKS5 UDP packet: %v", err)
			continue
		}
		if !s.acceptUDPSource(addr) {
			log.Printf("[UDP] dropping packet from non-client address %s", addr.String())
			continue
		}
		s.lastUDPUse = time.Now()
		fragments := fragmentUDP(datagram.payload, s.client.cfg.udpFragSize)
		for idx, frag := range fragments {
			info := map[string][]byte{"CMD": []byte("FORWARD"), "MARK": []byte(s.mark), "IP": []byte(datagram.host), "PORT": []byte(strconv.Itoa(datagram.port)), "DATA": frag.data}
			if frag.meta != nil {
				info["UDPFRAG"] = frag.meta
			}
			if !s.forwardUDPFragment(info, idx+1, len(fragments)) {
				return
			}
		}
		s.recordTune(len(datagram.payload), 0, 0)
	}
}

func parseSocksUDPDatagram(packet []byte) (socksUDPDatagram, error) {
	if len(packet) < 4 {
		return socksUDPDatagram{}, errors.New("packet is shorter than SOCKS5 UDP header")
	}
	if packet[0] != 0 || packet[1] != 0 {
		return socksUDPDatagram{}, errors.New("invalid SOCKS5 UDP RSV field")
	}
	if packet[2] != 0 {
		return socksUDPDatagram{}, errors.New("SOCKS5 UDP fragmentation is not supported")
	}
	offset := 4
	var host string
	switch packet[3] {
	case 1:
		if len(packet) < offset+4+2 {
			return socksUDPDatagram{}, errors.New("truncated SOCKS5 UDP IPv4 address")
		}
		host = net.IP(packet[offset : offset+4]).String()
		offset += 4
	case 3:
		if len(packet) < offset+1 {
			return socksUDPDatagram{}, errors.New("truncated SOCKS5 UDP domain length")
		}
		l := int(packet[offset])
		offset++
		if l == 0 || len(packet) < offset+l+2 {
			return socksUDPDatagram{}, errors.New("truncated SOCKS5 UDP domain address")
		}
		host = string(packet[offset : offset+l])
		offset += l
	case 4:
		if len(packet) < offset+16+2 {
			return socksUDPDatagram{}, errors.New("truncated SOCKS5 UDP IPv6 address")
		}
		host = net.IP(packet[offset : offset+16]).String()
		offset += 16
	default:
		return socksUDPDatagram{}, errors.New("unsupported SOCKS5 UDP ATYP")
	}
	port := int(binary.BigEndian.Uint16(packet[offset : offset+2]))
	offset += 2
	return socksUDPDatagram{host: host, port: port, payload: append([]byte(nil), packet[offset:]...)}, nil
}

func buildSocksUDPDatagram(host string, port int, data []byte) ([]byte, error) {
	if port < 0 || port > 65535 {
		return nil, errors.New("SOCKS5 UDP port is out of range")
	}
	out := []byte{0, 0, 0}
	ip := net.ParseIP(host)
	if ip4 := ip.To4(); ip4 != nil {
		out = append(out, 1)
		out = append(out, ip4...)
	} else if ip16 := ip.To16(); ip16 != nil {
		out = append(out, 4)
		out = append(out, ip16...)
	} else {
		if len(host) == 0 || len(host) > 255 {
			return nil, errors.New("SOCKS5 UDP domain address is too long")
		}
		out = append(out, 3, byte(len(host)))
		out = append(out, []byte(host)...)
	}
	pb := make([]byte, 2)
	binary.BigEndian.PutUint16(pb, uint16(port))
	out = append(out, pb...)
	out = append(out, data...)
	return out, nil
}

func (s *session) acceptUDPSource(addr *net.UDPAddr) bool {
	if addr == nil {
		return false
	}
	if s.udpControlIP != nil && !s.udpControlIP.Equal(addr.IP) {
		return false
	}
	s.udpMu.Lock()
	defer s.udpMu.Unlock()
	if s.udpClient == nil {
		s.udpClient = &net.UDPAddr{IP: append(net.IP(nil), addr.IP...), Port: addr.Port, Zone: addr.Zone}
		return true
	}
	return s.udpClient.Port == addr.Port && s.udpClient.IP.Equal(addr.IP) && s.udpClient.Zone == addr.Zone
}

func (s *session) udpDestination() *net.UDPAddr {
	s.udpMu.Lock()
	defer s.udpMu.Unlock()
	if s.udpClient == nil {
		return nil
	}
	return &net.UDPAddr{IP: append(net.IP(nil), s.udpClient.IP...), Port: s.udpClient.Port, Zone: s.udpClient.Zone}
}

func (s *session) watchUDPControl() {
	buf := make([]byte, 1)
	for {
		if _, err := s.local.Read(buf); err != nil {
			s.close()
			return
		}
	}
}

func (s *session) forwardUDPFragment(info map[string][]byte, index, count int) bool {
	for retry := 0; retry <= s.client.cfg.maxRetry; retry++ {
		rinfo, err := s.client.request(info, 5*time.Second)
		if err == nil && string(rinfo["STATUS"]) == "OK" {
			return true
		}
		if err != nil {
			s.logf(1, "[UDP] FORWARD failed mark=%s fragment=%d/%d retry=%d/%d: %v", s.mark, index, count, retry, s.client.cfg.maxRetry, err)
		} else {
			s.logf(1, "[UDP] FORWARD failed mark=%s fragment=%d/%d retry=%d/%d: status=%s error=%s", s.mark, index, count, retry, s.client.cfg.maxRetry, rinfo["STATUS"], rinfo["ERROR"])
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
