package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func (c *client) handleLocal(conn net.Conn) {
	s := &session{
		client:       c,
		local:        conn,
		closed:       make(chan struct{}),
		udpReasm:     map[uint32]*udpReasmEntry{},
		lastUDPUse:   time.Now(),
		activeMode:   c.cfg.mode,
		readBuf:      c.cfg.readBuf,
		maxReadSize:  c.cfg.maxReadSize,
		tuneStart:    time.Now(),
		tuneLastData: time.Now(),
	}
	if c.cfg.target != "" {
		if err := s.handleFixedTarget(); err != nil {
			log.Printf("[PORT FWD] %v", err)
			conn.Close()
			return
		}
	} else {
		if err := s.handleSocks5(); err != nil {
			log.Printf("[SOCKS5] %v", err)
			conn.Close()
			return
		}
	}
	if s.activeMode == "h3" {
		s.http3StreamExchange()
		return
	}
	if s.activeMode == "h2" {
		s.http2StreamExchange()
		return
	}
	if s.activeMode == "full-duplex" {
		s.fullDuplexExchange()
		return
	}
	if s.cmd == "UDP" {
		if s.activeMode == "half-duplex" {
			go s.halfDownlinkReader()
		} else {
			go s.udpReader()
		}
		s.udpWriter()
		return
	}
	if s.activeMode == "half-duplex" {
		go s.halfDownlinkReader()
	} else {
		go s.classicReader()
	}
	s.writer()
}

func (s *session) handleFixedTarget() error {
	host, portText, err := net.SplitHostPort(s.client.cfg.target)
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return err
	}
	s.cmd, s.target, s.port = "CONNECT", host, port
	return s.setupRemote()
}

func (c *client) handleRemoteForward() error {
	localHost, localPortText, err := net.SplitHostPort(c.cfg.target)
	if err != nil {
		return err
	}
	localPort, err := strconv.Atoi(localPortText)
	if err != nil {
		return err
	}
	s := &session{
		client:       c,
		cmd:          "BIND",
		target:       c.cfg.listen,
		port:         c.cfg.port,
		closed:       make(chan struct{}),
		udpReasm:     map[uint32]*udpReasmEntry{},
		lastUDPUse:   time.Now(),
		activeMode:   c.cfg.mode,
		readBuf:      c.cfg.readBuf,
		maxReadSize:  c.cfg.maxReadSize,
		tuneStart:    time.Now(),
		tuneLastData: time.Now(),
	}
	bindIP, bindPort, err := s.setupBind()
	if err != nil {
		return err
	}
	log.Printf("[REMOTE FWD] Waiting for peer on %s:%d", bindIP, bindPort)
	peerIP, peerPort, err := s.waitBindPeer()
	if err != nil {
		s.closeNoLocal()
		return err
	}
	log.Printf("[REMOTE FWD] Peer %s:%d connected, dialing local %s:%d", peerIP, peerPort, localHost, localPort)
	local, err := net.Dial("tcp", net.JoinHostPort(localHost, strconv.Itoa(localPort)))
	if err != nil {
		s.closeNoLocal()
		return err
	}
	s.local = local
	s.target, s.port = peerIP, peerPort
	s.bridge()
	return nil
}

func (s *session) bridge() {
	if s.activeMode == "h3" {
		s.http3StreamExchange()
		return
	}
	if s.activeMode == "h2" {
		s.http2StreamExchange()
		return
	}
	if s.activeMode == "full-duplex" {
		s.fullDuplexExchange()
		return
	}
	if s.activeMode == "half-duplex" {
		go s.halfDownlinkReader()
	} else {
		go s.classicReader()
	}
	s.writer()
}

func (s *session) setupRemote() error {
	s.mark = randMark()
	info := s.sessionInfo("CONNECT")
	info["IP"] = []byte(s.target)
	info["PORT"] = []byte(strconv.Itoa(s.port))
	return s.setupRequest(info)
}

func (s *session) setupBind() (string, int, error) {
	s.mark = randMark()
	info := s.sessionInfo("BIND")
	info["IP"] = []byte(s.target)
	info["PORT"] = []byte(strconv.Itoa(s.port))
	if s.isAsyncSetup() {
		_ = s.setupRequest(info)
		return s.target, s.port, nil
	}
	rinfo, err := s.client.request(info, 0)
	if err != nil {
		return "", 0, err
	}
	if string(rinfo["STATUS"]) != "OK" {
		return "", 0, fmt.Errorf("BIND failed: %s", rinfo["ERROR"])
	}
	ip := string(rinfo["IP"])
	port, _ := strconv.Atoi(string(rinfo["PORT"]))
	return ip, port, nil
}

func (s *session) setupUDP() error {
	s.mark = randMark()
	info := s.sessionInfo("UDP")
	info["IP"] = []byte(s.target)
	info["PORT"] = []byte(strconv.Itoa(s.port))
	if err := s.setupRequest(info); err != nil {
		return err
	}
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return err
	}
	s.udpConn = udp
	return nil
}

func (s *session) setupRequest(info map[string][]byte) error {
	timeout := time.Duration(0)
	if s.isAsyncSetup() {
		timeout = s.client.cfg.phpConnectTimeout
	}
	rinfo, err := s.client.request(info, timeout)
	if err != nil && s.isAsyncSetup() {
		return nil
	}
	if err != nil {
		return err
	}
	if string(rinfo["STATUS"]) != "OK" {
		return fmt.Errorf("%s failed: %s", info["CMD"], rinfo["ERROR"])
	}
	return nil
}

func (s *session) isAsyncSetup() bool {
	return s.client.cfg.asyncConnect || strings.Contains(s.client.cfg.urls[0], ".php")
}

func (s *session) waitBindPeer() (string, int, error) {
	for i := 0; i < 300; i++ {
		rinfo, err := s.client.request(map[string][]byte{"CMD": []byte("CHECK"), "MARK": []byte(s.mark)}, 5*time.Second)
		if err == nil && string(rinfo["STATUS"]) == "OK" && len(rinfo["IP"]) > 0 {
			port, _ := strconv.Atoi(string(rinfo["PORT"]))
			return string(rinfo["IP"]), port, nil
		}
		time.Sleep(s.client.cfg.readInterval)
	}
	return "", 0, errors.New("BIND peer did not connect")
}

func (s *session) sessionInfo(cmd string) map[string][]byte {
	info := map[string][]byte{"CMD": []byte(cmd), "MARK": []byte(s.mark)}
	info["READBUF"] = []byte(strconv.Itoa(s.currentReadBuf()))
	info["MAXREADSIZE"] = []byte(strconv.Itoa(s.currentMaxReadSize()))
	info["UDPFRAGSIZE"] = []byte(strconv.Itoa(s.client.cfg.udpFragSize))
	if s.client.cfg.halfClose {
		info["HALFCLOSE"] = []byte("1")
	} else {
		info["HALFCLOSE"] = []byte("0")
	}
	info["CLIENTCOMP"] = []byte(s.client.cfg.clientCompression)
	info["SERVERCOMP"] = []byte(s.client.cfg.serverCompression)
	info["CLIENTOPTLIMIT"] = []byte(strconv.Itoa(s.client.cfg.clientOptimalLimit))
	info["SERVEROPTLIMIT"] = []byte(strconv.Itoa(s.client.cfg.serverOptimalLimit))
	info["UDPTIMEOUT"] = []byte(strconv.Itoa(s.client.cfg.udpTimeout))
	info["MODE"] = []byte(protocolTransportMode(s.activeMode))
	return info
}

func (s *session) writer() {
	localEOF := false
	defer func() {
		if localEOF {
			s.closeIfHalfComplete()
			return
		}
		s.close()
	}()
	buf := make([]byte, s.currentReadBuf())
	for {
		if len(buf) != s.currentReadBuf() {
			buf = make([]byte, s.currentReadBuf())
		}
		n, err := s.local.Read(buf)
		if n > 0 {
			data := append([]byte(nil), buf[:n]...)
			info := map[string][]byte{"CMD": []byte("FORWARD"), "MARK": []byte(s.mark), "DATA": data}
			rinfo, reqErr := s.client.request(info, 0)
			if reqErr != nil || string(rinfo["STATUS"]) != "OK" {
				s.recordTune(0, 0, 1)
				return
			}
			s.requestCount++
			s.recordTune(len(data), 0, 0)
			log.Printf("[%s:%d] [%s] No.%d >>>> [%d byte]", s.target, s.port, s.mark, s.requestCount, len(data))
		}
		if err != nil {
			if s.client.cfg.halfClose && s.cmd != "UDP" {
				localEOF = s.shutdownRemoteWrite() == nil
				s.closeIfHalfComplete()
				return
			}
			return
		}
	}
}

func (s *session) classicReader() {
	remoteEOF := false
	defer func() {
		if remoteEOF {
			s.closeIfHalfComplete()
			return
		}
		s.close()
	}()
	for {
		select {
		case <-s.closed:
			return
		default:
		}
		rinfo, err := s.client.request(map[string][]byte{"CMD": []byte("READ"), "MARK": []byte(s.mark)}, 0)
		if err != nil || string(rinfo["STATUS"]) != "OK" {
			return
		}
		if s.client.cfg.halfClose && string(rinfo["CMD"]) == "SHUT_WR" {
			remoteEOF = true
		}
		if !s.handleDownlinkInfo(rinfo) {
			return
		}
		if remoteEOF {
			return
		}
		if len(rinfo["DATA"]) < 500 {
			time.Sleep(s.client.cfg.readInterval)
		}
	}
}

func (s *session) halfDownlinkReader() {
	remoteEOF := false
	defer func() {
		if remoteEOF {
			s.closeIfHalfComplete()
			return
		}
		s.close()
	}()
	info := map[string][]byte{"CMD": []byte("DOWNLINK"), "MARK": []byte(s.mark)}
	body := s.client.codec.encodeBody(info)
	req, err := s.client.newRequest(http.MethodPost, s.client.sampleURL(), strings.NewReader(body))
	if err != nil {
		return
	}
	req.Header = cloneHeader(s.client.headers)
	if s.client.cfg.httpVersion != "2" {
		req.Header.Set("Connection", "close")
	}
	resp, err := s.client.httpClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	reader := bufio.NewReader(resp.Body)
	for {
		select {
		case <-s.closed:
			return
		default:
		}
		rinfo, err := s.client.codec.readStreamFrame(reader)
		if err != nil {
			return
		}
		if s.client.cfg.halfClose && string(rinfo["CMD"]) == "SHUT_WR" {
			remoteEOF = true
		}
		if !s.handleDownlinkInfo(rinfo) {
			return
		}
		if remoteEOF {
			return
		}
	}
}

func (s *session) handleDownlinkInfo(rinfo map[string][]byte) bool {
	if string(rinfo["CMD"]) == "HEARTBEAT" {
		return true
	}
	if string(rinfo["STATUS"]) != "OK" {
		return false
	}
	remoteWriteClosed := s.client.cfg.halfClose && string(rinfo["CMD"]) == "SHUT_WR"
	data := rinfo["DATA"]
	if s.cmd == "UDP" {
		out := s.reassembleUDP(data, rinfo["UDPFRAG"])
		if out == nil {
			return true
		}
		data = out
		if s.udpClient == nil {
			return true
		}
		addr := append([]byte{0, 0, 0, 1}, net.ParseIP(string(rinfo["IP"])).To4()...)
		pb := make([]byte, 2)
		p, _ := strconv.Atoi(string(rinfo["PORT"]))
		binary.BigEndian.PutUint16(pb, uint16(p))
		packet := append(addr, pb...)
		packet = append(packet, data...)
		_, _ = s.udpConn.WriteToUDP(packet, s.udpClient)
		s.recordTune(0, len(data), 0)
		return true
	}
	if len(data) > 0 {
		_, err := s.local.Write(data)
		if err != nil {
			return false
		}
		s.replyCount++
		s.recordTune(0, len(data), 0)
		log.Printf("[%s:%d] [%s] No.%d <<<< [%d byte]", s.target, s.port, s.mark, s.replyCount, len(data))
	}
	if remoteWriteClosed {
		if tcp, ok := s.local.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		s.halfMu.Lock()
		s.remoteEOF = true
		s.halfMu.Unlock()
		s.closeIfHalfComplete()
	}
	return true
}

func (s *session) shutdownRemoteWrite() error {
	if !s.client.cfg.halfClose || s.mark == "" {
		return errors.New("half-close mode is disabled")
	}
	info := map[string][]byte{"CMD": []byte("SHUT_WR"), "MARK": []byte(s.mark)}
	rinfo, err := s.client.request(info, 0)
	if err != nil {
		return err
	}
	if string(rinfo["STATUS"]) != "OK" {
		return fmt.Errorf("SHUT_WR failed: %s", rinfo["ERROR"])
	}
	s.halfMu.Lock()
	s.localEOF = true
	s.halfMu.Unlock()
	return nil
}

func (s *session) closeIfHalfComplete() {
	s.halfMu.Lock()
	done := s.localEOF && s.remoteEOF
	s.halfMu.Unlock()
	if done {
		s.close()
	}
}

func (s *session) isClosed() bool {
	select {
	case <-s.closed:
		return true
	default:
		return false
	}
}

func (s *session) close() {
	s.closeOnce.Do(func() {
		close(s.closed)
		if s.local != nil {
			_ = s.local.Close()
		}
		if s.udpConn != nil {
			_ = s.udpConn.Close()
		}
		if s.mark != "" {
			_, _ = s.client.request(map[string][]byte{"CMD": []byte("DISCONNECT"), "MARK": []byte(s.mark)}, 5*time.Second)
		}
	})
}

func (s *session) closeNoLocal() {
	s.closeOnce.Do(func() {
		close(s.closed)
		if s.udpConn != nil {
			_ = s.udpConn.Close()
		}
		if s.mark != "" {
			_, _ = s.client.request(map[string][]byte{"CMD": []byte("DISCONNECT"), "MARK": []byte(s.mark)}, 5*time.Second)
		}
	})
}
