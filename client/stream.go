package main

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go/http3"
)

func (c *client) streamHTTPConnection() (net.Conn, *bufio.Reader, error) {
	u, err := url.Parse(c.sampleURL())
	if err != nil {
		return nil, nil, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, nil, errors.New("full-duplex mode supports only http and https URLs")
	}
	host := u.Hostname()
	if host == "" {
		return nil, nil, errors.New("full-duplex mode got URL without host")
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	path := u.RequestURI()
	if path == "" {
		path = "/"
	}

	conn, err := net.Dial("tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, nil, err
	}
	if u.Scheme == "https" {
		conn = tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: host})
	}

	headers := cloneHeader(c.headers)
	headers.Set("Host", u.Host)
	headers.Set("Accept-Encoding", "identity")
	headers.Set("Connection", "close")
	headers.Del("Content-Length")
	headers.Del("content-length")
	headers.Set("Transfer-Encoding", "chunked")

	var req strings.Builder
	req.WriteString("POST ")
	req.WriteString(path)
	req.WriteString(" HTTP/1.1\r\n")
	for key, values := range headers {
		for _, value := range values {
			req.WriteString(key)
			req.WriteString(": ")
			req.WriteString(value)
			req.WriteString("\r\n")
		}
	}
	req.WriteString("\r\n")
	if _, err := conn.Write([]byte(req.String())); err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	return conn, bufio.NewReader(conn), nil
}

func sendHTTPChunk(conn net.Conn, data []byte) error {
	if _, err := fmt.Fprintf(conn, "%x\r\n", len(data)); err != nil {
		return err
	}
	if _, err := conn.Write(data); err != nil {
		return err
	}
	_, err := conn.Write([]byte("\r\n"))
	return err
}

func finishHTTPChunks(conn net.Conn) error {
	_, err := conn.Write([]byte("0\r\n\r\n"))
	return err
}

func (s *session) sendFullDuplexFrame(conn net.Conn, sendMu *sync.Mutex, info map[string][]byte) error {
	frame := s.client.codec.encodeStreamFrame(info)
	sendMu.Lock()
	defer sendMu.Unlock()
	return sendHTTPChunk(conn, frame)
}

func (s *session) sendHTTP2StreamFrame(w io.Writer, sendMu *sync.Mutex, info map[string][]byte) error {
	frame := s.client.codec.encodeStreamFrame(info)
	sendMu.Lock()
	defer sendMu.Unlock()
	_, err := w.Write(frame)
	return err
}

func (s *session) sendHTTP3StreamFrame(w io.Writer, sendMu *sync.Mutex, info map[string][]byte) error {
	return s.sendHTTP2StreamFrame(w, sendMu, info)
}

func readFullDuplexResponseHeaders(reader *bufio.Reader) (int, map[string]string, error) {
	for {
		statusLine, err := reader.ReadString('\n')
		if err != nil {
			return 0, nil, err
		}
		parts := strings.SplitN(strings.TrimSpace(statusLine), " ", 3)
		if len(parts) < 2 {
			return 0, nil, errors.New("full-duplex HTTP status decode error")
		}
		status, err := strconv.Atoi(parts[1])
		if err != nil {
			return 0, nil, err
		}
		headers := map[string]string{}
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return 0, nil, err
			}
			line = strings.TrimRight(line, "\r\n")
			if line == "" {
				break
			}
			key, value, ok := strings.Cut(line, ":")
			if ok {
				headers[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
			}
		}
		if status != httpContinue {
			return status, headers, nil
		}
	}
}

const httpContinue = 100

func readFullDuplexExact(reader *bufio.Reader, size int) ([]byte, error) {
	data := make([]byte, size)
	_, err := io.ReadFull(reader, data)
	return data, err
}

func iterFullDuplexBody(reader *bufio.Reader, headers map[string]string, yield func([]byte) bool) error {
	if strings.Contains(strings.ToLower(headers["transfer-encoding"]), "chunked") {
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return err
			}
			sizeText := strings.TrimSpace(strings.SplitN(line, ";", 2)[0])
			if sizeText == "" {
				continue
			}
			size64, err := strconv.ParseInt(sizeText, 16, 32)
			if err != nil {
				return err
			}
			if size64 == 0 {
				for {
					trailer, err := reader.ReadString('\n')
					if err != nil {
						return err
					}
					if trailer == "\r\n" || trailer == "\n" {
						return nil
					}
				}
			}
			chunk, err := readFullDuplexExact(reader, int(size64))
			if err != nil {
				return err
			}
			tail, err := readFullDuplexExact(reader, 2)
			if err != nil {
				return err
			}
			if string(tail) != "\r\n" {
				return errors.New("full-duplex HTTP chunk delimiter decode error")
			}
			if len(chunk) > 0 && !yield(chunk) {
				return nil
			}
		}
	}

	if contentLength := strings.TrimSpace(headers["content-length"]); contentLength != "" {
		remaining, err := strconv.Atoi(contentLength)
		if err != nil {
			return err
		}
		for remaining > 0 {
			size := remaining
			if size > 4096 {
				size = 4096
			}
			chunk, err := readFullDuplexExact(reader, size)
			if err != nil {
				return err
			}
			remaining -= len(chunk)
			if !yield(chunk) {
				return nil
			}
		}
		return nil
	}

	buf := make([]byte, 4096)
	for {
		n, err := reader.Read(buf)
		if n > 0 && !yield(buf[:n]) {
			return nil
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

func (s *session) iterFullDuplexFrames(reader *bufio.Reader, headers map[string]string, yield func(map[string][]byte) bool) error {
	buffer := []byte{}
	return iterFullDuplexBody(reader, headers, func(chunk []byte) bool {
		buffer = append(buffer, chunk...)
		for len(buffer) >= 8 {
			frameLen, err := strconv.ParseInt(string(buffer[:8]), 16, 32)
			if err != nil {
				log.Printf("Stream frame length decode error: %v", err)
				return false
			}
			if len(buffer) < 8+int(frameLen) {
				break
			}
			frame := append([]byte(nil), buffer[8:8+int(frameLen)]...)
			buffer = buffer[8+int(frameLen):]
			rinfo, err := s.client.codec.decodeStreamFrame(frame)
			if err != nil {
				log.Printf("Stream frame decode error: %v", err)
				return false
			}
			if !yield(rinfo) {
				return false
			}
		}
		return true
	})
}

func (c *client) probeFullDuplexMode() bool {
	conn, reader, err := c.streamHTTPConnection()
	if err != nil {
		log.Printf("[PROBE] full failed: %v", err)
		return false
	}
	defer conn.Close()

	mark := "__roger_probe__full_go"
	frame := c.codec.encodeStreamFrame(map[string][]byte{"CMD": []byte("PROBE"), "MARK": []byte(mark), "MODE": []byte("full")})
	if err := sendHTTPChunk(conn, frame); err != nil {
		return false
	}
	if err := finishHTTPChunks(conn); err != nil {
		return false
	}
	status, headers, err := readFullDuplexResponseHeaders(reader)
	if err != nil || status < 200 || status >= 300 {
		return false
	}
	var ok bool
	probeSession := &session{client: c}
	_ = probeSession.iterFullDuplexFrames(reader, headers, func(rinfo map[string][]byte) bool {
		ok = string(rinfo["STATUS"]) == "OK"
		return false
	})
	return ok
}

func (c *client) probeHTTP2StreamMode() bool {
	pr, pw := io.Pipe()
	req, err := c.newRequest(http.MethodPost, c.sampleURL(), pr)
	if err != nil {
		return false
	}
	req.Header = cloneHeader(c.headers)
	req.Header.Set("Content-Type", "application/octet-stream")
	respCh := make(chan *http.Response, 1)
	errCh := make(chan error, 1)
	go func() {
		resp, err := c.httpClient.Do(req)
		if err != nil {
			errCh <- err
			return
		}
		respCh <- resp
	}()
	frame := c.codec.encodeStreamFrame(map[string][]byte{"CMD": []byte("PROBE"), "MARK": []byte("__roger_probe__h2_go"), "MODE": []byte("h2")})
	if _, err := pw.Write(frame); err != nil {
		_ = pw.Close()
		return false
	}
	_ = pw.Close()
	select {
	case err := <-errCh:
		log.Printf("[PROBE] h2 failed: %v", err)
		return false
	case resp := <-respCh:
		defer resp.Body.Close()
		if resp.ProtoMajor != 2 || resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return false
		}
		reader := bufio.NewReader(resp.Body)
		rinfo, err := c.codec.readStreamFrame(reader)
		return err == nil && string(rinfo["STATUS"]) == "OK"
	case <-time.After(5 * time.Second):
		_ = pr.Close()
		return false
	}
}

func (c *client) h3Client() *http.Client {
	return &http.Client{
		Timeout: 0,
		Transport: &http3.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				NextProtos:         []string{"h3"},
			},
		},
	}
}

func (c *client) probeHTTP3StreamMode() bool {
	pr, pw := io.Pipe()
	req, err := c.newRequest(http.MethodPost, c.sampleURL(), pr)
	if err != nil {
		return false
	}
	req.Header = cloneHeader(c.headers)
	req.Header.Set("Content-Type", "application/octet-stream")
	respCh := make(chan *http.Response, 1)
	errCh := make(chan error, 1)
	h3Client := c.h3Client()
	go func() {
		resp, err := h3Client.Do(req)
		if err != nil {
			errCh <- err
			return
		}
		respCh <- resp
	}()
	frame := c.codec.encodeStreamFrame(map[string][]byte{"CMD": []byte("PROBE"), "MARK": []byte("__roger_probe__h3_go"), "MODE": []byte("h3")})
	if _, err := pw.Write(frame); err != nil {
		_ = pw.Close()
		return false
	}
	_ = pw.Close()
	select {
	case err := <-errCh:
		log.Printf("[PROBE] h3 failed: %v", err)
		return false
	case resp := <-respCh:
		defer resp.Body.Close()
		if resp.ProtoMajor != 3 || resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return false
		}
		reader := bufio.NewReader(resp.Body)
		rinfo, err := c.codec.readStreamFrame(reader)
		return err == nil && string(rinfo["STATUS"]) == "OK"
	case <-time.After(5 * time.Second):
		_ = pr.Close()
		return false
	}
}

func (s *session) fullDuplexUpload(conn net.Conn, sendMu *sync.Mutex, remoteClosed <-chan struct{}, uploadDone chan<- struct{}) {
	defer close(uploadDone)
	localEOF := false
	if s.cmd == "UDP" {
		s.fullDuplexUDPUpload(conn, sendMu)
		_ = s.sendFullDuplexFrame(conn, sendMu, map[string][]byte{"CMD": []byte("DISCONNECT"), "MARK": []byte(s.mark)})
		_ = finishHTTPChunks(conn)
		return
	}

	buf := make([]byte, s.currentReadBuf())
	for {
		if len(buf) != s.currentReadBuf() {
			buf = make([]byte, s.currentReadBuf())
		}
		n, err := s.local.Read(buf)
		if n > 0 {
			data := append([]byte(nil), buf[:n]...)
			if err := s.sendFullDuplexFrame(conn, sendMu, map[string][]byte{"CMD": []byte("DATA"), "MARK": []byte(s.mark), "DATA": data}); err != nil {
				break
			}
			s.requestCount++
			s.recordTune(len(data), 0, 0)
			log.Printf("[%s:%d] [%s] No.%d >>>> [%d byte]", s.target, s.port, s.mark, s.requestCount, len(data))
		}
		if err != nil {
			if s.client.cfg.halfClose {
				_ = s.sendFullDuplexFrame(conn, sendMu, map[string][]byte{"CMD": []byte("SHUT_WR"), "MARK": []byte(s.mark)})
				s.halfMu.Lock()
				s.localEOF = true
				s.halfMu.Unlock()
				localEOF = true
			}
			break
		}
	}

	if s.client.cfg.halfClose && localEOF {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-s.closed:
				_ = finishHTTPChunks(conn)
				return
			case <-remoteClosed:
				_ = finishHTTPChunks(conn)
				return
			case <-ticker.C:
				if err := s.sendFullDuplexFrame(conn, sendMu, map[string][]byte{"CMD": []byte("HEARTBEAT"), "MARK": []byte(s.mark)}); err != nil {
					_ = finishHTTPChunks(conn)
					return
				}
			}
		}
	}

	if !s.isClosed() {
		_ = s.sendFullDuplexFrame(conn, sendMu, map[string][]byte{"CMD": []byte("DISCONNECT"), "MARK": []byte(s.mark)})
	}
	_ = finishHTTPChunks(conn)
}

func (s *session) fullDuplexUDPUpload(conn net.Conn, sendMu *sync.Mutex) {
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
		port := int(binaryBigEndianUint16(buf[offset : offset+2]))
		offset += 2
		payload := append([]byte(nil), buf[offset:n]...)
		for _, frag := range fragmentUDP(payload, s.client.cfg.udpFragSize) {
			info := map[string][]byte{
				"CMD":  []byte("DATA"),
				"MARK": []byte(s.mark),
				"IP":   []byte(host),
				"PORT": []byte(strconv.Itoa(port)),
				"DATA": frag.data,
			}
			if frag.meta != nil {
				info["UDPFRAG"] = frag.meta
			}
			if err := s.sendFullDuplexFrame(conn, sendMu, info); err != nil {
				return
			}
		}
		s.requestCount++
		s.recordTune(len(payload), 0, 0)
		log.Printf("[%s:%d] [%s] No.%d >>>> [%d byte]", s.target, s.port, s.mark, s.requestCount, len(payload))
	}
}

func (s *session) http2StreamUpload(w io.WriteCloser, sendMu *sync.Mutex, remoteClosed <-chan struct{}, uploadDone chan<- struct{}) {
	defer close(uploadDone)
	defer w.Close()
	localEOF := false
	if s.cmd == "UDP" {
		s.http2StreamUDPUpload(w, sendMu)
		_ = s.sendHTTP2StreamFrame(w, sendMu, map[string][]byte{"CMD": []byte("DISCONNECT"), "MARK": []byte(s.mark)})
		return
	}

	buf := make([]byte, s.currentReadBuf())
	for {
		if len(buf) != s.currentReadBuf() {
			buf = make([]byte, s.currentReadBuf())
		}
		n, err := s.local.Read(buf)
		if n > 0 {
			data := append([]byte(nil), buf[:n]...)
			if err := s.sendHTTP2StreamFrame(w, sendMu, map[string][]byte{"CMD": []byte("DATA"), "MARK": []byte(s.mark), "DATA": data}); err != nil {
				return
			}
			s.requestCount++
			s.recordTune(len(data), 0, 0)
			log.Printf("[%s:%d] [%s] No.%d >>>> [%d byte]", s.target, s.port, s.mark, s.requestCount, len(data))
		}
		if err != nil {
			if s.client.cfg.halfClose {
				_ = s.sendHTTP2StreamFrame(w, sendMu, map[string][]byte{"CMD": []byte("SHUT_WR"), "MARK": []byte(s.mark)})
				s.halfMu.Lock()
				s.localEOF = true
				s.halfMu.Unlock()
				localEOF = true
			}
			break
		}
	}

	if s.client.cfg.halfClose && localEOF {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-s.closed:
				return
			case <-remoteClosed:
				return
			case <-ticker.C:
				if err := s.sendHTTP2StreamFrame(w, sendMu, map[string][]byte{"CMD": []byte("HEARTBEAT"), "MARK": []byte(s.mark)}); err != nil {
					return
				}
			}
		}
	}

	if !s.isClosed() {
		_ = s.sendHTTP2StreamFrame(w, sendMu, map[string][]byte{"CMD": []byte("DISCONNECT"), "MARK": []byte(s.mark)})
	}
}

func (s *session) http2StreamUDPUpload(w io.Writer, sendMu *sync.Mutex) {
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
		port := int(binaryBigEndianUint16(buf[offset : offset+2]))
		offset += 2
		payload := append([]byte(nil), buf[offset:n]...)
		for _, frag := range fragmentUDP(payload, s.client.cfg.udpFragSize) {
			info := map[string][]byte{
				"CMD":  []byte("DATA"),
				"MARK": []byte(s.mark),
				"IP":   []byte(host),
				"PORT": []byte(strconv.Itoa(port)),
				"DATA": frag.data,
			}
			if frag.meta != nil {
				info["UDPFRAG"] = frag.meta
			}
			if err := s.sendHTTP2StreamFrame(w, sendMu, info); err != nil {
				return
			}
		}
		s.requestCount++
		s.recordTune(len(payload), 0, 0)
		log.Printf("[%s:%d] [%s] No.%d >>>> [%d byte]", s.target, s.port, s.mark, s.requestCount, len(payload))
	}
}

func binaryBigEndianUint16(data []byte) uint16 {
	return uint16(data[0])<<8 | uint16(data[1])
}

func (s *session) fullDuplexExchange() bool {
	conn, reader, err := s.client.streamHTTPConnection()
	if err != nil {
		log.Printf("[FULL-DUPLEX] %v", err)
		s.close()
		return false
	}
	defer conn.Close()

	sendMu := &sync.Mutex{}
	if err := s.sendFullDuplexFrame(conn, sendMu, map[string][]byte{"CMD": []byte("DUPLEX"), "MARK": []byte(s.mark)}); err != nil {
		s.close()
		return false
	}

	status, headers, err := readFullDuplexResponseHeaders(reader)
	if err != nil || status < 200 || status >= 300 {
		log.Printf("[FULL-DUPLEX] response status/read failed: %v", err)
		s.close()
		return false
	}

	remoteClosed := make(chan struct{})
	var remoteOnce sync.Once
	uploadDone := make(chan struct{})
	go s.fullDuplexUpload(conn, sendMu, remoteClosed, uploadDone)

	succeeded := false
	remoteEOF := false
	err = s.iterFullDuplexFrames(reader, headers, func(rinfo map[string][]byte) bool {
		if s.isClosed() {
			return false
		}
		succeeded = true
		if s.client.cfg.halfClose && string(rinfo["CMD"]) == "SHUT_WR" {
			remoteEOF = true
			remoteOnce.Do(func() { close(remoteClosed) })
		}
		keep := s.handleDownlinkInfo(rinfo)
		if s.client.cfg.halfClose {
			select {
			case <-uploadDone:
				if s.halfComplete() {
					return false
				}
			default:
			}
		}
		return keep
	})
	remoteOnce.Do(func() { close(remoteClosed) })
	if err != nil && !s.isClosed() {
		log.Printf("[FULL-DUPLEX] %v", err)
	}

	if s.cmd != "UDP" && remoteEOF {
		s.closeIfHalfComplete()
	} else if !s.isClosed() && succeeded {
		s.close()
	}
	return succeeded
}

func (s *session) http2StreamExchange() bool {
	pr, pw := io.Pipe()
	req, err := s.client.newRequest(http.MethodPost, s.client.sampleURL(), pr)
	if err != nil {
		log.Printf("[H2] %v", err)
		s.close()
		return false
	}
	req.Header = cloneHeader(s.client.headers)
	req.Header.Set("Content-Type", "application/octet-stream")

	respCh := make(chan *http.Response, 1)
	errCh := make(chan error, 1)
	go func() {
		resp, err := s.client.httpClient.Do(req)
		if err != nil {
			errCh <- err
			return
		}
		respCh <- resp
	}()

	sendMu := &sync.Mutex{}
	if err := s.sendHTTP2StreamFrame(pw, sendMu, map[string][]byte{"CMD": []byte("DUPLEX"), "MARK": []byte(s.mark)}); err != nil {
		_ = pw.Close()
		s.close()
		return false
	}

	var resp *http.Response
	select {
	case err := <-errCh:
		log.Printf("[H2] request failed: %v", err)
		_ = pw.Close()
		s.close()
		return false
	case resp = <-respCh:
	case <-time.After(10 * time.Second):
		log.Printf("[H2] response timeout")
		_ = pw.Close()
		s.close()
		return false
	}
	defer resp.Body.Close()
	if resp.ProtoMajor != 2 || resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Printf("[H2] response status/proto failed: %s %s", resp.Proto, resp.Status)
		_ = pw.Close()
		s.close()
		return false
	}

	remoteClosed := make(chan struct{})
	var remoteOnce sync.Once
	uploadDone := make(chan struct{})
	go s.http2StreamUpload(pw, sendMu, remoteClosed, uploadDone)

	succeeded := false
	remoteEOF := false
	reader := bufio.NewReader(resp.Body)
	for {
		rinfo, err := s.client.codec.readStreamFrame(reader)
		if err != nil {
			if !s.isClosed() {
				log.Printf("[H2] %v", err)
			}
			break
		}
		if s.isClosed() {
			break
		}
		succeeded = true
		if s.client.cfg.halfClose && string(rinfo["CMD"]) == "SHUT_WR" {
			remoteEOF = true
			remoteOnce.Do(func() { close(remoteClosed) })
		}
		keep := s.handleDownlinkInfo(rinfo)
		if s.client.cfg.halfClose {
			select {
			case <-uploadDone:
				if s.halfComplete() {
					remoteOnce.Do(func() { close(remoteClosed) })
					return true
				}
			default:
			}
		}
		if !keep {
			break
		}
	}
	remoteOnce.Do(func() { close(remoteClosed) })
	if s.cmd != "UDP" && remoteEOF {
		s.closeIfHalfComplete()
	} else if !s.isClosed() && succeeded {
		s.close()
	}
	return succeeded
}

func (s *session) http3StreamExchange() bool {
	pr, pw := io.Pipe()
	req, err := s.client.newRequest(http.MethodPost, s.client.sampleURL(), pr)
	if err != nil {
		log.Printf("[H3] %v", err)
		s.close()
		return false
	}
	req.Header = cloneHeader(s.client.headers)
	req.Header.Set("Content-Type", "application/octet-stream")

	h3Client := s.client.h3Client()
	respCh := make(chan *http.Response, 1)
	errCh := make(chan error, 1)
	go func() {
		resp, err := h3Client.Do(req)
		if err != nil {
			errCh <- err
			return
		}
		respCh <- resp
	}()

	sendMu := &sync.Mutex{}
	if err := s.sendHTTP3StreamFrame(pw, sendMu, map[string][]byte{"CMD": []byte("DUPLEX"), "MARK": []byte(s.mark)}); err != nil {
		_ = pw.Close()
		s.close()
		return false
	}

	var resp *http.Response
	select {
	case err := <-errCh:
		log.Printf("[H3] request failed: %v", err)
		_ = pw.Close()
		s.close()
		return false
	case resp = <-respCh:
	case <-time.After(10 * time.Second):
		log.Printf("[H3] response timeout")
		_ = pw.Close()
		s.close()
		return false
	}
	defer resp.Body.Close()
	if resp.ProtoMajor != 3 || resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Printf("[H3] response status/proto failed: %s %s", resp.Proto, resp.Status)
		_ = pw.Close()
		s.close()
		return false
	}

	remoteClosed := make(chan struct{})
	var remoteOnce sync.Once
	uploadDone := make(chan struct{})
	go s.http2StreamUpload(pw, sendMu, remoteClosed, uploadDone)

	succeeded := false
	remoteEOF := false
	reader := bufio.NewReader(resp.Body)
	for {
		rinfo, err := s.client.codec.readStreamFrame(reader)
		if err != nil {
			if !s.isClosed() {
				log.Printf("[H3] %v", err)
			}
			break
		}
		if s.isClosed() {
			break
		}
		succeeded = true
		if s.client.cfg.halfClose && string(rinfo["CMD"]) == "SHUT_WR" {
			remoteEOF = true
			remoteOnce.Do(func() { close(remoteClosed) })
		}
		keep := s.handleDownlinkInfo(rinfo)
		if s.client.cfg.halfClose {
			select {
			case <-uploadDone:
				if s.halfComplete() {
					remoteOnce.Do(func() { close(remoteClosed) })
					return true
				}
			default:
			}
		}
		if !keep {
			break
		}
	}
	remoteOnce.Do(func() { close(remoteClosed) })
	if s.cmd != "UDP" && remoteEOF {
		s.closeIfHalfComplete()
	} else if !s.isClosed() && succeeded {
		s.close()
	}
	return succeeded
}

func (s *session) halfComplete() bool {
	s.halfMu.Lock()
	defer s.halfMu.Unlock()
	return s.localEOF && s.remoteEOF
}
