package main

import (
	"bufio"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strings"
)

func (s *session) handleSocks5() error {
	br := bufio.NewReader(s.local)
	ver, err := br.ReadByte()
	if err != nil {
		return err
	}
	if ver != socksVersion {
		return errors.New("only SOCKS5 is supported")
	}
	nmethods, _ := br.ReadByte()
	methods := make([]byte, int(nmethods))
	if nmethods > 0 {
		if _, err := io.ReadFull(br, methods); err != nil {
			return err
		}
	}
	if s.client.cfg.socksUser != "" {
		if !hasSocksMethod(methods, socksUserPass) {
			_, _ = s.local.Write([]byte{socksVersion, socksNoMethod})
			return errors.New("SOCKS5 client does not support username/password authentication")
		}
		if _, err := s.local.Write([]byte{socksVersion, socksUserPass}); err != nil {
			return err
		}
		if err := s.handleSocksAuth(br); err != nil {
			return err
		}
	} else {
		if !hasSocksMethod(methods, socksNoAuth) {
			_, _ = s.local.Write([]byte{socksVersion, socksNoMethod})
			return errors.New("SOCKS5 client does not support no-auth method")
		}
		if _, err := s.local.Write([]byte{socksVersion, socksNoAuth}); err != nil {
			return err
		}
	}
	first, err := br.ReadByte()
	if err != nil {
		return err
	}
	h := make([]byte, 4)
	if first == 0x02 {
		if _, err := io.ReadFull(br, h); err != nil {
			return err
		}
	} else {
		h[0] = first
		if _, err := io.ReadFull(br, h[1:]); err != nil {
			return err
		}
	}
	cmd, atyp := h[1], h[3]
	host, err := readSocksAddr(br, atyp)
	if err != nil {
		return err
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(br, pb); err != nil {
		return err
	}
	port := int(binary.BigEndian.Uint16(pb))
	if isBlacklisted(host, s.client.cfg.blacklist) {
		_ = s.socksReply(socksRefused, net.IPv4(127, 0, 0, 1), port)
		return errors.New("host is blacklisted")
	}
	if s.client.cfg.localDNS {
		if ips, err := net.LookupIP(host); err == nil && len(ips) > 0 {
			host = ips[0].String()
		}
	}

	switch cmd {
	case 1:
		s.cmd, s.target, s.port = "CONNECT", host, port
		if err := s.setupRemote(); err != nil {
			_ = s.socksReply(socksRefused, net.IPv4(127, 0, 0, 1), port)
			return err
		}
		return s.socksReply(socksOK, parseIPv4(host, net.IPv4(127, 0, 0, 1)), port)
	case 2:
		s.cmd, s.target, s.port = "BIND", host, port
		ip, bindPort, err := s.setupBind()
		if err != nil {
			_ = s.socksReply(socksRefused, net.IPv4(0, 0, 0, 0), port)
			return err
		}
		if err := s.socksReply(socksOK, parseIPv4(ip, net.IPv4(0, 0, 0, 0)), bindPort); err != nil {
			return err
		}
		peerIP, peerPort, err := s.waitBindPeer()
		if err != nil {
			return err
		}
		s.target, s.port = peerIP, peerPort
		return s.socksReply(socksOK, parseIPv4(peerIP, net.IPv4(0, 0, 0, 0)), peerPort)
	case 3:
		s.cmd, s.target, s.port = "UDP", host, port
		if err := s.setupUDP(); err != nil {
			_ = s.socksReply(socksRefused, net.IPv4(0, 0, 0, 0), port)
			return err
		}
		addr := s.udpConn.LocalAddr().(*net.UDPAddr)
		return s.socksReply(socksOK, net.IPv4(0, 0, 0, 0), addr.Port)
	default:
		return errors.New("unsupported SOCKS5 command")
	}
}

func (s *session) handleSocksAuth(br *bufio.Reader) error {
	ver, err := br.ReadByte()
	if err != nil {
		return err
	}
	if ver != 0x01 {
		_, _ = s.local.Write([]byte{0x01, 0x01})
		return errors.New("invalid SOCKS5 username/password auth version")
	}
	ulen, err := br.ReadByte()
	if err != nil {
		return err
	}
	username := make([]byte, int(ulen))
	if _, err := io.ReadFull(br, username); err != nil {
		return err
	}
	plen, err := br.ReadByte()
	if err != nil {
		return err
	}
	password := make([]byte, int(plen))
	if _, err := io.ReadFull(br, password); err != nil {
		return err
	}
	sum := md5.Sum(password)
	passwordHash := hex.EncodeToString(sum[:])
	if string(username) != s.client.cfg.socksUser || !strings.EqualFold(passwordHash, s.client.cfg.socksHash) {
		_, _ = s.local.Write([]byte{0x01, 0x01})
		return errors.New("SOCKS5 username/password authentication failed")
	}
	_, err = s.local.Write([]byte{0x01, 0x00})
	return err
}

func hasSocksMethod(methods []byte, method byte) bool {
	for _, item := range methods {
		if item == method {
			return true
		}
	}
	return false
}

func readSocksAddr(r *bufio.Reader, atyp byte) (string, error) {
	switch atyp {
	case 1:
		ip := make([]byte, 4)
		_, err := io.ReadFull(r, ip)
		return net.IP(ip).String(), err
	case 3:
		n, err := r.ReadByte()
		if err != nil {
			return "", err
		}
		name := make([]byte, int(n))
		_, err = io.ReadFull(r, name)
		return string(name), err
	case 4:
		ip := make([]byte, 16)
		_, err := io.ReadFull(r, ip)
		return net.IP(ip).String(), err
	default:
		return "", errors.New("unsupported address type")
	}
}

func (s *session) socksReply(status byte, ip net.IP, port int) error {
	if ip4 := ip.To4(); ip4 != nil {
		msg := []byte{socksVersion, status, 0, 1}
		msg = append(msg, ip4...)
		p := make([]byte, 2)
		binary.BigEndian.PutUint16(p, uint16(port))
		msg = append(msg, p...)
		_, err := s.local.Write(msg)
		return err
	}
	return errors.New("only IPv4 replies are implemented")
}
