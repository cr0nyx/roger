package main

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestParseSocksUDPDatagram(t *testing.T) {
	packet := []byte{0, 0, 0, 1, 192, 0, 2, 10, 0x12, 0x34, 'o', 'k'}
	datagram, err := parseSocksUDPDatagram(packet)
	if err != nil {
		t.Fatalf("parse IPv4 datagram: %v", err)
	}
	if datagram.host != "192.0.2.10" || datagram.port != 0x1234 || string(datagram.payload) != "ok" {
		t.Fatalf("unexpected datagram: %#v", datagram)
	}

	packet = []byte{0, 0, 0, 3, 11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'o', 'r', 'g', 0, 53, 'q'}
	datagram, err = parseSocksUDPDatagram(packet)
	if err != nil {
		t.Fatalf("parse domain datagram: %v", err)
	}
	if datagram.host != "example.org" || datagram.port != 53 || string(datagram.payload) != "q" {
		t.Fatalf("unexpected domain datagram: %#v", datagram)
	}
}

func TestParseSocksUDPDatagramRejectsMalformed(t *testing.T) {
	cases := [][]byte{
		{},
		{0, 1, 0, 1, 127, 0, 0, 1, 0, 53},
		{0, 0, 1, 1, 127, 0, 0, 1, 0, 53},
		{0, 0, 0, 1, 127},
		{0, 0, 0, 3, 4, 't', 'e'},
		{0, 0, 0, 9, 0, 53},
	}
	for _, packet := range cases {
		if _, err := parseSocksUDPDatagram(packet); err == nil {
			t.Fatalf("expected malformed packet to fail: %#v", packet)
		}
	}
}

func TestBuildSocksUDPDatagramRoundTrip(t *testing.T) {
	cases := []struct {
		host string
		port int
		data []byte
	}{
		{"192.0.2.10", 53, []byte("ipv4")},
		{"2001:db8::1", 5353, []byte("ipv6")},
		{"example.org", 12345, []byte("domain")},
	}
	for _, tc := range cases {
		packet, err := buildSocksUDPDatagram(tc.host, tc.port, tc.data)
		if err != nil {
			t.Fatalf("build datagram for %s: %v", tc.host, err)
		}
		got, err := parseSocksUDPDatagram(packet)
		if err != nil {
			t.Fatalf("parse built datagram for %s: %v", tc.host, err)
		}
		if got.port != tc.port || !bytes.Equal(got.payload, tc.data) {
			t.Fatalf("round trip mismatch for %s: %#v", tc.host, got)
		}
		if net.ParseIP(tc.host) == nil && got.host != tc.host {
			t.Fatalf("domain host mismatch: %q", got.host)
		}
	}

	if _, err := buildSocksUDPDatagram("example.org", 65536, nil); err == nil {
		t.Fatalf("expected invalid port to fail")
	}
	if _, err := buildSocksUDPDatagram("", 53, nil); err == nil {
		t.Fatalf("expected empty domain to fail")
	}
}

func TestUDPSourceIsLockedToControlIPAndFirstDatagramAddress(t *testing.T) {
	cfg := defaultConfig()
	s := &session{
		client:       &client{cfg: cfg},
		udpControlIP: net.ParseIP("10.0.0.1"),
	}

	first := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1000}
	if !s.acceptUDPSource(first) {
		t.Fatalf("first UDP source should be accepted")
	}
	if !s.acceptUDPSource(&net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1000}) {
		t.Fatalf("same UDP source should be accepted")
	}
	if s.acceptUDPSource(&net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1001}) {
		t.Fatalf("different UDP source port should be rejected")
	}
	if s.acceptUDPSource(&net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 1000}) {
		t.Fatalf("different UDP source IP should be rejected")
	}

	dst := s.udpDestination()
	if dst == nil || !dst.IP.Equal(first.IP) || dst.Port != first.Port {
		t.Fatalf("unexpected UDP destination: %#v", dst)
	}
	dst.Port = 2000
	if s.udpDestination().Port != first.Port {
		t.Fatalf("udpDestination should return a copy")
	}
}

func TestUDPFragmentationAndReassembly(t *testing.T) {
	cfg := defaultConfig()
	cfg.udpMaxSize = 1024
	s := &session{client: &client{cfg: cfg}, udpReasm: map[uint32]*udpReasmEntry{}}
	data := []byte("hello fragmented datagram")

	frags := fragmentUDP(data, 5)
	if len(frags) < 2 {
		t.Fatalf("expected multiple fragments, got %d", len(frags))
	}
	for i, frag := range frags {
		got := s.reassembleUDP(frag.data, frag.meta)
		if i < len(frags)-1 && got != nil {
			t.Fatalf("reassembly completed too early at fragment %d", i)
		}
		if i == len(frags)-1 && !bytes.Equal(got, data) {
			t.Fatalf("reassembled data = %q", got)
		}
	}

	if got := s.reassembleUDP([]byte("whole"), nil); string(got) != "whole" {
		t.Fatalf("packet without UDPFRAG should be treated as whole datagram: %q", got)
	}
	if got := s.reassembleUDP([]byte("bad"), []byte{1, 2}); got != nil {
		t.Fatalf("bad fragment metadata should be rejected")
	}

	meta := make([]byte, 12)
	binary.BigEndian.PutUint32(meta[0:4], 1)
	binary.BigEndian.PutUint16(meta[4:6], 0)
	binary.BigEndian.PutUint16(meta[6:8], 1)
	binary.BigEndian.PutUint32(meta[8:12], uint32(cfg.udpMaxSize+1))
	if got := s.reassembleUDP([]byte("too-big"), meta); got != nil {
		t.Fatalf("oversized reassembly should be rejected")
	}
}

func TestUDPReassemblyExpiresIncompleteFragments(t *testing.T) {
	cfg := defaultConfig()
	cfg.udpMaxSize = 1024
	s := &session{client: &client{cfg: cfg}, udpReasm: map[uint32]*udpReasmEntry{
		99: &udpReasmEntry{count: 2, total: 10, created: time.Now().Add(-udpReassemblyTTL - time.Second), parts: map[uint16][]byte{0: []byte("old")}},
	}}
	meta := make([]byte, 12)
	binary.BigEndian.PutUint32(meta[0:4], 1)
	binary.BigEndian.PutUint16(meta[4:6], 0)
	binary.BigEndian.PutUint16(meta[6:8], 2)
	binary.BigEndian.PutUint32(meta[8:12], 10)
	if got := s.reassembleUDP([]byte("new"), meta); got != nil {
		t.Fatalf("first fragment should not complete reassembly")
	}
	if _, ok := s.udpReasm[99]; ok {
		t.Fatalf("expired incomplete fragment set should be removed")
	}
}
