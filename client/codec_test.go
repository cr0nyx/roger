package main

import (
	"bufio"
	"bytes"
	"strconv"
	"testing"
)

func newTestCodec(t *testing.T, cfg *config) *codec {
	t.Helper()
	if cfg == nil {
		cfg = defaultConfig()
	}
	cfg.key = "debug"
	c, err := newCodec(cfg.key, cfg)
	if err != nil {
		t.Fatalf("newCodec: %v", err)
	}
	return c
}

func TestCodecBodyRoundTripPlainAndCompressed(t *testing.T) {
	cfg := defaultConfig()
	cfg.clientCompression = "optimal"
	cfg.clientOptimalLimit = 4096
	c := newTestCodec(t, cfg)

	plain := map[string][]byte{
		"CMD":  []byte("READ"),
		"MARK": []byte("mark-1"),
		"DATA": []byte("hello"),
	}
	decoded, err := c.decodeBody([]byte(c.encodeBody(plain)))
	if err != nil {
		t.Fatalf("decode plain body: %v", err)
	}
	if string(decoded["CMD"]) != "READ" || string(decoded["MARK"]) != "mark-1" || string(decoded["DATA"]) != "hello" {
		t.Fatalf("unexpected decoded plain body: %#v", decoded)
	}
	if len(decoded["DATACOMP"]) != 0 {
		t.Fatalf("small body should not be compressed: %#v", decoded)
	}

	payload := bytes.Repeat([]byte("A"), 8192)
	compressed := map[string][]byte{
		"CMD":  []byte("FORWARD"),
		"MARK": []byte("mark-2"),
		"DATA": payload,
	}
	decoded, err = c.decodeBody([]byte(c.encodeBody(compressed)))
	if err != nil {
		t.Fatalf("decode compressed body: %v", err)
	}
	if !bytes.Equal(decoded["DATA"], payload) {
		t.Fatalf("compressed body did not round trip")
	}
	if string(decoded["DATACOMP"]) != "1" {
		t.Fatalf("expected DATACOMP marker, got %#v", decoded["DATACOMP"])
	}
}

func TestCodecStreamFrameRoundTrip(t *testing.T) {
	c := newTestCodec(t, nil)
	info := map[string][]byte{
		"CMD":  []byte("DATA"),
		"MARK": []byte("stream-mark"),
		"DATA": []byte("abc123"),
	}

	frame := c.encodeStreamFrame(info)
	if len(frame) < 8 {
		t.Fatalf("stream frame too short: %d", len(frame))
	}
	payloadLen, err := strconv.ParseInt(string(frame[:8]), 16, 32)
	if err != nil {
		t.Fatalf("decode frame length: %v", err)
	}
	if int(payloadLen) != len(frame[8:]) {
		t.Fatalf("frame length mismatch: prefix=%d actual=%d", payloadLen, len(frame[8:]))
	}
	if bytes.Contains(frame[8:], []byte("=")) {
		t.Fatalf("stream frame payload should use unpadded base64: %q", frame[8:])
	}

	decoded, err := c.decodeStreamFrame(frame[8:])
	if err != nil {
		t.Fatalf("decode stream frame payload: %v", err)
	}
	if string(decoded["CMD"]) != "DATA" || string(decoded["MARK"]) != "stream-mark" || string(decoded["DATA"]) != "abc123" {
		t.Fatalf("unexpected decoded stream payload: %#v", decoded)
	}

	decoded, err = c.readStreamFrame(bufio.NewReader(bytes.NewReader(frame)))
	if err != nil {
		t.Fatalf("read stream frame: %v", err)
	}
	if string(decoded["CMD"]) != "DATA" || string(decoded["MARK"]) != "stream-mark" || string(decoded["DATA"]) != "abc123" {
		t.Fatalf("unexpected decoded stream frame: %#v", decoded)
	}
}

func TestCompressionDecisions(t *testing.T) {
	lowEntropy := bytes.Repeat([]byte("A"), 2048)
	highEntropy := make([]byte, 2048)
	for i := range highEntropy {
		highEntropy[i] = byte(i)
	}

	if shouldCompressData("optimal", bytes.Repeat([]byte("A"), 1024), 1024) {
		t.Fatalf("payload at the threshold should not be compressed")
	}
	if !shouldCompressData("optimal", lowEntropy, 1024) {
		t.Fatalf("optimal compression should use size threshold")
	}
	if !shouldCompressData("smart", lowEntropy, 1024) {
		t.Fatalf("smart compression should compress low entropy payloads")
	}
	if shouldCompressData("smart", highEntropy, 1024) {
		t.Fatalf("smart compression should reject high entropy payloads")
	}
	if got := compressionLevel("smart", len(lowEntropy)); got != 1 {
		t.Fatalf("smart compression level = %d, want 1", got)
	}
	if got := compressionLevel("dynamic", 9000); got != 3 {
		t.Fatalf("dynamic compression level for medium payload = %d, want 3", got)
	}
}

func TestBLVDecodeRejectsMalformedLength(t *testing.T) {
	c := newTestCodec(t, nil)
	_, err := c.blvDecode([]byte{hCmd, 0, 0, 0, 0})
	if err == nil {
		t.Fatalf("expected malformed BLV length to fail")
	}
}
