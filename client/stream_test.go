package main

import (
	"bufio"
	"strings"
	"testing"
)

func TestIterFullDuplexBodyRejectsInvalidChunkLengths(t *testing.T) {
	headers := map[string]string{"transfer-encoding": "chunked"}
	for _, body := range []string{"-1\r\n", "ffffffff\r\n"} {
		t.Run(body, func(t *testing.T) {
			err := iterFullDuplexBody(bufio.NewReader(strings.NewReader(body)), headers, func([]byte) bool {
				t.Fatalf("yield should not be called for invalid chunk length")
				return false
			})
			if err == nil {
				t.Fatalf("expected invalid chunk length to fail")
			}
		})
	}
}

func TestIterFullDuplexFramesRejectsInvalidFrameLengths(t *testing.T) {
	c := newTestCodec(t, nil)
	s := &session{client: &client{cfg: defaultConfig(), codec: c}}
	headers := map[string]string{"content-length": "8"}
	for _, prefix := range []string{"-000001", "ffffffff"} {
		t.Run(prefix, func(t *testing.T) {
			err := s.iterFullDuplexFrames(bufio.NewReader(strings.NewReader(prefix)), headers, func(map[string][]byte) bool {
				t.Fatalf("yield should not be called for invalid frame length")
				return false
			})
			if err == nil {
				t.Fatalf("expected invalid frame length to fail")
			}
		})
	}
}
