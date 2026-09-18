package main

import (
	"fmt"
	"log"
	"sort"
	"strings"
)

func (c *client) logf(level int, format string, args ...any) {
	if c != nil && c.cfg != nil && c.cfg.verbose >= level {
		log.Printf(format, args...)
	}
}

func (s *session) logf(level int, format string, args ...any) {
	if s != nil && s.client != nil {
		s.client.logf(level, format, args...)
	}
}

func logInfoSummary(info map[string][]byte) string {
	if len(info) == 0 {
		return "{}"
	}
	keys := make([]string, 0, len(info))
	for key := range info {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		value := info[key]
		if key == "DATA" {
			parts = append(parts, fmt.Sprintf("DATA=<%d bytes>", len(value)))
			continue
		}
		if key == "UDPFRAG" {
			parts = append(parts, fmt.Sprintf("UDPFRAG=<%d bytes>", len(value)))
			continue
		}
		text := string(value)
		if len(text) > 80 {
			text = text[:80] + "..."
		}
		parts = append(parts, fmt.Sprintf("%s=%q", key, text))
	}
	return "{" + strings.Join(parts, ", ") + "}"
}
