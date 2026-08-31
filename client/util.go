package main

import (
	"crypto/rand"
	"encoding/base64"
	"net"
	"net/http"
	"strings"
)

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func randMark() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)[:16]
}

func cloneHeader(h http.Header) http.Header {
	out := make(http.Header)
	for k, vs := range h {
		for _, v := range vs {
			out.Add(k, v)
		}
	}
	return out
}

func firstBytes(b []byte, n int) []byte {
	if len(b) <= n {
		return b
	}
	return b[:n]
}

func containsMode(modes []string, want string) bool {
	for _, m := range modes {
		if strings.TrimSpace(m) == want {
			return true
		}
	}
	return false
}

func parseIPv4(host string, fallback net.IP) net.IP {
	ip := net.ParseIP(host)
	if ip4 := ip.To4(); ip4 != nil {
		return ip4
	}
	return fallback
}

func isBlacklisted(host string, rules []string) bool {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	for _, rule := range rules {
		rule = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(rule), "."))
		if ok, _ := pathMatch(rule, host); ok {
			return true
		}
	}
	return false
}

func pathMatch(pattern, name string) (bool, error) {
	// Minimal shell-style wildcard matching for hostnames.
	if pattern == "" {
		return false, nil
	}
	if pattern == "*" {
		return true, nil
	}
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == name, nil
	}
	if !strings.HasPrefix(name, parts[0]) {
		return false, nil
	}
	pos := len(parts[0])
	for _, p := range parts[1 : len(parts)-1] {
		idx := strings.Index(name[pos:], p)
		if idx < 0 {
			return false, nil
		}
		pos += idx + len(p)
	}
	return strings.HasSuffix(name, parts[len(parts)-1]), nil
}
