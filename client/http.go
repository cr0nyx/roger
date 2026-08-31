package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	mrand "math/rand"
)

func (c *client) askRoger() error {
	req, err := c.newRequest(http.MethodGet, c.cfg.urls[0], nil)
	if err != nil {
		return err
	}
	req.Header = cloneHeader(c.headers)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	body = bytes.TrimSpace(body)
	hello := c.codec.currentHello()
	switch {
	case bytes.Equal(body, hello) || bytes.Contains(body, hello):
		c.serverVer = version
	default:
		return fmt.Errorf("Roger is not ready, unexpected response: %q", firstBytes(body, 120))
	}
	log.Printf("[Ask Roger] Roger says, 'All seems fine' (server: %s)", c.serverVer)
	return nil
}

func (c *client) negotiateMode() string {
	modes := []string{"classic"}
	if rinfo, err := c.control(map[string][]byte{"CMD": []byte("CAPS"), "MARK": []byte("__roger_probe__caps")}, 5*time.Second); err == nil {
		if string(rinfo["STATUS"]) == "OK" && len(rinfo["MODES"]) > 0 {
			modes = strings.Split(string(rinfo["MODES"]), ",")
		}
	}
	for _, candidate := range []string{"h3", "h2", "full-duplex", "half-duplex", "classic"} {
		if c.cfg.ntlmAuth != "" && (candidate == "h3" || candidate == "h2" || candidate == "full-duplex") {
			continue
		}
		wireMode := protocolTransportMode(candidate)
		if !containsMode(modes, candidate) && !containsMode(modes, wireMode) {
			continue
		}
		if c.probeMode(candidate) {
			if candidate == "h3" {
				c.cfg.httpVersion = "3"
			} else if candidate == "h2" {
				c.cfg.httpVersion = "2"
			} else if c.cfg.httpVersion == "auto" {
				c.cfg.httpVersion = "1.1"
			}
			return candidate
		}
	}
	if c.cfg.httpVersion == "auto" {
		c.cfg.httpVersion = "1.1"
	}
	return "classic"
}

func (c *client) modeSupported(mode string) bool {
	mode = normalizeTransportMode(mode)
	rinfo, err := c.control(map[string][]byte{"CMD": []byte("CAPS"), "MARK": []byte("__roger_probe__caps")}, 5*time.Second)
	if err != nil {
		return mode == "classic"
	}
	modes := strings.Split(string(rinfo["MODES"]), ",")
	return containsMode(modes, mode) || containsMode(modes, protocolTransportMode(mode))
}

func (c *client) probeMode(mode string) bool {
	if mode == "h3" {
		if c.cfg.ntlmAuth != "" {
			return false
		}
		if c.cfg.httpVersion == "1.1" || c.cfg.httpVersion == "2" {
			return false
		}
		return c.probeHTTP3StreamMode()
	}
	if mode == "h2" {
		if c.cfg.ntlmAuth != "" {
			return false
		}
		if c.cfg.httpVersion == "1.1" || c.cfg.httpVersion == "3" {
			return false
		}
		return c.probeHTTP2StreamMode()
	}
	if mode == "full-duplex" {
		if c.cfg.httpVersion == "2" || c.cfg.httpVersion == "3" {
			return false
		}
		return c.probeFullDuplexMode()
	}
	wireMode := protocolTransportMode(mode)
	mark := "__roger_probe__" + wireMode + "_go"
	rinfo, err := c.control(map[string][]byte{"CMD": []byte("PROBE"), "MARK": []byte(mark), "MODE": []byte(wireMode)}, 5*time.Second)
	return err == nil && string(rinfo["STATUS"]) == "OK"
}

func (c *client) control(info map[string][]byte, timeout time.Duration) (map[string][]byte, error) {
	body := c.wrapRequestBody(c.codec.encodeBody(info))
	req, err := c.newRequest(http.MethodPost, c.sampleURL(), strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header = cloneHeader(c.headers)
	client := *c.httpClient
	client.Timeout = timeout
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return c.codec.decodeBody(c.extractResponseBody(bytes.TrimSpace(data)))
}

func (c *client) request(info map[string][]byte, timeout time.Duration) (map[string][]byte, error) {
	body := c.wrapRequestBody(c.codec.encodeBody(info))
	req, err := c.newRequest(http.MethodPost, c.sampleURL(), strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header = cloneHeader(c.headers)
	client := *c.httpClient
	client.Timeout = timeout
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return c.codec.decodeBody(c.extractResponseBody(bytes.TrimSpace(data)))
}

func (c *client) sampleURL() string {
	if len(c.cfg.urls) == 1 {
		return c.cfg.urls[0]
	}
	return c.cfg.urls[mrand.Intn(len(c.cfg.urls))]
}

func (c *client) newRequest(method, url string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	if c.cfg.ntlmAuth != "" {
		req.SetBasicAuth(c.cfg.ntlmUser, c.cfg.ntlmPassword)
	}
	return req, nil
}

func (c *client) wrapRequestBody(body string) string {
	if c.cfg.requestTemplate == "" {
		return body
	}
	template := c.cfg.requestTemplate
	if data, err := os.ReadFile(template); err == nil {
		template = string(data)
	}
	if before, after, ok := strings.Cut(template, "ROGERBODY"); ok {
		return before + body + after
	}
	return body
}

func (c *client) extractResponseBody(data []byte) []byte {
	if c.cfg.cutLeft > 0 && c.cfg.cutLeft < len(data) {
		data = data[c.cfg.cutLeft:]
	}
	if c.cfg.cutRight > 0 && c.cfg.cutRight < len(data) {
		data = data[:len(data)-c.cfg.cutRight]
	}
	if c.cfg.extract != "" {
		if before, after, ok := strings.Cut(c.cfg.extract, "ROGERBODY"); ok {
			start := bytes.Index(data, []byte(before))
			if start >= 0 {
				start += len(before)
				rest := data[start:]
				end := bytes.Index(rest, []byte(after))
				if end >= 0 {
					return rest[:end]
				}
			}
		}
	}
	return bytes.TrimSpace(data)
}
