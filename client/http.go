package main

import (
	"bytes"
	"context"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	mrand "math/rand"
)

const maxHTTPResponseSize = 4 * 1024 * 1024

func (c *client) askRoger() error {
	method := http.MethodGet
	var requestBody io.Reader
	if len(c.cfg.redirectURLs) > 0 {
		info := map[string][]byte{}
		c.addRedirect(info)
		method = http.MethodPost
		requestBody = strings.NewReader(c.wrapRequestBody(c.codec.encodeBody(info)))
	}
	req, err := c.newRequest(method, c.cfg.urls[0], requestBody)
	if err != nil {
		return err
	}
	req.Header = cloneHeader(c.headers)
	if requestBody != nil {
		req.Header.Set("Content-Type", "application/octet-stream")
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := readLimited(resp.Body, maxHTTPResponseSize)
	if err != nil {
		return err
	}
	if err := c.capturePHPSessionCookie(resp); err != nil {
		return err
	}
	body = bytes.TrimSpace(body)
	extracted := c.extractResponseBody(body)
	hello := c.codec.currentHello()
	switch {
	case bytes.Equal(extracted, hello):
		c.serverVer = version
	default:
		if err := c.wrappedHelloError(body, hello); err != nil {
			return err
		}
		return fmt.Errorf("Roger is not ready, unexpected response: %q", firstBytes(body, 120))
	}
	log.Printf("[Ask Roger] Roger says, 'All seems fine' (server: %s)", c.serverVer)
	return nil
}

func (c *client) wrappedHelloError(body, hello []byte) error {
	left := bytes.Index(body, hello)
	if left < 0 {
		return nil
	}
	right := len(body) - (left + len(hello))
	args := []string{}
	if left > 0 {
		args = append(args, fmt.Sprintf("--cut-left %d", left))
	}
	if right > 0 {
		args = append(args, fmt.Sprintf("--cut-right %d", right))
	}
	if len(args) == 0 {
		return nil
	}
	return fmt.Errorf("Roger is ready, but response body needs extraction offsets; use %s", strings.Join(args, " "))
}

func (c *client) capturePHPSessionCookie(resp *http.Response) error {
	if c.cfg.phpSkipCookie || (!c.cfg.asyncConnect && !strings.Contains(strings.ToLower(c.cfg.urls[0]), ".php")) {
		return nil
	}

	expires := resp.Header.Get("Expires")
	if expires == "" {
		return nil
	}
	expiresAt, err := http.ParseTime(expires)
	if err != nil {
		c.logf(1, "[Ask Roger] Expires has an invalid format: %s", expires)
		return nil
	}
	if !expiresAt.Before(time.Now()) {
		return nil
	}

	cookies := resp.Cookies()
	merged := parseCookieHeader(c.headers.Get("Cookie"))
	for _, cookie := range cookies {
		if cookie.Name != "" {
			merged[cookie.Name] = cookie.Value
		}
	}
	if len(cookies) == 0 && len(merged) == 0 {
		return fmt.Errorf("PHP session response expired without setting a cookie")
	}
	if len(cookies) == 0 {
		c.logf(1, "[Ask Roger] Reusing existing PHP session cookie(s)")
		return nil
	}

	c.headers.Set("Cookie", formatCookieHeader(merged))
	c.logf(1, "[Ask Roger] Retained %d PHP session cookie(s)", len(cookies))
	return nil
}

func parseCookieHeader(header string) map[string]string {
	values := map[string]string{}
	for _, part := range strings.Split(header, ";") {
		name, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && name != "" {
			values[name] = value
		}
	}
	return values
}

func formatCookieHeader(values map[string]string) string {
	parts := make([]string, 0, len(values))
	for name, value := range values {
		if name != "" {
			parts = append(parts, name+"="+value)
		}
	}
	return strings.Join(parts, "; ")
}

func (c *client) negotiateMode() string {
	if c.cfg.requestTemplate != "" {
		log.Printf("[MODE] Request templates require classic mode; auto selected classic")
		c.cfg.httpVersion = "1.1"
		return "classic"
	}
	if len(c.cfg.redirectURLs) > 0 {
		return "classic"
	}
	modes := []string{"classic"}
	if rinfo, err := c.control(map[string][]byte{"CMD": []byte("CAPS"), "MARK": []byte("__roger_probe__caps")}, 5*time.Second); err == nil {
		if string(rinfo["STATUS"]) == "OK" && len(rinfo["MODES"]) > 0 {
			modes = strings.Split(string(rinfo["MODES"]), ",")
		}
	}
	canonicalModes := make([]string, 0, len(modes))
	for _, mode := range modes {
		canonical := canonicalTransportMode(strings.TrimSpace(mode))
		if canonical != "" && !containsMode(canonicalModes, canonical) {
			canonicalModes = append(canonicalModes, canonical)
		}
	}
	proxyIncompatible := make([]string, 0)
	if c.cfg.proxy != "" {
		for _, mode := range canonicalModes {
			if !proxyCompatibleTransportMode(mode) {
				proxyIncompatible = append(proxyIncompatible, mode)
			}
		}
	}

	for _, candidate := range []string{"h3", "h2", "full-duplex", "half-duplex", "classic"} {
		if c.cfg.ntlmAuth != "" && (candidate == "h3" || candidate == "h2" || candidate == "full-duplex") {
			continue
		}
		if c.cfg.proxy != "" && !proxyCompatibleTransportMode(candidate) {
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
			if c.cfg.proxy != "" {
				excluded := "none"
				if len(proxyIncompatible) > 0 {
					excluded = strings.Join(proxyIncompatible, ", ")
				}
				log.Printf(
					"[MODE] Server supports: %s; modes incompatible with --proxy: %s; selected highest-priority proxy-compatible mode: %s",
					strings.Join(canonicalModes, ", "), excluded, candidate,
				)
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
	if len(c.cfg.redirectURLs) > 0 && mode != "classic" {
		return false
	}
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
	c.addRedirect(info)
	body := c.wrapRequestBody(c.codec.encodeBody(info))
	url := c.sampleURL()
	c.logf(3, "[HTTP] control request url=%s info=%s body=%d bytes http_timeout=%s", url, logInfoSummary(info), len(body), timeout)
	req, err := c.newRequest(http.MethodPost, url, strings.NewReader(body))
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
	data, err := readLimited(resp.Body, maxHTTPResponseSize)
	if err != nil {
		return nil, err
	}
	rinfo, err := c.codec.decodeBody(c.extractResponseBody(bytes.TrimSpace(data)))
	if err == nil {
		c.logf(3, "[HTTP] control response status=%s info=%s body=%d bytes", resp.Status, logInfoSummary(rinfo), len(data))
	}
	return rinfo, err
}

func (c *client) request(info map[string][]byte, timeout time.Duration) (map[string][]byte, error) {
	return c.requestContext(context.Background(), info, timeout)
}

func (c *client) requestContext(ctx context.Context, info map[string][]byte, timeout time.Duration) (map[string][]byte, error) {
	c.addRedirect(info)
	body := c.wrapRequestBody(c.codec.encodeBody(info))
	url := c.sampleURL()
	c.logf(3, "[HTTP] request url=%s info=%s body=%d bytes http_timeout=%s", url, logInfoSummary(info), len(body), timeout)
	req, err := c.newRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	req.Header = cloneHeader(c.headers)
	client := *c.httpClient
	client.Timeout = timeout
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := readLimited(resp.Body, maxHTTPResponseSize)
	if err != nil {
		return nil, err
	}
	rinfo, err := c.codec.decodeBody(c.extractResponseBody(bytes.TrimSpace(data)))
	if err == nil {
		c.logf(3, "[HTTP] response status=%s info=%s body=%d bytes", resp.Status, logInfoSummary(rinfo), len(data))
	}
	return rinfo, err
}

func readLimited(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("response body exceeds limit: %d bytes", limit)
	}
	return data, nil
}

func (c *client) sampleURL() string {
	if len(c.cfg.urls) == 1 {
		return c.cfg.urls[0]
	}
	return c.cfg.urls[mrand.Intn(len(c.cfg.urls))]
}

func (c *client) addRedirect(info map[string][]byte) {
	if len(c.cfg.redirectURLs) == 0 {
		return
	}
	index := 0
	if mark := info["MARK"]; len(mark) > 0 {
		hash := fnv.New32a()
		_, _ = hash.Write(mark)
		index = int(hash.Sum32() % uint32(len(c.cfg.redirectURLs)))
	}
	info["REDIRECTURL"] = []byte(c.cfg.redirectURLs[index])
	if c.cfg.forceRedirect {
		info["FORCEREDIRECT"] = []byte("TRUE")
	} else {
		info["FORCEREDIRECT"] = []byte("FALSE")
	}
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
