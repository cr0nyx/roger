package main

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestRequestTemplateWrappingAndResponseExtraction(t *testing.T) {
	c := &client{cfg: defaultConfig()}
	c.cfg.requestTemplate = "prefix ROGERBODY suffix"
	if got := c.wrapRequestBody("BODY"); got != "prefix BODY suffix" {
		t.Fatalf("wrapped body = %q", got)
	}
	c.cfg.requestTemplate = "no placeholder"
	if got := c.wrapRequestBody("BODY"); got != "BODY" {
		t.Fatalf("body without placeholder = %q", got)
	}

	c.cfg.cutLeft = 2
	c.cfg.cutRight = 3
	if got := string(c.extractResponseBody([]byte("xxPAYLOADyyy"))); got != "PAYLOAD" {
		t.Fatalf("cut response = %q", got)
	}
	c.cfg.cutLeft = 0
	c.cfg.cutRight = 0
	c.cfg.extract = "before ROGERBODY after"
	if got := string(c.extractResponseBody([]byte("noise before VALUE after noise"))); got != "VALUE" {
		t.Fatalf("extracted response = %q", got)
	}
}

func TestAskRogerHelloExtractionPolicy(t *testing.T) {
	c := &client{cfg: defaultConfig()}
	codec, err := newCodec(c.cfg.key, c.cfg)
	if err != nil {
		t.Fatalf("codec: %v", err)
	}
	c.codec = codec
	hello := c.codec.currentHello()

	if err := c.wrappedHelloError(hello, hello); err != nil {
		t.Fatalf("exact hello should not need offsets: %v", err)
	}
	if err := c.wrappedHelloError([]byte("xx"+string(hello)+"yyy"), hello); err == nil {
		t.Fatalf("wrapped hello should report required offsets")
	} else if !strings.Contains(err.Error(), "--cut-left 2") || !strings.Contains(err.Error(), "--cut-right 3") {
		t.Fatalf("wrapped hello error = %q", err)
	}

	c.cfg.cutLeft = 2
	c.cfg.cutRight = 3
	if got := c.extractResponseBody([]byte("xx" + string(hello) + "yyy")); !bytes.Equal(got, hello) {
		t.Fatalf("configured offsets should extract hello, got %q", got)
	}
}

func TestAddRedirectIsDeterministicAndRespectsForceFlag(t *testing.T) {
	c := &client{cfg: defaultConfig()}
	c.cfg.redirectURLs = []string{"https://relay-a.example/", "https://relay-b.example/"}
	c.cfg.forceRedirect = true

	first := map[string][]byte{"MARK": []byte("same-mark")}
	second := map[string][]byte{"MARK": []byte("same-mark")}
	c.addRedirect(first)
	c.addRedirect(second)

	if string(first["REDIRECTURL"]) == "" || string(first["REDIRECTURL"]) != string(second["REDIRECTURL"]) {
		t.Fatalf("redirect should be deterministic by mark: %#v %#v", first, second)
	}
	if string(first["FORCEREDIRECT"]) != "TRUE" {
		t.Fatalf("force redirect marker = %q", first["FORCEREDIRECT"])
	}

	c.cfg.forceRedirect = false
	third := map[string][]byte{"MARK": []byte("another-mark")}
	c.addRedirect(third)
	if string(third["FORCEREDIRECT"]) != "FALSE" {
		t.Fatalf("non-force redirect marker = %q", third["FORCEREDIRECT"])
	}
}

func TestCapturePHPSessionCookie(t *testing.T) {
	c := &client{cfg: defaultConfig(), headers: http.Header{}}
	c.cfg.urls = []string{"https://example.test/tunnel.php"}
	resp := &http.Response{Header: http.Header{}}
	resp.Header.Set("Expires", time.Now().Add(-time.Minute).UTC().Format(http.TimeFormat))
	resp.Header.Add("Set-Cookie", "PHPSESSID=abc123; Path=/")

	if err := c.capturePHPSessionCookie(resp); err != nil {
		t.Fatalf("capture PHP cookie: %v", err)
	}
	if got := c.headers.Get("Cookie"); !strings.Contains(got, "PHPSESSID=abc123") {
		t.Fatalf("captured cookie = %q", got)
	}
	if got := c.headers.Get("Cookie"); strings.Contains(got, "access=keep") {
		t.Fatalf("test setup should not contain access cookie yet: %q", got)
	}

	c.headers = http.Header{"Cookie": []string{"access=keep; PHPSESSID=old"}}
	if err := c.capturePHPSessionCookie(resp); err != nil {
		t.Fatalf("merge PHP cookie: %v", err)
	}
	got := c.headers.Get("Cookie")
	if !strings.Contains(got, "access=keep") || !strings.Contains(got, "PHPSESSID=abc123") {
		t.Fatalf("merged cookie should preserve existing cookies and replace PHPSESSID: %q", got)
	}

	respNoCookie := &http.Response{Header: http.Header{}}
	respNoCookie.Header.Set("Expires", time.Now().Add(-time.Minute).UTC().Format(http.TimeFormat))
	if err := c.capturePHPSessionCookie(respNoCookie); err != nil {
		t.Fatalf("existing PHP cookie should be reusable: %v", err)
	}

	c.headers = http.Header{}
	c.cfg.phpSkipCookie = true
	if err := c.capturePHPSessionCookie(resp); err != nil {
		t.Fatalf("skip PHP cookie: %v", err)
	}
	if got := c.headers.Get("Cookie"); got != "" {
		t.Fatalf("cookie should not be captured when skipped: %q", got)
	}
}
