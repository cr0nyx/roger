package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestConfigFileAppliesCommonAndConnectSections(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	data := []byte(`
common:
  key: from-config
  url:
    - https://one.example/tunnel
  header: ["X-One: 1", "X-Two: 2"]
  request_template: body=ROGERBODY
  max_read_size: 256
  udp_frag_size: 900
connect:
  url:
    - https://two.example/tunnel
  redirect_url:
    - https://relay.example/tunnel
  listen_port: 2080
  force_redirect: true
  verbose: 2
  php_connect_timeout: 1.5
  read_interval: 25
  write_interval: 50
  max_connections: 9
  blacklist: "*.blocked.test"
generate:
  listen_port: 9999
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg := defaultConfig()
	if err := applyConfigFile(cfg, path, "connect"); err != nil {
		t.Fatalf("applyConfigFile: %v", err)
	}

	if cfg.key != "from-config" {
		t.Fatalf("key = %q", cfg.key)
	}
	if !reflect.DeepEqual(cfg.urls, []string{"https://one.example/tunnel", "https://two.example/tunnel"}) {
		t.Fatalf("urls = %#v", cfg.urls)
	}
	if !reflect.DeepEqual(cfg.headers, []string{"X-One: 1", "X-Two: 2"}) {
		t.Fatalf("headers = %#v", cfg.headers)
	}
	if cfg.requestTemplate != "body=ROGERBODY" {
		t.Fatalf("request template = %q", cfg.requestTemplate)
	}
	if cfg.maxReadSize != 256*1024 || cfg.udpFragSize != 900 {
		t.Fatalf("sizes maxRead=%d udpFrag=%d", cfg.maxReadSize, cfg.udpFragSize)
	}
	if cfg.port != 2080 || !cfg.forceRedirect {
		t.Fatalf("connect options were not applied: port=%d force=%v", cfg.port, cfg.forceRedirect)
	}
	if cfg.verbose != 2 {
		t.Fatalf("verbose = %d", cfg.verbose)
	}
	if cfg.phpConnectTimeout != 1500*time.Millisecond {
		t.Fatalf("php timeout = %v", cfg.phpConnectTimeout)
	}
	if cfg.readInterval != 25*time.Millisecond || cfg.writeInterval != 50*time.Millisecond {
		t.Fatalf("intervals read=%v write=%v", cfg.readInterval, cfg.writeInterval)
	}
	if cfg.maxConnections != 9 || !reflect.DeepEqual(cfg.blacklist, []string{"*.blocked.test"}) {
		t.Fatalf("limits maxConnections=%d blacklist=%#v", cfg.maxConnections, cfg.blacklist)
	}
}

func TestConfigHelpers(t *testing.T) {
	if path, args := parseConfigArg([]string{"--config", "cfg.yml", "-u", "x"}); path != "cfg.yml" || !reflect.DeepEqual(args, []string{"-u", "x"}) {
		t.Fatalf("parseConfigArg long = %q %#v", path, args)
	}
	if path, args := parseConfigArg([]string{"-v", "--config=cfg.yml", "-k", "key"}); path != "cfg.yml" || !reflect.DeepEqual(args, []string{"-v", "-k", "key"}) {
		t.Fatalf("parseConfigArg equals = %q %#v", path, args)
	}
	if got := parseConfigScalar(`"quoted"`); got != "quoted" {
		t.Fatalf("parse quoted scalar = %q", got)
	}
	if got := parseConfigScalar("~"); got != "" {
		t.Fatalf("parse null scalar = %q", got)
	}
	if !validCompressionMode("smart") || validCompressionMode("gzip") {
		t.Fatalf("compression mode validation failed")
	}
	if !validTransportMode("h3") || validTransportMode("half") {
		t.Fatalf("transport mode validation failed")
	}
	if canonicalTransportMode("half") != "half-duplex" || protocolTransportMode("full-duplex") != "full" {
		t.Fatalf("transport canonicalization failed")
	}
	if !proxyCompatibleTransportMode("h2") || proxyCompatibleTransportMode("h3") || proxyCompatibleTransportMode("full-duplex") {
		t.Fatalf("proxy compatibility validation failed")
	}
	if user, pass, err := parseNTLMAuth(`DOMAIN\user:secret`); err != nil || user != `DOMAIN\user` || pass != "secret" {
		t.Fatalf("parse NTLM auth = user=%q pass=%q err=%v", user, pass, err)
	}
	if _, _, err := parseNTLMAuth("missing-separator"); err == nil {
		t.Fatalf("expected malformed NTLM auth to fail")
	}
	if !isMD5Hex("0123456789abcdefABCDEF0123456789") || isMD5Hex("not-md5") {
		t.Fatalf("MD5 hex validation failed")
	}
}

func TestUtilityHelpers(t *testing.T) {
	if !containsMode([]string{"classic", " h2 "}, "h2") {
		t.Fatalf("containsMode should trim entries")
	}
	if !isBlacklisted("Host.Blocked.Test.", []string{"*.blocked.test"}) {
		t.Fatalf("wildcard blacklist should match normalized host")
	}
	if isBlacklisted("allowed.test", []string{"*.blocked.test"}) {
		t.Fatalf("unexpected blacklist match")
	}
	if got := firstBytes([]byte("abcdef"), 3); string(got) != "abc" {
		t.Fatalf("firstBytes = %q", got)
	}
}
