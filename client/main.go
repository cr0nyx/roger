package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Azure/go-ntlmssp"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "generate" {
		if err := runGenerate(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
		return
	}

	cfg := parseFlags()
	if cfg.key == "" || len(cfg.urls) == 0 {
		fmt.Fprintln(os.Stderr, "required: -k KEY and at least one -u URL")
		os.Exit(2)
	}

	cdc, err := newCodec(cfg.key, cfg)
	if err != nil {
		log.Fatal(err)
	}
	proxyFunc := http.ProxyFromEnvironment
	if cfg.proxy != "" {
		proxyURL, err := url.Parse(cfg.proxy)
		if err != nil {
			log.Fatal(err)
		}
		proxyFunc = http.ProxyURL(proxyURL)
	}
	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: cfg.skipTLSVerify},
		Proxy:             proxyFunc,
		ForceAttemptHTTP2: cfg.httpVersion != "1.1" && cfg.ntlmAuth == "",
		TLSNextProto:      tlsNextProto(cfg.httpVersion),
	}
	var roundTripper http.RoundTripper = transport
	if cfg.ntlmAuth != "" {
		roundTripper = ntlmssp.Negotiator{RoundTripper: transport}
	}
	cl := &client{
		cfg:             cfg,
		codec:           cdc,
		connectionSlots: make(chan struct{}, cfg.maxConnections),
		httpClient: &http.Client{
			Timeout:   0,
			Transport: roundTripper,
		},
		headers: make(http.Header),
	}
	cl.headers.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126 Safari/537.36")
	for _, line := range cfg.headers {
		if name, value, ok := strings.Cut(line, ":"); ok {
			cl.headers.Set(strings.TrimSpace(name), strings.TrimSpace(value))
		}
	}
	if cfg.cookie != "" {
		cl.headers.Set("Cookie", cfg.cookie)
	}

	if !cfg.skip {
		if err := cl.askRoger(); err != nil {
			log.Fatalf("[Ask Roger] %v", err)
		}
	}

	if cfg.mode == "auto" {
		cfg.mode = cl.negotiateMode()
		if cfg.proxy == "" {
			log.Printf("[MODE] Auto selected %s", cfg.mode)
		}
	}

	if cfg.tunName != "" {
		if err := cl.runTunMode(); err != nil {
			log.Fatal(err)
		}
		return
	}

	if cfg.remote {
		log.Printf("[REMOTE FWD] Server listening on %s:%d => local %s", cfg.listen, cfg.port, cfg.target)
		for {
			cl.acquireConnection()
			err := func() error {
				defer cl.releaseConnection()
				return cl.handleRemoteForward()
			}()
			if err != nil {
				log.Printf("[REMOTE FWD] %v", err)
				time.Sleep(cfg.readInterval)
				continue
			}
		}
	}

	addr := fmt.Sprintf("%s:%d", cfg.listen, cfg.port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	if cfg.target != "" {
		log.Printf("[PORT FWD] Listening on %s => %s", addr, cfg.target)
	} else {
		log.Printf("[SOCKS5] Listening on %s", addr)
		if cfg.socksUser != "" {
			log.Printf("[SOCKS5] Username/password authentication enabled for user: %s", cfg.socksUser)
		}
	}
	for {
		cl.acquireConnection()
		conn, err := ln.Accept()
		if err != nil {
			cl.releaseConnection()
			log.Printf("[SOCKS5] accept: %v", err)
			continue
		}
		go func(local net.Conn) {
			defer cl.releaseConnection()
			cl.handleLocal(local)
		}(conn)
	}
}

func (c *client) acquireConnection() {
	c.connectionSlots <- struct{}{}
}

func (c *client) releaseConnection() {
	<-c.connectionSlots
}

func tlsNextProto(httpVersion string) map[string]func(string, *tls.Conn) http.RoundTripper {
	if httpVersion == "1.1" {
		return map[string]func(string, *tls.Conn) http.RoundTripper{}
	}
	return nil
}
