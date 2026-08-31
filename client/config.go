package main

import (
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

func parseFlags() *config {
	var urls multiFlag
	var headers multiFlag
	var redirectURLs multiFlag
	var verbose countFlag
	configPath, args := parseConfigArg(os.Args[1:])
	cfg := defaultConfig()
	if configPath != "" {
		if err := applyConfigFile(cfg, configPath, "connect"); err != nil {
			fmt.Fprintf(os.Stderr, "config error: %v\n", err)
			os.Exit(2)
		}
		cfg.configPath = configPath
	}
	urls = append(urls, cfg.urls...)
	headers = append(headers, cfg.headers...)
	redirectURLs = append(redirectURLs, cfg.redirectURLs...)
	phpConnectTimeoutSeconds := cfg.phpConnectTimeout.Seconds()
	readIntervalMS := int(cfg.readInterval / time.Millisecond)
	writeIntervalMS := int(cfg.writeInterval / time.Millisecond)
	readBufKB := cfg.readBuf / 1024
	maxReadSizeKB := cfg.maxReadSize / 1024
	udpMaxSizeKB := cfg.udpMaxSize / 1024
	fs := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	fs.Usage = func() {
		printUsage(fs, fmt.Sprintf("Roger Go client %s\n\nGenerate templates:\n  %s generate [options]", version, fs.Name()), []optionHelp{
			{[]string{"--config"}, "load options from YAML config file", cfg.configPath},
			{[]string{"-u", "--url"}, "tunnel URL, can be repeated", []string(urls)},
			{[]string{"-r", "--redirect-url"}, "redirect URL, can be repeated", []string(redirectURLs)},
			{[]string{"-H", "--header"}, "custom HTTP header, can be repeated", []string(headers)},
			{[]string{"-k", "--key"}, "connection key", cfg.key},
			{[]string{"-l", "--listen-on"}, "listen address", cfg.listen},
			{[]string{"-p", "--listen-port"}, "listen port", cfg.port},
			{[]string{"-t", "--target"}, "fixed forwarding target IP:PORT", cfg.target},
			{[]string{"--remote"}, "use -l/-p as server-side BIND listener and -t as local forwarding target", cfg.remote},
			{[]string{"--tun"}, "enable TUN mode with this interface name", cfg.tunName},
			{[]string{"--tun-cidr"}, "assign CIDR address to TUN interface", cfg.tunCIDR},
			{[]string{"--tun-mtu"}, "TUN MTU", cfg.tunMTU},
			{[]string{"-s", "--skip"}, "skip Roger hello check", cfg.skip},
			{[]string{"-R", "--force-redirect"}, "force redirect", cfg.forceRedirect},
			{[]string{"-c", "--cookie"}, "custom init cookies", cfg.cookie},
			{[]string{"-x", "--proxy"}, "proxy URL", cfg.proxy},
			{[]string{"-T", "--request-template"}, "HTTP request template string or file", cfg.requestTemplate},
			{[]string{"--local-dns"}, "resolve domain names locally", cfg.localDNS},
			{[]string{"--read-buff"}, "local read buffer in KB", readBufKB},
			{[]string{"--max-read-size"}, "remote max read size in KB", maxReadSizeKB},
			{[]string{"--udp-frag-size"}, "UDP fragment size in bytes", cfg.udpFragSize},
			{[]string{"--udp-max-size"}, "UDP max reassembly size in KB", udpMaxSizeKB},
			{[]string{"--udp-timeout"}, "UDP idle timeout in seconds", cfg.udpTimeout},
			{[]string{"--mode"}, "transport mode: classic, half-duplex, full-duplex, h2, h3, auto", cfg.mode},
			{[]string{"--half-close"}, "enable TCP SHUT_WR half-close command", cfg.halfClose},
			{[]string{"--auto-tune"}, "automatically tune READBUF and MAXREADSIZE during live sessions", cfg.autoTune},
			{[]string{"-a", "--async-connect"}, "do not wait for CONNECT/BIND/UDP setup response", cfg.asyncConnect},
			{[]string{"--php-skip-cookie"}, "skip cookie availability check in php", cfg.phpSkipCookie},
			{[]string{"--go"}, "use go connection method", cfg.goServer},
			{[]string{"--php-connect-timeout"}, "async PHP setup timeout in seconds", phpConnectTimeoutSeconds},
			{[]string{"--client-compression"}, "optimal, dynamic, or smart", cfg.clientCompression},
			{[]string{"--server-compression"}, "optimal, dynamic, or smart", cfg.serverCompression},
			{[]string{"--client-optimal-limit"}, "client compression threshold", cfg.clientOptimalLimit},
			{[]string{"--server-optimal-limit"}, "server compression threshold", cfg.serverOptimalLimit},
			{[]string{"--read-interval"}, "read interval in milliseconds", readIntervalMS},
			{[]string{"--write-interval"}, "write interval in milliseconds", writeIntervalMS},
			{[]string{"--max-threads"}, "max threads", cfg.maxThreads},
			{[]string{"--max-retry"}, "max retry", cfg.maxRetry},
			{[]string{"--cut-left"}, "truncate left side of response body", cfg.cutLeft},
			{[]string{"--cut-right"}, "truncate right side of response body", cfg.cutRight},
			{[]string{"--extract"}, "manual extract expression", cfg.extract},
			{[]string{"--ntlm-auth"}, "NTLM auth USER:PASS", cfg.ntlmAuth},
			{[]string{"--socks-user"}, "require SOCKS5 username/password authentication with this username", cfg.socksUser},
			{[]string{"--socks-hash"}, "MD5 hash of the SOCKS5 password", cfg.socksHash},
			{[]string{"--blacklist"}, "SOCKS5-only comma-separated host wildcards", cfg.blacklist},
			{[]string{"-v"}, "increase verbosity", 0},
		})
	}
	fs.StringVar(&cfg.configPath, "config", cfg.configPath, "load options from YAML config file")
	fs.Var(&urls, "u", "tunnel URL, can be repeated")
	fs.Var(&urls, "url", "tunnel URL, can be repeated")
	fs.Var(&redirectURLs, "r", "redirect URL, can be repeated")
	fs.Var(&redirectURLs, "redirect-url", "redirect URL, can be repeated")
	fs.Var(&headers, "H", "custom HTTP header, can be repeated")
	fs.Var(&headers, "header", "custom HTTP header, can be repeated")
	fs.StringVar(&cfg.key, "k", cfg.key, "connection key")
	fs.StringVar(&cfg.key, "key", cfg.key, "connection key")
	fs.StringVar(&cfg.listen, "l", cfg.listen, "listen address")
	fs.StringVar(&cfg.listen, "listen-on", cfg.listen, "listen address")
	fs.IntVar(&cfg.port, "p", cfg.port, "listen port")
	fs.IntVar(&cfg.port, "listen-port", cfg.port, "listen port")
	fs.StringVar(&cfg.target, "t", cfg.target, "fixed forwarding target IP:PORT")
	fs.StringVar(&cfg.target, "target", cfg.target, "fixed forwarding target IP:PORT")
	fs.BoolVar(&cfg.remote, "remote", cfg.remote, "use -l/-p as server-side BIND listener and -t as local forwarding target")
	fs.StringVar(&cfg.tunName, "tun", cfg.tunName, "enable TUN mode with this interface name")
	fs.StringVar(&cfg.tunCIDR, "tun-cidr", cfg.tunCIDR, "assign CIDR address to TUN interface")
	fs.IntVar(&cfg.tunMTU, "tun-mtu", cfg.tunMTU, "TUN MTU")
	fs.BoolVar(&cfg.skip, "s", cfg.skip, "skip Roger hello check")
	fs.BoolVar(&cfg.skip, "skip", cfg.skip, "skip Roger hello check")
	fs.BoolVar(&cfg.forceRedirect, "R", cfg.forceRedirect, "force redirect")
	fs.BoolVar(&cfg.forceRedirect, "force-redirect", cfg.forceRedirect, "force redirect")
	fs.StringVar(&cfg.cookie, "c", cfg.cookie, "custom init cookies")
	fs.StringVar(&cfg.cookie, "cookie", cfg.cookie, "custom init cookies")
	fs.StringVar(&cfg.proxy, "x", cfg.proxy, "proxy URL")
	fs.StringVar(&cfg.proxy, "proxy", cfg.proxy, "proxy URL")
	fs.StringVar(&cfg.requestTemplate, "T", cfg.requestTemplate, "HTTP request template string or file")
	fs.StringVar(&cfg.requestTemplate, "request-template", cfg.requestTemplate, "HTTP request template string or file")
	fs.BoolVar(&cfg.localDNS, "local-dns", cfg.localDNS, "resolve domain names locally")
	fs.IntVar(&readBufKB, "read-buff", readBufKB, "local read buffer in KB")
	fs.IntVar(&maxReadSizeKB, "max-read-size", maxReadSizeKB, "remote max read size in KB")
	fs.IntVar(&cfg.udpFragSize, "udp-frag-size", cfg.udpFragSize, "UDP fragment size in bytes")
	fs.IntVar(&udpMaxSizeKB, "udp-max-size", udpMaxSizeKB, "UDP max reassembly size in KB")
	fs.IntVar(&cfg.udpTimeout, "udp-timeout", cfg.udpTimeout, "UDP idle timeout in seconds")
	fs.StringVar(&cfg.mode, "mode", cfg.mode, "transport mode: classic, half-duplex, full-duplex, h2, h3, auto")
	fs.BoolVar(&cfg.halfClose, "half-close", cfg.halfClose, "enable TCP SHUT_WR half-close command")
	fs.BoolVar(&cfg.autoTune, "auto-tune", cfg.autoTune, "automatically tune READBUF and MAXREADSIZE during live sessions")
	fs.BoolVar(&cfg.asyncConnect, "a", cfg.asyncConnect, "do not wait for CONNECT/BIND/UDP setup response")
	fs.BoolVar(&cfg.asyncConnect, "async-connect", cfg.asyncConnect, "do not wait for CONNECT/BIND/UDP setup response")
	fs.BoolVar(&cfg.phpSkipCookie, "php-skip-cookie", cfg.phpSkipCookie, "skip cookie availability check in php")
	fs.BoolVar(&cfg.goServer, "go", cfg.goServer, "use go connection method")
	fs.Float64Var(&phpConnectTimeoutSeconds, "php-connect-timeout", phpConnectTimeoutSeconds, "async PHP setup timeout in seconds")
	fs.StringVar(&cfg.clientCompression, "client-compression", cfg.clientCompression, "optimal, dynamic, or smart")
	fs.StringVar(&cfg.serverCompression, "server-compression", cfg.serverCompression, "optimal, dynamic, or smart")
	fs.IntVar(&cfg.clientOptimalLimit, "client-optimal-limit", cfg.clientOptimalLimit, "client compression threshold")
	fs.IntVar(&cfg.serverOptimalLimit, "server-optimal-limit", cfg.serverOptimalLimit, "server compression threshold")
	fs.IntVar(&readIntervalMS, "read-interval", readIntervalMS, "read interval in milliseconds")
	fs.IntVar(&writeIntervalMS, "write-interval", writeIntervalMS, "write interval in milliseconds")
	fs.IntVar(&cfg.maxThreads, "max-threads", cfg.maxThreads, "max threads")
	fs.IntVar(&cfg.maxRetry, "max-retry", cfg.maxRetry, "max retry")
	fs.IntVar(&cfg.cutLeft, "cut-left", cfg.cutLeft, "truncate left side of response body")
	fs.IntVar(&cfg.cutRight, "cut-right", cfg.cutRight, "truncate right side of response body")
	fs.StringVar(&cfg.extract, "extract", cfg.extract, "manual extract expression")
	fs.StringVar(&cfg.ntlmAuth, "ntlm-auth", cfg.ntlmAuth, "NTLM auth USER:PASS")
	fs.StringVar(&cfg.socksUser, "socks-user", cfg.socksUser, "SOCKS5 authentication username")
	fs.StringVar(&cfg.socksHash, "socks-hash", cfg.socksHash, "MD5 hash of the SOCKS5 password")
	var blacklist string
	blacklist = strings.Join(cfg.blacklist, ",")
	fs.StringVar(&blacklist, "blacklist", "", "SOCKS5-only comma-separated host wildcards")
	fs.Var(&verbose, "v", "increase verbosity")
	_ = fs.Parse(expandVerbosityArgs(args))
	cfg.verbose = int(verbose)
	cfg.urls = urls
	cfg.headers = headers
	cfg.redirectURLs = redirectURLs
	cfg.readBuf = readBufKB * 1024
	cfg.maxReadSize = maxReadSizeKB * 1024
	cfg.udpMaxSize = udpMaxSizeKB * 1024
	cfg.phpConnectTimeout = time.Duration(phpConnectTimeoutSeconds * float64(time.Second))
	cfg.readInterval = time.Duration(readIntervalMS) * time.Millisecond
	cfg.writeInterval = time.Duration(writeIntervalMS) * time.Millisecond
	cfg.mode = normalizeTransportMode(cfg.mode)
	if blacklist != "" {
		cfg.blacklist = nil
		for _, item := range strings.Split(blacklist, ",") {
			item = strings.TrimSpace(item)
			if item != "" {
				cfg.blacklist = append(cfg.blacklist, item)
			}
		}
	}
	for name, mode := range map[string]string{
		"client-compression": cfg.clientCompression,
		"server-compression": cfg.serverCompression,
	} {
		if !validCompressionMode(mode) {
			fmt.Fprintf(os.Stderr, "invalid --%s %q: expected optimal, dynamic, or smart\n", name, mode)
			os.Exit(2)
		}
	}
	if !validTransportMode(cfg.mode) {
		fmt.Fprintf(os.Stderr, "invalid --mode %q: expected classic, half-duplex, full-duplex, h2, h3, or auto\n", cfg.mode)
		os.Exit(2)
	}
	cfg.httpVersion = "1.1"
	if cfg.mode == "h2" {
		cfg.httpVersion = "2"
	} else if cfg.mode == "h3" {
		cfg.httpVersion = "3"
	} else if cfg.mode == "auto" {
		cfg.httpVersion = "auto"
	}
	if cfg.proxy != "" {
		if _, err := url.Parse(cfg.proxy); err != nil {
			fmt.Fprintf(os.Stderr, "invalid --proxy: %v\n", err)
			os.Exit(2)
		}
	}
	if cfg.target != "" {
		if _, _, err := net.SplitHostPort(cfg.target); err != nil {
			fmt.Fprintf(os.Stderr, "invalid --target %q: expected IP:PORT or HOST:PORT\n", cfg.target)
			os.Exit(2)
		}
	}
	if cfg.tunName != "" {
		if cfg.target != "" {
			fmt.Fprintln(os.Stderr, "--tun cannot be used with -t/--target port forwarding")
			os.Exit(2)
		}
		if cfg.remote {
			fmt.Fprintln(os.Stderr, "--tun cannot be used with --remote port forwarding")
			os.Exit(2)
		}
		if len(cfg.blacklist) > 0 {
			fmt.Fprintln(os.Stderr, "--blacklist works only with the public SOCKS5 server; remove --blacklist or do not use --tun")
			os.Exit(2)
		}
		if cfg.socksUser != "" || cfg.socksHash != "" {
			fmt.Fprintln(os.Stderr, "--socks-user/--socks-hash protect only the public SOCKS5 server; remove them or do not use --tun")
			os.Exit(2)
		}
		if cfg.tunMTU < 0 {
			fmt.Fprintln(os.Stderr, "--tun-mtu must be zero or greater")
			os.Exit(2)
		}
	}
	if len(cfg.blacklist) > 0 && cfg.target != "" {
		fmt.Fprintln(os.Stderr, "--blacklist works only with the SOCKS5 server; remove --blacklist or do not use -t/--target")
		os.Exit(2)
	}
	if cfg.remote && cfg.target == "" {
		fmt.Fprintln(os.Stderr, "--remote requires -t/--target")
		os.Exit(2)
	}
	if (cfg.socksUser == "") != (cfg.socksHash == "") {
		fmt.Fprintln(os.Stderr, "--socks-user and --socks-hash must be specified together")
		os.Exit(2)
	}
	if cfg.socksHash != "" && !isMD5Hex(cfg.socksHash) {
		fmt.Fprintln(os.Stderr, "--socks-hash must be a 32-character MD5 hex string")
		os.Exit(2)
	}
	if cfg.socksUser != "" && cfg.target != "" {
		fmt.Fprintln(os.Stderr, "SOCKS5 authentication cannot protect -t/--target port forwarding; remove --socks-user/--socks-hash or do not use -t")
		os.Exit(2)
	}
	if cfg.ntlmAuth != "" {
		user, password, err := parseNTLMAuth(cfg.ntlmAuth)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid --ntlm-auth: %v\n", err)
			os.Exit(2)
		}
		cfg.ntlmUser = user
		cfg.ntlmPassword = password
		if cfg.mode == "h2" || cfg.mode == "h3" {
			fmt.Fprintln(os.Stderr, "[NTLM] NTLM authentication is supported only with HTTP/1.1; do not use --mode h2 or --mode h3")
			os.Exit(2)
		}
		if cfg.mode == "full-duplex" {
			fmt.Fprintln(os.Stderr, "[NTLM] NTLM authentication is not supported with full-duplex mode because it uses a raw HTTP/1.1 stream; use classic, half-duplex, or auto")
			os.Exit(2)
		}
	}
	return cfg
}

func defaultConfig() *config {
	return &config{
		listen:             "127.0.0.1",
		port:               1080,
		tunMTU:             1400,
		readBuf:            7 * 1024,
		maxReadSize:        512 * 1024,
		udpFragSize:        1200,
		udpMaxSize:         256 * 1024,
		udpTimeout:         30,
		mode:               "auto",
		phpConnectTimeout:  500 * time.Millisecond,
		clientCompression:  "optimal",
		serverCompression:  "optimal",
		clientOptimalLimit: 1024,
		serverOptimalLimit: 1024,
		httpVersion:        "auto",
		autoTune:           false,
		readInterval:       300 * time.Millisecond,
		writeInterval:      200 * time.Millisecond,
		maxThreads:         400,
		maxRetry:           10,
	}
}

func parseConfigArg(args []string) (string, []string) {
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--config" && i+1 < len(args) {
			return args[i+1], append(out, args[i+2:]...)
		}
		if strings.HasPrefix(arg, "--config=") {
			return strings.TrimPrefix(arg, "--config="), append(out, args[i+1:]...)
		}
		out = append(out, arg)
	}
	return "", out
}

func validCompressionMode(mode string) bool {
	return mode == "optimal" || mode == "dynamic" || mode == "smart"
}

func validTransportMode(mode string) bool {
	return mode == "classic" || mode == "half-duplex" || mode == "full-duplex" || mode == "h2" || mode == "h3" || mode == "auto"
}

func normalizeTransportMode(mode string) string {
	return mode
}

func protocolTransportMode(mode string) string {
	switch mode {
	case "half-duplex":
		return "half"
	case "full-duplex":
		return "full"
	default:
		return mode
	}
}

func expandVerbosityArgs(args []string) []string {
	out := make([]string, 0, len(args))
	for _, arg := range args {
		if strings.HasPrefix(arg, "-v") && len(arg) > 2 && strings.Trim(arg[1:], "v") == "" {
			for i := 0; i < len(arg)-1; i++ {
				out = append(out, "-v")
			}
			continue
		}
		out = append(out, arg)
	}
	return out
}

func parseConfigScalar(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, "\"'")
	if value == "null" || value == "~" {
		return ""
	}
	return value
}

func applyConfigFile(cfg *config, path string, section string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	current := ""
	listKey := ""
	for _, rawLine := range strings.Split(string(data), "\n") {
		line := strings.SplitN(rawLine, "#", 2)[0]
		if strings.TrimSpace(line) == "" {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		trimmed := strings.TrimSpace(line)
		if indent == 0 && strings.HasSuffix(trimmed, ":") {
			current = strings.TrimSuffix(trimmed, ":")
			listKey = ""
			continue
		}
		if current != "common" && current != section {
			continue
		}
		if strings.HasPrefix(trimmed, "- ") && listKey != "" {
			applyConfigValue(cfg, listKey, parseConfigScalar(strings.TrimPrefix(trimmed, "- ")))
			continue
		}
		key, value, ok := strings.Cut(trimmed, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		listKey = ""
		if value == "[]" {
			continue
		}
		if value == "" {
			listKey = key
			continue
		}
		if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
			inner := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(value, "["), "]"))
			if inner == "" {
				continue
			}
			for _, item := range strings.Split(inner, ",") {
				applyConfigValue(cfg, key, parseConfigScalar(item))
			}
			continue
		}
		applyConfigValue(cfg, key, parseConfigScalar(value))
	}
	return nil
}

func applyConfigValue(cfg *config, key, value string) {
	key = strings.ReplaceAll(key, "-", "_")
	switch key {
	case "key":
		cfg.key = value
	case "url":
		if value != "" {
			cfg.urls = append(cfg.urls, value)
		}
	case "redirect_url":
		if value != "" {
			cfg.redirectURLs = append(cfg.redirectURLs, value)
		}
	case "header":
		if value != "" {
			cfg.headers = append(cfg.headers, value)
		}
	case "listen_on":
		cfg.listen = value
	case "listen_port":
		cfg.port = atoiDefault(value, cfg.port)
	case "target":
		cfg.target = value
	case "remote":
		cfg.remote = parseBool(value)
	case "tun":
		cfg.tunName = value
	case "tun_cidr":
		cfg.tunCIDR = value
	case "tun_mtu":
		cfg.tunMTU = atoiDefault(value, cfg.tunMTU)
	case "skip":
		cfg.skip = parseBool(value)
	case "force_redirect":
		cfg.forceRedirect = parseBool(value)
	case "cookie":
		cfg.cookie = value
	case "proxy":
		cfg.proxy = value
	case "request_template":
		cfg.requestTemplate = value
	case "async_connect":
		cfg.asyncConnect = parseBool(value)
	case "php_skip_cookie":
		cfg.phpSkipCookie = parseBool(value)
	case "go":
		cfg.goServer = parseBool(value)
	case "php_connect_timeout":
		if seconds, err := strconv.ParseFloat(value, 64); err == nil {
			cfg.phpConnectTimeout = time.Duration(seconds * float64(time.Second))
		}
	case "local_dns":
		cfg.localDNS = parseBool(value)
	case "read_buff":
		cfg.readBuf = atoiDefault(value, cfg.readBuf/1024) * 1024
	case "max_read_size":
		cfg.maxReadSize = atoiDefault(value, cfg.maxReadSize/1024) * 1024
	case "udp_frag_size":
		cfg.udpFragSize = atoiDefault(value, cfg.udpFragSize)
	case "udp_max_size":
		cfg.udpMaxSize = atoiDefault(value, cfg.udpMaxSize/1024) * 1024
	case "udp_timeout":
		cfg.udpTimeout = atoiDefault(value, cfg.udpTimeout)
	case "mode":
		cfg.mode = value
	case "auto_tune":
		cfg.autoTune = parseBool(value)
	case "client_compression":
		cfg.clientCompression = value
	case "server_compression":
		cfg.serverCompression = value
	case "client_optimal_limit":
		cfg.clientOptimalLimit = atoiDefault(value, cfg.clientOptimalLimit)
	case "server_optimal_limit":
		cfg.serverOptimalLimit = atoiDefault(value, cfg.serverOptimalLimit)
	case "read_interval":
		cfg.readInterval = time.Duration(atoiDefault(value, int(cfg.readInterval/time.Millisecond))) * time.Millisecond
	case "write_interval":
		cfg.writeInterval = time.Duration(atoiDefault(value, int(cfg.writeInterval/time.Millisecond))) * time.Millisecond
	case "max_threads":
		cfg.maxThreads = atoiDefault(value, cfg.maxThreads)
	case "max_retry":
		cfg.maxRetry = atoiDefault(value, cfg.maxRetry)
	case "cut_left":
		cfg.cutLeft = atoiDefault(value, cfg.cutLeft)
	case "cut_right":
		cfg.cutRight = atoiDefault(value, cfg.cutRight)
	case "extract":
		cfg.extract = value
	case "ntlm_auth":
		cfg.ntlmAuth = value
	case "socks_user":
		cfg.socksUser = value
	case "socks_hash":
		cfg.socksHash = value
	case "blacklist":
		if value != "" {
			cfg.blacklist = append(cfg.blacklist, value)
		}
	case "half_close":
		cfg.halfClose = parseBool(value)
	}
}

func atoiDefault(value string, fallback int) int {
	n, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return n
}

func parseBool(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func parseNTLMAuth(value string) (string, string, error) {
	user, password, ok := strings.Cut(value, ":")
	if !ok || user == "" {
		return "", "", fmt.Errorf("expected USER:PASS or DOMAIN\\USER:PASS")
	}
	return user, password, nil
}

func isMD5Hex(value string) bool {
	if len(value) != 32 {
		return false
	}
	for _, ch := range value {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') && (ch < 'A' || ch > 'F') {
			return false
		}
	}
	return true
}
