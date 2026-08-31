package main

import (
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

func runGenerate(args []string) error {
	configPath, args := parseConfigArg(args)
	cfg := defaultGenerateConfig()
	if configPath != "" {
		if err := applyGenerateConfigFile(cfg, configPath); err != nil {
			return err
		}
	}
	fs := flag.NewFlagSet(os.Args[0]+" generate", flag.ExitOnError)
	fs.Usage = func() {
		printUsage(fs, fmt.Sprintf("Roger Go template generator %s", version), []optionHelp{
			{[]string{"--config"}, "load options from YAML config file", configPath},
			{[]string{"-k", "--key"}, "connection key", cfg.key},
			{[]string{"-o", "--outdir"}, "output directory", cfg.outDir},
			{[]string{"-f", "--file"}, "camouflage html page file", cfg.camouflageFile},
			{[]string{"-c", "--httpcode"}, "HTTP response code", cfg.httpCode},
			{[]string{"-T", "--request-template"}, "HTTP request template string or file", cfg.requestTemplate},
			{[]string{"--read-buff"}, "remote read buffer in bytes", cfg.readBuf},
			{[]string{"--max-read-size"}, "remote max read size in KB", cfg.maxReadSize},
			{[]string{"--udp-frag-size"}, "UDP fragment size in bytes", cfg.udpFragSize},
			{[]string{"--udp-max-size"}, "UDP reassembly max size in KB", cfg.udpMaxSize},
		})
	}
	fs.StringVar(&configPath, "config", configPath, "load options from YAML config file")
	fs.StringVar(&cfg.key, "k", cfg.key, "connection key")
	fs.StringVar(&cfg.key, "key", cfg.key, "connection key")
	fs.StringVar(&cfg.outDir, "o", cfg.outDir, "output directory")
	fs.StringVar(&cfg.outDir, "outdir", cfg.outDir, "output directory")
	fs.StringVar(&cfg.camouflageFile, "f", cfg.camouflageFile, "camouflage html page file")
	fs.StringVar(&cfg.camouflageFile, "file", cfg.camouflageFile, "camouflage html page file")
	fs.IntVar(&cfg.httpCode, "c", cfg.httpCode, "HTTP response code")
	fs.IntVar(&cfg.httpCode, "httpcode", cfg.httpCode, "HTTP response code")
	fs.StringVar(&cfg.requestTemplate, "T", cfg.requestTemplate, "HTTP request template string or file")
	fs.StringVar(&cfg.requestTemplate, "request-template", cfg.requestTemplate, "HTTP request template string or file")
	fs.IntVar(&cfg.readBuf, "read-buff", cfg.readBuf, "remote read buffer in bytes")
	fs.IntVar(&cfg.maxReadSize, "max-read-size", cfg.maxReadSize, "remote max read size in KB")
	fs.IntVar(&cfg.udpFragSize, "udp-frag-size", cfg.udpFragSize, "UDP fragment size in bytes")
	fs.IntVar(&cfg.udpMaxSize, "udp-max-size", cfg.udpMaxSize, "UDP reassembly max size in KB")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if cfg.key == "" {
		return errors.New("required: generate -k KEY")
	}
	if cfg.udpFragSize <= 0 {
		return errors.New("--udp-frag-size must be greater than zero")
	}
	cfg.maxReadSize *= 1024
	cfg.udpMaxSize *= 1024
	if cfg.udpMaxSize < cfg.udpFragSize {
		return errors.New("--udp-max-size must be greater than or equal to --udp-frag-size")
	}

	genRuntimeCfg := &config{
		key:                cfg.key,
		clientCompression:  "optimal",
		serverCompression:  "optimal",
		clientOptimalLimit: 1024,
		serverOptimalLimit: 1024,
	}
	cdc, err := newCodec(cfg.key, genRuntimeCfg)
	if err != nil {
		return err
	}
	rogerHelloSource := cdc.currentHello()
	if cfg.camouflageFile != "" {
		rogerHelloSource, err = os.ReadFile(cfg.camouflageFile)
		if err != nil {
			return fmt.Errorf("read camouflage file: %w", err)
		}
	}
	rogerHello := cdc.mapBase64([]byte(base64.StdEncoding.EncodeToString(rogerHelloSource)))

	useRequestTemplate := 0
	requestTemplateStart := 0
	requestTemplateEnd := 0
	if cfg.requestTemplate != "" {
		template := cfg.requestTemplate
		if data, err := os.ReadFile(cfg.requestTemplate); err == nil {
			template = string(data)
		}
		parts := strings.SplitN(template, "ROGERBODY", 2)
		if len(parts) != 2 {
			return errors.New("request template must contain ROGERBODY")
		}
		useRequestTemplate = 1
		requestTemplateStart = len(parts[0])
		requestTemplateEnd = len(parts[1])
	}

	if err := os.MkdirAll(cfg.outDir, 0755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(cfg.outDir, "key.txt"), []byte(cfg.key), 0644); err != nil {
		return err
	}

	templateDir := filepath.Join(filepath.Dir(os.Args[0]), "templates")
	if _, err := os.Stat(templateDir); err != nil {
		templateDir = filepath.Join("src", "templates")
	}
	entries, err := os.ReadDir(templateDir)
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	base64Array := cdc.base64ArrayList()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasPrefix(name, "tunnel.") {
			continue
		}
		path := filepath.Join(templateDir, name)
		textBytes, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		text := string(textBytes)
		text = strings.ReplaceAll(text, "Roger says, 'All seems fine'", string(rogerHello))
		text = strings.ReplaceAll(text, "BASE64 CHARSLIST", cdc.mappedBase64)
		replacements := map[string]string{
			"HTTPCODE":             strconv.Itoa(cfg.httpCode),
			"READBUF":              strconv.Itoa(cfg.readBuf),
			"MAXREADSIZE":          strconv.Itoa(cfg.maxReadSize),
			"UDPFRAGSIZE":          strconv.Itoa(cfg.udpFragSize),
			"UDPMAXSIZE":           strconv.Itoa(cfg.udpMaxSize),
			"UDP_IDLE_TIMEOUT":     "30",
			"HALF_CLOSE_MODE":      "false",
			"USE_REQUEST_TEMPLATE": strconv.Itoa(useRequestTemplate),
			"START_INDEX":          strconv.Itoa(requestTemplateStart),
			"END_INDEX":            strconv.Itoa(requestTemplateEnd),
			"BLV_L_OFFSET":         strconv.FormatInt(int64(cdc.blvOffset), 10),
			"BLVHEAD_LEN":          strconv.Itoa(len(headByName) + 1),
		}
		for marker, value := range replacements {
			text = replaceWord(text, marker, value)
		}
		text = strings.ReplaceAll(text, "BASE64 ARRAYLIST", base64Array)
		if err := os.WriteFile(filepath.Join(cfg.outDir, name), []byte(text), 0644); err != nil {
			return err
		}
		fmt.Printf("=> %s\n", filepath.Join(cfg.outDir, name))
	}
	return nil
}

func defaultGenerateConfig() *generateConfig {
	return &generateConfig{
		outDir:      "tunnels",
		httpCode:    200,
		readBuf:     513,
		maxReadSize: 512,
		udpFragSize: 1200,
		udpMaxSize:  256,
	}
}

func applyGenerateConfigFile(cfg *generateConfig, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	current := ""
	for _, rawLine := range strings.Split(string(data), "\n") {
		line := strings.SplitN(rawLine, "#", 2)[0]
		if strings.TrimSpace(line) == "" {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		trimmed := strings.TrimSpace(line)
		if indent == 0 && strings.HasSuffix(trimmed, ":") {
			current = strings.TrimSuffix(trimmed, ":")
			continue
		}
		if current != "common" && current != "generate" {
			continue
		}
		key, value, ok := strings.Cut(trimmed, ":")
		if !ok {
			continue
		}
		applyGenerateConfigValue(cfg, strings.TrimSpace(key), parseConfigScalar(value))
	}
	return nil
}

func applyGenerateConfigValue(cfg *generateConfig, key, value string) {
	key = strings.ReplaceAll(key, "-", "_")
	switch key {
	case "key":
		cfg.key = value
	case "outdir":
		cfg.outDir = value
	case "file":
		cfg.camouflageFile = value
	case "httpcode":
		cfg.httpCode = atoiDefault(value, cfg.httpCode)
	case "request_template":
		cfg.requestTemplate = value
	case "read_buff":
		cfg.readBuf = atoiDefault(value, cfg.readBuf)
	case "max_read_size":
		cfg.maxReadSize = atoiDefault(value, cfg.maxReadSize)
	case "udp_frag_size":
		cfg.udpFragSize = atoiDefault(value, cfg.udpFragSize)
	case "udp_max_size":
		cfg.udpMaxSize = atoiDefault(value, cfg.udpMaxSize)
	}
}

func replaceWord(text, marker, value string) string {
	re := regexp.MustCompile(`\b` + regexp.QuoteMeta(marker) + `\b`)
	return re.ReplaceAllString(text, value)
}
