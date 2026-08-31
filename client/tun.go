package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/engine"
)

func (c *client) runTunMode() error {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer ln.Close()

	go c.serveInternalSocks(ln)

	device := tunDeviceSpec(c.cfg.tunName)
	proxy := "socks5://" + ln.Addr().String()
	key := &engine.Key{
		Device:     device,
		Proxy:      proxy,
		MTU:        c.cfg.tunMTU,
		LogLevel:   tunLogLevel(c.cfg.verbose),
		UDPTimeout: time.Duration(c.cfg.udpTimeout) * time.Second,
	}

	engine.Insert(key)
	engine.Start()
	defer engine.Stop()

	if c.cfg.tunCIDR != "" || c.cfg.tunMTU > 0 {
		if err := waitAndConfigureTun(tunInterfaceName(c.cfg.tunName), c.cfg.tunCIDR, c.cfg.tunMTU, 5*time.Second); err != nil {
			return err
		}
	}

	log.Printf("[TUN] %s <-> internal SOCKS5 %s <-> Roger", device, ln.Addr().String())
	log.Printf("[TUN] Routing is not managed by Roger; add routes to %s yourself", tunInterfaceName(c.cfg.tunName))

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	return nil
}

func (c *client) serveInternalSocks(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[TUN] internal SOCKS5 accept: %v", err)
			return
		}
		go c.handleLocal(conn)
	}
}

func tunDeviceSpec(name string) string {
	if strings.Contains(name, "://") {
		return name
	}
	return "tun://" + name
}

func tunInterfaceName(name string) string {
	if before, after, ok := strings.Cut(name, "://"); ok && before != "" {
		return after
	}
	return name
}

func tunLogLevel(verbose int) string {
	switch {
	case verbose >= 3:
		return "debug"
	case verbose >= 1:
		return "info"
	default:
		return "warn"
	}
}

func tunConfigTimeout(name string) error {
	return fmt.Errorf("TUN interface %q did not appear before timeout", name)
}
