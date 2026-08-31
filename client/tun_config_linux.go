//go:build linux

package main

import (
	"time"

	"github.com/vishvananda/netlink"
)

func waitAndConfigureTun(name, cidr string, mtu int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var link netlink.Link
	var err error
	for time.Now().Before(deadline) {
		link, err = netlink.LinkByName(name)
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if link == nil {
		return tunConfigTimeout(name)
	}
	if mtu > 0 {
		if err := netlink.LinkSetMTU(link, mtu); err != nil {
			return err
		}
	}
	if cidr != "" {
		addr, err := netlink.ParseAddr(cidr)
		if err != nil {
			return err
		}
		if err := netlink.AddrReplace(link, addr); err != nil {
			return err
		}
	}
	return netlink.LinkSetUp(link)
}
