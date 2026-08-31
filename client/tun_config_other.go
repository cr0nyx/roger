//go:build !linux

package main

import (
	"errors"
	"time"
)

func waitAndConfigureTun(name, cidr string, mtu int, timeout time.Duration) error {
	if cidr == "" {
		return nil
	}
	return errors.New("automatic TUN address/MTU configuration is currently implemented only on Linux")
}
