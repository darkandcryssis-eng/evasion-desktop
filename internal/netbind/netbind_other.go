//go:build !windows

package netbind

import (
	"errors"
	"syscall"
)

var errNoRoutes = errors.New("маршруты в обход VPN поддержаны только в Windows")

// Detect вне Windows туннель не ищет: перехват там не работает.
func Detect() (Route, error) { return Route{}, nil }

func bindControl(uint32) func(network, address string, c syscall.RawConn) error { return nil }

// Add вне Windows не поддержан.
func (r HostRoute) Add() error { return errNoRoutes }

// Delete вне Windows не поддержан.
func (r HostRoute) Delete() error { return errNoRoutes }
