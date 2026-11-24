//go:build !windows

package netbind

import "syscall"

// Detect вне Windows туннель не ищет: перехват там не работает.
func Detect() (Route, error) { return Route{}, nil }

func bindControl(uint32) func(network, address string, c syscall.RawConn) error { return nil }
