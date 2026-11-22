//go:build windows

package main

import (
	"syscall"

	"golang.org/x/sys/windows"
)

func busyErrno() syscall.Errno { return windows.WSAEADDRINUSE }
