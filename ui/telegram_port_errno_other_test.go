//go:build !windows

package main

import "syscall"

func busyErrno() syscall.Errno { return syscall.EADDRINUSE }
