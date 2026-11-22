//go:build !windows

package main

import (
	"errors"
	"syscall"
)

func addrInUse(err error) bool              { return errors.Is(err, syscall.EADDRINUSE) }
func findPortHolder(int) (portHolder, bool) { return portHolder{}, false }
func retireProcess(uint32)                  {}
