//go:build !windows

package main

import "os/exec"

func hideCommandWindow(*exec.Cmd) {}
