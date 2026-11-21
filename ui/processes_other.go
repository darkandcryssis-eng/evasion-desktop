//go:build !windows

package main

func runningProcessNames() ([]string, error) { return nil, errWindowsOnly }
