//go:build !windows

package main

func startupTaskEnabled() (bool, error) { return false, errWindowsOnly }
func setStartupTask(bool, string) error { return errWindowsOnly }
