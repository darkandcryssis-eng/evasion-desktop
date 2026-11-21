//go:build !windows

package main

func readDriverServices() []driverService { return []driverService{} }
