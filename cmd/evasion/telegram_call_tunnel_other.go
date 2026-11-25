//go:build !windows

package main

func makeInboundReinject(reinject any) any {
	return reinject
}
