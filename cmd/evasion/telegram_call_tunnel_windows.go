//go:build windows

package main

import "github.com/fitting-1c/evasion/internal/windivert"

const telegramCallTunnelSupported = true

func openTelegramCallTunnelHandle() (tgTunnelConn, error) {
	return windivert.OpenPriority(telegramCallTunnelFilter, telegramCallTunnelPriority)
}

func makeInboundReinject(reinject any) any {
	addr, ok := reinject.(windivert.Address)
	if !ok {
		return reinject
	}
	addr[10] &^= 2
	addr[10] |= (1 << 5) | (1 << 6) | (1 << 7)
	return addr
}
