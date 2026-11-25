//go:build !windows

package main

import "github.com/fitting-1c/evasion/internal/windivert"

const telegramCallTunnelSupported = false

func openTelegramCallTunnelHandle() (tgTunnelConn, error) {
	return nil, windivert.ErrUnsupported
}

func makeInboundReinject(reinject any) any {
	return reinject
}
