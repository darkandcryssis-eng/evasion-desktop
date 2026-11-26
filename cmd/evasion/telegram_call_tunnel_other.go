//go:build !windows

package main

import "errors"

const telegramCallTunnelSupported = false

func openTelegramCallTunnelHandle() (tgTunnelConn, error) {
	return nil, errors.ErrUnsupported
}

func makeInboundReinject(reinject any) any {
	return reinject
}
