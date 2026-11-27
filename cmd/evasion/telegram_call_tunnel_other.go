//go:build !windows

package main

import "errors"

const telegramCallTunnelSupported = false

func openTelegramCallTunnelHandle(_ string) (tgTunnelConn, error) {
	return nil, errors.ErrUnsupported
}

func makeInboundReinject(reinject any) any {
	return reinject
}
