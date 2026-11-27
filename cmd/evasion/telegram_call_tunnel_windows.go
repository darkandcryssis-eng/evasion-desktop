//go:build windows

package main

import (
	"fmt"
	"net/netip"

	"github.com/fitting-1c/evasion/internal/windivert"
)

const telegramCallTunnelSupported = true

func openTelegramCallTunnelHandle(peer string) (tgTunnelConn, error) {
	filter, err := telegramCallTunnelFilterForPeer(peer)
	if err != nil {
		return nil, err
	}
	return windivert.OpenPriority(filter, telegramCallTunnelPriority)
}

func telegramCallTunnelFilterForPeer(peer string) (string, error) {
	endpoint, err := netip.ParseAddrPort(peer)
	if err != nil || endpoint.Port() == 0 || endpoint.Addr().Zone() != "" || endpoint.Addr().Unmap().IsUnspecified() {
		return "", fmt.Errorf("некорректный UDP-адрес узла WARP %q", peer)
	}
	addr := endpoint.Addr().Unmap()
	family := "ip"
	if addr.Is6() {
		family = "ipv6"
	}
	// The relay must not intercept the packets that carry its own UDP tunnel.
	return fmt.Sprintf("%s and (not %s or %s.DstAddr != %s or udp.DstPort != %d)",
		telegramCallTunnelFilter, family, family, addr, endpoint.Port()), nil
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
