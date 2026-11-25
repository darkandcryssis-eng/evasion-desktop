//go:build !windows

package main

import "net/netip"

type noopTelegramUDPOwner struct{}

func (noopTelegramUDPOwner) OwnsUDP(netip.Addr, uint16) bool { return false }

func newTelegramUDPOwner() telegramUDPOwner { return noopTelegramUDPOwner{} }
