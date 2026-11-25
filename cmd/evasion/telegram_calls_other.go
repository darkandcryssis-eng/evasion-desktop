//go:build !windows

package main

type noopTelegramUDPOwner struct{}

func (noopTelegramUDPOwner) OwnsUDP(uint16) bool { return false }

func newTelegramUDPOwner() telegramUDPOwner { return noopTelegramUDPOwner{} }
