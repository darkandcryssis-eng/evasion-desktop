package main

import (
	"net/netip"
	"testing"
)

func TestVoiceSessionsSwitchPathAfterRepeatedFailures(t *testing.T) {
	var s voiceSessions
	server := func(n byte) netip.Addr { return netip.AddrFrom4([4]byte{104, 29, 153, n}) }

	path, verdict := s.begin(server(1), true)
	if path != voiceDirect || verdict != nil {
		t.Fatalf("первый сеанс: path=%v verdict=%v", path, verdict)
	}
	// Второй сокет того же сеанса ничего не меняет.
	if path, verdict = s.begin(server(1), true); path != voiceDirect || verdict != nil {
		t.Fatalf("повтор запроса: path=%v verdict=%v", path, verdict)
	}
	s.count(server(1), false)
	s.count(server(9), true) // чужой адрес не считается

	// Первый срыв: путь пока прежний.
	path, verdict = s.begin(server(2), true)
	if path != voiceDirect || verdict == nil || verdict.alive || verdict.switched || verdict.out != 1 || verdict.in != 0 {
		t.Fatalf("после первого срыва: path=%v verdict=%+v", path, verdict)
	}
	// Второй срыв подряд: голос уходит в туннель.
	path, verdict = s.begin(server(3), true)
	if path != voiceTunnel || verdict == nil || !verdict.switched || verdict.next != voiceTunnel {
		t.Fatalf("после второго срыва: path=%v verdict=%+v", path, verdict)
	}
	// Живой сеанс в туннеле закрепляет путь.
	for i := 0; i < voiceAliveInbound; i++ {
		s.count(server(3), true)
	}
	path, verdict = s.begin(server(4), true)
	if path != voiceTunnel || verdict == nil || !verdict.alive || verdict.switched {
		t.Fatalf("после живого сеанса: path=%v verdict=%+v", path, verdict)
	}
	// Туннель срывается дважды — возврат на прямой путь.
	s.begin(server(5), true)
	if path, verdict = s.begin(server(6), true); path != voiceDirect || !verdict.switched || verdict.next != voiceDirect {
		t.Fatalf("возврат на прямой путь: path=%v verdict=%+v", path, verdict)
	}
	// Запрос, уже идущий мимо VPN, остаётся прямым; отказ маршрута оставляет сеанс в туннеле.
	if path, _ = s.begin(server(7), false); path != voiceDirect {
		t.Fatalf("запрос мимо VPN: %v", path)
	}
	s.keepTunnel(server(7))
	if _, got, _, _, _ := s.snapshot(); got != voiceTunnel {
		t.Fatalf("keepTunnel: %v", got)
	}
}
