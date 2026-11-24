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

func TestVoiceSessionStalledInPlace(t *testing.T) {
	var s voiceSessions
	server := netip.MustParseAddr("104.29.157.172")
	s.begin(server, true)
	for i := 0; i < voiceDeadOutbound-1; i++ {
		s.count(server, false)
	}
	if s.stalled() != nil {
		t.Fatal("рано: исходящих пакетов ещё мало")
	}
	s.count(server, false)
	verdict := s.stalled()
	if verdict == nil || verdict.alive || verdict.switched {
		t.Fatalf("первый срыв на месте: %+v", verdict)
	}
	if s.stalled() != nil {
		t.Fatal("сеанс засчитывается один раз")
	}
	// Следующий сеанс не пересчитывает уже засчитанный и тоже срывается —
	// даже если клиент вернулся на тот же сервер.
	other := server
	if _, v := s.begin(other, true); v != nil {
		t.Fatalf("сорванный сеанс засчитан повторно: %+v", v)
	}
	for i := 0; i < voiceDeadOutbound; i++ {
		s.count(other, false)
	}
	if verdict = s.stalled(); verdict == nil || !verdict.switched || verdict.next != voiceTunnel {
		t.Fatalf("второй срыв должен перевести голос в туннель: %+v", verdict)
	}
	// Сеанс с ответами сервера сорванным не считается.
	s.begin(server, true)
	s.count(server, true)
	for i := 0; i < voiceDeadOutbound; i++ {
		s.count(server, false)
	}
	if s.stalled() != nil {
		t.Fatal("сеанс с ответами сервера засчитан как сорванный")
	}
}
