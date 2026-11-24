package main

import (
	"net/netip"
	"sync"
)

// voicePath — каким путём идёт голос Discord при стороннем VPN.
type voicePath uint8

const (
	// voiceDirect — мимо VPN, через физический адаптер и голосовой десинк.
	voiceDirect voicePath = iota
	// voiceTunnel — внутри туннеля VPN, без вмешательства.
	voiceTunnel
)

func (p voicePath) String() string {
	if p == voiceTunnel {
		return "через VPN"
	}
	return "мимо VPN"
}

const (
	// voiceAliveInbound — сколько пакетов голоса должно прийти от сервера,
	// чтобы сеанс считался рабочим. Сервер отвечает на проверки связи и в
	// пустом канале, так что у живого сеанса входящие есть всегда.
	voiceAliveInbound = 3
	// voicePathFailures — после скольких сорванных сеансов подряд голос
	// переводится на другой путь.
	voicePathFailures = 2
)

// voiceVerdict — итог завершившегося сеанса голоса.
type voiceVerdict struct {
	server  netip.Addr
	path    voicePath
	in, out int
	alive   bool
	// switched — после этого сеанса голос переведён на другой путь.
	switched bool
	next     voicePath
}

// voiceSessions выбирает путь для голоса по факту. Сеанс начинается с запроса
// IP discovery к голосовому серверу и считается рабочим, если от сервера
// приходит голос. Когда сеансы на текущем пути срываются подряд, следующие
// идут другим путём: голос работает, если работает хотя бы один из двух.
type voiceSessions struct {
	mu     sync.Mutex
	prefer voicePath
	fails  [2]int

	active  bool
	server  netip.Addr
	path    voicePath
	in, out int
}

// begin отмечает запрос IP discovery к серверу server. onTunnel — запрос шёл в
// туннель и путь ещё можно выбрать; иначе он уже идёт мимо VPN. Возвращает
// путь сеанса и, если этим запросом начался новый сеанс, итог предыдущего.
func (s *voiceSessions) begin(server netip.Addr, onTunnel bool) (voicePath, *voiceVerdict) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active && s.server == server {
		return s.path, nil
	}
	var verdict *voiceVerdict
	if s.active {
		verdict = &voiceVerdict{server: s.server, path: s.path, in: s.in, out: s.out, alive: s.in >= voiceAliveInbound}
		if verdict.alive {
			s.fails[s.path] = 0
		} else {
			s.fails[s.path]++
		}
		if s.fails[s.prefer] >= voicePathFailures {
			s.prefer = 1 - s.prefer
			s.fails[s.prefer] = 0
			verdict.switched = true
		}
		verdict.next = s.prefer
	}
	s.active, s.server, s.in, s.out = true, server, 0, 0
	s.path = voiceDirect
	if onTunnel {
		s.path = s.prefer
	}
	return s.path, verdict
}

// keepTunnel оставляет текущий сеанс в туннеле: маршрут мимо VPN не встал.
func (s *voiceSessions) keepTunnel(server netip.Addr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active && s.server == server {
		s.path = voiceTunnel
	}
}

// count учитывает пакет голоса к серверу или от него.
func (s *voiceSessions) count(server netip.Addr, inbound bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.active || s.server != server {
		return
	}
	if inbound {
		s.in++
	} else {
		s.out++
	}
}

// snapshot возвращает текущий сеанс для сводки в журнале.
func (s *voiceSessions) snapshot() (server netip.Addr, path voicePath, in, out int, active bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.server, s.path, s.in, s.out, s.active
}
