package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"testing"

	"github.com/fitting-1c/evasion/internal/capture"
	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/discordvoice"
	"github.com/fitting-1c/evasion/internal/packet"
)

// udpDiscoveryPacket собирает исходящий IPv4+UDP пакет Discord IP discovery
// (74-байтная нагрузка: тип 0x0001, длина 70) с верными суммами.
func udpDiscoveryPacket(t *testing.T) capture.Packet {
	t.Helper()
	payload := make([]byte, 74)
	binary.BigEndian.PutUint16(payload[0:], 0x0001) // тип: запрос
	binary.BigEndian.PutUint16(payload[2:], 70)     // длина тела

	buf := make([]byte, 20+8+len(payload))
	buf[0] = 0x45
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(buf)))
	buf[8] = 64
	buf[9] = 17 // UDP
	copy(buf[12:16], net.ParseIP("10.0.0.1").To4())
	copy(buf[16:20], net.ParseIP("66.22.200.1").To4())
	binary.BigEndian.PutUint16(buf[20:22], 51000)
	binary.BigEndian.PutUint16(buf[22:24], 50010)
	binary.BigEndian.PutUint16(buf[24:26], uint16(8+len(payload)))
	copy(buf[28:], payload)

	d, err := packet.Dissect(buf)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if !d.RecomputeChecksums(buf) {
		t.Fatalf("суммы не пересчитаны")
	}
	return capture.Packet{Data: buf, Dir: core.DirectionOutbound}
}

func TestBuildVoiceDecoysOnDiscovery(t *testing.T) {
	pkt := udpDiscoveryPacket(t)
	pkts, applied := buildVoiceDecoys(pkt, discordvoice.FoolTTL, 6, 3, voicePayloadNeutral)
	if !applied {
		t.Fatal("на пакете Discord IP discovery приём должен примениться")
	}
	// Три decoy плюс оригинал последним.
	// Три decoy каждого приёма плюс оригинал последним.
	if len(pkts) != 7 {
		t.Fatalf("ожидалось 6 decoy + оригинал = 7 пакетов, получено %d", len(pkts))
	}
	// Последний — ровно исходный пакет.
	if string(pkts[6].Data) != string(pkt.Data) {
		t.Fatal("последним должен идти настоящий пакет без изменений")
	}
	// Decoy'и отличаются от оригинала (низкий TTL меняет байты/сумму).
	for i := 0; i < 6; i++ {
		if string(pkts[i].Data) == string(pkt.Data) {
			t.Fatalf("decoy %d не должен совпадать с оригиналом", i)
		}
	}
}

// TestVoiceDecoysCarryBenignPayload: decoy'и НЕ должны повторять форму Discord
// IP discovery. В этом вся суть приёма — если бы decoy нёс ту же подпись (тип
// 0x0001, длина 70), DPI увидел бы начало голоса в первом же пакете, ровно то,
// что прячем. Настоящий пакет при этом уходит последним и неизменным.
func TestVoiceDecoysCarryBenignPayload(t *testing.T) {
	pkt := udpDiscoveryPacket(t)
	pkts, applied := buildVoiceDecoys(pkt, discordvoice.FoolTTL, 6, 6, voicePayloadNeutral)
	if !applied {
		t.Fatal("на пакете Discord IP discovery приём должен примениться")
	}
	if len(pkts) != 13 {
		t.Fatalf("ожидалось 12 decoy + оригинал = 13, получено %d", len(pkts))
	}
	// Каждый decoy (все, кроме последнего) должен иметь нейтральную нагрузку,
	// которую строгий детектор голосом НЕ признаёт.
	for i := 0; i < 12; i++ {
		d, err := packet.Dissect(pkts[i].Data)
		if err != nil {
			t.Fatalf("decoy %d: разбор: %v", i, err)
		}
		pl, ok := d.Payload(pkts[i].Data)
		if !ok {
			t.Fatalf("decoy %d: нет нагрузки", i)
		}
		if discordvoice.IsIPDiscoveryRequest(pl) {
			t.Fatalf("decoy %d не должен повторять форму IP discovery", i)
		}
	}
	// Последний — ровно настоящий IP discovery, без изменений: только он
	// доходит до сервера.
	if string(pkts[12].Data) != string(pkt.Data) {
		t.Fatal("последним должен идти неизменный настоящий пакет")
	}
	last, err := packet.Dissect(pkts[12].Data)
	if err != nil {
		t.Fatalf("настоящий пакет: разбор: %v", err)
	}
	if pl, ok := last.Payload(pkts[12].Data); !ok || !discordvoice.IsIPDiscoveryRequest(pl) {
		t.Fatal("настоящий пакет должен оставаться валидным IP discovery")
	}
}

// TestVoiceFakePayloadNotDiscovery: нейтральная нагрузка нужной длины не
// опознаётся как запрос IP discovery (первые байты не 0x0001).
func TestVoiceFakePayloadNotDiscovery(t *testing.T) {
	fake := voiceFakePayload(74, voicePayloadNeutral)
	if len(fake) != 74 {
		t.Fatalf("длина нейтральной нагрузки: ожидалось 74, получено %d", len(fake))
	}
	if discordvoice.IsIPDiscoveryRequest(fake) {
		t.Fatal("нейтральная нагрузка не должна совпадать с формой IP discovery")
	}
	if binary.BigEndian.Uint16(fake[0:]) == 0x0001 {
		t.Fatal("первые два байта нейтральной нагрузки не должны быть 0x0001")
	}
}

// TestVoiceFakePayloadQUIC: benign-QUIC нагрузка 74 байт имеет сигнатуру QUIC v1
// Initial long-header и НЕ совпадает ни с IP discovery, ни с нейтральным узором.
func TestVoiceFakePayloadQUIC(t *testing.T) {
	fake := voiceFakePayload(74, voicePayloadQUIC)
	if len(fake) != 74 {
		t.Fatalf("длина QUIC нагрузки: ожидалось 74, получено %d", len(fake))
	}
	if discordvoice.IsIPDiscoveryRequest(fake) {
		t.Fatal("QUIC нагрузка не должна совпадать с формой IP discovery")
	}
	// Flags = 0xc0 (long header + fixed + Initial + PN len 1).
	if fake[0] != 0xc0 {
		t.Fatalf("flags 0x%02x, ожидали 0xc0", fake[0])
	}
	// Version = 0x00000001 (QUIC v1).
	if binary.BigEndian.Uint32(fake[1:5]) != 0x00000001 {
		t.Fatalf("version 0x%08x, ожидали 0x00000001", binary.BigEndian.Uint32(fake[1:5]))
	}
	// Отличается от нейтрального.
	neutral := voiceFakePayload(74, voicePayloadNeutral)
	if string(fake) == string(neutral) {
		t.Fatal("QUIC и neutral нагрузки совпали — расхождение в типе проигнорировано")
	}
}

// TestVoiceFakePayloadQUICFallsBackOnNon74: при длине не 74 QUIC-пресет не
// лепится (мы его не умеем масштабировать); возвращается нейтральный узор.
func TestVoiceFakePayloadQUICFallsBackOnNon74(t *testing.T) {
	fake := voiceFakePayload(50, voicePayloadQUIC)
	if len(fake) != 50 {
		t.Fatalf("длина fallback: ожидалось 50, получено %d", len(fake))
	}
	// Не похож на QUIC long-header (первый байт нейтрального узора 0x2b).
	if fake[0] == 0xc0 {
		t.Fatal("fallback при длине ≠ 74 не должен быть QUIC-подобным")
	}
}

// TestBuildVoiceDecoysWithQUICPayload: при voicePayloadQUIC decoy'и несут
// QUIC-подобную нагрузку, настоящий IP discovery по-прежнему идёт последним.
func TestBuildVoiceDecoysWithQUICPayload(t *testing.T) {
	pkt := udpDiscoveryPacket(t)
	pkts, applied := buildVoiceDecoys(pkt, discordvoice.FoolTTL, 6, 3, voicePayloadQUIC)
	if !applied {
		t.Fatal("приём должен примениться")
	}
	if len(pkts) != 7 {
		t.Fatalf("ожидалось 7 пакетов, получено %d", len(pkts))
	}
	// Каждый decoy должен содержать QUIC-подобный заголовок.
	for i := 0; i < 6; i++ {
		d, err := packet.Dissect(pkts[i].Data)
		if err != nil {
			t.Fatalf("decoy %d: разбор: %v", i, err)
		}
		pl, ok := d.Payload(pkts[i].Data)
		if !ok {
			t.Fatalf("decoy %d: нет нагрузки", i)
		}
		if len(pl) < 5 || pl[0] != 0xc0 {
			t.Fatalf("decoy %d: ожидался QUIC long-header, первый байт 0x%02x", i, pl[0])
		}
	}
}

func TestBuildVoiceDecoysSkipsNonDiscovery(t *testing.T) {
	pkt := udpDiscoveryPacket(t)
	// Портим тип — уже не IP discovery.
	binary.BigEndian.PutUint16(pkt.Data[28:], 0x00FF)
	d, _ := packet.Dissect(pkt.Data)
	_ = d.RecomputeChecksums(pkt.Data)

	if _, applied := buildVoiceDecoys(pkt, discordvoice.FoolTTL, 6, 3, voicePayloadNeutral); applied {
		t.Fatal("на не-discovery UDP приём применяться не должен")
	}
}

func TestBuildVoiceDecoysSkipsInbound(t *testing.T) {
	pkt := udpDiscoveryPacket(t)
	pkt.Dir = core.DirectionInbound
	if _, applied := buildVoiceDecoys(pkt, discordvoice.FoolTTL, 6, 3, voicePayloadNeutral); applied {
		t.Fatal("входящий пакет десинку голоса не подлежит")
	}
}

// TestParseVoiceModeQUICVariants: новые режимы ttl-quic и badsum-quic
// разбираются корректно.
func TestParseVoiceModeQUICVariants(t *testing.T) {
	cases := []struct {
		s         string
		enabled   bool
		fool      discordvoice.Fooling
		payload   voicePayload
		shouldErr bool
	}{
		{"ttl", true, discordvoice.FoolTTL, voicePayloadNeutral, false},
		{"ttl-quic", true, discordvoice.FoolTTL, voicePayloadQUIC, false},
		{"badsum", true, discordvoice.FoolBadChecksum, voicePayloadNeutral, false},
		{"badsum-quic", true, discordvoice.FoolBadChecksum, voicePayloadQUIC, false},
		{"neverheard", false, 0, 0, true},
	}
	for _, c := range cases {
		m, err := parseVoiceMode(c.s)
		if c.shouldErr {
			if err == nil {
				t.Fatalf("parseVoiceMode(%q) должен был ошибиться", c.s)
			}
			continue
		}
		if err != nil {
			t.Fatalf("parseVoiceMode(%q): %v", c.s, err)
		}
		if m.enabled != c.enabled || m.fool != c.fool || m.payload != c.payload {
			t.Fatalf("parseVoiceMode(%q): %+v, ожидали enabled=%t fool=%d payload=%d",
				c.s, m, c.enabled, c.fool, c.payload)
		}
	}
}

// TestTallyUDPShapedStrict: ровно пакет Discord IP discovery (74 байта, тип
// 0x0001, длина 70) — и мягкий, и строгий счётчики попадают, адресат
// извлекается как «ip:port».
func TestTallyUDPShapedStrict(t *testing.T) {
	pkt := udpDiscoveryPacket(t)
	d, err := packet.Dissect(pkt.Data)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	c := tallyUDPShaped(pkt.Data, d)
	if !c.loose {
		t.Fatal("74-байтная нагрузка должна дать мягкое попадание")
	}
	if !c.strict {
		t.Fatal("строгая форма IP discovery должна быть распознана")
	}
	if c.endpoint != "66.22.200.1:50010" {
		t.Fatalf("адресат: ожидалось 66.22.200.1:50010, получено %q", c.endpoint)
	}
}

// TestTallyUDPShapedLooseOnly: 74 байта произвольного содержимого — мягкий да,
// строгий нет. Ровно эта разница и отделяет шум от сигнала.
func TestTallyUDPShapedLooseOnly(t *testing.T) {
	pkt := udpDiscoveryPacket(t)
	// Испортим тип: длина осталась 74 — мягкий счётчик считает, но форма уже
	// не IP discovery запроса. Пересчёт сумм не нужен — tally их не читает.
	binary.BigEndian.PutUint16(pkt.Data[28:], 0xDEAD)
	d, err := packet.Dissect(pkt.Data)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	c := tallyUDPShaped(pkt.Data, d)
	if !c.loose {
		t.Fatal("длина 74 должна давать мягкое попадание независимо от типа")
	}
	if c.strict {
		t.Fatal("без типа 0x0001 строгий счётчик срабатывать не должен")
	}
	if c.endpoint != "" {
		t.Fatalf("для не-строгого попадания адресат должен быть пустым, получено %q", c.endpoint)
	}
}

// TestTallyUDPShapedNonUDP: разобранный не-UDP пакет (например, TCP) не должен
// давать никаких попаданий — иначе счётчики ловили бы форму на чужих протоколах.
func TestTallyUDPShapedNonUDP(t *testing.T) {
	// Минимальный TCP-пакет: IPv4 + TCP без нагрузки.
	buf := make([]byte, 20+20)
	buf[0] = 0x45
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(buf)))
	buf[8] = 64
	buf[9] = 6 // TCP
	copy(buf[12:16], net.ParseIP("10.0.0.1").To4())
	copy(buf[16:20], net.ParseIP("10.0.0.2").To4())
	// Минимальный TCP: 5*4 = 20 байт заголовка.
	binary.BigEndian.PutUint16(buf[20:22], 12345)
	binary.BigEndian.PutUint16(buf[22:24], 443)
	buf[32] = 0x50 // Data Offset = 5

	d, err := packet.Dissect(buf)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	c := tallyUDPShaped(buf, d)
	if c.loose || c.strict {
		t.Fatalf("не-UDP пакет не должен давать попаданий, получено %+v", c)
	}
}

// TestAppendStrictEndpoint: пустые адреса игнорируются, предел maxStrictEndpoints
// соблюдается. Простая, но важная проверка: без неё лог может залить тысячей
// адресов одного и того же соединения с ретрансмитами.
func TestAppendStrictEndpoint(t *testing.T) {
	var dst []string
	dst = appendStrictEndpoint(dst, "")
	if len(dst) != 0 {
		t.Fatal("пустой адрес добавлять нельзя")
	}
	for i := 0; i < maxStrictEndpoints+5; i++ {
		dst = appendStrictEndpoint(dst, fmt.Sprintf("1.2.3.%d:443", i))
	}
	if len(dst) != maxStrictEndpoints {
		t.Fatalf("ожидалось %d адресов, получено %d", maxStrictEndpoints, len(dst))
	}
}

func TestParseVoiceMode(t *testing.T) {
	cases := map[string]struct {
		enabled bool
		fool    discordvoice.Fooling
		wantErr bool
	}{
		"":       {enabled: false},
		"off":    {enabled: false},
		"ttl":    {enabled: true, fool: discordvoice.FoolTTL},
		"badsum": {enabled: true, fool: discordvoice.FoolBadChecksum},
		"bogus":  {wantErr: true},
	}
	for in, want := range cases {
		m, err := parseVoiceMode(in)
		if want.wantErr {
			if err == nil {
				t.Fatalf("%q: ожидалась ошибка", in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if m.enabled != want.enabled || m.fool != want.fool {
			t.Fatalf("%q: получено %+v, ожидалось enabled=%v fool=%v", in, m, want.enabled, want.fool)
		}
	}
}

// Оба приёма идут вместе в любом режиме: короткий TTL не достаёт до далёкого
// DPI, битую сумму режут некоторые роутеры — сеть пользователя заранее неизвестна.
func TestVoiceDecoysUseBothFoolings(t *testing.T) {
	pkt := udpDiscoveryPacket(t)
	for _, fool := range []discordvoice.Fooling{discordvoice.FoolTTL, discordvoice.FoolBadChecksum} {
		pkts, applied := buildVoiceDecoys(pkt, fool, voiceDecoyTTL, 2, voicePayloadNeutral)
		if !applied || len(pkts) != 5 {
			t.Fatalf("fool %d: applied=%v, пакетов %d", fool, applied, len(pkts))
		}
		short, far := 0, 0
		for _, p := range pkts[:4] {
			d, err := packet.Dissect(p.Data)
			if err != nil {
				t.Fatal(err)
			}
			h, _ := d.IPv4(p.Data)
			valid := append([]byte(nil), p.Data...)
			d.RecomputeChecksums(valid)
			bad := string(valid) != string(p.Data)
			switch {
			case h.TTL() == voiceDecoyTTL && !bad:
				short++
			case h.TTL() == voiceBadsumTTL && bad:
				far++
			}
		}
		if short != 2 || far != 2 {
			t.Fatalf("fool %d: коротких TTL %d, с битой суммой %d", fool, short, far)
		}
	}
}
