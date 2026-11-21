package main

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/fitting-1c/evasion/internal/capture"
	"github.com/fitting-1c/evasion/internal/config"
	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/packet"
	"github.com/fitting-1c/evasion/internal/quic"
)

// TestQUICDesyncRewritesRadius — в режиме desync QUIC к домену радиуса
// переписывается: та же длина, суммы верны, сервер по-прежнему читает имя.
func TestQUICDesyncRewritesRadius(t *testing.T) {
	pkt := capture.Packet{Data: udp4(443, mustHex(t, clientInitialExampleCom)), Dir: core.DirectionOutbound}
	out, sni, done := quicDesyncPacket(pkt, domainSetFor(t, "example.com"))
	if !done {
		t.Fatal("QUIC к example.com в режиме desync должен переписываться")
	}
	if sni != "example.com" {
		t.Fatalf("имя: ожидалось example.com, получено %q", sni)
	}
	if len(out.Data) != len(pkt.Data) {
		t.Fatalf("длина пакета изменилась: %d → %d", len(pkt.Data), len(out.Data))
	}
	d, err := packet.Dissect(out.Data)
	if err != nil {
		t.Fatalf("переписанный пакет не разбирается: %v", err)
	}
	if !d.VerifyChecksums(out.Data) {
		t.Error("контрольные суммы переписанного пакета неверны")
	}
	payload, _ := d.Payload(out.Data)
	if sni2, ok := quic.PeekSNI(payload); !ok || sni2 != "example.com" {
		t.Fatalf("сервер должен прочитать переписанный пакет как example.com, получено %q ok=%v", sni2, ok)
	}
}

// TestQUICDesyncLeavesNonRadius — чужой QUIC в режиме desync не трогается.
func TestQUICDesyncLeavesNonRadius(t *testing.T) {
	pkt := capture.Packet{Data: udp4(443, mustHex(t, clientInitialExampleCom)), Dir: core.DirectionOutbound}
	out, _, done := quicDesyncPacket(pkt, domainSetFor(t, "youtube.com"))
	if done {
		t.Fatal("чужой QUIC трогать нельзя")
	}
	if string(out.Data) != string(pkt.Data) {
		t.Fatal("нерадиусный пакет должен уйти как есть")
	}
}

// clientInitialExampleCom — защищённый клиентский QUIC Initial из RFC 9001 A.2;
// его ClientHello называет SNI "example.com". Берём как готовую QUIC-датаграмму.
const clientInitialExampleCom = `
c000000001088394c8f03e5157080000 449e7b9aec34d1b1c98dd7689fb8ec11
d242b123dc9bd8bab936b47d92ec356c 0bab7df5976d27cd449f63300099f399
1c260ec4c60d17b31f8429157bb35a12 82a643a8d2262cad67500cadb8e7378c
8eb7539ec4d4905fed1bee1fc8aafba1 7c750e2c7ace01e6005f80fcb7df6212
30c83711b39343fa028cea7f7fb5ff89 eac2308249a02252155e2347b63d58c5
457afd84d05dfffdb20392844ae81215 4682e9cf012f9021a6f0be17ddd0c208
4dce25ff9b06cde535d0f920a2db1bf3 62c23e596d11a4f5a6cf3948838a3aec
4e15daf8500a6ef69ec4e3feb6b1d98e 610ac8b7ec3faf6ad760b7bad1db4ba3
485e8a94dc250ae3fdb41ed15fb6a8e5 eba0fc3dd60bc8e30c5c4287e53805db
059ae0648db2f64264ed5e39be2e20d8 2df566da8dd5998ccabdae053060ae6c
7b4378e846d29f37ed7b4ea9ec5d82e7 961b7f25a9323851f681d582363aa5f8
9937f5a67258bf63ad6f1a0b1d96dbd4 faddfcefc5266ba6611722395c906556
be52afe3f565636ad1b17d508b73d874 3eeb524be22b3dcbc2c7468d54119c74
68449a13d8e3b95811a198f3491de3e7 fe942b330407abf82a4ed7c1b311663a
c69890f4157015853d91e923037c227a 33cdd5ec281ca3f79c44546b9d90ca00
f064c99e3dd97911d39fe9c5d0b23a22 9a234cb36186c4819e8b9c5927726632
291d6a418211cc2962e20fe47feb3edf 330f2c603a9d48c0fcb5699dbfe58964
25c5bac4aee82e57a85aaf4e2513e4f0 5796b07ba2ee47d80506f8d2c25e50fd
14de71e6c418559302f939b0e1abd576 f279c4b2e0feb85c1f28ff18f58891ff
ef132eef2fa09346aee33c28eb130ff2 8f5b766953334113211996d20011a198
e3fc433f9f2541010ae17c1bf202580f 6047472fb36857fe843b19f5984009dd
c324044e847a4f4a0ab34f719595de37 252d6235365e9b84392b061085349d73
203a4a13e96f5432ec0fd4a1ee65accd d5e3904df54c1da510b0ff20dcc0c77f
cb2c0e0eb605cb0504db87632cf3d8b4 dae6e705769d1de354270123cb11450e
fc60ac47683d7b8d0f811365565fd98c 4c8eb936bcab8d069fc33bd801b03ade
a2e1fbc5aa463d08ca19896d2bf59a07 1b851e6c239052172f296bfb5e724047
90a2181014f3b94a4e97d117b4381303 68cc39dbb2d198065ae3986547926cd2
162f40a29f0c3c8745c0f50fba3852e5 66d44575c29d39a03f0cda721984b6f4
40591f355e12d439ff150aab7613499d bd49adabc8676eef023b15b65bfc5ca0
6948109f23f350db82123535eb8a7433 bdabcb909271a6ecbcb58b936a88cd4e
8f2e6ff5800175f113253d8fa9ca8885 c2f552e657dc603f252e1a8e308f76f0
be79e2fb8f5d5fbbe2e30ecadd220723 c8c0aea8078cdfcb3868263ff8f09400
54da48781893a7e49ad5aff4af300cd8 04a6b6279ab3ff3afb64491c85194aab
760d58a606654f9f4400e8b38591356f bf6425aca26dc85244259ff2b19c41b9
f96f3ca9ec1dde434da7d2d392b905dd f3d1f9af93d1af5950bd493f5aa731b4
056df31bd267b6b90a079831aaf579be 0a39013137aac6d404f518cfd4684064
7e78bfe706ca4cf5e9c5453e9f7cfd2b 8b4c8d169a44e55c88d4a9a7f9474241
e221af44860018ab0856972e194cd934`

// mustHex декодирует hex из тест-вектора, убирая пробелы.
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.NewReplacer(" ", "", "\n", "", "\t", "").Replace(s))
	if err != nil {
		t.Fatalf("негодный hex: %v", err)
	}
	return b
}

// udp4 оборачивает полезную нагрузку в пакет IPv4+UDP к указанному порту
// назначения. Контрольные суммы не ставятся: разбор их не проверяет.
func udp4(dstPort uint16, payload []byte) []byte {
	const ip, udp = 20, 8
	total := ip + udp + len(payload)
	b := make([]byte, total)
	b[0] = 0x45 // версия 4, IHL 5
	binary.BigEndian.PutUint16(b[2:], uint16(total))
	b[8] = 64 // TTL
	b[9] = 17 // протокол UDP
	copy(b[12:], []byte{192, 0, 2, 1})
	copy(b[16:], []byte{192, 0, 2, 2})
	binary.BigEndian.PutUint16(b[ip+2:], dstPort)
	binary.BigEndian.PutUint16(b[ip+4:], uint16(udp+len(payload)))
	copy(b[ip+udp:], payload)
	return b
}

func domainSetFor(t *testing.T, domains ...string) *config.DomainSet {
	t.Helper()
	cfg := &config.Config{Groups: map[string][]string{"g": domains}}
	ds, err := cfg.DomainSet(nil)
	if err != nil {
		t.Fatal(err)
	}
	return ds
}

// TestQUICShouldBlockMatchingDomain: исходящий QUIC Initial к домену радиуса
// роняется, и возвращается распознанное имя.
func TestQUICShouldBlockMatchingDomain(t *testing.T) {
	pkt := capture.Packet{Data: udp4(443, mustHex(t, clientInitialExampleCom)), Dir: core.DirectionOutbound}
	sni, block := quicShouldBlock(pkt, domainSetFor(t, "example.com"), quic.NewReassembler(), time.Now())
	if !block {
		t.Fatal("QUIC к example.com в радиусе должен блокироваться")
	}
	if sni != "example.com" {
		t.Fatalf("имя сервера: ожидалось example.com, получено %q", sni)
	}
}

// TestQUICShouldNotBlock собирает случаи, где ронять нельзя: чужой домен,
// входящий пакет, не-QUIC нагрузка UDP, не-UDP пакет.
func TestQUICShouldNotBlock(t *testing.T) {
	initial := mustHex(t, clientInitialExampleCom)

	t.Run("домен вне радиуса", func(t *testing.T) {
		pkt := capture.Packet{Data: udp4(443, initial), Dir: core.DirectionOutbound}
		if _, block := quicShouldBlock(pkt, domainSetFor(t, "youtube.com"), quic.NewReassembler(), time.Now()); block {
			t.Fatal("чужой QUIC трогать нельзя")
		}
	})
	t.Run("входящий", func(t *testing.T) {
		pkt := capture.Packet{Data: udp4(443, initial), Dir: core.DirectionInbound}
		if _, block := quicShouldBlock(pkt, domainSetFor(t, "example.com"), quic.NewReassembler(), time.Now()); block {
			t.Fatal("входящий пакет не блокируем")
		}
	})
	t.Run("не-QUIC UDP", func(t *testing.T) {
		pkt := capture.Packet{Data: udp4(443, []byte("not a quic initial")), Dir: core.DirectionOutbound}
		if _, block := quicShouldBlock(pkt, domainSetFor(t, "example.com"), quic.NewReassembler(), time.Now()); block {
			t.Fatal("нераспознанный UDP пропускаем, а не блокируем")
		}
	})
	t.Run("пустой радиус", func(t *testing.T) {
		empty, _ := (&config.Config{}).DomainSet(nil)
		pkt := capture.Packet{Data: udp4(443, initial), Dir: core.DirectionOutbound}
		if _, block := quicShouldBlock(pkt, empty, quic.NewReassembler(), time.Now()); block {
			t.Fatal("при пустом радиусе не блокируем ничего")
		}
	})
}

// udp4From — udp4 с заданным портом источника: отдельный UDP-поток.
func udp4From(srcPort uint16, payload []byte) []byte {
	b := udp4(443, payload)
	binary.BigEndian.PutUint16(b[20:], srcPort)
	return b
}

// TestQUICFlowsBlockAfterDCIDChange: когда ClientHello к радиусу собран, поток
// блокируется целиком. Живой Chrome после сброса повторяет Initial с новым DCID
// (его сборщик расшифровать не может) и шлёт пакеты с коротким заголовком — они
// не должны проходить, иначе рукопожатие QUIC завершается мимо блокировки.
func TestQUICFlowsBlockAfterDCIDChange(t *testing.T) {
	parts, ok := quic.SplitClientInitial(mustHex(t, clientInitialExampleCom), 20)
	if !ok || len(parts) != 2 {
		t.Fatalf("не удалось разбить Initial: ok=%v частей=%d", ok, len(parts))
	}
	ds := domainSetFor(t, "example.com")
	reasm, flows, now := quic.NewReassembler(), newQUICFlows(nil), time.Now()
	out := func(srcPort uint16, payload []byte) capture.Packet {
		return capture.Packet{Data: udp4From(srcPort, payload), Dir: core.DirectionOutbound}
	}

	if _, block := flows.shouldBlock(out(50000, parts[0]), ds, reasm, now); block {
		t.Fatal("первая часть ClientHello: имени ещё нет, блокировать рано")
	}
	if sni, block := flows.shouldBlock(out(50000, parts[1]), ds, reasm, now); !block || sni != "example.com" {
		t.Fatalf("собранный ClientHello к радиусу: sni=%q block=%v", sni, block)
	}

	// Повтор с новым DCID: ключи остались от исходного, сборщику его не разобрать.
	retry := append([]byte(nil), parts[1]...)
	retry[6] ^= 0x80
	if _, ok := quic.NewReassembler().Offer(retry, now); ok {
		t.Fatal("тест-вектор негоден: повтор с чужим DCID не должен разбираться")
	}
	if sni, block := flows.shouldBlock(out(50000, retry), ds, reasm, now); !block || sni != "example.com" {
		t.Fatalf("повтор с новым DCID на заблокированном потоке прошёл: sni=%q block=%v", sni, block)
	}
	short := []byte{0x40, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
	if _, block := flows.shouldBlock(out(50000, short), ds, reasm, now); !block {
		t.Fatal("короткий заголовок на заблокированном потоке прошёл")
	}

	if _, block := flows.shouldBlock(out(50001, retry), ds, reasm, now); block {
		t.Fatal("чужой поток (другой порт) блокировать нельзя")
	}
	in := capture.Packet{Data: udp4From(50000, short), Dir: core.DirectionInbound}
	if _, block := flows.shouldBlock(in, ds, reasm, now); block {
		t.Fatal("входящий пакет не блокируем")
	}
	if _, block := flows.shouldBlock(out(50000, short), ds, reasm, now.Add(quicFlowTTL+2*time.Second)); block {
		t.Fatal("после простоя дольше quicFlowTTL поток должен быть забыт")
	}
}

// TestQUICFlowsReleaseOnOtherDomain: собранное имя вне радиуса на том же потоке
// снимает блокировку — порт мог достаться другому соединению.
func TestQUICFlowsReleaseOnOtherDomain(t *testing.T) {
	ds := domainSetFor(t, "example.com")
	reasm, flows, now := quic.NewReassembler(), newQUICFlows(nil), time.Now()
	pkt := func(payload []byte) capture.Packet {
		return capture.Packet{Data: udp4From(50000, payload), Dir: core.DirectionOutbound}
	}
	if _, block := flows.shouldBlock(pkt(mustHex(t, clientInitialExampleCom)), ds, reasm, now); !block {
		t.Fatal("Initial к радиусу должен блокироваться")
	}
	if _, block := flows.shouldBlock(pkt(initialForYouTube(t)), ds, reasm, now); block {
		t.Fatal("Initial к домену вне радиуса блокировать нельзя")
	}
	if _, block := flows.shouldBlock(pkt([]byte{0x40, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}), ds, reasm, now); block {
		t.Fatal("после чужого ClientHello поток должен быть разблокирован")
	}
}

// TestQUICFlowsKnownFlowNoAllocs: вердикт по уже известному потоку — горячий
// путь (каждая датаграмма установленной сессии) и памяти не выделяет.
func TestQUICFlowsKnownFlowNoAllocs(t *testing.T) {
	ds := domainSetFor(t, "example.com")
	reasm, flows, now := quic.NewReassembler(), newQUICFlows(nil), time.Now()
	if _, block := flows.shouldBlock(capture.Packet{Data: udp4From(50000, mustHex(t, clientInitialExampleCom)), Dir: core.DirectionOutbound}, ds, reasm, now); !block {
		t.Fatal("Initial к радиусу должен блокироваться")
	}
	short := capture.Packet{Data: udp4From(50000, []byte{0x40, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}), Dir: core.DirectionOutbound}
	if n := testing.AllocsPerRun(100, func() {
		if _, block := flows.shouldBlock(short, ds, reasm, now); !block {
			t.Fatal("известный поток должен блокироваться")
		}
	}); n != 0 {
		t.Fatalf("вердикт по известному потоку выделяет память: %v на вызов", n)
	}
}
