package tunnel

import (
	"crypto/rand"
	"encoding/binary"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/fitting-1c/evasion/internal/quic"
)

const (
	wgHandshakeInitiationLen  = 148
	wgHandshakeInitiationType = 1
	wgJunkMinLen              = 40
	wgJunkMaxLen              = 90
)

// Mimic — чем притвориться первым пакетом UDP-потока до WireGuard
// (AmneziaWG 1.5, параметр I1). Cloudflare WARP молча отбрасывает всё, что не
// является сообщением WireGuard, поэтому имитация для пира безвредна, а DPI,
// который решает судьбу потока по первым пакетам, видит знакомый протокол.
type Mimic uint8

const (
	// MimicNone — без имитации, только случайный мусор (как раньше).
	MimicNone Mimic = iota
	// MimicQUIC — настоящий защищённый QUIC v1 Initial (1200 байт) с
	// ClientHello для MimicSNI: DPI снимает начальную защиту и видит начало
	// QUIC-соединения к безобидному сайту.
	MimicQUIC
	// MimicDNS — обычный DNS-запрос A для MimicSNI.
	MimicDNS
)

// Obfuscation — маскировка начала WireGuard-потока. Нулевое значение — без
// маскировки.
type Obfuscation struct {
	// Name — короткое имя профиля для журнала.
	Name string
	// Mimic — пакет-имитация перед мусором и Handshake Initiation.
	Mimic Mimic
	// MimicSNI — имя сайта внутри имитации (QUIC SNI или вопрос DNS).
	MimicSNI string
	// Junk — сколько случайных пакетов (AmneziaWG Jc) отправить перед каждым
	// Handshake Initiation.
	Junk int
	// JunkMin, JunkMax — границы длины мусорного пакета; 0 — 40..90 байт.
	JunkMin, JunkMax int
}

func (o Obfuscation) enabled() bool { return o.Junk > 0 || o.Mimic != MimicNone }

// junkBind wraps a WireGuard conn.Bind and emits AmneziaWG-style packets from
// the same bound socket right before each WireGuard Handshake Initiation: an
// optional protocol imitation (QUIC Initial / DNS query) and random junk.
// Cloudflare WARP endpoints silently drop non-WG packets, while stateful DPI
// filters that match the 148-byte 01 00 00 00 flow opening lose the signature.
type junkBind struct {
	conn.Bind
	obfs Obfuscation
}

func newJunkBind(inner conn.Bind, junkCount int) conn.Bind {
	return newObfuscatedBind(inner, Obfuscation{Junk: junkCount})
}

func newObfuscatedBind(inner conn.Bind, obfs Obfuscation) conn.Bind {
	if !obfs.enabled() {
		return inner
	}
	if obfs.JunkMin <= 0 || obfs.JunkMax < obfs.JunkMin {
		obfs.JunkMin, obfs.JunkMax = wgJunkMinLen, wgJunkMaxLen
	}
	return &junkBind{Bind: inner, obfs: obfs}
}

func isWGHandshakeInitiation(pkt []byte) bool {
	return len(pkt) == wgHandshakeInitiationLen &&
		pkt[0] == wgHandshakeInitiationType &&
		pkt[1] == 0 && pkt[2] == 0 && pkt[3] == 0
}

func (b *junkBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	hasInit := false
	for _, pkt := range bufs {
		if isWGHandshakeInitiation(pkt) {
			hasInit = true
			break
		}
	}
	if hasInit {
		b.sendPrelude(ep)
	}
	return b.Bind.Send(bufs, ep)
}

// sendPrelude отправляет имитацию и мусор. Ошибки не мешают рукопожатию:
// маскировка — подсказка для DPI, а не условие работы туннеля.
func (b *junkBind) sendPrelude(ep conn.Endpoint) {
	if mimic := buildMimicPacket(b.obfs.Mimic, b.obfs.MimicSNI); mimic != nil {
		if err := b.Bind.Send([][]byte{mimic}, ep); err != nil {
			return
		}
	}
	for range b.obfs.Junk {
		junk := buildWGJunkPacketSized(b.obfs.JunkMin, b.obfs.JunkMax)
		if err := b.Bind.Send([][]byte{junk}, ep); err != nil {
			return
		}
	}
}

func buildMimicPacket(kind Mimic, sni string) []byte {
	if sni == "" {
		sni = "ya.ru"
	}
	switch kind {
	case MimicQUIC:
		dcid := make([]byte, 8)
		_, _ = rand.Read(dcid)
		pkt, ok := quic.BuildClientInitial(sni, dcid)
		if !ok {
			return nil
		}
		return pkt
	case MimicDNS:
		return buildDNSMimic(sni)
	default:
		return nil
	}
}

// buildDNSMimic собирает DNS-запрос A IN для name. Старший байт ID держится
// вне 0x01..0x04, чтобы пир не принял пакет за сообщение WireGuard.
func buildDNSMimic(name string) []byte {
	var id [2]byte
	_, _ = rand.Read(id[:])
	id[0] = 0x10 + id[0]%0xE0
	q := []byte{id[0], id[1], 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			label := name[start:i]
			if len(label) == 0 || len(label) > 63 {
				return nil
			}
			q = append(q, byte(len(label)))
			q = append(q, label...)
			start = i + 1
		}
	}
	return append(q, 0x00, 0x00, 0x01, 0x00, 0x01)
}

func buildWGJunkPacket() []byte {
	return buildWGJunkPacketSized(wgJunkMinLen, wgJunkMaxLen)
}

func buildWGJunkPacketSized(minLen, maxLen int) []byte {
	if minLen < 1 {
		minLen = 1
	}
	if maxLen < minLen {
		maxLen = minLen
	}
	var lenBuf [2]byte
	_, _ = rand.Read(lenBuf[:])
	span := maxLen - minLen + 1
	n := minLen + int(binary.LittleEndian.Uint16(lenBuf[:]))%span
	buf := make([]byte, n)
	_, _ = rand.Read(buf)
	// Avoid WireGuard message types 0x01..0x04 so the peer discards it cleanly.
	buf[0] = 0x10 + (buf[0] % 0xE0)
	return buf
}

// WARPObfuscationProfiles — профили маскировки для резерва звонков, по
// порядку перебора. Первый повторяет прежнее поведение (на сетях, где оно
// работало, ничего не меняется); остальные пробуются, когда провайдер
// пропускает рукопожатие, но режет поток через пару секунд.
var WARPObfuscationProfiles = []Obfuscation{
	{Name: "junk", Junk: 4},
	{Name: "quic-ya", Mimic: MimicQUIC, MimicSNI: "ya.ru", Junk: 4},
	{Name: "dns-vk", Mimic: MimicDNS, MimicSNI: "vk.com", Junk: 4},
	{Name: "quic-vk-heavy", Mimic: MimicQUIC, MimicSNI: "vk.com", Junk: 10, JunkMin: 64, JunkMax: 256},
}

// WARPObfuscationProfile возвращает профиль по имени и его индекс.
func WARPObfuscationProfile(name string) (Obfuscation, int, bool) {
	for i, p := range WARPObfuscationProfiles {
		if p.Name == name {
			return p, i, true
		}
	}
	return Obfuscation{}, -1, false
}
