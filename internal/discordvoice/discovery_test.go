package discordvoice

import (
	"encoding/binary"
	"testing"
)

// buildDiscovery собирает пакет обнаружения внешнего IP заданного типа по
// официальной раскладке Discord. Эталон для golden-проверки распознавания.
func buildDiscovery(typ uint16) []byte {
	p := make([]byte, discoveryLen)
	binary.BigEndian.PutUint16(p[0:], typ)    // тип
	binary.BigEndian.PutUint16(p[2:], 70)     // длина тела
	binary.BigEndian.PutUint32(p[4:], 0x1234) // SSRC
	// адрес (8..71) и порт (72..73) у запроса клиента — нули.
	return p
}

func TestIsIPDiscoveryRequestGolden(t *testing.T) {
	req := buildDiscovery(discoveryTypeReq)
	if !IsIPDiscoveryRequest(req) {
		t.Fatal("эталонный 74-байтный запрос IP discovery не распознан")
	}
	if len(req) != 74 {
		t.Fatalf("эталон должен быть 74 байта, получено %d", len(req))
	}
}

func TestIsIPDiscoveryRequestRejectsResponse(t *testing.T) {
	// Ответ сервера (0x0002) — это не запрос клиента: момент десинка не на нём.
	resp := buildDiscovery(discoveryTypeResp)
	if IsIPDiscoveryRequest(resp) {
		t.Fatal("ответ сервера не должен считаться запросом клиента")
	}
	// Но как пакет IP discovery распознаётся оба направления.
	if !IsIPDiscovery(resp) {
		t.Fatal("ответ сервера должен распознаваться как пакет IP discovery")
	}
}

func TestIsIPDiscoveryRequestRejectsWrongShape(t *testing.T) {
	cases := []struct {
		name    string
		payload []byte
	}{
		{"пусто", nil},
		{"короче 74", make([]byte, 73)},
		{"длиннее 74", make([]byte, 75)},
		{"устаревшие 70 байт", make([]byte, 70)},
		{"верная длина, чужой тип", func() []byte {
			p := buildDiscovery(0x0003)
			return p
		}()},
		{"верная длина и тип, но поле длины не 70", func() []byte {
			p := buildDiscovery(discoveryTypeReq)
			binary.BigEndian.PutUint16(p[2:], 64)
			return p
		}()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if IsIPDiscoveryRequest(c.payload) {
				t.Fatalf("%s: не должно распознаваться как запрос IP discovery", c.name)
			}
		})
	}
}

// TestRejectsArbitraryUDPOfSameLength: 74-байтный «мусор» не из Discord не
// должен ложно опознаваться — иначе десинк пошёл бы по чужому UDP (1.6).
func TestRejectsArbitraryUDPOfSameLength(t *testing.T) {
	junk := make([]byte, 74)
	for i := range junk {
		junk[i] = byte(i)
	}
	if IsIPDiscoveryRequest(junk) {
		t.Fatal("произвольные 74 байта не должны считаться запросом Discord")
	}
}

func TestIsSTUNBindingRequest(t *testing.T) {
	stun := func(kind uint16, attrs int) []byte {
		b := make([]byte, 20+attrs)
		binary.BigEndian.PutUint16(b[0:], kind)
		binary.BigEndian.PutUint16(b[2:], uint16(attrs))
		binary.BigEndian.PutUint32(b[4:], 0x2112A442)
		return b
	}
	if !IsSTUNBindingRequest(stun(0x0001, 0)) || !IsSTUNBindingRequest(stun(0x0001, 80)) {
		t.Fatal("запрос STUN Binding не распознан")
	}
	noCookie := stun(0x0001, 80)
	noCookie[4] = 0
	badLen := stun(0x0001, 80)[:96]
	for name, p := range map[string][]byte{
		"ответ": stun(0x0101, 80), "без cookie": noCookie, "длина": badLen,
		"короткий": stun(0x0001, 0)[:19], "discovery": buildDiscovery(discoveryTypeReq),
	} {
		if IsSTUNBindingRequest(p) {
			t.Fatalf("%s: принят за запрос STUN Binding", name)
		}
	}
}
