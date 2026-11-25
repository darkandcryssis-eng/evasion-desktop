package telegramtune

import (
	"errors"
	"net/netip"
	"strconv"
	"strings"

	"github.com/fitting-1c/evasion/internal/strategy"
)

// Domains — official Telegram web, API, and media domains.
var Domains = []string{
	"telegram.org",
	"t.me",
	"telegram.me",
	"tdesktop.com",
	"telegra.ph",
	"telesco.pe",
	"cdn-telegram.org",
	"tx.me",
	"tg.dev",
}

// CIDRs — official Telegram data-center address ranges (IPv4 and IPv6).
var CIDRs = []string{
	"149.154.160.0/20",
	"91.108.4.0/22",
	"91.108.8.0/22",
	"91.108.12.0/22",
	"91.108.16.0/22",
	"91.108.20.0/22",
	"91.108.56.0/22",
	"91.105.192.0/23",
	"185.76.151.0/24",
	"2001:b28:f23d::/48",
	"2001:b28:f23f::/48",
	"2001:67c:4e8::/48",
	"2001:b28:f23c::/48",
	"2a0a:f280::/32",
}

// Profiles — ordered DPI bypass strategy profiles for Telegram traffic, from
// cleanest overlap/fragmentation to stronger fake-packet bursts.
var Profiles = []string{
	"overlap-vk",
	"overlap-yandex",
	"fake-seq-disorder",
	"fake-burst-overlap",
	"fake-ttl-split",
	"fake-badsum-split",
	"split-offset",
}

var telegramPrefixes = mustParsePrefixes(CIDRs)

func mustParsePrefixes(raw []string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(raw))
	for _, s := range raw {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			panic("telegramtune: invalid CIDR " + s + ": " + err.Error())
		}
		out = append(out, p.Masked())
	}
	return out
}

// IsTelegramHost reports whether host belongs to Telegram's domains.
func IsTelegramHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		return false
	}
	for _, d := range Domains {
		if host == d || (len(host) > len(d) && host[len(host)-len(d)-1:] == "."+d) {
			return true
		}
	}
	return false
}

// IsTelegramIP reports whether raw parses as an IP inside Telegram's DC ranges.
func IsTelegramIP(raw string) bool {
	ip, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	ip = ip.Unmap()
	for _, p := range telegramPrefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// IsTelegramTarget reports whether either SNI or destination host/IP targets Telegram.
func IsTelegramTarget(sni, host string) bool {
	return IsTelegramHost(sni) || IsTelegramHost(host) || IsTelegramIP(host)
}

func fakeBurst(inner, preset string, count int, badseqDelta uint64) string {
	fake := `{"kind":"tamper","params":{"field":"tcp_seq","mode":"add","value":` + strconv.FormatUint(badseqDelta, 10) +
		`},"left":{"kind":"tamper","params":{"field":"payload","mode":"replace","preset":"` + preset + `"},"left":{"kind":"send"}}}`
	action := inner
	for range count {
		action = `{"kind":"duplicate","left":` + fake + `,"right":` + action + `}`
	}
	return action
}

// NamedStrategy pairs a human-readable profile name with its compiled strategy.
type NamedStrategy struct {
	Name        string
	Strategy    *strategy.Strategy
	NeedsSNI    bool
	NeedsLongCH bool
}

// Profile builds one named Telegram DPI bypass strategy.
func Profile(name string) (NamedStrategy, error) {
	var action string
	var needsSNI, needsLongCH bool
	switch name {
	case "overlap-vk":
		action = `{"kind":"tcp_overlap","params":{"preset":"tls_cover_681","offset":1}}`
		needsLongCH = true
	case "overlap-yandex":
		action = `{"kind":"tcp_overlap","params":{"preset":"tls_cover_681_yandex","offset":1}}`
		needsLongCH = true
	case "fake-seq-disorder":
		inner := `{"kind":"fragment","params":{"proto":"tcp","at":"inside_sld","order":"reverse"},"left":{"kind":"send"},"right":{"kind":"send"}}`
		action = fakeBurst(inner, "tls_clienthello_vk", 1, 4294957296)
		needsSNI = true
	case "fake-burst-overlap":
		inner := `{"kind":"tcp_overlap","params":{"preset":"tls_cover_681","offset":1}}`
		action = fakeBurst(inner, "tls_clienthello_yandex", 6, 4294957296)
		needsLongCH = true
	case "fake-ttl-split":
		action = `{"kind":"duplicate","left":{"kind":"tamper","params":{"field":"ipv4_ttl","mode":"auto_ttl","value":1},"left":{"kind":"tamper","params":{"field":"payload","mode":"replace","preset":"tls_clienthello_google"},"left":{"kind":"send"}}},"right":{"kind":"fragment","params":{"proto":"tcp","at":"inside_sni","order":"forward"},"left":{"kind":"send"},"right":{"kind":"send"}}}`
		needsSNI = true
	case "fake-badsum-split":
		action = `{"kind":"duplicate","left":{"kind":"tamper","params":{"field":"tcp_checksum","mode":"corrupt"},"left":{"kind":"tamper","params":{"field":"payload","mode":"replace","preset":"tls_clienthello_google"},"left":{"kind":"send"}}},"right":{"kind":"fragment","params":{"proto":"tcp","at":"inside_sni","order":"forward"},"left":{"kind":"send"},"right":{"kind":"send"}}}`
		needsSNI = true
	case "split-offset":
		action = `{"kind":"fragment","params":{"proto":"tcp","offset":2,"order":"reverse"},"left":{"kind":"send"},"right":{"kind":"send"}}`
	default:
		return NamedStrategy{}, errors.New("неизвестный профиль Telegram")
	}
	s, err := strategy.Unmarshal([]byte(`{"rules":[{"direction":"outbound","trigger":{"match":"client_hello"},"action":`+action+`}]}`), strategy.DefaultLimits())
	if err != nil {
		return NamedStrategy{}, err
	}
	return NamedStrategy{
		Name:        name,
		Strategy:    s,
		NeedsSNI:    needsSNI,
		NeedsLongCH: needsLongCH,
	}, nil
}

// Portfolio compiles all built-in Telegram DPI bypass strategies in priority order.
func Portfolio() ([]NamedStrategy, error) {
	out := make([]NamedStrategy, 0, len(Profiles))
	for _, name := range Profiles {
		item, err := Profile(name)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, nil
}
