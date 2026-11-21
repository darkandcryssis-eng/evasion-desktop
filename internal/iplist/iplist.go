// Package iplist — пользовательский список IP-адресов и подсетей, к которым
// обход применяется по адресу назначения, а не по имени сервера (аналог
// ipset-all.txt в zapret).
package iplist

import (
	"fmt"
	"net/netip"
	"os"
	"strings"
)

// MaxEntries ограничивает список: поиск линейный и идёт на каждый ClientHello.
const MaxEntries = 4096

// Set — неизменяемый набор подсетей.
type Set struct{ prefixes []netip.Prefix }

// Parse разбирает текст: по одному IP или CIDR на строку, «#» начинает
// комментарий. Запятые и точки с запятой тоже разделяют записи.
// Частные, loopback и слишком широкие диапазоны отклоняются: список не должен
// превращаться в «обход для всего интернета» или трогать локальную сеть.
func Parse(text string) (*Set, error) {
	set := &Set{}
	seen := map[netip.Prefix]bool{}
	for n, line := range strings.Split(text, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		for _, field := range strings.FieldsFunc(line, func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\r' }) {
			p, err := parseEntry(field)
			if err != nil {
				return nil, fmt.Errorf("строка %d: %w", n+1, err)
			}
			if seen[p] {
				continue
			}
			if len(set.prefixes) >= MaxEntries {
				return nil, fmt.Errorf("в списке больше %d записей", MaxEntries)
			}
			seen[p] = true
			set.prefixes = append(set.prefixes, p)
		}
	}
	return set, nil
}

func parseEntry(s string) (netip.Prefix, error) {
	var p netip.Prefix
	if strings.Contains(s, "/") {
		parsed, err := netip.ParsePrefix(s)
		if err != nil {
			return p, fmt.Errorf("%q — не подсеть (пример: 203.0.113.0/24)", s)
		}
		p = netip.PrefixFrom(parsed.Addr().Unmap(), parsed.Bits()).Masked()
		if parsed.Addr().Is4In6() {
			p = netip.PrefixFrom(parsed.Addr().Unmap(), max(0, parsed.Bits()-96)).Masked()
		}
	} else {
		addr, err := netip.ParseAddr(s)
		if err != nil || addr.Zone() != "" {
			return p, fmt.Errorf("%q — не IP-адрес (пример: 203.0.113.7)", s)
		}
		addr = addr.Unmap()
		p = netip.PrefixFrom(addr, addr.BitLen())
	}
	minBits := 8
	if p.Addr().Is6() {
		minBits = 16
	}
	if p.Bits() < minBits {
		return p, fmt.Errorf("%s — слишком широкая подсеть (минимум /%d)", s, minBits)
	}
	if a := p.Addr(); !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() {
		return p, fmt.Errorf("%s — локальный или служебный адрес, обход к нему не нужен", s)
	}
	return p, nil
}

// Load читает список из файла. Отсутствующий файл — пустой список.
func Load(path string) (*Set, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &Set{}, nil
	}
	if err != nil {
		return nil, err
	}
	return Parse(strings.TrimPrefix(string(b), "\ufeff"))
}

// Len — число записей.
func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.prefixes)
}

// Contains сообщает, попадает ли адрес в список.
func (s *Set) Contains(ip netip.Addr) bool {
	if s == nil {
		return false
	}
	ip = ip.Unmap()
	// Широкая запись (172.0.0.0/8) может накрыть частную сеть — её не трогаем.
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, p := range s.prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// Entries — записи в каноническом виде (одиночный адрес без /32 и /128).
func (s *Set) Entries() []string {
	out := make([]string, 0, s.Len())
	if s == nil {
		return out
	}
	for _, p := range s.prefixes {
		if p.IsSingleIP() {
			out = append(out, p.Addr().String())
		} else {
			out = append(out, p.String())
		}
	}
	return out
}
