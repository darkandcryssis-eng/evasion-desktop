package config

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

// DomainSet — множество доменов, по которому решается, попадает ли хост под
// заданный радиус поражения.
//
// Строится из выбранных групп конфига. Сопоставление идёт по суффиксу: хост
// принадлежит множеству, если он равен домену или является его поддоменом
// (например, "www.youtube.com" ⊂ "youtube.com"). Это привычная для списков
// доменов семантика; точного совпадения мало — приложение ходит на поддомены.
type DomainSet struct {
	// domains — нормализованные домены множества. Храним срезом, а не картой:
	// проверка суффикса всё равно требует перебора, а множеств доменов — единицы
	// на соединение не влияют (горячий путь это не трогает).
	domains []string
}

// normalizeHost приводит имя хоста к форме для сравнения: нижний регистр, без
// завершающей точки, без порта. Возвращает пустую строку, если на входе был IP:
// по IP групповое сопоставление не делается (группы заданы доменами).
func normalizeHost(host string) string {
	host = strings.TrimSpace(host)
	// Если это host:port — отрезаем порт. SplitHostPort вернёт ошибку для
	// голого имени без порта, поэтому ошибку просто игнорируем.
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		return ""
	}
	if net.ParseIP(host) != nil {
		return ""
	}
	return host
}

// normalizeDomain приводит домен из конфига к канонической форме: нижний
// регистр, без завершающей точки и без ведущей (пользователь мог написать
// ".youtube.com" или "youtube.com." — считаем это одним и тем же).
func normalizeDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	d = strings.TrimSuffix(d, ".")
	d = strings.TrimPrefix(d, ".")
	return d
}

// normalizeGroups приводит домены всех групп к канонической форме. Делается при
// разборе, чтобы сопоставление на горячем пути не нормализовало повторно.
func normalizeGroups(groups map[string][]string) map[string][]string {
	if groups == nil {
		return nil
	}
	out := make(map[string][]string, len(groups))
	for name, domains := range groups {
		norm := make([]string, 0, len(domains))
		for _, d := range domains {
			norm = append(norm, normalizeDomain(d))
		}
		out[name] = norm
	}
	return out
}

// DomainSet собирает множество доменов из указанных групп.
//
// Пустой список имён означает «все группы конфига» — радиус не сужается флагом
// --groups. Неизвестное имя группы — ошибка: молча игнорировать опечатку в
// --groups нельзя, иначе стратегия тихо применилась бы шире задуманного.
func (c *Config) DomainSet(groupNames []string) (*DomainSet, error) {
	var names []string
	if len(groupNames) == 0 {
		for name := range c.Groups {
			names = append(names, name)
		}
	} else {
		for _, name := range groupNames {
			if _, ok := c.Groups[name]; !ok {
				return nil, fmt.Errorf("config: группа %q не задана в конфиге", name)
			}
			names = append(names, name)
		}
	}

	seen := make(map[string]struct{})
	var domains []string
	for _, name := range names {
		for _, d := range c.Groups[name] {
			if d == "" {
				continue
			}
			if _, dup := seen[d]; dup {
				continue
			}
			seen[d] = struct{}{}
			domains = append(domains, d)
		}
	}
	// Детерминированный порядок — чтобы вывод и тесты были стабильны.
	sort.Strings(domains)
	return &DomainSet{domains: domains}, nil
}

// Empty сообщает, что множество не содержит доменов. Пустое множество не
// совпадает ни с чем: при отсутствии групп стратегия не применяется (радиус
// нулевой), а не ко всему трафику — так безопаснее.
func (s *DomainSet) Empty() bool { return s == nil || len(s.domains) == 0 }

// Matches сообщает, попадает ли хост в множество доменов. host — имя из
// SOCKS-запроса, sni — имя из ClientHello; совпадение по любому из них считается
// попаданием, потому что цель может быть задана как именем, так и через SNI.
func (s *DomainSet) Matches(host, sni string) bool {
	if s.Empty() {
		return false
	}
	return s.matchOne(normalizeHost(host)) || s.matchOne(normalizeHost(sni))
}

// matchOne проверяет один нормализованный хост против всех доменов множества.
func (s *DomainSet) matchOne(host string) bool {
	if host == "" {
		return false
	}
	for _, d := range s.domains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// Domains возвращает отсортированную копию доменов множества — для вывода в
// status/doctor и тестов. Копия, чтобы потребитель не изменил внутреннее
// состояние.
func (s *DomainSet) Domains() []string {
	if s.Empty() {
		return nil
	}
	out := make([]string, len(s.domains))
	copy(out, s.domains)
	return out
}
