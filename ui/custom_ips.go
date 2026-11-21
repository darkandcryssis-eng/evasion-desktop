package main

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

// customIPsFile — пользовательский список IP и подсетей в папке данных. Движок
// получает его флагом --ip-list и применяет обход по адресу назначения.
const customIPsFile = "custom-ips.txt"

const customIPsMax = 4096

// CustomIPsView — список для экрана «Сервисы».
type CustomIPsView struct {
	Text  string `json:"text"`
	Count int    `json:"count"`
	Path  string `json:"path"`
}

// checkCustomIPs повторяет правила internal/iplist движка (оболочка — отдельный
// модуль и его пакеты не импортирует): ошибка видна сразу при сохранении, а не
// при следующем запуске движка.
func checkCustomIPs(text string) (int, error) {
	seen := map[netip.Prefix]bool{}
	for n, line := range strings.Split(text, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		for _, s := range strings.FieldsFunc(line, func(r rune) bool { return strings.ContainsRune(",; \t\r", r) }) {
			var p netip.Prefix
			if strings.Contains(s, "/") {
				parsed, err := netip.ParsePrefix(s)
				if err != nil {
					return 0, fmt.Errorf("строка %d: %q — не подсеть (пример: 203.0.113.0/24)", n+1, s)
				}
				bits := parsed.Bits()
				if parsed.Addr().Is4In6() {
					bits = max(0, bits-96)
				}
				p = netip.PrefixFrom(parsed.Addr().Unmap(), bits).Masked()
			} else {
				addr, err := netip.ParseAddr(s)
				if err != nil || addr.Zone() != "" {
					return 0, fmt.Errorf("строка %d: %q — не IP-адрес (пример: 203.0.113.7)", n+1, s)
				}
				addr = addr.Unmap()
				p = netip.PrefixFrom(addr, addr.BitLen())
			}
			minBits := 8
			if p.Addr().Is6() {
				minBits = 16
			}
			if p.Bits() < minBits {
				return 0, fmt.Errorf("строка %d: %s — слишком широкая подсеть (минимум /%d)", n+1, s, minBits)
			}
			if a := p.Addr(); !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() {
				return 0, fmt.Errorf("строка %d: %s — локальный или служебный адрес, обход к нему не нужен", n+1, s)
			}
			seen[p] = true
		}
	}
	if len(seen) > customIPsMax {
		return 0, fmt.Errorf("в списке больше %d записей", customIPsMax)
	}
	return len(seen), nil
}

func readCustomIPs(base string) (string, error) {
	b, err := os.ReadFile(filepath.Join(base, customIPsFile))
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if len(b) > 1<<20 {
		return "", errors.New("список IP слишком большой")
	}
	return strings.TrimPrefix(string(b), "\ufeff"), nil
}

// customIPArgs — флаги движка для списка. Пустой или испорченный вручную
// список не передаётся: обход сервисов важнее и должен запуститься без него.
func customIPArgs(base string) []string {
	text, err := readCustomIPs(base)
	if err != nil {
		return nil
	}
	if n, err := checkCustomIPs(text); err != nil || n == 0 {
		return nil
	}
	return []string{"--ip-list", filepath.Join(base, customIPsFile)}
}

func (a *App) GetCustomIPs() (CustomIPsView, error) {
	l, err := resolveLayout()
	if err != nil {
		return CustomIPsView{}, err
	}
	v := CustomIPsView{Path: filepath.Join(l.Base, customIPsFile)}
	if v.Text, err = readCustomIPs(l.Base); err != nil {
		return v, err
	}
	// Счётчик — сколько записей реально уйдёт в движок; при ошибке в файле 0.
	v.Count, _ = checkCustomIPs(v.Text)
	return v, nil
}

// SetCustomIPs сохраняет список. Действует со следующего подключения.
func (a *App) SetCustomIPs(text string) (CustomIPsView, error) {
	if len(text) > 1<<20 {
		return CustomIPsView{}, errors.New("список IP слишком большой")
	}
	text = strings.ReplaceAll(text, "\r\n", "\n")
	n, err := checkCustomIPs(text)
	if err != nil {
		return CustomIPsView{}, err
	}
	l, err := resolveLayout()
	if err != nil {
		return CustomIPsView{}, err
	}
	path := filepath.Join(l.Base, customIPsFile)
	if err := writeAtomic(path, []byte(text)); err != nil {
		return CustomIPsView{}, err
	}
	return CustomIPsView{Text: text, Count: n, Path: path}, nil
}
