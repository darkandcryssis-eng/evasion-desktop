package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Защита российских сервисов. Движок вмешивается только в домены из groups
// конфига, поэтому достаточно гарантировать, что российских доменов там нет —
// даже если их добавили в пользовательский config.json. Тогда трафик к ним
// идёт так же, как без Evasion: без десинка, без блокировки QUIC, без hosts.

var ruZones = []string{".ru", ".su", ".xn--p1ai", ".рф", ".xn--80adxhks", ".москва", ".xn--p1acf", ".рус", ".moscow", ".tatar"}

// Российские площадки вне национальных зон.
var ruServices = []string{
	"vk.com", "vk.me", "vk.cc", "vkuser.net", "vkuservideo.net", "vk-cdn.net", "userapi.com", "vkvideo.com", "okcdn.com",
	"yandex.com", "yandex.net", "yandex.cloud", "yandex.kz", "yandex.by", "yastatic.net", "yandexcloud.net", "ya.cc", "dzeninfra.net",
	"mycdn.me", "imgsmail.com", "sberbank.com", "sber.me", "sbrf.com", "tbank-online.com", "tinkoff.com", "tochka.com",
	"ozone.com", "ozonusercontent.com", "wbstatic.net", "wbbasket.com", "avito.st", "2gis.com", "kaspersky.com", "rt.com", "mts.com",
}

func isRussianDomain(domain string) bool {
	d := strings.ToLower(strings.TrimSpace(domain))
	d = strings.TrimPrefix(d, "*")
	d = strings.Trim(d, ".")
	if d == "" {
		return false
	}
	for _, z := range ruZones {
		if strings.HasSuffix(d, z) || d == strings.TrimPrefix(z, ".") {
			return true
		}
	}
	for _, s := range ruServices {
		if d == s || strings.HasSuffix(d, "."+s) {
			return true
		}
	}
	return false
}

// sanitizeConfig убирает российские домены из groups. changed=false — конфиг
// чист и возвращён как есть. Группа, оставшаяся без доменов, удаляется вместе
// со своей стратегией.
func sanitizeConfig(raw []byte) (out []byte, removed []string, err error) {
	var top map[string]json.RawMessage
	if err = json.Unmarshal(raw, &top); err != nil {
		return raw, nil, err
	}
	var groups map[string][]string
	if g, ok := top["groups"]; !ok || json.Unmarshal(g, &groups) != nil {
		return raw, nil, nil
	}
	var strategies map[string]json.RawMessage
	if s, ok := top["strategies"]; ok {
		_ = json.Unmarshal(s, &strategies)
	}
	for name, domains := range groups {
		kept := domains[:0:0]
		for _, d := range domains {
			if isRussianDomain(d) {
				removed = append(removed, d)
			} else {
				kept = append(kept, d)
			}
		}
		if len(kept) == 0 && len(domains) > 0 {
			delete(groups, name)
			delete(strategies, name)
			continue
		}
		groups[name] = kept
	}
	if len(removed) == 0 {
		return raw, nil, nil
	}
	sort.Strings(removed)
	if top["groups"], err = json.Marshal(groups); err != nil {
		return raw, nil, err
	}
	if strategies != nil {
		if top["strategies"], err = json.Marshal(strategies); err != nil {
			return raw, nil, err
		}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err = enc.Encode(top); err != nil {
		return raw, nil, err
	}
	return buf.Bytes(), removed, nil
}

// guardLayout подменяет конфиг очищенной копией, если в нём нашлись российские
// домены. Любая ошибка оставляет исходный конфиг: защита не должна мешать запуску.
func guardLayout(l layout) (layout, []string) {
	raw, err := os.ReadFile(l.Config)
	if err != nil {
		return l, nil
	}
	clean, removed, err := sanitizeConfig(raw)
	if err != nil || len(removed) == 0 {
		return l, nil
	}
	path := filepath.Join(filepath.Dir(l.Config), "config.guarded.json")
	if os.WriteFile(path, clean, 0o600) != nil {
		return l, nil
	}
	l.Config = path
	return l, removed
}
