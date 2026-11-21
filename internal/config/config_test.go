package config

import (
	"strings"
	"testing"
)

// strategyJSON — рукописная стратегия сегментации для встраивания в конфиг.
const strategyJSON = `{
  "rules": [{
    "direction": "outbound",
    "trigger": {"match": "client_hello"},
    "action": {
      "kind": "fragment",
      "params": {"proto": "tcp", "offset": 5},
      "left": {"kind": "send"},
      "right": {"kind": "send"}
    }
  }]
}`

func TestParseDefaults(t *testing.T) {
	cfg, err := parse([]byte(`{}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.Listen != DefaultListen {
		t.Fatalf("адрес по умолчанию: получили %q, ожидали %q", cfg.Listen, DefaultListen)
	}
	if cfg.Strategy != nil {
		t.Fatal("стратегия должна отсутствовать")
	}
	// Блокировка QUIC включена по умолчанию (3.3): без явного block_quic: false
	// цель вроде YouTube уходила бы в QUIC мимо TCP-десинка.
	if !cfg.BlockQUIC {
		t.Fatal("block_quic по умолчанию должен быть включён")
	}
}

func TestParseBlockQUICDisabled(t *testing.T) {
	cfg, err := parse([]byte(`{"block_quic": false}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.BlockQUIC {
		t.Fatal("block_quic: false должен отключать блокировку")
	}
}

func TestParseUnknownFieldRejected(t *testing.T) {
	_, err := parse([]byte(`{"bogus": 1}`))
	if err == nil {
		t.Fatal("ожидалась ошибка на неизвестный ключ")
	}
}

func TestParseWithStrategyAndGroups(t *testing.T) {
	src := `{
	  "listen": "127.0.0.1:9050",
	  "groups": {"youtube": ["YouTube.com", ".googlevideo.com."]},
	  "strategy": ` + strategyJSON + `
	}`
	cfg, err := parse([]byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.Listen != "127.0.0.1:9050" {
		t.Fatalf("listen: %q", cfg.Listen)
	}
	if cfg.Strategy == nil || cfg.Strategy.ID == "" {
		t.Fatal("стратегия не разобрана или без идентификатора")
	}
	// Домены нормализованы: нижний регистр, без ведущей/замыкающей точки.
	got := cfg.Groups["youtube"]
	want := []string{"youtube.com", "googlevideo.com"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("нормализация доменов: получили %v, ожидали %v", got, want)
	}
}

func TestParseInvalidStrategyRejected(t *testing.T) {
	// Лист с параметрами — невалидная стратегия, конфиг обязан отказать.
	src := `{"strategy": {"rules":[{"direction":"outbound","trigger":{"match":"always"},"action":{"kind":"send","params":{"field":"ipv4_ttl","mode":"replace"}}}]}}`
	if _, err := parse([]byte(src)); err == nil {
		t.Fatal("ожидалась ошибка валидации стратегии")
	}
}

func TestParseEmptyGroupRejected(t *testing.T) {
	if _, err := parse([]byte(`{"groups": {"youtube": []}}`)); err == nil {
		t.Fatal("ожидалась ошибка на пустую группу")
	}
}

func TestDomainSetAllGroups(t *testing.T) {
	cfg := &Config{Groups: map[string][]string{
		"youtube": {"youtube.com"},
		"discord": {"discord.com"},
	}}
	ds, err := cfg.DomainSet(nil) // nil → все группы
	if err != nil {
		t.Fatalf("DomainSet: %v", err)
	}
	if len(ds.Domains()) != 2 {
		t.Fatalf("ожидалось 2 домена, получили %v", ds.Domains())
	}
}

func TestDomainSetUnknownGroupRejected(t *testing.T) {
	cfg := &Config{Groups: map[string][]string{"youtube": {"youtube.com"}}}
	if _, err := cfg.DomainSet([]string{"нет-такой"}); err == nil {
		t.Fatal("ожидалась ошибка на неизвестную группу")
	}
}

func TestDomainSetMatches(t *testing.T) {
	cfg := &Config{Groups: map[string][]string{"youtube": {"youtube.com"}}}
	ds, err := cfg.DomainSet(nil)
	if err != nil {
		t.Fatalf("DomainSet: %v", err)
	}

	cases := []struct {
		name     string
		host     string
		sni      string
		expected bool
	}{
		{"точное совпадение по host", "youtube.com", "", true},
		{"поддомен по host", "www.youtube.com", "", true},
		{"совпадение по SNI", "1.2.3.4", "rr.youtube.com", true},
		{"с портом", "youtube.com:443", "", true},
		{"регистр", "WWW.YouTube.COM", "", true},
		{"чужой домен", "example.com", "", false},
		{"подстрока, но не поддомен", "notyoutube.com", "", false},
		{"голый IP не совпадает", "1.2.3.4", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ds.Matches(c.host, c.sni); got != c.expected {
				t.Fatalf("Matches(%q,%q)=%t, ожидали %t", c.host, c.sni, got, c.expected)
			}
		})
	}
}

func TestEmptyDomainSetMatchesNothing(t *testing.T) {
	// Нет групп → пустой радиус → не совпадает ни с чем (безопасно по умолчанию).
	cfg := &Config{}
	ds, err := cfg.DomainSet(nil)
	if err != nil {
		t.Fatalf("DomainSet: %v", err)
	}
	if !ds.Empty() {
		t.Fatal("ожидалось пустое множество")
	}
	if ds.Matches("youtube.com", "") {
		t.Fatal("пустой радиус не должен совпадать")
	}
}

// TestTransportFallbackAbsent — отсутствие ключа transport_fallback в конфиге
// означает «не применять»: Enabled=false, прочие поля нулевые. Проверяется ЯВНО,
// потому что раньше в проекте уже путали «ключа нет» и «значение по
// умолчанию».
func TestTransportFallbackAbsent(t *testing.T) {
	cfg, err := parse([]byte(`{}`))
	if err != nil {
		t.Fatalf("разбор пустого конфига: %v", err)
	}
	if cfg.TransportFallback.Enabled {
		t.Fatal("по умолчанию transport_fallback.enabled должен быть false")
	}
}

// TestTransportFallbackParses — валидный блок читается в структуру.
func TestTransportFallbackParses(t *testing.T) {
	in := `{
		"transport_fallback": {
			"enabled": true,
			"safe_ip": "23.227.38.74",
			"domains": ["discord.com", "cdn.discordapp.com"]
		}
	}`
	cfg, err := parse([]byte(in))
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if !cfg.TransportFallback.Enabled {
		t.Fatal("Enabled не прочитан")
	}
	if cfg.TransportFallback.SafeIP != "23.227.38.74" {
		t.Fatalf("SafeIP: %q", cfg.TransportFallback.SafeIP)
	}
	if len(cfg.TransportFallback.Domains) != 2 {
		t.Fatalf("Domains: %v", cfg.TransportFallback.Domains)
	}
}

// TestTransportFallbackRejectsInvalid — при Enabled=true плохие поля отвергаются
// на валидации. Enabled=false оставляет поля любыми (их не читают).
func TestTransportFallbackRejectsInvalid(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{
			name:    "enabled без safe_ip",
			in:      `{"transport_fallback": {"enabled": true, "domains": ["x.com"]}}`,
			wantErr: true,
		},
		{
			name:    "enabled без domains",
			in:      `{"transport_fallback": {"enabled": true, "safe_ip": "1.2.3.4"}}`,
			wantErr: true,
		},
		{
			name:    "enabled с негодным IP",
			in:      `{"transport_fallback": {"enabled": true, "safe_ip": "not-an-ip", "domains": ["x.com"]}}`,
			wantErr: true,
		},
		{
			name:    "enabled с пустым доменом",
			in:      `{"transport_fallback": {"enabled": true, "safe_ip": "1.2.3.4", "domains": [""]}}`,
			wantErr: true,
		},
		{
			name: "disabled с любыми полями — ок",
			in:   `{"transport_fallback": {"enabled": false, "safe_ip": "garbage", "domains": []}}`,
		},
		{
			name: "валидный IPv6",
			in:   `{"transport_fallback": {"enabled": true, "safe_ip": "::1", "domains": ["x.com"]}}`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := parse([]byte(c.in))
			if c.wantErr && err == nil {
				t.Fatal("ожидалась ошибка валидации")
			}
			if !c.wantErr && err != nil {
				t.Fatalf("валидация провалилась: %v", err)
			}
		})
	}
}

// TestParseStrategiesPerGroup — переопределения стратегий по группам
// разбираются и попадают в cfg.Strategies, не сталкиваясь с общей cfg.Strategy.
func TestParseStrategiesPerGroup(t *testing.T) {
	src := `{
	  "groups": {
	    "discord_voice": ["discord.media"],
	    "discord": ["discord.com"]
	  },
	  "strategy": ` + strategyJSON + `,
	  "strategies": {
	    "discord_voice": ` + strategyJSON + `,
	    "discord": ` + strategyJSON + `
	  }
	}`
	cfg, err := parse([]byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.Strategy == nil {
		t.Fatal("общая стратегия должна остаться")
	}
	if len(cfg.Strategies) != 2 {
		t.Fatalf("ожидалось 2 переопределения, получили %d", len(cfg.Strategies))
	}
	if cfg.Strategies["discord_voice"] == nil || cfg.Strategies["discord"] == nil {
		t.Fatalf("не разобраны: %+v", cfg.Strategies)
	}
}

// TestParseStrategiesUnknownGroupRejected — опечатка в имени группы отклоняется
// на валидации, а не молча игнорируется: иначе переопределение «не сработало
// бы» без ошибки, и это выглядело бы как провал движка.
func TestParseStrategiesUnknownGroupRejected(t *testing.T) {
	src := `{
	  "groups": {"discord": ["discord.com"]},
	  "strategies": {
	    "discord_voice": ` + strategyJSON + `
	  }
	}`
	_, err := parse([]byte(src))
	if err == nil {
		t.Fatal("ожидалась ошибка на неизвестную группу в strategies")
	}
	if !strings.Contains(err.Error(), "discord_voice") {
		t.Fatalf("ошибка должна называть группу, но: %v", err)
	}
}

// TestParseStrategiesInvalidPayloadNamesGroup — ошибка внутри одной записи
// должна называть имя группы, чтобы владельцу было видно, какую строку
// править. Без этого диагностика сводилась бы к «где-то в strategies плохо».
func TestParseStrategiesInvalidPayloadNamesGroup(t *testing.T) {
	// Лист send с параметрами — невалидная стратегия.
	src := `{
	  "groups": {"discord": ["discord.com"]},
	  "strategies": {
	    "discord": {"rules":[{"direction":"outbound","trigger":{"match":"always"},"action":{"kind":"send","params":{"field":"ipv4_ttl","mode":"replace"}}}]}
	  }
	}`
	_, err := parse([]byte(src))
	if err == nil {
		t.Fatal("ожидалась ошибка на невалидную стратегию")
	}
	if !strings.Contains(err.Error(), "discord") {
		t.Fatalf("ошибка должна называть группу: %v", err)
	}
}

// TestParseStrategiesEmptyNoop — пустой map strategies ничего не меняет: это
// как не писать ключ вовсе.
func TestParseStrategiesEmptyNoop(t *testing.T) {
	src := `{"groups": {"d": ["d.com"]}, "strategies": {}}`
	cfg, err := parse([]byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(cfg.Strategies) != 0 {
		t.Fatalf("ожидалось отсутствие переопределений, получили %d", len(cfg.Strategies))
	}
}
