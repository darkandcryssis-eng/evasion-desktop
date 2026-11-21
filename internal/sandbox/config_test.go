package sandbox

import (
	"strings"
	"testing"
	"time"
)

func TestDefaultConfigValid(t *testing.T) {
	if err := DefaultConfig().validate(); err != nil {
		t.Fatalf("конфиг по умолчанию недействителен: %v", err)
	}
}

func TestDefaultConfigPortsOutsideEphemeral(t *testing.T) {
	c := DefaultConfig()
	// Диапазон по умолчанию обязан лежать ниже динамического диапазона Windows
	// (49152–65535): иначе коллизия с исходящим портом пользователя была бы
	// возможна, и разделение по порту перестало бы быть честным (5.2).
	if c.PortHi >= 49152 {
		t.Fatalf("верх диапазона %d попадает в эфемерный диапазон Windows", c.PortHi)
	}
	if c.ports() != int(c.PortHi-c.PortLo)+1 {
		t.Fatalf("число портов посчитано неверно: %d", c.ports())
	}
}

func TestConfigValidateRejects(t *testing.T) {
	base := DefaultConfig()
	cases := []struct {
		name  string
		mutate func(*Config)
	}{
		{"пустой диапазон", func(c *Config) { c.PortLo = 0 }},
		{"верх ниже низа", func(c *Config) { c.PortLo, c.PortHi = 100, 50 }},
		{"нет воркеров", func(c *Config) { c.Workers = 0 }},
		{"воркеров выше потолка", func(c *Config) { c.Workers = workersCeiling + 1 }},
		{"нет предела на цель", func(c *Config) { c.PerTarget = 0 }},
		{"предел на цель больше воркеров", func(c *Config) { c.Workers, c.PerTarget = 2, 3 }},
		{"отрицательный джиттер", func(c *Config) { c.Jitter = -time.Second }},
		{"нулевая пауза обхода", func(c *Config) { c.Round = 0 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := base
			tc.mutate(&c)
			if err := c.validate(); err == nil {
				t.Fatalf("ожидалась ошибка для случая %q, её нет", tc.name)
			}
		})
	}
}

func TestPortPredicatesDisjoint(t *testing.T) {
	c := Config{PortLo: 40000, PortHi: 40127}
	product, sandbox := c.PortPredicates()

	// Предикаты должны называть обе границы диапазона.
	for _, want := range []string{"40000", "40127"} {
		if !strings.Contains(product, want) || !strings.Contains(sandbox, want) {
			t.Fatalf("граница %s не упомянута: product=%q sandbox=%q", want, product, sandbox)
		}
	}
	// Продуктовый берёт порт ВНЕ диапазона, песочный — внутри: по построению
	// непересекающиеся множества (один <lo или >hi, другой >=lo и <=hi).
	if !strings.Contains(product, "SrcPort < 40000") || !strings.Contains(product, "SrcPort > 40127") {
		t.Fatalf("продуктовый предикат не исключает диапазон: %q", product)
	}
	if !strings.Contains(sandbox, "SrcPort >= 40000") || !strings.Contains(sandbox, "SrcPort <= 40127") {
		t.Fatalf("песочный предикат не ограничен диапазоном: %q", sandbox)
	}
}

func TestConfigZeroJitterAllowed(t *testing.T) {
	c := DefaultConfig()
	c.Jitter = 0
	if err := c.validate(); err != nil {
		t.Fatalf("нулевой джиттер должен быть законен (для тестов): %v", err)
	}
}
