package windivert

import "testing"

// TestAddressOutbound — разбор бита направления из адреса проверяется на любой
// ОС: это самая тонкая часть (смещение байта признаков и номер бита), и
// ошибиться в ней значило бы развернуть весь трафик наоборот.
func TestAddressOutbound(t *testing.T) {
	var out Address
	out[flagsOffset] = flagOutbound
	if !out.Outbound() {
		t.Errorf("пакет с установленным битом Outbound должен быть исходящим")
	}

	// Только бит Sniffed (0) — не исходящий.
	var sniffed Address
	sniffed[flagsOffset] = 1 << 0
	if sniffed.Outbound() {
		t.Errorf("бит Sniffed не должен читаться как Outbound")
	}

	// Outbound вместе с соседними битами (Loopback и т.п.) — всё равно исходящий.
	var mixed Address
	mixed[flagsOffset] = flagOutbound | (1 << 2) | (1 << 4)
	if !mixed.Outbound() {
		t.Errorf("Outbound должен распознаваться среди прочих признаков")
	}

	var zero Address
	if zero.Outbound() {
		t.Errorf("нулевой адрес не исходящий")
	}
}
