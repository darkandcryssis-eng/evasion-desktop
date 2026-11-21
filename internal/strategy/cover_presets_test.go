package strategy

import "testing"

// coverPresets — все cover-пресеты фиксированного размера для ActionTCPOverlap.
// Базовый плюс SNI-варианты: приём рассчитывает, что каждый ровно 681 байт.
var coverPresets = []string{
	PresetTLSCover681,
	PresetTLSCover681Apple,
	PresetTLSCover681Microsoft,
	PresetTLSCover681Yandex,
}

// Каждый cover-пресет должен быть в реестре и иметь РОВНО 681 байт. Смещение
// overlap-пакета считается как L - M (M — длина cover'а); разошёлся размер —
// рукопожатие под tcp_overlap сорвётся. Единый размер делает варианты
// взаимозаменяемыми в одной стратегии.
func TestCoverPresetsRegisteredAndSized(t *testing.T) {
	const want = 681
	for _, name := range coverPresets {
		b, ok := FakePreset(name)
		if !ok {
			t.Fatalf("cover-пресет %q не зарегистрирован в fakePresets", name)
		}
		if len(b) != want {
			t.Fatalf("cover-пресет %q: %d байт, ожидали %d", name, len(b), want)
		}
	}
}

// Валидация tcp_overlap принимает каждый cover-пресет: имя есть в реестре.
// Это прямая проверка того, что конфиг с любым из вариантов не будет
// отвергнут при разборе.
func TestTCPOverlapAcceptsAllCoverPresets(t *testing.T) {
	for _, name := range coverPresets {
		p := &TCPOverlapParams{Preset: name}
		if err := p.validate(DefaultLimits()); err != nil {
			t.Fatalf("tcp_overlap отверг cover-пресет %q: %v", name, err)
		}
	}
}

// Все cover-пресеты присутствуют в детерминированном перечне FakePresetNames
// (от него зависит перебор генератором и вывод doctor).
func TestCoverPresetsInNames(t *testing.T) {
	names := make(map[string]bool)
	for _, n := range FakePresetNames() {
		names[n] = true
	}
	for _, name := range coverPresets {
		if !names[name] {
			t.Fatalf("cover-пресет %q отсутствует в FakePresetNames()", name)
		}
	}
}
