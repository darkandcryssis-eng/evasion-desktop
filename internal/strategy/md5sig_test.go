package strategy

import (
	"testing"

	"github.com/fitting-1c/evasion/internal/core"
)

// TestMD5SigJSONRoundtripAndCaps — md5sig разбирается из JSON, требует
// CapMD5Sig и переживает сериализацию без потерь.
func TestMD5SigJSONRoundtripAndCaps(t *testing.T) {
	js := []byte(`{"rules":[{"direction":"outbound","trigger":{"match":"client_hello"},` +
		`"action":{"kind":"duplicate","left":{"kind":"md5sig","left":{"kind":"send"}},` +
		`"right":{"kind":"send"}}}]}`)

	s, err := Unmarshal(js, DefaultLimits())
	if err != nil {
		t.Fatalf("Unmarshal md5sig: %v", err)
	}

	caps := RequiredCapabilities(s)
	if !caps.Has(core.CapMD5Sig) {
		t.Error("стратегия с md5sig не требует CapMD5Sig")
	}

	out, err := Marshal(s)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if _, err := Unmarshal(out, DefaultLimits()); err != nil {
		t.Fatalf("повторный разбор сериализованного: %v", err)
	}
}

// TestMD5SigRejectsParams — у md5sig нет параметров: описание с params должно
// отвергаться (строгий разбор недоверенного ввода).
func TestMD5SigRejectsParams(t *testing.T) {
	js := []byte(`{"rules":[{"direction":"outbound","trigger":{"match":"client_hello"},` +
		`"action":{"kind":"md5sig","params":{"preset":"x"},"left":{"kind":"send"}}}]}`)
	if _, err := Unmarshal(js, DefaultLimits()); err == nil {
		t.Error("ожидалась ошибка: у md5sig не должно быть параметров")
	}
}

// TestMD5SigRequiresBranch — md5sig это узел арности 1: без ветви left
// валидация обязана отказать.
func TestMD5SigRequiresBranch(t *testing.T) {
	js := []byte(`{"rules":[{"direction":"outbound","trigger":{"match":"client_hello"},` +
		`"action":{"kind":"md5sig"}}]}`)
	if _, err := Unmarshal(js, DefaultLimits()); err == nil {
		t.Error("ожидалась ошибка: у md5sig обязательна ветвь left")
	}
}

// TestMD5SigKindRegistered — вид включён в реестр (генератор и обходы узнают
// пространство действий отсюда).
func TestMD5SigKindRegistered(t *testing.T) {
	var found bool
	for _, k := range Kinds() {
		if k == core.ActionMD5Sig {
			found = true
		}
	}
	if !found {
		t.Error("ActionMD5Sig отсутствует в Kinds()")
	}
}

// TestIPv6ExtJSONAndCaps — ipv6_ext разбирается из JSON и требует
// CapIPv6ExtHeader.
func TestIPv6ExtJSONAndCaps(t *testing.T) {
	js := []byte(`{"rules":[{"direction":"outbound","trigger":{"match":"client_hello"},` +
		`"action":{"kind":"ipv6_ext","left":{"kind":"send"}}}]}`)
	s, err := Unmarshal(js, DefaultLimits())
	if err != nil {
		t.Fatalf("Unmarshal ipv6_ext: %v", err)
	}
	if !RequiredCapabilities(s).Has(core.CapIPv6ExtHeader) {
		t.Error("стратегия с ipv6_ext не требует CapIPv6ExtHeader")
	}
	var found bool
	for _, k := range Kinds() {
		if k == core.ActionIPv6Ext {
			found = true
		}
	}
	if !found {
		t.Error("ActionIPv6Ext отсутствует в Kinds()")
	}
}
