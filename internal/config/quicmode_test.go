package config

import "testing"

// TestQUICModeParsing — quic_mode канонично, block_quic остаётся совместимым
// псевдонимом, неизвестное значение отвергается.
func TestQUICModeParsing(t *testing.T) {
	cases := []struct {
		name    string
		json    string
		want    QUICMode
		wantErr bool
	}{
		{"дефолт", `{}`, QUICBlock, false},
		{"quic_mode desync", `{"quic_mode":"desync"}`, QUICDesync, false},
		{"quic_mode off", `{"quic_mode":"off"}`, QUICOff, false},
		{"quic_mode block", `{"quic_mode":"block"}`, QUICBlock, false},
		{"block_quic false → off", `{"block_quic":false}`, QUICOff, false},
		{"block_quic true → block", `{"block_quic":true}`, QUICBlock, false},
		{"quic_mode важнее block_quic", `{"block_quic":true,"quic_mode":"off"}`, QUICOff, false},
		{"неизвестный режим", `{"quic_mode":"bogus"}`, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := parse([]byte(tc.json))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ожидалась ошибка")
				}
				return
			}
			if err != nil {
				t.Fatalf("неожиданная ошибка: %v", err)
			}
			if c.QUICMode != tc.want {
				t.Errorf("режим %q, ожидался %q", c.QUICMode, tc.want)
			}
			// BlockQUIC обязан быть согласован с режимом.
			if c.BlockQUIC != (c.QUICMode == QUICBlock) {
				t.Errorf("BlockQUIC=%v рассогласован с режимом %q", c.BlockQUIC, c.QUICMode)
			}
		})
	}
}
