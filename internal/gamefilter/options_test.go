package gamefilter

import "testing"

func TestTunnelComponentCannotBeSelectedAsGame(t *testing.T) {
	o := Default()
	o.Executables = []string{"C:/Tools/xray.exe"}
	if !Protected("XRAY.EXE") || o.Match("C:/Tools/xray.exe") != "" || o.Validate() == nil {
		t.Fatal("tunnel component could route its own egress")
	}
}
