package main

import (
	"strings"
	"testing"
)

func TestConflictDetection(t *testing.T) {
	for _, name := range []string{"winws.exe", "WinWS.EXE", "goodbyedpi.exe", "ciadpi.exe", "winws2.exe"} {
		if !isConflictProcess(name) {
			t.Errorf("%s not recognised", name)
		}
	}
	for _, name := range []string{"evasion.exe", "Evasion.exe", "Discord.exe", "chrome.exe", "winws.exe.bak"} {
		if isConflictProcess(name) {
			t.Errorf("%s must not be stopped", name)
		}
	}
	services := []struct {
		name, image string
		want        bool
	}{
		{"zapret", "", true},
		{"GoodbyeDPI", `"C:\gdpi\x86_64\goodbyedpi.exe" -9`, true},
		{"zapret_discord", `"C:\Program Files\zapret\bin\winws.exe" --wf-tcp=443`, true},
		{"custom", `C:\tools\winws.exe --wf-tcp=443 --dpi-desync=fake`, true},
		{"WinDivert", `\??\C:\zapret\bin\WinDivert64.sys`, false},
		{"BFE", `C:\Windows\system32\svchost.exe -k LocalServiceNoNetworkFirewall -p`, false},
		{"Dnscache", `C:\Windows\system32\svchost.exe -k winws.exe`, false},
	}
	for _, s := range services {
		if got := isConflictService(s.name, s.image); got != s.want {
			t.Errorf("service %s (%s) = %v, want %v", s.name, s.image, got, s.want)
		}
	}
}

func TestStaleDriver(t *testing.T) {
	present := map[string]bool{`c:\zapret\bin\windivert64.sys`: true, `c:\windows\system32\drivers\windivert64.sys`: true}
	exists := func(p string) bool { return present[strings.ToLower(p)] }
	cases := []struct {
		image    string
		disabled bool
		want     bool
	}{
		{`\??\C:\zapret\bin\WinDivert64.sys`, false, false},
		{`\??\C:\old\removed\WinDivert64.sys`, false, true},
		{`\??\C:\zapret\bin\WinDivert64.sys`, true, true},
		{`\SystemRoot\System32\drivers\WinDivert64.sys`, false, false},
		{`system32\drivers\WinDivert64.sys`, false, false},
		{`system32\drivers\gone.sys`, false, true},
		{``, false, false},
	}
	for _, c := range cases {
		if got := staleDriver(c.image, c.disabled, `C:\Windows`, exists); got != c.want {
			t.Errorf("staleDriver(%q, %v) = %v, want %v", c.image, c.disabled, got, c.want)
		}
	}
}

func TestConflictSummary(t *testing.T) {
	if s := (conflictReport{}).summary(); s != "" {
		t.Fatalf("empty report = %q", s)
	}
	s := conflictReport{Stopped: []string{"winws.exe"}, Failed: []string{"служба zapret"}}.summary()
	if !strings.Contains(s, "winws.exe") || !strings.Contains(s, "служба zapret") {
		t.Fatalf("summary = %q", s)
	}
}
