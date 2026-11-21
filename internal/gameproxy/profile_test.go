package gameproxy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func fixtureProfile() Profile {
	return Profile{[]outbound{{Protocol: "vless", Tag: "game-1", Settings: settings{[]server{{Address: "198.51.100.10", Port: 443, Users: []user{{ID: "12345678-1234-4234-8234-123456789abc", Encryption: "none", Flow: "xtls-rprx-vision"}}}}}, Stream: stream{Network: "tcp", Security: "reality", Reality: reality{Fingerprint: "firefox", PublicKey: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), ServerName: "example.com", ShortID: "50"}}}}}
}

func TestProfileDropsForeignClientSettingsAndDuplicates(t *testing.T) {
	p := fixtureProfile()
	o := p.Outbounds[0]
	data, _ := json.Marshal(map[string]any{"outbounds": []outbound{o, o}, "inbounds": []any{map[string]any{"listen": "0.0.0.0", "port": 80}}, "routing": map[string]string{"secret": "SECRET-CANARY"}, "log": map[string]string{"access": "SECRET-CANARY"}})
	parsed, err := ParseProfile(data)
	if err != nil || len(parsed.Outbounds) != 1 {
		t.Fatal("valid profile rejected", err)
	}
	config, err := parsed.Config(54321)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(config), "SECRET-CANARY") || strings.Contains(string(config), "0.0.0.0") {
		t.Fatal("foreign settings entered runtime")
	}
	if !strings.Contains(string(config), "127.0.0.1") || !strings.Contains(string(config), "54321") {
		t.Fatal("runtime is not loopback-only")
	}
}

func TestRuntimeAllowsGameUDP443WithoutMutatingStoredProfile(t *testing.T) {
	p := fixtureProfile()
	b, e := p.Config(54321)
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(string(b), "xtls-rprx-vision-udp443") || p.Outbounds[0].Settings.VNext[0].Users[0].Flow != "xtls-rprx-vision" {
		t.Fatal("UDP 443 disabled or profile mutated")
	}
}

func TestProfileRejectsUnsafeAndMalformedOutbounds(t *testing.T) {
	for _, name := range []string{"protocol", "security", "private", "uuid", "key", "short", "transport", "flow", "multiple_users"} {
		t.Run(name, func(t *testing.T) {
			p := fixtureProfile()
			o := &p.Outbounds[0]
			switch name {
			case "protocol":
				o.Protocol = "freedom"
			case "security":
				o.Stream.Security = "none"
			case "private":
				o.Settings.VNext[0].Address = "127.0.0.1"
			case "uuid":
				o.Settings.VNext[0].Users[0].ID = "SECRET-CANARY"
			case "key":
				o.Stream.Reality.PublicKey = "SECRET-CANARY"
			case "short":
				o.Stream.Reality.ShortID = "xyz"
			case "transport":
				o.Stream.Network = "exec"
			case "flow":
				o.Settings.VNext[0].Users[0].Flow = "unknown"
			case "multiple_users":
				o.Settings.VNext[0].Users = append(o.Settings.VNext[0].Users, o.Settings.VNext[0].Users[0])
			}
			b, _ := json.Marshal(p)
			_, err := ParseProfile(b)
			if err == nil {
				t.Fatal("invalid profile accepted")
			}
			if strings.Contains(err.Error(), "SECRET-CANARY") {
				t.Fatal("error leaked input")
			}
		})
	}
}

func TestProfileURIBase64AndGRPC(t *testing.T) {
	p := fixtureProfile()
	o := p.Outbounds[0]
	uri := "vless://" + o.Settings.VNext[0].Users[0].ID + "@node.example.com:443?security=reality&type=grpc&serviceName=games&pbk=" + o.Stream.Reality.PublicKey + "&sni=example.com&sid=50&fp=firefox"
	for _, data := range []string{uri, base64.StdEncoding.EncodeToString([]byte(uri)), base64.RawURLEncoding.EncodeToString([]byte(uri))} {
		got, err := ParseProfile([]byte(data))
		if err != nil || len(got.Outbounds) != 1 || got.Outbounds[0].Stream.GRPC.ServiceName != "games" {
			t.Fatal("subscription URI rejected", err)
		}
	}
	if _, err := ImportInput(context.Background(), "https://127.0.0.1/private"); err == nil {
		t.Fatal("local subscription endpoint accepted")
	}
	if _, err := ParseProfile(make([]byte, profileLimit+1)); err == nil {
		t.Fatal("oversized profile accepted")
	}
}

func TestProfileRuntimeAcceptedByBundledXray(t *testing.T) {
	exe := os.Getenv("EVASION_XRAY_TEST_EXE")
	if exe == "" {
		t.Skip("native Xray validation")
	}
	data, err := fixtureProfile().Config(54321)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "run", "-test", "-config", "stdin:")
	cmd.Stdin = strings.NewReader(string(data))
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("fixture configuration rejected: %s", output)
	}
}

func TestYouTubeProbeDoesNotChangeDefaultRuntime(t *testing.T) {
	p := fixtureProfile()
	standard, err := p.Config(54321)
	if err != nil {
		t.Fatal(err)
	}
	youtube, err := p.ConfigProbe(54321, "https://redirector.googlevideo.com/generate_204")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(standard), `"probeUrl":"https://cp.cloudflare.com/generate_204"`) || strings.Contains(string(standard), "googlevideo") {
		t.Fatal("default game/Discord runtime changed")
	}
	if !strings.Contains(string(youtube), `"probeUrl":"https://redirector.googlevideo.com/generate_204"`) {
		t.Fatal("YouTube-specific probe was not applied")
	}
}
