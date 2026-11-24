package config

import "testing"

func TestTransportFallbackCandidatesAndValidation(t *testing.T) {
	cfg, err := parse([]byte(`{
		"transport_fallback": {
			"enabled": true,
			"entries": [{
				"safe_ip": "162.159.138.232",
				"safe_ips": ["23.227.38.74", "162.159.138.232"],
				"domains": ["gateway.discord.gg"]
			}]
		}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	got := cfg.TransportFallback.Entries[0].Candidates()
	want := []string{"162.159.138.232", "23.227.38.74"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("candidate order/dedup = %v, want %v", got, want)
	}

	cfg, err = parse([]byte(`{
		"transport_fallback": {
			"enabled": true,
			"entries": [{
				"safe_ips": ["23.227.38.74"],
				"domains": ["gateway.discord.gg"]
			}]
		}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.TransportFallback.Entries[0].Candidates(); len(got) != 1 || got[0] != "23.227.38.74" {
		t.Fatalf("safe_ips-only candidates = %v", got)
	}

	if _, err := parse([]byte(`{
		"transport_fallback": {
			"enabled": true,
			"entries": [{
				"safe_ip": "162.159.138.232",
				"safe_ips": ["not-an-ip"],
				"domains": ["gateway.discord.gg"]
			}]
		}
	}`)); err == nil {
		t.Fatal("invalid safe_ips candidate must be rejected")
	}
	if _, err := parse([]byte(`{
		"transport_fallback": {
			"enabled": true,
			"entries": [{
				"safe_ip": "162.159.138.232",
				"safe_ips": [""],
				"domains": ["gateway.discord.gg"]
			}]
		}
	}`)); err == nil {
		t.Fatal("empty safe_ips candidate must be rejected")
	}
}
