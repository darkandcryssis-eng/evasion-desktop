package config

import (
	"os"
	"testing"
)

func TestDefaultServicesExcludeInstagram(t *testing.T) {
	b, err := os.ReadFile("../../examples/config.json")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg.Groups["instagram"]; ok {
		t.Fatal("Instagram must not be bundled")
	}
	for _, group := range []string{"video", "discord", "discord_gateway", "discord_voice"} {
		if len(cfg.Groups[group]) == 0 {
			t.Fatalf("missing group %s", group)
		}
	}
}
