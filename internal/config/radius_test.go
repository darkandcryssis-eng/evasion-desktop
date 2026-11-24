package config

import "testing"

func TestRadiusDefaultsAndValidation(t *testing.T) {
	cfg, err := parse([]byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Radius.Mode != RadiusGroups {
		t.Fatalf("default radius.mode = %q", cfg.Radius.Mode)
	}

	cfg, err = parse([]byte(`{"radius":{"mode":"all","exclude":[".Example.org.","vk.com"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Radius.Mode != RadiusAll {
		t.Fatalf("radius.mode = %q", cfg.Radius.Mode)
	}
	if len(cfg.Radius.Exclude) != 2 || cfg.Radius.Exclude[0] != "example.org" {
		t.Fatalf("normalized exclusions = %v", cfg.Radius.Exclude)
	}
	if _, err := parse([]byte(`{"radius":{"mode":"internet"}}`)); err == nil {
		t.Fatal("unknown radius mode must be rejected")
	}
	if _, err := parse([]byte(`{"radius":{"exclude":["."]}}`)); err == nil {
		t.Fatal("empty normalized exclusion must be rejected")
	}
}
