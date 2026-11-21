package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestYouTubeHealthRequiresCurrentPIDAndFreshState(t *testing.T) {
	base := t.TempDir()
	os.Mkdir(filepath.Join(base, "state"), 0700)
	path := filepath.Join(base, "state", "youtube-health.json")
	now := time.Now().UTC()
	write := func(pid int, at time.Time) {
		b, _ := json.Marshal(map[string]any{"pid": pid, "at": at, "phase": "healthy", "profile": "fake-split", "checks": []YouTubeCheck{{Target: "site", Stage: "http", OK: true, Code: 204}}})
		os.WriteFile(path, b, 0600)
	}
	write(123, now)
	if v := readYouTubeHealth(base, 123, true, now); !v.Fresh || v.Profile != "fake-split" || len(v.Checks) != 1 {
		t.Fatal(v)
	}
	for _, tc := range []struct {
		pid int
		at  time.Time
	}{{124, now}, {123, now.Add(-6 * time.Minute)}, {123, now.Add(2 * time.Minute)}} {
		write(tc.pid, tc.at)
		if v := readYouTubeHealth(base, 123, true, now); v.Fresh || v.Phase != "waiting" {
			t.Fatal("stale/wrong process health used", v)
		}
	}
	write(123, now)
	if v := readYouTubeHealth(base, 123, false, now); v.Fresh || v.Phase != "stopped" {
		t.Fatal("stopped engine claimed healthy", v)
	}
}
func TestYouTubeHealthReportHasNoFreeText(t *testing.T) {
	v := sanitizeYouTubeHealth(YouTubeHealthView{Phase: "PRIVATE-TOKEN", Profile: "https://private.example/key", Switches: -1, Failures: 99999999, Checks: []YouTubeCheck{{Target: "PRIVATE-TOKEN", Stage: "tls"}, {Target: "site", Stage: "PRIVATE-TOKEN", MS: 9999999, Code: 9999}, {Target: "site", Stage: "http"}}})
	b, _ := json.Marshal(v)
	if strings.Contains(string(b), "PRIVATE-TOKEN") || strings.Contains(string(b), "private.example") || v.Switches != 0 || v.Failures != 1000000 || len(v.Checks) != 1 || v.Checks[0].MS != 60000 || v.Checks[0].Code != 599 {
		t.Fatal("unsafe YouTube report", string(b))
	}
}

func TestYouTubeHealthRequiresObservedVideoServerForHealthyStatus(t *testing.T) {
	for _, phase := range []string{"healthy", "recovered", "awaiting_media"} {
		v := sanitizeYouTubeHealth(YouTubeHealthView{Phase: phase})
		if v.Phase != "awaiting_media" {
			t.Fatal("unobserved video server reported healthy", v)
		}
	}
	if v := sanitizeYouTubeHealth(YouTubeHealthView{Phase: "healthy", MediaObserved: true}); v.Phase != "healthy" {
		t.Fatal("actual video check was lost", v)
	}
}
