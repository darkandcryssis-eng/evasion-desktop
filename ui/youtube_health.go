package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

type YouTubeCheck struct {
	Target string `json:"target"`
	Stage  string `json:"stage"`
	OK     bool   `json:"ok"`
	Code   int    `json:"code"`
	MS     int64  `json:"ms"`
	DNS    string `json:"dns,omitempty"`
}
type YouTubeHealthView struct {
	Running       bool           `json:"running"`
	Fresh         bool           `json:"fresh"`
	Phase         string         `json:"phase"`
	Profile       string         `json:"profile"`
	Route         string         `json:"route,omitempty"`
	CheckedAt     string         `json:"checkedAt"`
	Switches      int            `json:"switches"`
	Rollbacks     int            `json:"rollbacks"`
	Failures      int            `json:"failures"`
	MediaObserved bool           `json:"mediaObserved"`
	Checks        []YouTubeCheck `json:"checks"`
}

func sanitizeYouTubeHealth(v YouTubeHealthView) YouTubeHealthView {
	v.Phase = allowed(v.Phase, "waiting", "awaiting_media", "stopped", "disabled", "checking", "healthy", "degraded", "network_down", "recovering", "recovered", "unavailable", "dns_error")
	if !v.MediaObserved && (v.Phase == "healthy" || v.Phase == "recovered") {
		v.Phase = "awaiting_media"
	}
	v.Profile = allowed(v.Profile, "current", "split", "split-forward", "overlap", "multisplit", "fake-split", "fake-overlap", "fake-multisplit", "fake-disorder", "fake-forward", "split-sld", "fake-sld", "media-sld")
	v.Route = allowed(v.Route, "", "direct", "vless")
	if v.Route == "unknown" {
		v.Route = ""
	}
	v.CheckedAt = reportTime(v.CheckedAt)
	v.Switches = max(0, min(1000000, v.Switches))
	v.Rollbacks = max(0, min(1000000, v.Rollbacks))
	v.Failures = max(0, min(1000000, v.Failures))
	checks := []YouTubeCheck{}
	seen := map[string]bool{}
	for _, c := range v.Checks {
		target := allowed(c.Target, "site", "image", "media_transport")
		if target == "unknown" || seen[target] {
			continue
		}
		seen[target] = true
		c.Target = target
		c.Stage = allowed(c.Stage, "dns", "tcp", "tls", "http")
		if c.OK || c.Stage != "dns" || allowed(c.DNS, "timeout", "not_found", "error") == "unknown" {
			c.DNS = ""
		}
		c.Code = max(0, min(599, c.Code))
		c.MS = max(0, min(60000, c.MS))
		checks = append(checks, c)
	}
	v.Checks = checks
	return v
}
func readYouTubeHealth(base string, pid int, running bool, now time.Time) YouTubeHealthView {
	v := YouTubeHealthView{Running: running, Phase: "stopped", Checks: []YouTubeCheck{}}
	if !running {
		return v
	}
	v.Phase = "waiting"
	b, e := os.ReadFile(filepath.Join(base, "state", "youtube-health.json"))
	if e != nil || len(b) > 16384 {
		return v
	}
	var raw struct {
		PID           int            `json:"pid"`
		At            time.Time      `json:"at"`
		CheckedAt     time.Time      `json:"checkedAt"`
		Phase         string         `json:"phase"`
		Profile       string         `json:"profile"`
		Route         string         `json:"route"`
		Switches      int            `json:"switches"`
		Rollbacks     int            `json:"rollbacks"`
		Failures      int            `json:"failures"`
		MediaObserved bool           `json:"mediaObserved"`
		Checks        []YouTubeCheck `json:"checks"`
	}
	if json.Unmarshal(b, &raw) != nil || raw.PID != pid || now.Sub(raw.At) > 5*time.Minute || raw.At.After(now.Add(time.Minute)) {
		return v
	}
	return sanitizeYouTubeHealth(YouTubeHealthView{Running: true, Fresh: true, Phase: raw.Phase, Profile: raw.Profile, Route: raw.Route, CheckedAt: func() string {
		if raw.CheckedAt.IsZero() {
			return ""
		}
		return raw.CheckedAt.UTC().Format(time.RFC3339Nano)
	}(), Switches: raw.Switches, Rollbacks: raw.Rollbacks, Failures: raw.Failures, MediaObserved: raw.MediaObserved, Checks: raw.Checks})
}
func (a *App) youTubeHealth() YouTubeHealthView {
	state := a.engine.snapshot()
	return readYouTubeHealth(dataDir(), state.PID, state.Phase == phaseRunning, time.Now())
}
