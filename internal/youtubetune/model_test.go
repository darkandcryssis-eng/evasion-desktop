package youtubetune

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/fitting-1c/evasion/internal/config"
	"github.com/fitting-1c/evasion/internal/strategy"
)

func score(ok bool) Score { return Score{Checks: []Check{{OK: ok}, {OK: ok}, {OK: ok}, {OK: ok}}} }

func TestPlanSelectionAndVerification(t *testing.T) {
	for _, tc := range []struct {
		name, working, quic string
		verifyFails, err    bool
	}{
		{"baseline", "current", "off", false, false},
		{"split", "split", "off", false, false},
		{"overlap", "overlap", "desync", false, false},
		{"tcp-fallback", "split", "block", false, false},
		{"unavailable", "none", "none", false, true},
		{"verification-fails", "split", "desync", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stage := ""
			var calls []string
			r, err := Run(context.Background(), func(ctx context.Context, p, m, proto string) (Score, error) {
				calls = append(calls, stage)
				if stage == "verify" && tc.verifyFails {
					return score(false), nil
				}
				if proto == "tcp" {
					return score(p == tc.working), nil
				}
				return score(m == tc.quic), nil
			}, func(s string) { stage = s })
			if (err != nil) != tc.err || r.Verified == tc.err {
				t.Fatalf("result=%+v err=%v", r, err)
			}
			if !tc.err && (r.Profile != tc.working || r.QUIC != tc.quic || calls[len(calls)-1] != "verify") {
				t.Fatalf("wrong selection: %+v %v", r, calls)
			}
			if tc.working == "current" && len(r.TCP) != 1 {
				t.Fatal("working baseline must stop TCP search")
			}
		})
	}
}

func TestPlanCancellationAndWorkerFailure(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{true: "worker", false: "cancel"}[fail], func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			r, err := Run(ctx, func(context.Context, string, string, string) (Score, error) {
				calls++
				if fail {
					return Score{}, errors.New("worker exited")
				}
				cancel()
				return score(true), nil
			}, func(string) {})
			if err == nil || r.Verified || calls != 1 {
				t.Fatalf("result=%+v err=%v calls=%d", r, err, calls)
			}
		})
	}
}

func TestFlakyOrIncompleteScoresRejected(t *testing.T) {
	s := score(true)
	s.Checks[2].OK = false
	if s.Reliable() || (Score{Checks: []Check{{OK: true}}}).Reliable() {
		t.Fatal("incomplete/flaky result accepted")
	}
	if mode, ok := ChooseQUIC(score(false), score(false), false); ok || mode != "" {
		t.Fatal("no reliable transport must fail")
	}
	if p, ok := ChooseTCP([]Score{{Name: "current", Checks: s.Checks}, {Name: "split", Checks: score(true).Checks}}); !ok || p != "split" {
		t.Fatal(p, ok)
	}
}

func TestYouTubeHostBoundaries(t *testing.T) {
	for host, want := range map[string]bool{"youtube.com": true, "R1.GOOGLEVIDEO.COM.": true, "i.ytimg.com": true, "evilyoutube.com": false, "youtube.com.evil.test": false, "discord.com": false, "": false} {
		if got := IsYouTube(host); got != want {
			t.Errorf("%q got %v", host, got)
		}
	}
}

func TestOverlayPreservesOtherServicesAndUnknownFields(t *testing.T) {
	original := []byte(`{"groups":{"video":["youtube.com","googlevideo.com"],"discord":["discord.com"]},"strategies":{"discord":{"rules":[]}},"quic_mode":"desync","voice":{"custom":3},"future_option":[1,2]}`)
	var before map[string]any
	json.Unmarshal(original, &before)
	for _, name := range Profiles {
		t.Run(name, func(t *testing.T) {
			b, err := Overlay(original, name, "block")
			if err != nil {
				t.Fatal(err)
			}
			var after map[string]any
			json.Unmarshal(b, &after)
			for _, key := range []string{"groups", "quic_mode", "voice", "future_option"} {
				if !reflect.DeepEqual(before[key], after[key]) {
					t.Errorf("changed %s", key)
				}
			}
			if !reflect.DeepEqual(before["strategies"].(map[string]any)["discord"], after["strategies"].(map[string]any)["discord"]) {
				t.Fatal("Discord changed")
			}
			if after["youtube_quic_mode"] != "block" {
				t.Fatal("override absent")
			}
			if name != "current" {
				if _, err = Profile(name, nil); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
	for _, input := range []string{`{}`, `{"groups":{"video":["discord.com"]}}`, `null`} {
		if _, err := Overlay([]byte(input), "split", "off"); err == nil {
			t.Fatal("unsafe overlay accepted")
		}
	}
	for _, pair := range [][2]string{{"unknown", "off"}, {"current", "invalid"}} {
		if _, err := Overlay(original, pair[0], pair[1]); err == nil {
			t.Fatal("invalid option accepted")
		}
	}
}

func TestRejectAmbiguousGroups(t *testing.T) {
	c := config.Default()
	c.Groups = map[string][]string{"video": {"youtube.com"}, "custom": {"youtube.com"}}
	if ValidateVideoGroup(c) == nil {
		t.Fatal("overlap accepted")
	}
	delete(c.Groups, "custom")
	if err := ValidateVideoGroup(c); err != nil {
		t.Fatal(err)
	}
}

func TestZapretInspiredProfilesAreValidAndBounded(t *testing.T) {
	for _, name := range []string{"multisplit", "fake-multisplit", "fake-disorder"} {
		p, err := Profile(name, nil)
		if err != nil || p == nil {
			t.Fatalf("%s: %v", name, err)
		}
		encoded, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		wantFakes := 0
		if name != "multisplit" {
			wantFakes = 6
		}
		if got := bytes.Count(encoded, []byte(`tls_clienthello_google`)); got != wantFakes {
			t.Fatalf("%s: fake count=%d want=%d", name, got, wantFakes)
		}
	}
}

func TestYouTubeEssentialDomainCoverage(t *testing.T) {
	for _, host := range []string{"youtu.be", "www.youtubekids.com", "yt3.ggpht.com", "youtube.googleapis.com", "youtubeembeddedplayer.googleapis.com", "jnn-pa.googleapis.com"} {
		if !IsYouTube(host) {
			t.Errorf("essential YouTube endpoint is outside scope: %s", host)
		}
	}
}

// Ротация группы video — это профиль «current» автоподбора, а не повод его
// отключать: иначе YouTube остаётся без проверки и запасного пути.
func TestRotationKeepsVideoGroupValid(t *testing.T) {
	c := config.Default()
	c.Groups = map[string][]string{"video": {"youtube.com"}}
	c.StrategiesRotation = map[string][]*strategy.Strategy{"video": {{}, {}}}
	if err := ValidateVideoGroup(c); err != nil {
		t.Fatal(err)
	}
}
