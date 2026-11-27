package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fitting-1c/evasion/internal/capture"
	"github.com/fitting-1c/evasion/internal/config"
	"github.com/fitting-1c/evasion/internal/packet"
	"github.com/fitting-1c/evasion/internal/proxy"
	"github.com/fitting-1c/evasion/internal/vantage"
	"github.com/fitting-1c/evasion/internal/youtubetune"
)

func goodYouTubeChecks(ok bool) []youtubeCheck {
	return []youtubeCheck{{Target: "site", OK: ok}, {Target: "image", OK: ok}, {Target: "media_transport", OK: ok}}
}
func recoveryFixture(t *testing.T) (*youtubeRecovery, *int) {
	t.Helper()
	cfg := config.Default()
	cfg.Groups = map[string][]string{"video": youtubetune.Domains}
	d, _ := cfg.DomainSet(nil)
	p, e := newYouTubeMux(proxy.StaticProvider{}, d)
	if e != nil {
		t.Fatal(e)
	}
	p.media = "rr1---example.googlevideo.com"
	p.mediaAt = time.Now()
	saved := 0
	a := &youtubeRecovery{p: p, network: "network", identity: func() string { return "network" }, control: func(context.Context) bool { return true }, load: func(string) string { return "" }, store: func(string, string, string) { saved++ }, publish: func(youtubeHealth) {}}
	return a, &saved
}

func TestYouTubeCanaryDoesNotConfirmPlaybackOrSaveProfile(t *testing.T) {
	a, saved := recoveryFixture(t)
	a.p.media = ""
	a.measure = func(context.Context, string, bool) []youtubeCheck { return goodYouTubeChecks(true) }
	a.round(context.Background())
	a.round(context.Background())
	if a.state.Phase != "awaiting_media" || *saved != 0 || a.state.MediaObserved {
		t.Fatal("canary promoted to verified video connectivity", a.state)
	}
}

func TestYouTubeProbeDistinguishesDNSFromOtherDialErrors(t *testing.T) {
	a, _ := recoveryFixture(t)
	for _, tt := range []struct {
		err   error
		stage string
		dns   string
	}{
		{&net.DNSError{IsNotFound: true}, "dns", "not_found"},
		{&net.DNSError{IsTimeout: true}, "dns", "timeout"},
		{&net.DNSError{Err: "resolver error"}, "dns", "error"},
		{errors.New("dial rejected"), "tcp", ""},
	} {
		a.p.dial = func(context.Context, string, string) (net.Conn, error) { return nil, tt.err }
		check := a.p.probe(t.Context(), "active", "site", "https://www.youtube.com/generate_204", false)
		if check.OK || check.Stage != tt.stage || check.DNS != tt.dns {
			t.Errorf("dial error %v: got %+v, want %s / %s", tt.err, check, tt.stage, tt.dns)
		}
	}
}

func TestYouTubeProbeClassifiesDeadlineAtCurrentStage(t *testing.T) {
	for _, resolve := range []bool{false, true} {
		a, _ := recoveryFixture(t)
		a.p.dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
			trace := httptrace.ContextClientTrace(ctx)
			if trace.DNSStart != nil {
				trace.DNSStart(httptrace.DNSStartInfo{Host: "www.youtube.com"})
			}
			if resolve {
				if trace.DNSDone != nil {
					trace.DNSDone(httptrace.DNSDoneInfo{})
				}
				trace.ConnectStart("tcp", "192.0.2.1:443")
			}
			return nil, context.DeadlineExceeded
		}
		check := a.p.probe(t.Context(), "active", "site", "https://www.youtube.com/generate_204", false)
		stage, dns := "dns", "timeout"
		if resolve {
			stage, dns = "tcp", ""
		}
		if check.Stage != stage || check.DNS != dns {
			t.Errorf("DNS completed=%t: got %+v; want stage=%s dns=%s", resolve, check, stage, dns)
		}
	}
}

func TestYouTubeDNSFailureKeepsProfileAndChecksConfiguredFallback(t *testing.T) {
	a, _ := recoveryFixture(t)
	a.p.media = ""
	a.p.set("media-sld")
	routed := false
	a.route = func(on bool) { routed = on }
	fallbackProbes := 0
	a.tunnelMeasure = func(context.Context, bool) []youtubeCheck {
		fallbackProbes++
		return goodYouTubeChecks(fallbackProbes > 1)
	}
	dnsChecks := goodYouTubeChecks(true)
	dnsChecks[0] = youtubeCheck{Target: "site", Stage: "dns", DNS: "not_found"}
	a.measure = func(_ context.Context, name string, _ bool) []youtubeCheck {
		if name != "active" {
			t.Errorf("TLS candidate probed despite a DNS-only failure: %s", name)
		}
		return dnsChecks
	}
	a.round(t.Context())
	a.round(t.Context())
	if routed || a.state.Phase != "dns_error" || a.state.MediaObserved {
		t.Fatalf("unverified fallback or media: %+v", a.state)
	}
	a.round(t.Context())
	if !routed || fallbackProbes != 2 || a.p.current() != "media-sld" || !a.lastScan.IsZero() || a.state.Switches != 0 {
		t.Fatalf("DNS-only recovery changed the TLS profile or missed a verified fallback: %+v", a.state)
	}
	a.measure = func(context.Context, string, bool) []youtubeCheck { return goodYouTubeChecks(true) }
	for range 4 {
		a.round(t.Context())
	}
	if routed || a.state.Phase != "awaiting_media" {
		t.Fatalf("stable DNS should return to direct without claiming playback: %+v", a.state)
	}
}

func TestYouTubeMixedDNSAndTLSFailuresStillTryProfiles(t *testing.T) {
	a, _ := recoveryFixture(t)
	checks := goodYouTubeChecks(true)
	checks[0] = youtubeCheck{Target: "site", Stage: "dns", DNS: "timeout"}
	checks[1] = youtubeCheck{Target: "image", Stage: "tls"}
	a.measure = func(context.Context, string, bool) []youtubeCheck { return checks }
	a.round(t.Context())
	a.round(t.Context())
	if a.lastScan.IsZero() || a.state.Phase == "dns_error" {
		t.Fatalf("mixed failures suppressed TLS profile recovery: %+v", a.state)
	}
}

func TestYouTubeObservedCDNWakesMonitorAndRemainsProbeTarget(t *testing.T) {
	a, _ := recoveryFixture(t)
	p := a.p
	p.media = ""
	m := proxy.ConnMeta{Host: "192.0.2.1", Port: 443, LocalPort: 45000, SNI: "rr2---example.googlevideo.com", IsClientHello: true}
	p.Select(m)
	select {
	case <-p.wake:
	default:
		t.Fatal("new video server did not wake monitor")
	}
	p.mediaAt = time.Now().Add(-time.Hour)
	if host, observed := p.mediaHost(); !observed || host != m.SNI {
		t.Fatal("real video server replaced by canary")
	}
	p.Select(m)
	select {
	case <-p.wake:
		t.Fatal("unchanged endpoint repeatedly woke monitor")
	default:
	}
}

func TestYouTubeNewCDNDoesNotInheritOldCooldown(t *testing.T) {
	a, _ := recoveryFixture(t)
	a.measure = func(context.Context, string, bool) []youtubeCheck { return goodYouTubeChecks(false) }
	a.round(context.Background())
	a.round(context.Background())
	if a.lastScan.IsZero() {
		t.Fatal("fixture did not scan")
	}
	a.p.media = "rr2---example.googlevideo.com"
	a.round(context.Background())
	if !a.lastScan.IsZero() || a.state.Failures != 1 {
		t.Fatal("new CDN inherited old failures or cooldown")
	}
}

func TestYouTubeNewCDNCancelsInFlightProbe(t *testing.T) {
	a, saved := recoveryFixture(t)
	started := make(chan struct{})
	a.measure = func(ctx context.Context, _ string, _ bool) []youtubeCheck {
		close(started)
		<-ctx.Done()
		return goodYouTubeChecks(false)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	finished := make(chan time.Duration, 1)
	go func() { finished <- a.round(ctx) }()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("probe did not start")
	}
	a.p.Select(proxy.ConnMeta{IsClientHello: true, SNI: "rr2---example.googlevideo.com", Host: "192.0.2.2", Port: 443, LocalPort: 45000})
	select {
	case delay := <-finished:
		if delay != 0 || a.state.Failures != 0 || *saved != 0 || a.nextShort {
			t.Fatal("discarded probe affected recovery", delay, a.state)
		}
	case <-ctx.Done():
		t.Fatal("probe was not canceled when the CDN changed")
	}
}

func TestYouTubeNetworkChangeDiscardsOldMedia(t *testing.T) {
	a, saved := recoveryFixture(t)
	id := a.network
	a.identity = func() string { return id }
	a.measure = func(context.Context, string, bool) []youtubeCheck { return goodYouTubeChecks(true) }
	a.round(t.Context())
	a.measure = func(context.Context, string, bool) []youtubeCheck {
		id = "other-network"
		return goodYouTubeChecks(true)
	}
	if a.round(t.Context()) != 0 || *saved != 0 {
		t.Fatal("measurement was accepted after the network changed")
	}
	a.round(t.Context())
	a.round(t.Context())
	if a.state.Phase != "awaiting_media" || a.state.MediaObserved || *saved != 0 {
		t.Fatal("previous network's CDN was treated as observed", a.state)
	}
}

func TestYouTubeTransportProbeFinishesAtHeaders(t *testing.T) {
	a, _ := recoveryFixture(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	check := a.p.probe(ctx, "active", "media_transport", server.URL, false)
	if !check.OK || check.Code != http.StatusNotFound || ctx.Err() != nil {
		t.Fatal("transport check waited for the HTTP body", check)
	}
}

func TestYouTubeCDNChangeDuringValidationRejectsCandidate(t *testing.T) {
	a, saved := recoveryFixture(t)
	a.measure = func(_ context.Context, name string, _ bool) []youtubeCheck {
		if name == "active" && a.p.current() != "current" {
			a.p.mu.Lock()
			a.p.media = "rr3---example.googlevideo.com"
			a.p.mu.Unlock()
			return goodYouTubeChecks(true)
		}
		return goodYouTubeChecks(name == "split-forward")
	}
	a.round(context.Background())
	a.round(context.Background())
	if a.p.current() != "current" || *saved != 0 {
		t.Fatal("candidate validated against a different CDN")
	}
}
func TestYouTubeRecoveryVerifiesBeforeSwitching(t *testing.T) {
	a, saved := recoveryFixture(t)
	a.control = nil
	a.measure = func(_ context.Context, name string, _ bool) []youtubeCheck {
		if name == "active" {
			name = a.p.current()
		}
		return goodYouTubeChecks(name == "split-forward")
	}
	a.round(context.Background())
	if a.p.current() != "current" || *saved != 0 {
		t.Fatal("single failure changed production")
	}
	a.round(context.Background())
	if a.p.current() != "split-forward" || a.state.Switches != 1 || *saved != 1 {
		t.Fatal("verified alternative not committed", a.state)
	}
	a.round(context.Background())
	if a.state.Switches != 1 {
		t.Fatal("healthy profile churned")
	}
}
func TestYouTubeRecoveryRollsBackAndRateLimitsFailedScan(t *testing.T) {
	a, saved := recoveryFixture(t)
	var calls atomic.Int32
	a.measure = func(_ context.Context, name string, _ bool) []youtubeCheck {
		calls.Add(1)
		return goodYouTubeChecks(name == "split-forward")
	}
	a.round(context.Background())
	a.round(context.Background())
	if a.p.current() != "current" || a.state.Rollbacks != 1 || *saved != 0 {
		t.Fatal("failed production check was retained", a.state)
	}
	before := calls.Load()
	a.round(context.Background())
	if calls.Load() != before+1 {
		t.Fatal("failed scans not throttled")
	}
}
func TestYouTubeRecoveryDoesNotBlameStrategyForOfflineNetwork(t *testing.T) {
	a, _ := recoveryFixture(t)
	a.control = func(context.Context) bool { return false }
	a.measure = func(context.Context, string, bool) []youtubeCheck { return goodYouTubeChecks(false) }
	a.round(context.Background())
	a.round(context.Background())
	if a.state.Phase != "network_down" || a.p.current() != "current" {
		t.Fatal(a.state)
	}
}
func TestYouTubeRecoveryCancellationAndNetworkChangeDiscardCandidate(t *testing.T) {
	for _, change := range []bool{false, true} {
		a, saved := recoveryFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var changed atomic.Bool
		a.identity = func() string {
			if changed.Load() {
				return "other-network"
			}
			return "network"
		}
		a.measure = func(_ context.Context, name string, _ bool) []youtubeCheck {
			if name == "active" && a.p.current() != "current" {
				if change {
					changed.Store(true)
				} else {
					cancel()
				}
				return goodYouTubeChecks(true)
			}
			return goodYouTubeChecks(name == "split-forward")
		}
		a.round(ctx)
		a.round(ctx)
		if a.p.current() != "current" || *saved != 0 {
			t.Fatal("canceled or wrong-network candidate committed")
		}
	}
}
func TestYouTubeCandidateLeaseAndScopeAreExact(t *testing.T) {
	a, _ := recoveryFixture(t)
	p := a.p
	meta := proxy.ConnMeta{Host: "1.1.1.1", Port: 443, LocalPort: 45000, SNI: "www.youtube.com", IsClientHello: true, PayloadLength: 1800}
	p.leases[youtubeLease{45000, "1.1.1.1", 443}] = "fake-split"
	if p.Select(meta).Strategy == nil {
		t.Fatal("registered probe not selected")
	}
	meta.LocalPort++
	if p.Select(meta).Strategy != nil {
		t.Fatal("candidate escaped its socket")
	}
	meta.LocalPort--
	meta.SNI = "discord.com"
	if p.Select(meta).Strategy != nil {
		t.Fatal("candidate escaped YouTube")
	}
	p.set("overlap")
	meta.SNI = "www.youtube.com"
	meta.LocalPort++
	meta.PayloadLength = 300
	if p.Select(meta).ID != p.choices["split-forward"].ID {
		t.Fatal("short ClientHello used oversized overlap")
	}
}

func TestYouTubeMediaProfilePreservesWebsiteStrategy(t *testing.T) {
	a, _ := recoveryFixture(t)
	p := a.p
	p.set("media-sld")
	m := proxy.ConnMeta{IsClientHello: true, Host: "192.0.2.1", Port: 443, LocalPort: 44000, PayloadLength: 1500}
	for _, host := range []string{"www.youtube.com", "i.ytimg.com", "youtubei.googleapis.com", "redirector.googlevideo.com"} {
		m.SNI = host
		if got := p.Select(m); got.ID != p.choices["fake-sld"].ID {
			t.Fatal("website strategy changed", host)
		}
	}
	m.SNI = "rr1---example.googlevideo.com"
	for _, size := range []int{300, 1500} {
		m.PayloadLength = size
		if p.Select(m).ID != p.choices["split-sld"].ID {
			t.Fatal("media did not use domain split")
		}
	}
	m.SNI = "discord.com"
	if p.Select(m).Strategy != nil {
		t.Fatal("new method escaped YouTube")
	}
}

func TestYouTubeCompositeProfileIsVerifiedAndCached(t *testing.T) {
	a, saved := recoveryFixture(t)
	a.measure = func(_ context.Context, name string, _ bool) []youtubeCheck {
		if name == "active" {
			name = a.p.current()
		}
		return goodYouTubeChecks(name == "media-sld")
	}
	a.round(context.Background())
	a.round(context.Background())
	if a.p.current() != "media-sld" || *saved != 1 || !youtubeProfileAllowed("media-sld") {
		t.Fatal("verified media method not retained", a.state)
	}
}

func TestYouTubeRecoveryCanSelectProtectedDomainSplit(t *testing.T) {
	a, saved := recoveryFixture(t)
	a.measure = func(_ context.Context, name string, _ bool) []youtubeCheck {
		if name == "active" {
			name = a.p.current()
		}
		return goodYouTubeChecks(name == "fake-sld")
	}
	a.round(context.Background())
	a.round(context.Background())
	if a.p.current() != "fake-sld" || *saved != 1 || a.state.Switches != 1 {
		t.Fatal("protected domain strategy was not verified and selected", a.state)
	}
}

func TestYouTubeRedirectorCannotBecomeObservedMedia(t *testing.T) {
	a, _ := recoveryFixture(t)
	a.p.media = ""
	a.p.Select(proxy.ConnMeta{IsClientHello: true, SNI: "redirector.googlevideo.com"})
	if _, observed := a.p.mediaHost(); observed {
		t.Fatal("generic canary reported as real video server")
	}
}
func TestPrepareYouTubeAutoPreservesOtherServices(t *testing.T) {
	cfg := config.Default()
	cfg.Groups = map[string][]string{"video": {"youtube.com", "googlevideo.com", "ytimg.com"}, "discord": {"discord.com"}}
	d, _ := cfg.DomainSet([]string{"discord"})
	_, on := prepareYouTubeAuto(cfg, d, []string{"discord"})
	if on || cfg.YouTubeQUICMode != nil {
		t.Fatal("unselected video changed")
	}
	d, _ = cfg.DomainSet(nil)
	next, on := prepareYouTubeAuto(cfg, d, nil)
	if !on || !next.Matches("youtubei.googleapis.com", "") || cfg.QUICMode != config.Default().QUICMode {
		t.Fatal("YouTube API coverage or general QUIC changed")
	}
}

func TestYouTubeShortHandshakeFailureIsNotMaskedByHealthyLong(t *testing.T) {
	a, _ := recoveryFixture(t)
	a.measure = func(_ context.Context, name string, short bool) []youtubeCheck {
		if name == "active" {
			name = a.p.current()
		}
		return goodYouTubeChecks(name == "split-forward" || name == "current" && !short)
	}
	for range 3 {
		a.round(context.Background())
	}
	if a.state.Switches != 0 || a.state.Failures != 1 {
		t.Fatal("handshake-specific evidence lost", a.state)
	}
	a.round(context.Background())
	if a.p.current() != "split-forward" || a.state.Switches != 1 {
		t.Fatal("repeated short TLS failure did not recover", a.state)
	}
}

func TestYouTubeRecoveryPausesWithEngineConnectivityGuard(t *testing.T) {
	a, saved := recoveryFixture(t)
	a.paused = func() bool { return true }
	a.measure = func(context.Context, string, bool) []youtubeCheck {
		t.Fatal("probe ran while engine was transparent")
		return nil
	}
	a.round(context.Background())
	if a.state.Phase != "network_down" || *saved != 0 || a.p.current() != "current" {
		t.Fatal(a.state)
	}
}

func TestYouTubeWarmProfileSurvivesOvernightButIsNetworkScoped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "warm.json")
	now := time.Now().UTC()
	for _, tc := range []struct {
		name, id, profile, want string
		age                     time.Duration
	}{
		{"overnight", "network", "media-sld", "media-sld", 18 * time.Hour},
		{"expired", "network", "media-sld", "", youtubeWarmMaxAge + time.Second},
		{"other-network", "other", "media-sld", "", time.Hour},
		{"empty-identity", "", "media-sld", "", time.Hour},
		{"unknown-profile", "network", "unknown", "", time.Hour},
		{"future", "network", "media-sld", "", -2 * time.Minute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writeYouTubeJSON(path, youtubeWarmProfile{Identity: "network", Profile: tc.profile, At: now.Add(-tc.age)})
			if got := loadYouTubeWarmProfile(path, tc.id, now); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
	os.WriteFile(path, []byte(`{"profile":`), 0600)
	if loadYouTubeWarmProfile(path, "network", now) != "" {
		t.Fatal("invalid cache accepted")
	}
}

func TestYouTubeRouteIdentityIgnoresUnusedVirtualInterfaces(t *testing.T) {
	local := net.ParseIP("192.168.50.20")
	physical := vantage.Iface{Up: true, HardwareAddr: net.HardwareAddr{0, 1, 2, 3, 4, 5}, Addrs: []net.IPNet{{IP: local, Mask: net.CIDRMask(24, 32)}}}
	virtual := vantage.Iface{Up: true, HardwareAddr: net.HardwareAddr{6, 7, 8, 9, 10, 11}, Addrs: []net.IPNet{{IP: net.ParseIP("10.20.30.40"), Mask: net.CIDRMask(24, 32)}}}
	routed := youtubeRouteInterfaces(local, []vantage.Iface{virtual, physical})
	if len(routed) != 1 || routed[0].HardwareAddr.String() != physical.HardwareAddr.String() {
		t.Fatal("unused virtual interface entered the YouTube route identity")
	}
	base, err := vantage.Fingerprint(youtubeInterfaces{physical})
	if err != nil {
		t.Fatal(err)
	}
	withVirtual, err := vantage.Fingerprint(youtubeInterfaces(routed))
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Strategy, _ = youtubetune.Profile("split", nil)
	if youtubeIdentityForFingerprint(cfg, base) != youtubeIdentityForFingerprint(cfg, withVirtual) {
		t.Fatal("virtual adapter changed the YouTube network identity")
	}
}

func TestYouTubeWarmProfileAppliedBeforeFirstProbe(t *testing.T) {
	a, _ := recoveryFixture(t)
	a.p.media = ""
	cfg := config.Default()
	cfg.Strategy, _ = youtubetune.Profile("split", nil)
	id := youtubeIdentity(cfg)
	if id == "" {
		t.Skip("no network identity available")
	}
	dir := t.TempDir()
	media := "rr1---example.googlevideo.com"
	writeYouTubeJSON(filepath.Join(dir, "youtube-known-good.json"), youtubeWarmProfile{Identity: id, Profile: "fake-sld", At: time.Now().Add(-18 * time.Hour), Media: media})
	warm := newYouTubeRecovery(a.p, cfg, dir)
	if warm.p.current() != "fake-sld" || !warm.state.CheckedAt.IsZero() {
		t.Fatal("working profile was not applied before monitoring, or was falsely confirmed")
	}
	if host, observed := warm.p.mediaHost(); !observed || host != media {
		t.Fatal("verified media endpoint was not restored for the first startup check")
	}
	if warm.startProfile("media-sld") || warm.p.current() != "fake-sld" {
		t.Fatal("startup fallback overwrote the network-specific working profile")
	}
	warm.store(id, "fake-sld", media)
	saved, ok := loadYouTubeWarm(filepath.Join(dir, "youtube-known-good.json"), id, time.Now())
	if !ok || saved.Media != media {
		t.Fatal("verified media endpoint was not retained")
	}

	fallback, _ := recoveryFixture(t)
	if !fallback.startProfile("media-sld") || fallback.p.current() != "media-sld" {
		t.Fatal("cold start without cache did not use the immediate fallback")
	}
}

func TestYouTubeRepeatFailureUsesFastConfirmation(t *testing.T) {
	a, _ := recoveryFixture(t)
	a.control = func(context.Context) bool { return false }
	calls := 0
	a.measure = func(ctx context.Context, _ string, _ bool) []youtubeCheck {
		calls++
		deadline, limited := ctx.Deadline()
		if calls == 1 && limited {
			t.Fatal("initial check lost its normal timeout")
		}
		if calls == 2 && (!limited || time.Until(deadline) > youtubeRetryTimeout) {
			t.Fatal("confirmation retained a full failure timeout")
		}
		return goodYouTubeChecks(false)
	}
	if wait := a.round(context.Background()); wait > 250*time.Millisecond {
		t.Fatal("unnecessary delay before confirming failure", wait)
	}
	a.round(context.Background())
	if calls != 2 || a.state.Phase != "network_down" {
		t.Fatal("offline protection bypassed")
	}
}

func TestYouTubeFastCandidateDoesNotWaitForBlockedAlternative(t *testing.T) {
	a, saved := recoveryFixture(t)
	var inFlight atomic.Int32
	var shapes atomic.Int32
	a.measure = func(ctx context.Context, name string, short bool) []youtubeCheck {
		inFlight.Add(1)
		defer inFlight.Add(-1)
		if name == "fake-sld" {
			<-ctx.Done()
			return goodYouTubeChecks(false)
		}
		if name == "media-sld" {
			if short {
				shapes.Or(2)
			} else {
				shapes.Or(1)
			}
		}
		if name == "active" {
			name = a.p.current()
		}
		return goodYouTubeChecks(name == "media-sld")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	a.round(ctx)
	a.round(ctx)
	if ctx.Err() != nil || a.p.current() != "media-sld" || *saved != 1 || shapes.Load() != 3 {
		t.Fatal("fast verified alternative was held behind a timeout", a.state)
	}
	if inFlight.Load() != 0 {
		t.Fatal("candidate probes survived cancellation")
	}
}

func TestYouTubeCandidateConcurrencyIsBoundedAndCancelled(t *testing.T) {
	a, _ := recoveryFixture(t)
	started := make(chan string, 8)
	var inFlight, peak atomic.Int32
	a.measure = func(ctx context.Context, name string, _ bool) []youtubeCheck {
		n := inFlight.Add(1)
		defer inFlight.Add(-1)
		for prev := peak.Load(); n > prev && !peak.CompareAndSwap(prev, n); prev = peak.Load() {
		}
		started <- name
		<-ctx.Done()
		return goodYouTubeChecks(false)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	results := a.candidates(ctx, "current")
	names := map[string]bool{}
	for range youtubeScanWorkers * 2 {
		select {
		case name := <-started:
			names[name] = true
		case <-ctx.Done():
			t.Fatal("candidate checks were not concurrent")
		}
	}
	cancel()
	for range results {
		t.Fatal("cancelled candidate accepted")
	}
	if len(names) != youtubeScanWorkers || peak.Load() != int32(youtubeScanWorkers*2) || inFlight.Load() != 0 {
		t.Fatal("unbounded or leaked candidate probes", names, peak.Load(), inFlight.Load())
	}
}

func TestYouTubeSameCDNActivityWakesWithoutFlooding(t *testing.T) {
	a, _ := recoveryFixture(t)
	p := a.p
	m := proxy.ConnMeta{Host: "192.0.2.1", Port: 443, LocalPort: 45000, SNI: p.media, IsClientHello: true}
	p.lastWake = time.Now().Add(-youtubeActivityInterval - time.Second)
	p.Select(m)
	select {
	case <-p.wake:
	default:
		t.Fatal("same CDN retry waited for background timer")
	}
	p.Select(m)
	select {
	case <-p.wake:
		t.Fatal("connection burst flooded monitor")
	default:
	}
}

func TestYouTubePacketSinkZerosIPv4IDAndPreservesChecksum(t *testing.T) {
	data := udp4(443, []byte{1, 2, 3})
	h, err := packet.ParseIPv4Header(data)
	if err != nil {
		t.Fatal(err)
	}
	h.SetID(4242)
	h.RecomputeChecksum()
	var base capture.SyntheticSink
	if err := (youtubePacketSink{&base}).Send(capture.Packet{Data: data}); err != nil {
		t.Fatal(err)
	}
	got := base.Sent()[0].Data
	ip, err := packet.ParseIPv4Header(got)
	if err != nil || ip.ID() != 0 || ip.Checksum() != packet.IPv4HeaderChecksum(ip) {
		t.Fatalf("invalid generated IPv4 header: id=%d checksum=%x err=%v", ip.ID(), ip.Checksum(), err)
	}
}

func TestYouTubeFallbackRequiresConfirmedFailures(t *testing.T) {
	a, _ := recoveryFixture(t)
	var routes []bool
	a.route = func(enabled bool) { routes = append(routes, enabled) }
	a.measure = func(context.Context, string, bool) []youtubeCheck { return goodYouTubeChecks(false) }
	a.round(t.Context())
	if len(routes) != 0 || a.fallback {
		t.Fatal("single failure enabled VLESS")
	}
	a.lastScan = time.Now()
	a.round(t.Context())
	if !a.fallback || len(routes) != 1 || !routes[0] || a.state.Route != "vless" {
		t.Fatal("confirmed failure did not enable VLESS", a.state, routes)
	}
}

func TestYouTubeFallbackDoesNotHideNetworkOutage(t *testing.T) {
	a, _ := recoveryFixture(t)
	a.route = func(bool) { t.Fatal("VLESS enabled during a general network outage") }
	a.control = func(context.Context) bool { return false }
	a.measure = func(context.Context, string, bool) []youtubeCheck { return goodYouTubeChecks(false) }
	a.round(t.Context())
	a.round(t.Context())
	if a.fallback || a.state.Phase != "network_down" {
		t.Fatal("unexpected fallback", a.state)
	}
}

func TestYouTubeFallbackReturnsAfterStableDirectChecks(t *testing.T) {
	a, _ := recoveryFixture(t)
	var routes []bool
	a.route = func(enabled bool) { routes = append(routes, enabled) }
	a.setFallback(true)
	a.media = a.p.media
	a.checkedShape = [2]bool{true, true}
	a.measure = func(context.Context, string, bool) []youtubeCheck { return goodYouTubeChecks(true) }
	for i := 0; i < 2; i++ {
		a.round(t.Context())
		if !a.fallback {
			t.Fatalf("returned to direct after %d healthy rounds", i+1)
		}
	}
	a.round(t.Context())
	if a.fallback || a.state.Route != "direct" {
		t.Fatal("stable direct route was not restored", a.state)
	}
	if len(routes) != 2 || !routes[0] || routes[1] {
		t.Fatal("unexpected route transitions", routes)
	}
}

func TestYouTubeFallbackRequiresHealthyTunnel(t *testing.T) {
	a, _ := recoveryFixture(t)
	a.route = func(bool) { t.Fatal("unhealthy VLESS route was enabled") }
	a.tunnelMeasure = func(context.Context, bool) []youtubeCheck { return goodYouTubeChecks(false) }
	a.measure = func(context.Context, string, bool) []youtubeCheck { return goodYouTubeChecks(false) }
	a.round(t.Context())
	a.lastScan = time.Now()
	a.round(t.Context())
	if a.fallback {
		t.Fatal("unhealthy VLESS route was enabled")
	}
}
