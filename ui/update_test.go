package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersionNewer(t *testing.T) {
	cases := []struct {
		latest, current string
		want            bool
	}{
		{"v0.1.2", "0.1.1", true},
		{"v0.1.10", "0.1.9", true},
		{"v0.2.0", "0.1.99", true},
		{"v0.1.1", "0.1.1", false},
		{"v0.1.0", "0.1.1", false},
		{"v0.1.2", "dev", false},
		{"latest", "0.1.1", false},
	}
	for _, c := range cases {
		if got := versionNewer(c.latest, c.current); got != c.want {
			t.Errorf("versionNewer(%q, %q) = %v, want %v", c.latest, c.current, got, c.want)
		}
	}
}

func releaseServer(t *testing.T, tag string, body []byte, sum string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/releases/tag/"+tag, http.StatusFound)
	})
	mux.HandleFunc("/releases/tag/"+tag, func(http.ResponseWriter, *http.Request) {})
	mux.HandleFunc("/releases/download/"+tag+"/Evasion.exe", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) })
	mux.HandleFunc("/releases/download/"+tag+"/Evasion.exe.sha256", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(sum + "  Evasion.exe\n"))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func testUpdater(t *testing.T, srv *httptest.Server, exe string, launched *[]string) *updater {
	t.Helper()
	old := appVersion
	appVersion = "0.1.1"
	t.Cleanup(func() { appVersion = old })
	u := newUpdater()
	u.releases = srv.URL + "/releases"
	u.exePath = func() (string, error) { return exe, nil }
	u.launch = func(exe string, args ...string) error { *launched = append([]string{exe}, args...); return nil }
	return u
}

func TestUpdateInstallReplacesExecutable(t *testing.T) {
	fresh := []byte("new build")
	sum := sha256.Sum256(fresh)
	srv := releaseServer(t, "v0.1.2", fresh, hex.EncodeToString(sum[:]))
	exe := filepath.Join(t.TempDir(), "Evasion.exe")
	if err := os.WriteFile(exe, []byte("old build"), 0o755); err != nil {
		t.Fatal(err)
	}
	var launched []string
	u := testUpdater(t, srv, exe, &launched)

	st, err := u.check(context.Background())
	if err != nil || !st.Available || st.Latest != "0.1.2" {
		t.Fatalf("check = %+v, %v", st, err)
	}
	if err := u.install(context.Background(), []string{resumeFlag}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(exe); string(b) != "new build" {
		t.Fatalf("exe = %q", b)
	}
	if b, _ := os.ReadFile(exe + ".old"); string(b) != "old build" {
		t.Fatalf("old = %q", b)
	}
	if len(launched) != 3 || launched[0] != exe || !strings.HasPrefix(launched[1], updatedFromFlag) || launched[2] != resumeFlag {
		t.Fatalf("launched = %v", launched)
	}
}

func TestUpdateInstallRejectsBadChecksum(t *testing.T) {
	srv := releaseServer(t, "v0.1.2", []byte("tampered"), strings.Repeat("0", 64))
	exe := filepath.Join(t.TempDir(), "Evasion.exe")
	if err := os.WriteFile(exe, []byte("old build"), 0o755); err != nil {
		t.Fatal(err)
	}
	var launched []string
	u := testUpdater(t, srv, exe, &launched)
	if _, err := u.check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := u.install(context.Background(), nil); err == nil {
		t.Fatal("install accepted a file with a wrong checksum")
	}
	if b, _ := os.ReadFile(exe); string(b) != "old build" {
		t.Fatalf("exe = %q", b)
	}
	if _, err := os.Stat(exe + ".new"); err == nil || launched != nil {
		t.Fatalf("leftovers: launched=%v", launched)
	}
	if st := u.snapshot(); st.Downloading || st.Error == "" {
		t.Fatalf("state = %+v", st)
	}
}

func TestUpdateCheckSkipsDevBuild(t *testing.T) {
	u := newUpdater()
	u.releases = "http://127.0.0.1:1/releases"
	st, err := u.check(context.Background())
	if err != nil || st.Available {
		t.Fatalf("check = %+v, %v", st, err)
	}
}
