//go:build windows

package gameproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestProtectedProfileRoundTripAndAtomicValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "route.dat")
	p := fixtureProfile()
	if err := SaveProfile(path, p); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte(p.Outbounds[0].Settings.VNext[0].Users[0].ID)) || bytes.Contains(b, []byte("example.com")) {
		t.Fatal("profile stored as plaintext")
	}
	loaded, err := LoadProfile(path)
	if err != nil || len(loaded.Outbounds) != 1 {
		t.Fatal("round trip failed", err)
	}
	if SaveProfile(path, Profile{}) == nil {
		t.Fatal("invalid replacement accepted")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(b, after) {
		t.Fatal("failed import overwrote existing profile")
	}
	os.WriteFile(path, []byte(profileMagic+"invalid"), 0600)
	if _, err = LoadProfile(path); err == nil {
		t.Fatal("damaged profile accepted")
	}
}

func TestNativeWorkerProcessHelper(t *testing.T) {
	profile, exe, ready := os.Getenv("EVASION_WORKER_PROFILE"), os.Getenv("EVASION_XRAY_TEST_EXE"), os.Getenv("EVASION_WORKER_READY")
	if profile == "" || exe == "" || ready == "" {
		t.Skip("native parent-crash fixture")
	}
	w, err := StartWorker(context.Background(), profile, exe)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	b, _ := json.Marshal(map[string]int{"child": w.cmd.Process.Pid})
	if os.WriteFile(ready, b, 0600) != nil {
		t.Fatal("fixture handshake failed")
	}
	select {
	case <-time.After(20 * time.Second):
	case <-w.Done():
		t.Fatal("worker exited unexpectedly")
	}
}
