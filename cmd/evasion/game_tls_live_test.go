package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Subprocess fixture: run only when a native test controller explicitly opts in.
func TestGameTLSProcessHelper(t *testing.T) {
	if os.Getenv("EVASION_GAME_TLS_HELPER") != "1" {
		t.Skip("native per-process TLS fixture")
	}
	ready, signal, result := os.Getenv("EVASION_HELPER_READY"), os.Getenv("EVASION_HELPER_SIGNAL"), os.Getenv("EVASION_HELPER_RESULT")
	if ready == "" || signal == "" || result == "" {
		t.Fatal("missing fixture paths")
	}
	if err := os.WriteFile(ready, []byte(filepath.Base(os.Args[0])), 0600); err != nil {
		t.Fatal(err)
	}
	timer := time.NewTimer(25 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
wait:
	for {
		if _, err := os.Stat(signal); err == nil {
			break wait
		}
		select {
		case <-timer.C:
			t.Fatal("controller did not start fixture")
		case <-ticker.C:
		}
	}
	type check struct {
		Short  bool   `json:"short"`
		Status int    `json:"status"`
		XML    bool   `json:"xml"`
		Error  string `json:"error,omitempty"`
	}
	checks := []check{}
	for _, short := range []bool{false, true} {
		tc := &tls.Config{MinVersion: tls.VersionTLS12}
		if short {
			tc.CurvePreferences = []tls.CurveID{tls.X25519}
		}
		tr := &http.Transport{Proxy: nil, TLSClientConfig: tc, TLSHandshakeTimeout: 5 * time.Second, DialContext: (&net.Dialer{Timeout: 4 * time.Second}).DialContext, DisableKeepAlives: true}
		client := &http.Client{Transport: tr, Timeout: 7 * time.Second}
		c := check{Short: short}
		r, err := client.Get("https://live.albiononline.com/autoupdate/manifest.xml")
		if err != nil {
			c.Error = err.Error()
		} else {
			c.Status = r.StatusCode
			b, _ := io.ReadAll(io.LimitReader(r.Body, 256))
			r.Body.Close()
			c.XML = bytes.Contains(b, []byte("patchsitemanifest")) || strings.Contains(r.Header.Get("Content-Type"), "xml")
		}
		tr.CloseIdleConnections()
		checks = append(checks, c)
	}
	b, _ := json.Marshal(checks)
	if err := os.WriteFile(result, b, 0600); err != nil {
		t.Fatal(err)
	}
	for _, c := range checks {
		if c.Status != 200 || !c.XML {
			t.Errorf("native TLS probe failed: %+v", c)
		}
	}
}
