package main

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestYouTubeDeepSiteCheckNeedsFullPage(t *testing.T) {
	for _, tc := range []struct {
		name string
		size int
		code int
		want bool
	}{
		{"full page", youtubePageBytes + 1024, 200, true},
		{"frozen early", 16 << 10, 200, false},
		{"redirect", 0, 302, true},
		{"blocked", 0, 403, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.code)
				_, _ = w.Write(make([]byte, tc.size))
			}))
			defer srv.Close()
			p := &youtubeMux{leases: map[youtubeLease]string{}, deep: true, dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
			}}
			old := youtubeProbeTLS
			youtubeProbeTLS = func(c *tls.Config) { c.InsecureSkipVerify = true }
			defer func() { youtubeProbeTLS = old }()
			got := p.probe(context.Background(), "active", "site_page", "https://www.youtube.com/", false)
			if got.OK != tc.want || got.Target != "site" {
				t.Fatalf("got %+v, want ok=%v target=site", got, tc.want)
			}
		})
	}
}
