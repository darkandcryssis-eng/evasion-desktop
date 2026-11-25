package tgproxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestCommunityDomainDecodingAndValidation(t *testing.T) {
	if got := decodeCommunityDomain("virkgj.com"); got != "pclead.co.uk" {
		t.Fatalf("unexpected decoded domain: %q", got)
	}
	values := normalizeDomains([]string{"PCLEAD.co.uk", "pclead.co.uk", "bad domain", "offshor.co.uk", "noskomnadzor.co.uk"})
	want := []string{"pclead.co.uk", "offshor.co.uk", "noskomnadzor.co.uk"}
	if !reflect.DeepEqual(values, want) {
		t.Fatalf("normalized domains = %#v", values)
	}
}

func TestFetchCommunityDomainsUsesOnlyValidatedPayload(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("virkgj.com\n# comment\ninvalid\nvmmzovy.com\nmkuosckvso.com\n"))
	}))
	defer server.Close()
	domains, err := fetchCommunityDomains(context.Background(), server.Client(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(domains) != 3 || domains[0] != "pclead.co.uk" || domains[2] != "cakeisalie.co.uk" {
		t.Fatalf("unexpected domains: %#v", domains)
	}
	pool := newDomainPool()
	if !pool.replace(domains) {
		t.Fatal("valid list rejected")
	}
	pool.prefer(2, "offshor.co.uk")
	if got := pool.forDC(2)[0]; got != "offshor.co.uk" {
		t.Fatalf("preferred domain not first: %q", got)
	}
}

func TestDirectRoutesIncludeFrontingAfterFixedAddress(t *testing.T) {
	routes := routesFor(2, false)
	if len(routes) != 6 {
		t.Fatalf("route count = %d, want 6 (kws + zws)", len(routes))
	}
	front := routes[2]
	if !front.fronting || front.address != "149.154.167.220:443" || front.host != "kws2.web.telegram.org" {
		t.Fatalf("invalid fronting route: %+v", front)
	}
	if routes[3].host != "zws2.web.telegram.org" || !routes[3].isEncryptedWSS() {
		t.Fatalf("missing WebZ WSS fallback route: %+v", routes[3])
	}
}
