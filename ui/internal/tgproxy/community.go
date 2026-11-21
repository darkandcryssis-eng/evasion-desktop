package tgproxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Public relay snapshot from Flowseal/tg-ws-proxy (MIT; see LICENSE).
// The built-in list works offline; a validated domain-only list is refreshed hourly.
var communityDomains = []string{
	"pclead.co.uk", "offshor.co.uk", "cakeisalie.co.uk", "noskomnadzor.co.uk",
	"lovetrue.co.uk", "sorokdva.co.uk", "pyatdesyatdva.co.uk", "kartoshka.co.uk",
	"sorokodin.co.uk", "pyatdesyatodin.co.uk", "notelega.co.uk", "ebally.co.uk",
	"nebally.co.uk", "havegreatday.co.uk", "pomogite.co.uk", "fixtelega.co.uk",
	"sadnews.co.uk", "onedaychamp.co.uk", "stopblocking.co.uk", "nothingthere.co.uk",
}

const communityDomainsURL = "https://raw.githubusercontent.com/Flowseal/tg-ws-proxy/main/.github/cfproxy-domains.txt"

type domainPool struct {
	mu        sync.Mutex
	domains   []string
	preferred map[int]string
}

func newDomainPool() *domainPool {
	return &domainPool{domains: append([]string(nil), communityDomains...), preferred: map[int]string{}}
}

func (p *domainPool) all() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.domains...)
}

func (p *domainPool) forDC(dc int) []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := append([]string(nil), p.domains...)
	rand.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	if current := p.preferred[dc]; current != "" {
		for i, domain := range out {
			if domain == current {
				out[0], out[i] = out[i], out[0]
				break
			}
		}
	}
	return out
}

func (p *domainPool) prefer(dc int, domain string) {
	p.mu.Lock()
	p.preferred[dc] = domain
	p.mu.Unlock()
}

func (p *domainPool) replace(domains []string) bool {
	if len(domains) < 3 {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.domains = append([]string(nil), domains...)
	for dc := range p.preferred {
		p.preferred[dc] = domains[rand.Intn(len(domains))]
	}
	return true
}

func validDomain(domain string) bool {
	if len(domain) < 4 || len(domain) > 253 || strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return false
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if r != '-' && (r < 'a' || r > 'z') && (r < '0' || r > '9') {
				return false
			}
		}
	}
	tld := labels[len(labels)-1]
	if len(tld) < 2 {
		return false
	}
	for _, r := range tld {
		if r < 'a' || r > 'z' {
			return false
		}
	}
	return true
}

// decodeCommunityDomain mirrors upstream's public domain-list encoding.
func decodeCommunityDomain(value string) string {
	if !strings.HasSuffix(value, ".com") {
		return value
	}
	prefix := strings.TrimSuffix(value, ".com")
	count := 0
	for _, r := range prefix {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			count++
		}
	}
	var out strings.Builder
	for _, r := range prefix {
		base := rune(0)
		if r >= 'a' && r <= 'z' {
			base = 'a'
		} else if r >= 'A' && r <= 'Z' {
			base = 'A'
		}
		if base != 0 {
			r = (r-base-rune(count))%26 + base
			if r < base {
				r += 26
			}
		}
		out.WriteRune(r)
	}
	out.WriteString(".co.uk")
	return out.String()
}

func normalizeDomains(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		domain := strings.ToLower(strings.TrimSpace(value))
		if !validDomain(domain) {
			continue
		}
		if _, ok := seen[domain]; ok {
			continue
		}
		seen[domain] = struct{}{}
		out = append(out, domain)
	}
	return out
}

func communityHTTPClient() *http.Client {
	dialer := &net.Dialer{Timeout: 8 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err == nil && strings.EqualFold(host, "raw.githubusercontent.com") {
			address = net.JoinHostPort("185.199.109.133", port)
		}
		return dialer.DialContext(ctx, network, address)
	}
	return &http.Client{Timeout: 10 * time.Second, Transport: transport}
}

func fetchCommunityDomains(ctx context.Context, client *http.Client, source string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s?%d", source, time.Now().UnixNano()), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "tg-ws-proxy")
	response, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("domain list HTTP %d", response.StatusCode)
	}
	var encoded []string
	scanner := bufio.NewScanner(io.LimitReader(response.Body, 64<<10))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			encoded = append(encoded, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	decoded := make([]string, 0, len(encoded))
	for _, value := range encoded {
		decoded = append(decoded, decodeCommunityDomain(value))
	}
	domains := normalizeDomains(decoded)
	if len(domains) < 3 {
		return nil, fmt.Errorf("domain list contains only %d valid entries", len(domains))
	}
	return domains, nil
}
