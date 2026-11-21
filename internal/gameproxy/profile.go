package gameproxy

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/fitting-1c/evasion/internal/gamefilter"
	"github.com/google/uuid"
)

const profileLimit = 2 << 20

var errProfile = errors.New("не найден подходящий профиль VLESS/Reality: вставьте ссылку подписки, VLESS-ссылку или JSON из Happ")

type user struct {
	ID         string `json:"id"`
	Encryption string `json:"encryption"`
	Flow       string `json:"flow,omitempty"`
}
type server struct {
	Address string `json:"address"`
	Port    uint16 `json:"port"`
	Users   []user `json:"users"`
}
type settings struct {
	VNext []server `json:"vnext"`
}
type reality struct {
	Fingerprint string `json:"fingerprint"`
	PublicKey   string `json:"publicKey"`
	ServerName  string `json:"serverName"`
	ShortID     string `json:"shortId"`
}
type grpc struct {
	ServiceName string `json:"serviceName"`
	Authority   string `json:"authority,omitempty"`
}
type stream struct {
	Network  string  `json:"network"`
	Security string  `json:"security"`
	Reality  reality `json:"realitySettings"`
	GRPC     *grpc   `json:"grpcSettings,omitempty"`
}
type outbound struct {
	Protocol string   `json:"protocol"`
	Tag      string   `json:"tag"`
	Settings settings `json:"settings"`
	Stream   stream   `json:"streamSettings"`
}
type Profile struct {
	Outbounds []outbound `json:"outbounds"`
}

func hostOK(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	if a, e := netip.ParseAddr(s); e == nil {
		return gamefilter.Public(a)
	}
	if strings.EqualFold(s, "localhost") || !strings.Contains(s, ".") {
		return false
	}
	for _, c := range s {
		if c != '.' && c != '-' && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}
func plain(s string, limit int) bool {
	if len(s) > limit {
		return false
	}
	for _, r := range s {
		if r < 32 || r == 127 {
			return false
		}
	}
	return true
}

func validate(o outbound) bool {
	if o.Protocol != "vless" || o.Stream.Security != "reality" || len(o.Settings.VNext) != 1 {
		return false
	}
	s := o.Settings.VNext[0]
	if !hostOK(s.Address) || s.Port == 0 || len(s.Users) != 1 {
		return false
	}
	u := s.Users[0]
	if _, e := uuid.Parse(u.ID); e != nil {
		return false
	}
	if u.Encryption != "none" || (u.Flow != "" && u.Flow != "xtls-rprx-vision" && u.Flow != "xtls-rprx-vision-udp443") {
		return false
	}
	r := o.Stream.Reality
	k, e := base64.RawURLEncoding.DecodeString(r.PublicKey)
	if e != nil || len(k) != 32 || !hostOK(r.ServerName) || !plain(r.Fingerprint, 64) || r.Fingerprint == "" {
		return false
	}
	id, e := hex.DecodeString(r.ShortID)
	if e != nil || len(id) > 8 {
		return false
	}
	switch o.Stream.Network {
	case "tcp", "raw":
		return true
	case "grpc":
		return u.Flow == "" && o.Stream.GRPC != nil && plain(o.Stream.GRPC.ServiceName, 256) && plain(o.Stream.GRPC.Authority, 253)
	default:
		return false
	}
}

func fromURI(line string) (outbound, bool) {
	u, e := url.Parse(strings.TrimSpace(line))
	if e != nil || u.Scheme != "vless" || u.User == nil {
		return outbound{}, false
	}
	if _, ok := u.User.Password(); ok {
		return outbound{}, false
	}
	port := 443
	if u.Port() != "" {
		port, e = strconv.Atoi(u.Port())
		if e != nil || port < 1 || port > 65535 {
			return outbound{}, false
		}
	}
	q := u.Query()
	network := q.Get("type")
	if network == "" {
		network = "tcp"
	}
	fp := q.Get("fp")
	if fp == "" {
		fp = "chrome"
	}
	encryption := q.Get("encryption")
	if encryption == "" {
		encryption = "none"
	}
	o := outbound{Protocol: "vless", Settings: settings{[]server{{u.Hostname(), uint16(port), []user{{u.User.Username(), encryption, q.Get("flow")}}}}}, Stream: stream{Network: network, Security: q.Get("security"), Reality: reality{fp, q.Get("pbk"), q.Get("sni"), q.Get("sid")}}}
	if network == "grpc" {
		o.Stream.GRPC = &grpc{q.Get("serviceName"), q.Get("authority")}
	}
	return o, validate(o)
}

func ParseProfile(data []byte) (Profile, error) {
	if len(data) == 0 || len(data) > profileLimit {
		return Profile{}, errProfile
	}
	s := strings.TrimSpace(strings.TrimPrefix(string(data), "\ufeff"))
	if !strings.HasPrefix(s, "{") && !strings.HasPrefix(s, "[") && !strings.HasPrefix(s, "vless://") {
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			if b, e := enc.DecodeString(strings.Join(strings.Fields(s), "")); e == nil {
				s = strings.TrimSpace(string(b))
				break
			}
		}
	}
	p := Profile{}
	seen := map[string]bool{}
	add := func(o outbound) {
		if len(p.Outbounds) >= 16 || !validate(o) {
			return
		}
		o.Tag = ""
		b, _ := json.Marshal(o)
		if seen[string(b)] {
			return
		}
		seen[string(b)] = true
		o.Tag = "game-" + strconv.Itoa(len(p.Outbounds)+1)
		p.Outbounds = append(p.Outbounds, o)
	}
	if strings.HasPrefix(s, "vless://") {
		for _, line := range strings.Fields(s) {
			if o, ok := fromURI(line); ok {
				add(o)
			}
		}
	} else {
		var walk func(json.RawMessage, int)
		walk = func(raw json.RawMessage, depth int) {
			if depth > 4 || len(p.Outbounds) >= 16 {
				return
			}
			var many []json.RawMessage
			if json.Unmarshal(raw, &many) == nil {
				for _, v := range many {
					walk(v, depth+1)
				}
				return
			}
			var object struct {
				Protocol  string            `json:"protocol"`
				Outbounds []json.RawMessage `json:"outbounds"`
				Configs   []json.RawMessage `json:"configs"`
			}
			if json.Unmarshal(raw, &object) != nil {
				return
			}
			if object.Protocol == "vless" {
				var o outbound
				if json.Unmarshal(raw, &o) == nil {
					add(o)
				}
			}
			for _, v := range object.Outbounds {
				walk(v, depth+1)
			}
			for _, v := range object.Configs {
				walk(v, depth+1)
			}
		}
		walk(json.RawMessage(s), 0)
	}
	if len(p.Outbounds) == 0 {
		return Profile{}, errProfile
	}
	return p, nil
}

func ImportInput(ctx context.Context, input string) (Profile, error) {
	input = strings.TrimSpace(input)
	if len(input) > profileLimit {
		return Profile{}, errProfile
	}
	if strings.HasPrefix(strings.ToLower(input), "https://") {
		u, e := url.Parse(input)
		if e != nil || u.User != nil || !hostOK(u.Hostname()) {
			return Profile{}, errProfile
		}
		client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 || req.URL.Scheme != "https" || req.URL.Host != u.Host {
				return errors.New("недопустимое перенаправление подписки")
			}
			return nil
		}}
		req, e := http.NewRequestWithContext(ctx, "GET", input, nil)
		if e != nil {
			return Profile{}, errProfile
		}
		req.Header.Set("User-Agent", "Happ/1.0 Evasion-profile-import")
		r, e := client.Do(req)
		if e != nil {
			return Profile{}, errors.New("не удалось получить подписку; проверьте её доступность в Happ")
		}
		defer r.Body.Close()
		if r.StatusCode != 200 {
			return Profile{}, errors.New("сервер подписки не выдал профиль")
		}
		b, e := io.ReadAll(io.LimitReader(r.Body, profileLimit+1))
		if e != nil {
			return Profile{}, errProfile
		}
		return ParseProfile(b)
	}
	return ParseProfile([]byte(input))
}

func (p Profile) Config(port uint16) ([]byte, error) {
	return p.ConfigProbe(port, "https://cp.cloudflare.com/generate_204")
}

func (p Profile) ConfigProbe(port uint16, probeURL string) ([]byte, error) {
	if len(p.Outbounds) == 0 || len(p.Outbounds) > 16 {
		return nil, errProfile
	}
	tags := []string{}
	outbounds := make([]outbound, 0, len(p.Outbounds))
	for _, o := range p.Outbounds {
		if !validate(o) {
			return nil, errProfile
		}
		tags = append(tags, o.Tag)
		s := o.Settings.VNext[0]
		s.Users = append([]user(nil), s.Users...)
		if s.Users[0].Flow == "xtls-rprx-vision" {
			s.Users[0].Flow = "xtls-rprx-vision-udp443"
		}
		o.Settings.VNext = []server{s}
		outbounds = append(outbounds, o)
	}
	return json.Marshal(map[string]any{
		"log":         map[string]any{"loglevel": "none"},
		"inbounds":    []any{map[string]any{"tag": "games", "listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": map[string]any{"auth": "noauth", "udp": true}}},
		"outbounds":   outbounds,
		"observatory": map[string]any{"subjectSelector": tags, "probeUrl": probeURL, "probeInterval": "30s", "enableConcurrency": true},
		"routing":     map[string]any{"balancers": []any{map[string]any{"tag": "available", "selector": tags, "fallbackTag": tags[0], "strategy": map[string]any{"type": "leastPing"}}}, "rules": []any{map[string]any{"type": "field", "inboundTag": []string{"games"}, "network": "tcp,udp", "balancerTag": "available"}}},
	})
}
