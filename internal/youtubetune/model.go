package youtubetune

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/fitting-1c/evasion/internal/config"
	"github.com/fitting-1c/evasion/internal/strategy"
)

var Domains = []string{
	"youtube.com", "youtu.be", "youtubekids.com", "youtube-nocookie.com",
	"googlevideo.com", "ytimg.com", "ytimg.l.google.com",
	"yt3.ggpht.com", "yt4.ggpht.com", "yt3.googleusercontent.com",
	"youtubei.googleapis.com", "youtube.googleapis.com", "youtubeembeddedplayer.googleapis.com",
	"jnn-pa.googleapis.com", "youtube-ui.l.google.com", "wide-youtube.l.google.com", "yt-video-upload.l.google.com",
}
var Profiles = []string{"current", "split", "overlap", "multisplit", "split-forward", "fake-split", "fake-overlap", "fake-multisplit", "fake-disorder", "fake-forward", "split-sld", "fake-sld"}

func fakeBurst(inner string, count int, badseqDelta uint64) string {
	fake := `{"kind":"tamper","params":{"field":"tcp_seq","mode":"add","value":` + strconv.FormatUint(badseqDelta, 10) + `},"left":{"kind":"tamper","params":{"field":"payload","mode":"replace","preset":"tls_clienthello_google"},"left":{"kind":"send"}}}`
	action := inner
	for range count {
		action = `{"kind":"duplicate","left":` + fake + `,"right":` + action + `}`
	}
	return action
}

func Profile(name string, current *strategy.Strategy) (*strategy.Strategy, error) {
	if name == "current" {
		return current, nil
	}
	action := ""
	switch name {
	case "split-sld":
		action = `{"kind":"fragment","params":{"proto":"tcp","at":"inside_sld","order":"reverse"},"left":{"kind":"send"},"right":{"kind":"send"}}`
	case "split":
		action = `{"kind":"fragment","params":{"proto":"tcp","at":"inside_sni","order":"reverse"},"left":{"kind":"send"},"right":{"kind":"send"}}`
	case "overlap":
		action = `{"kind":"tcp_overlap","params":{"preset":"tls_cover_681"}}`
	case "multisplit":
		action = `{"kind":"tcp_overlap","params":{"preset":"tls_cover_681","offset":1}}`
	case "split-forward":
		action = `{"kind":"fragment","params":{"proto":"tcp","at":"inside_sni","order":"forward"},"left":{"kind":"send"},"right":{"kind":"send"}}`
	case "fake-multisplit":
		action = fakeBurst(`{"kind":"tcp_overlap","params":{"preset":"tls_cover_681","offset":1}}`, 6, 4294966296)
	case "fake-disorder":
		inner := `{"kind":"fragment","params":{"proto":"tcp","offset":1,"order":"reverse"},"left":{"kind":"send"},"right":{"kind":"fragment","params":{"proto":"tcp","at":"inside_sld","order":"reverse"},"left":{"kind":"send"},"right":{"kind":"send"}}}`
		action = fakeBurst(inner, 6, 4294957296)
	case "fake-split", "fake-overlap", "fake-forward", "fake-sld":
		inner := `{"kind":"fragment","params":{"proto":"tcp","at":"inside_sni","order":"reverse"},"left":{"kind":"send"},"right":{"kind":"send"}}`
		if name == "fake-sld" {
			inner = strings.ReplaceAll(inner, `"at":"inside_sni"`, `"at":"inside_sld"`)
		}
		if name == "fake-forward" {
			inner = strings.ReplaceAll(inner, `"order":"reverse"`, `"order":"forward"`)
		}
		if name == "fake-overlap" {
			inner = `{"kind":"tcp_overlap","params":{"preset":"tls_cover_681"}}`
		}
		action = fakeBurst(inner, 1, 4294957296)
	default:
		return nil, errors.New("неизвестный профиль YouTube")
	}
	return strategy.Unmarshal([]byte(`{"rules":[{"direction":"outbound","trigger":{"match":"client_hello"},"action":`+action+`} ]}`), strategy.DefaultLimits())
}

func IsYouTube(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, d := range Domains {
		if host == d || len(host) > len(d) && host[len(host)-len(d)-1:] == "."+d {
			return true
		}
	}
	return false
}

func ValidateVideoGroup(cfg *config.Config) error {
	for name, hosts := range cfg.Groups {
		if name == "video" {
			continue
		}
		for _, host := range hosts {
			if IsYouTube(host) {
				return errors.New("домены YouTube встречаются в других группах: автоподбор пропущен")
			}
		}
	}
	if len(cfg.Groups["video"]) == 0 {
		return errors.New("в конфигурации нет группы video")
	}
	for _, host := range cfg.Groups["video"] {
		if !IsYouTube(host) {
			return errors.New("группа video содержит другие сервисы: автоподбор пропущен")
		}
	}
	return nil
}

func Overlay(original []byte, name, mode string) ([]byte, error) {
	if mode != "off" && mode != "desync" && mode != "block" {
		return nil, errors.New("неизвестный режим QUIC YouTube")
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(original, &root); err != nil {
		return nil, err
	}
	var groups map[string][]string
	if json.Unmarshal(root["groups"], &groups) != nil || len(groups["video"]) == 0 {
		return nil, errors.New("нет группы video")
	}
	for _, host := range groups["video"] {
		if !IsYouTube(host) {
			return nil, errors.New("неоднозначная группа video")
		}
	}
	if name != "current" {
		p, err := Profile(name, nil)
		if err != nil {
			return nil, err
		}
		overrides := map[string]json.RawMessage{}
		if old := root["strategies"]; len(old) > 0 {
			if err := json.Unmarshal(old, &overrides); err != nil {
				return nil, err
			}
		}
		overrides["video"], err = strategy.Marshal(p)
		if err != nil {
			return nil, err
		}
		root["strategies"], err = json.Marshal(overrides)
		if err != nil {
			return nil, err
		}
	}
	root["youtube_quic_mode"], _ = json.Marshal(mode)
	return json.MarshalIndent(root, "", "  ")
}

type Check struct {
	OK       bool   `json:"ok"`
	MS       int64  `json:"ms"`
	Protocol string `json:"protocol"`
	Target   string `json:"target"`
}
type Score struct {
	Name   string  `json:"name"`
	Checks []Check `json:"checks"`
}

func (s Score) Reliable() bool {
	if len(s.Checks) != 4 {
		return false
	}
	for _, v := range s.Checks {
		if !v.OK {
			return false
		}
	}
	return true
}
func ChooseTCP(scores []Score) (string, bool) {
	for _, s := range scores {
		if s.Name == "current" && s.Reliable() {
			return s.Name, true
		}
	}
	for _, name := range Profiles {
		for _, s := range scores {
			if s.Name == name && s.Reliable() {
				return name, true
			}
		}
	}
	return "current", false
}
func ChooseQUIC(native, desync Score, tcpReliable bool) (string, bool) {
	if native.Reliable() {
		return "off", true
	}
	if desync.Reliable() {
		return "desync", true
	}
	if tcpReliable {
		return "block", true
	}
	return "", false
}
