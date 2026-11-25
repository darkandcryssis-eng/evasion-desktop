package main

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	wr "github.com/wailsapp/wails/v2/pkg/runtime"
)

type reportStep struct {
	Stage  string `json:"stage"`
	Status string `json:"status"`
	Code   string `json:"code"`
	MS     int64  `json:"ms"`
}
type reportService struct {
	Service   string       `json:"service"`
	Status    string       `json:"status"`
	CheckedAt string       `json:"checkedAt"`
	Steps     []reportStep `json:"steps"`
}
type reportRoute struct {
	Code      string `json:"code"`
	Transport string `json:"transport"`
	Status    string `json:"status"`
	CheckedAt string `json:"checkedAt"`
	LatencyMS int64  `json:"latencyMs"`
	Failures  int    `json:"failures"`
	Stability int    `json:"stability,omitempty"`
	Drops     int    `json:"drops,omitempty"`
}
type reportDisconnect struct {
	At         string `json:"at"`
	Transport  string `json:"transport"`
	DC         int    `json:"dc"`
	Media      bool   `json:"media"`
	Stage      string `json:"stage"`
	Cause      string `json:"cause"`
	DurationMS int64  `json:"durationMs"`
	Recovered  bool   `json:"recovered"`
}
type reportTraffic struct {
	Running     bool               `json:"running"`
	Active      int64              `json:"active"`
	Connections uint64             `json:"connections"`
	BytesUp     uint64             `json:"bytesUp"`
	BytesDown   uint64             `json:"bytesDown"`
	Failures    uint64             `json:"failures"`
	Switches    uint64             `json:"switches,omitempty"`
	Rejected    uint64             `json:"rejected"`
	Speeds      []SpeedSample      `json:"speeds"`
	Disconnects []reportDisconnect `json:"disconnects,omitempty"`
}
type reportEngine struct {
	Voice       string `json:"voice"`
	Quic        string `json:"quic"`
	Boost       bool   `json:"boost"`
	Restarts    int    `json:"restarts"`
	Complete    int64  `json:"helloComplete"`
	Assembled   int64  `json:"helloAssembled"`
	Skipped     int64  `json:"helloSkipped"`
	Retransmits int64  `json:"helloRetransmits"`
}
type reportConflicts struct {
	Stopped []string `json:"stopped"`
	Failed  []string `json:"failed"`
}
type safeReport struct {
	Version         string             `json:"version,omitempty"`
	Elevated        bool               `json:"elevated"`
	PreviousUnclean bool               `json:"previousUnclean"`
	Engine          *reportEngine      `json:"engine,omitempty"`
	Conflicts       *reportConflicts   `json:"conflicts,omitempty"`
	YouTube         *YouTubeHealthView `json:"youtube,omitempty"`
	Games           *reportGames       `json:"games,omitempty"`
	Driver          *reportDriver      `json:"driver,omitempty"`
	Schema          int                `json:"schema"`
	GeneratedAt     string             `json:"generatedAt"`
	Platform        string             `json:"platform"`
	EnginePhase     string             `json:"enginePhase"`
	Services        []reportService    `json:"services"`
	Routes          []reportRoute      `json:"routes"`
	Telegram        reportTraffic      `json:"telegram"`
}

func allowed(value string, values ...string) string {
	for _, candidate := range values {
		if value == candidate {
			return value
		}
	}
	return "unknown"
}
func reportTime(value string) string {
	t, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}
func reportCode(value string) string {
	if value == "" {
		return ""
	}
	for _, stage := range []string{"dns", "tcp", "tls", "https", "gateway", "mtproto", "channel"} {
		for _, suffix := range []string{"_ok", "_timeout", "_error"} {
			if value == stage+suffix {
				return value
			}
		}
	}
	if value == "tls_certificate" || value == "cancelled" || value == "mtproto_unavailable" {
		return value
	}
	if len(value) == 8 && value[:5] == "http_" {
		if n, err := strconv.Atoi(value[5:]); err == nil && n >= 100 && n <= 599 {
			return "http_" + strconv.Itoa(n)
		}
	}
	return "unknown"
}

// Build only permitted fields; raw logs, paths, URLs and configuration never enter this type.
func buildSafeReport(phase string, telegram TelegramState, services []ServiceDiagnostic, routes []TelegramRoute, drivers ...driverDiagnostic) safeReport {
	r := safeReport{Schema: 1, GeneratedAt: time.Now().UTC().Format(time.RFC3339Nano), Platform: runtime.GOOS + "/" + runtime.GOARCH, EnginePhase: allowed(phase, "stopped", "starting", "running", "stopping", "failed"), Services: []reportService{}, Routes: []reportRoute{}, Telegram: reportTraffic{Running: telegram.Running, Active: telegram.Active, Connections: telegram.Connections, BytesUp: telegram.BytesUp, BytesDown: telegram.BytesDown, Failures: telegram.Failures, Switches: telegram.Switches, Rejected: telegram.Rejected, Speeds: []SpeedSample{}}}
	for _, s := range services {
		id := allowed(s.ID, "telegram", "telegram-web", "discord-api", "discord-gateway")
		if id == "unknown" {
			continue
		}
		v := reportService{Service: id, Status: allowed(s.Status, "ok", "fail"), CheckedAt: reportTime(s.CheckedAt), Steps: []reportStep{}}
		for _, step := range s.Steps {
			v.Steps = append(v.Steps, reportStep{Stage: allowed(step.ID, "dns", "tcp", "tls", "https", "gateway", "mtproto"), Status: allowed(step.Status, "ok", "fail"), Code: reportCode(step.Code), MS: max(0, step.MS)})
		}
		r.Services = append(r.Services, v)
	}
	for _, v := range routes {
		r.Routes = append(r.Routes, reportRoute{Code: reportCode(v.Code), Transport: allowed(v.Kind, "WSS", "Резерв WSS", "TCP", "WSS · фиксированный адрес", "Туннель VLESS"), Status: allowed(v.Status, "untested", "checking", "verified", "opened", "cooldown", "failed"), CheckedAt: reportTime(v.CheckedAt), LatencyMS: max(0, v.LatencyMS), Failures: max(0, v.Failures), Stability: min(100, max(0, v.Stability)), Drops: max(0, v.Drops)})
	}
	for _, d := range telegram.Disconnects[:min(len(telegram.Disconnects), 50)] {
		r.Telegram.Disconnects = append(r.Telegram.Disconnects, reportDisconnect{
			At:         reportTime(d.At),
			Transport:  allowed(d.Transport, "wss", "wss_fixed", "wss_front", "relay_wss", "relay_ws", "tcp", "vless"),
			DC:         max(0, d.DC),
			Media:      d.Media,
			Stage:      allowed(d.Stage, "connect", "first_reply", "relay_read", "relay_write", "switch"),
			Cause:      allowed(d.Cause, "reset", "timeout", "eof", "ws_close", "tls", "dns", "mtproto", "cancelled", "error"),
			DurationMS: max(0, d.DurationMS),
			Recovered:  d.Recovered,
		})
	}
	for _, v := range telegram.Speeds[max(0, len(telegram.Speeds)-120):] {
		if math.IsNaN(v.Up) || math.IsNaN(v.Down) || math.IsInf(v.Up, 0) || math.IsInf(v.Down, 0) {
			continue
		}
		r.Telegram.Speeds = append(r.Telegram.Speeds, SpeedSample{At: reportTime(v.At), Up: max(0, v.Up), Down: max(0, v.Down)})
	}
	if len(drivers) > 0 {
		r.Driver = safeDriverReport(drivers[0])
	}
	return r
}

// safeVersion пропускает только номер релиза: в сборке без -ldflags там "dev".
func safeVersion(v string) string {
	n, ok := parseVersion(v)
	if !ok {
		return "dev"
	}
	return fmt.Sprintf("%d.%d.%d", n[0], n[1], n[2])
}

func safeEngineReport(st EngineState) *reportEngine {
	r := &reportEngine{Voice: "unknown", Quic: "unknown", Boost: st.Options.Boost, Restarts: max(0, st.Restarts)}
	if allowedVoice[st.Options.Voice] {
		r.Voice = st.Options.Voice
	}
	if allowedQuic[st.Options.Quic] {
		r.Quic = st.Options.Quic
	}
	if h := st.Hello; h != nil {
		r.Complete, r.Assembled, r.Skipped, r.Retransmits = max(0, h.Complete), max(0, h.Assembled), max(0, h.Skipped), max(0, h.Retransmits)
	}
	return r
}

// safeConflicts оставляет только известные имена: имя чужой службы с подходящим
// бинарником произвольно и в отчёт не попадает.
func safeConflicts(c conflictReport) *reportConflicts {
	known := func(names []string) []string {
		out := []string{}
		for _, name := range names {
			kind := ""
			if rest, ok := strings.CutPrefix(name, "служба "); ok {
				name, kind = rest, "service:"
			}
			switch {
			case strings.Contains(name, "WinDivert"):
				out = append(out, "windivert-stale")
			case isConflictProcess(name) || slices.ContainsFunc(conflictServices, func(k string) bool { return strings.EqualFold(k, name) }):
				out = append(out, kind+strings.ToLower(name))
			default:
				out = append(out, kind+"other")
			}
		}
		return out
	}
	return &reportConflicts{Stopped: known(c.Stopped), Failed: known(c.Failed)}
}

func writeReport(path string, report safeReport) error {
	b, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".evasion-report-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(0o600); err == nil {
		_, err = f.Write(append(b, '\n'))
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(tmp, path)
}

func (a *App) ExportDiagnosticReport() (string, error) {
	path, err := wr.SaveFileDialog(a.ctx, wr.SaveDialogOptions{Title: "Сохранить отчёт без секретов", DefaultFilename: "Evasion-report-" + time.Now().Format("20060102-150405") + ".json", Filters: []wr.FileFilter{{DisplayName: "Отчёт JSON", Pattern: "*.json"}}, CanCreateDirectories: true})
	if err != nil || path == "" {
		return "", err
	}
	if filepath.Ext(path) == "" {
		path += ".json"
	}
	engine := a.engine.snapshot()
	// Без проверки связи в отчёте нет данных о Discord: при работающем обходе
	// запускаем её сами.
	if engine.Phase == phaseRunning && len(a.GetServiceDiagnostics()) == 0 {
		_, _ = a.RunServiceDiagnostics()
	}
	report := buildSafeReport(string(engine.Phase), a.GetTelegramState(), a.GetServiceDiagnostics(), a.GetTelegramRoutes(), a.driverDiagnostic())
	report.Version = safeVersion(appVersion)
	report.Elevated, _ = isElevated()
	report.Engine = safeEngineReport(engine)
	a.settingsMu.Lock()
	report.PreviousUnclean = a.previousUnclean
	report.Conflicts = safeConflicts(a.conflicts)
	a.settingsMu.Unlock()
	report.Games = safeGameReport(a.GetGameFilter())
	youtube := sanitizeYouTubeHealth(a.youTubeHealth())
	report.YouTube = &youtube
	if err := writeReport(path, report); err != nil {
		return "", fmt.Errorf("не удалось сохранить отчёт: %w", err)
	}
	return path, nil
}

type reportDriver struct {
	Status   string          `json:"status"`
	Code     uint32          `json:"code"`
	Services []driverService `json:"services"`
}

func safeDriverReport(d driverDiagnostic) *reportDriver {
	r := &reportDriver{Status: allowed(d.Status, "ok", "warn", "unknown"), Code: safeDriverCode(d.Code), Services: []driverService{}}
	for _, s := range d.Services {
		if s.ID != "windivert" && s.ID != "bfe" && s.ID != "battleye" {
			continue
		}
		r.Services = append(r.Services, driverService{ID: s.ID, State: allowed(s.State, "running", "stopped", "start_pending", "stop_pending", "missing", "unknown"), Start: allowed(s.Start, "boot", "system", "auto", "demand", "disabled", "unknown"), PendingDeletion: s.PendingDeletion, Code: safeDriverCode(s.Code)})
	}
	return r
}
func safeDriverCode(code uint32) uint32 {
	switch code {
	case 2, 3, 5, 87, 126, 577, 1058, 1060, 1068, 1072, 1275, 1753:
		return code
	}
	return 0
}

type reportGames struct {
	Transport   GameTransportState `json:"transport"`
	Observation GameAdaptiveState  `json:"observation"`
	Running     bool               `json:"running"`
	Fresh       bool               `json:"fresh"`
	Mode        string             `json:"mode"`
	Protocol    string             `json:"protocol"`
	Adaptive    bool               `json:"adaptive"`
	Processes   []GameProcessState `json:"processes"`
	Stats       GameFilterStats    `json:"stats"`
}

func safeGameReport(v GameFilterView) *reportGames {
	r := &reportGames{Running: v.EngineRunning, Fresh: v.Fresh, Mode: allowed(v.ActiveMode, "off", "auto", "gentle", "balanced", "strong"), Protocol: allowed(v.ActiveProtocol, "both", "tcp", "udp"), Adaptive: v.Settings.Adaptive, Processes: []GameProcessState{}, Stats: v.Stats}
	r.Observation = GameAdaptiveState{Stage: allowed(v.Adaptive.Stage, "watching", "gentle", "balanced", "strong"), Watching: max(0, min(8192, v.Adaptive.Watching)), Helping: max(0, min(8192, v.Adaptive.Helping)), Responsive: max(0, min(8192, v.Adaptive.Responsive))}
	r.Transport = GameTransportState{Stage: allowed(v.Transport.Stage, "idle", "tcp_connecting", "tls_waiting", "exchanging", "tcp_unanswered", "tls_unanswered", "tls_closed", "tcp_closed"), Connecting: max(0, min(8192, v.Transport.Connecting)), TLSWaiting: max(0, min(8192, v.Transport.TLSWaiting)), Responding: max(0, min(8192, v.Transport.Responding)), NoTCPReply: max(0, min(8192, v.Transport.NoTCPReply)), NoTLSReply: max(0, min(8192, v.Transport.NoTLSReply)), TLSClosed: max(0, min(8192, v.Transport.TLSClosed)), TCPClosed: max(0, min(8192, v.Transport.TCPClosed))}
	for _, p := range v.Processes {
		if p.Family != "custom" {
			continue
		}
		r.Processes = append(r.Processes, GameProcessState{Family: p.Family, Launchers: max(0, min(65535, p.Launchers)), Clients: max(0, min(65535, p.Clients)), Helpers: max(0, min(65535, p.Helpers))})
	}
	return r
}
