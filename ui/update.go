package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// appVersion задаёт сборка релиза: -ldflags "-X main.appVersion=0.1.7".
// Локальная сборка остаётся "dev" и обновлений не ищет.
var appVersion = "dev"

var updateFirstCheck = 10 * time.Second

// updateReleases — страница релизов; проверочная сборка может подменить её
// через -X main.updateReleases=... и обновляться с тестового сервера.
var updateReleases = "https://github.com/darkandcryssis-eng/evasion-desktop/releases"

const (
	updateAsset     = "Evasion.exe"
	updateAssetMac  = "Evasion-macOS.zip"
	updateInterval  = 2 * time.Minute
	updatedFromFlag = "--updated-from="
	resumeFlag      = "--resume="
)

// UpdateState — что оболочка знает о новых версиях.
type UpdateState struct {
	Current     string `json:"current"`
	Latest      string `json:"latest"`
	Available   bool   `json:"available"`
	URL         string `json:"url"`
	Checking    bool   `json:"checking"`
	Downloading bool   `json:"downloading"`
	Progress    int    `json:"progress"`
	Error       string `json:"error"`
	CheckedAt   string `json:"checkedAt"`
}

// updater ищет новый релиз на GitHub и заменяет Evasion.exe по запросу
// пользователя. Версию берёт из адреса, на который ведёт releases/latest:
// у этого запроса нет лимита, в отличие от api.github.com.
type updater struct {
	mu       sync.Mutex
	state    UpdateState
	releases string
	client   *http.Client
	exePath  func() (string, error)
	launch   func(exe string, args ...string) error
	announce func(latest string) // найдена новая версия: показать уведомление
}

func newUpdater() *updater {
	return &updater{
		state:    UpdateState{Current: appVersion},
		releases: updateReleases,
		client:   &http.Client{},
		exePath:  currentExecutable,
		launch:   func(exe string, args ...string) error { return exec.Command(exe, args...).Start() },
	}
}

func currentExecutable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(exe)
}

func (u *updater) snapshot() UpdateState {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.state
}

func (u *updater) change(fn func(*UpdateState)) UpdateState {
	u.mu.Lock()
	fn(&u.state)
	defer u.mu.Unlock()
	return u.state
}

// parseVersion разбирает "v1.2.3" в числа; ok=false для "dev" и мусора.
func parseVersion(v string) ([3]int, bool) {
	var out [3]int
	parts := strings.Split(strings.TrimPrefix(strings.TrimSpace(v), "v"), ".")
	if len(parts) == 0 || len(parts) > 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

func versionNewer(latest, current string) bool {
	l, ok := parseVersion(latest)
	c, ok2 := parseVersion(current)
	if !ok || !ok2 {
		return false
	}
	for i := range l {
		if l[i] != c[i] {
			return l[i] > c[i]
		}
	}
	return false
}

// latestTag возвращает тег последнего релиза ("v0.1.7").
func (u *updater) latestTag(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, u.releases+"/latest", nil)
	if err != nil {
		return "", err
	}
	resp, err := u.client.Do(req)
	if err != nil {
		return "", err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub ответил %s", resp.Status)
	}
	final := resp.Request.URL.Path
	if path.Base(path.Dir(final)) != "tag" {
		return "", errors.New("релизов пока нет")
	}
	return path.Base(final), nil
}

func (u *updater) check(ctx context.Context) (UpdateState, error) {
	if _, ok := parseVersion(appVersion); !ok {
		return u.snapshot(), nil
	}
	u.mu.Lock()
	if u.state.Checking || u.state.Downloading {
		st := u.state
		u.mu.Unlock()
		return st, nil
	}
	u.state.Checking = true
	u.mu.Unlock()

	tag, err := u.latestTag(ctx)
	st := u.change(func(s *UpdateState) {
		s.Checking = false
		if err != nil {
			return
		}
		s.Error = ""
		s.CheckedAt = time.Now().Format(time.RFC3339)
		s.Latest = strings.TrimPrefix(tag, "v")
		s.Available = versionNewer(tag, s.Current)
		s.URL = u.releases + "/tag/" + tag
	})
	if err != nil {
		return st, fmt.Errorf("не удалось проверить обновления: %w", err)
	}
	return st, nil
}

func (u *updater) loop(ctx context.Context) {
	timer := time.NewTimer(updateFirstCheck)
	defer timer.Stop()
	announced := ""
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		if st, err := u.check(ctx); err == nil && st.Available && st.Latest != announced {
			// Об одной версии говорим один раз, а не каждые две минуты.
			announced = st.Latest
			if u.announce != nil {
				u.announce(st.Latest)
			}
		}
		timer.Reset(updateInterval)
	}
}

func (u *updater) expectedSum(ctx context.Context, tag string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.releases+"/download/"+tag+"/"+updateAsset+".sha256", nil)
	if err != nil {
		return "", err
	}
	resp, err := u.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("контрольная сумма: GitHub ответил %s", resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if err != nil {
		return "", err
	}
	fields := strings.Fields(string(b))
	if len(fields) == 0 || len(fields[0]) != sha256.Size*2 {
		return "", errors.New("контрольная сумма релиза не читается")
	}
	return strings.ToLower(fields[0]), nil
}

// download пишет Evasion.exe релиза в dst и сверяет SHA-256 с файлом релиза.
func (u *updater) download(ctx context.Context, tag, dst string) error {
	want, err := u.expectedSum(ctx, tag)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.releases+"/download/"+tag+"/"+updateAsset, nil)
	if err != nil {
		return err
	}
	resp, err := u.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GitHub ответил %s", resp.Status)
	}
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	sum := sha256.New()
	buf := make([]byte, 256<<10)
	var done int64
	last := -1
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if _, err = f.Write(buf[:n]); err != nil {
				break
			}
			sum.Write(buf[:n])
			done += int64(n)
			if resp.ContentLength > 0 {
				if pct := int(done * 100 / resp.ContentLength); pct != last {
					last = pct
					u.change(func(s *UpdateState) { s.Progress = pct })
				}
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			err = rerr
			break
		}
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && hex.EncodeToString(sum.Sum(nil)) != want {
		err = errors.New("скачанный файл повреждён: контрольная сумма не совпала")
	}
	if err != nil {
		_ = os.Remove(dst)
	}
	return err
}

// install скачивает новую версию, ставит её на место текущего Evasion.exe и
// запускает. Работающий exe в Windows нельзя перезаписать, но можно
// переименовать: старая копия остаётся рядом как .old до следующего запуска.
func (u *updater) install(ctx context.Context, relaunchArgs []string) error {
	u.mu.Lock()
	if u.state.Downloading {
		u.mu.Unlock()
		return nil
	}
	if !u.state.Available {
		u.mu.Unlock()
		return errors.New("новой версии нет")
	}
	tag := "v" + u.state.Latest
	u.state.Downloading, u.state.Progress, u.state.Error = true, 0, ""
	u.mu.Unlock()

	err := u.replace(ctx, tag, relaunchArgs)
	u.change(func(s *UpdateState) {
		s.Downloading = false
		if err != nil {
			s.Error = err.Error()
		}
	})
	return err
}

func (u *updater) replace(ctx context.Context, tag string, relaunchArgs []string) error {
	exe, err := u.exePath()
	if err != nil {
		return err
	}
	fresh, old := exe+".new", exe+".old"
	if err := u.download(ctx, tag, fresh); err != nil {
		return fmt.Errorf("не удалось скачать обновление: %w", err)
	}
	_ = os.Remove(old)
	if err := os.Rename(exe, old); err != nil {
		_ = os.Remove(fresh)
		return fmt.Errorf("не удалось заменить %s: %w", exe, err)
	}
	if err := os.Rename(fresh, exe); err != nil {
		_ = os.Rename(old, exe)
		_ = os.Remove(fresh)
		return fmt.Errorf("не удалось заменить %s: %w", exe, err)
	}
	args := append([]string{updatedFromFlag + strconv.Itoa(os.Getpid())}, relaunchArgs...)
	if err := u.launch(exe, args...); err != nil {
		_ = os.Remove(exe)
		_ = os.Rename(old, exe)
		return fmt.Errorf("не удалось запустить новую версию: %w", err)
	}
	return nil
}

// finishUpdate вызывается новой копией до старта окна: ждёт выхода старой
// (иначе сработает блокировка одного экземпляра) и убирает её файл.
func finishUpdate(args []string) {
	for _, arg := range args {
		pid, err := strconv.Atoi(strings.TrimPrefix(arg, updatedFromFlag))
		if !strings.HasPrefix(arg, updatedFromFlag) || err != nil {
			continue
		}
		for deadline := time.Now().Add(30 * time.Second); pidAlive(pid) && time.Now().Before(deadline); {
			time.Sleep(200 * time.Millisecond)
		}
	}
	if exe, err := currentExecutable(); err == nil {
		_ = os.Remove(exe + ".old")
		_ = os.Remove(exe + ".new")
	}
}

func (a *App) startUpdater(ctx context.Context) {
	a.updates.announce = a.notifyUpdate
	go a.updates.loop(ctx)
}

// GetUpdate — последнее известное состояние обновления.
func (a *App) GetUpdate() UpdateState { return a.updates.snapshot() }

// CheckUpdate проверяет GitHub сейчас (кнопка в «Настройках»).
func (a *App) CheckUpdate() (UpdateState, error) { return a.updates.check(context.Background()) }

// resumeState — что было включено до обновления; новая копия получает это
// в --resume= и включает обратно с теми же параметрами.
type resumeState struct {
	Engine  bool         `json:"engine"`
	Games   bool         `json:"games"`
	Options StartOptions `json:"options"`
}

func (r resumeState) arg() string {
	b, _ := json.Marshal(r)
	return resumeFlag + base64.RawURLEncoding.EncodeToString(b)
}

func parseResume(args []string) (resumeState, bool) {
	for _, arg := range args {
		if !strings.HasPrefix(arg, resumeFlag) {
			continue
		}
		var r resumeState
		b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(arg, resumeFlag))
		if err != nil || json.Unmarshal(b, &r) != nil || r.Options.validate() != nil {
			return resumeState{}, false
		}
		return r, r.Engine || r.Games
	}
	return resumeState{}, false
}

func (a *App) resumeAfterUpdate(ctx context.Context, r resumeState) {
	if r.Engine {
		a.connectAtLogin(ctx, &r.Options)
	}
	if r.Games && ctx.Err() == nil {
		if err := a.ApplyGameFilter(r.Options); err != nil {
			a.engine.consumeLogLine("Игровой фильтр после обновления не включён: " + err.Error())
		}
	}
}

// InstallUpdate ставит найденную версию и перезапускает Evasion. Всё, что
// было включено (обход, игровой фильтр), новая копия включит снова.
func (a *App) InstallUpdate() error {
	if runtime.GOOS == "darwin" {
		// Приложение на macOS — пакет .app: новую версию ставит пользователь.
		return openPath(updateReleases + "/latest/download/" + updateAssetMac)
	}
	engine := a.engine.snapshot()
	games := a.games.snapshot().Phase
	r := resumeState{
		Engine:  engine.Phase == phaseRunning || engine.Phase == phaseStarting,
		Games:   a.gameArmed.Load() || games == phaseRunning || games == phaseStarting,
		Options: engine.Options,
	}
	if !r.Engine {
		r.Options = defaultLaunchSettings().Options
		a.settingsMu.Lock()
		if s, err := readLaunchSettings(launchSettingsPath()); err == nil {
			r.Options = s.Options
		}
		a.settingsMu.Unlock()
	}
	var args []string
	if r.Engine || r.Games {
		args = append(args, r.arg())
	}
	if err := a.updates.install(context.Background(), args); err != nil {
		return err
	}
	a.ExitApplication()
	return nil
}
