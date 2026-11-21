package main

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"
)

type launchSettings struct {
	AutoStart  bool         `json:"autoStart"`
	Executable string       `json:"executable"`
	Options    StartOptions `json:"options"`
}

func defaultLaunchSettings() launchSettings {
	return launchSettings{Options: StartOptions{Voice: "ttl", Quic: "off", Boost: true}}
}

func readLaunchSettings(path string) (launchSettings, error) {
	s := defaultLaunchSettings()
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if len(b) > 65536 {
		return s, errors.New("файл настроек автозапуска слишком большой")
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return s, fmt.Errorf("настройки автозапуска повреждены: %w", err)
	}
	return s, s.Options.validate()
}

func launchSettingsPath() string { return filepath.Join(dataDir(), "launch-settings.json") }

func writeLaunchSettings(path string, s launchSettings) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return writeAtomic(path, b)
}

type taskUpdater func(bool, string) error

func updateLaunchSettings(path string, enabled bool, opts StartOptions, executable string, updateTask taskUpdater) error {
	if err := opts.validate(); err != nil {
		return err
	}
	old, err := readLaunchSettings(path)
	if err != nil {
		return err
	}
	next := launchSettings{AutoStart: enabled, Executable: executable, Options: opts}
	if err := updateTask(enabled, executable); err != nil {
		return err
	}
	if err := writeLaunchSettings(path, next); err != nil {
		if rollback := updateTask(old.AutoStart, old.Executable); rollback != nil {
			return fmt.Errorf("не удалось сохранить настройки: %v; восстановить задачу: %w", err, rollback)
		}
		return err
	}
	return nil
}

func (a *App) GetAutoStart() (bool, error) {
	a.settingsMu.Lock()
	defer a.settingsMu.Unlock()
	s, err := readLaunchSettings(launchSettingsPath())
	if err != nil || !s.AutoStart {
		return false, err
	}
	return startupTaskEnabled()
}

func (a *App) SetAutoStart(enabled bool, opts StartOptions) error {
	a.settingsMu.Lock()
	defer a.settingsMu.Unlock()
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	return updateLaunchSettings(launchSettingsPath(), enabled, opts, executable, setStartupTask)
}

func (a *App) rememberLaunchOptions(opts StartOptions) {
	a.settingsMu.Lock()
	defer a.settingsMu.Unlock()
	s, err := readLaunchSettings(launchSettingsPath())
	if err == nil && s.AutoStart {
		s.Options = opts
		if err := writeLaunchSettings(launchSettingsPath(), s); err != nil {
			b, _ := json.Marshal(map[string]string{"level": "WARN", "msg": "Параметры автозапуска не сохранены", "error": err.Error()})
			a.engine.consumeLogLine(string(b))
		}
	}
}

func startupTaskXML(executable, sid string) (string, error) {
	if !filepath.IsAbs(executable) || strings.ContainsAny(executable, "\x00\r\n") || sid == "" || strings.ContainsAny(sid, "\x00\r\n") {
		return "", errors.New("недопустимый путь или пользователь для автозапуска")
	}
	escape := func(s string) string {
		var b strings.Builder
		_ = xml.EscapeText(&b, []byte(s))
		return b.String()
	}
	return `<?xml version="1.0" encoding="UTF-8"?>
<Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>` + escape(sid) + `</UserId><Delay>PT5S</Delay></LogonTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>` + escape(sid) + `</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><StartWhenAvailable>true</StartWhenAvailable><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Enabled>true</Enabled></Settings>
  <Actions Context="Author"><Exec><Command>` + escape(executable) + `</Command><Arguments>--autostart</Arguments><WorkingDirectory>` + escape(filepath.Dir(executable)) + `</WorkingDirectory></Exec></Actions>
</Task>`, nil
}

func startupTaskFile(document string) []byte {
	document = strings.Replace(document, `encoding="UTF-8"`, `encoding="UTF-16"`, 1)
	units := utf16.Encode([]rune(document))
	b := make([]byte, 2+len(units)*2)
	b[0], b[1] = 0xff, 0xfe
	for i, unit := range units {
		b[2+i*2], b[3+i*2] = byte(unit), byte(unit>>8)
	}
	return b
}

func taskEnabledXML(b []byte) (bool, error) {
	if len(b) >= 2 && (b[1] == 0 || (b[0] == 0xff && b[1] == 0xfe) || (b[0] == 0xfe && b[1] == 0xff)) {
		bigEndian := b[0] == 0xfe && b[1] == 0xff
		start := 0
		if b[0] == 0xff || bigEndian {
			start = 2
		}
		if (len(b)-start)%2 != 0 {
			return false, errors.New("неполный XML задачи")
		}
		units := make([]uint16, 0, (len(b)-start)/2)
		for i := start; i+1 < len(b); i += 2 {
			v := uint16(b[i]) | uint16(b[i+1])<<8
			if bigEndian {
				v = uint16(b[i])<<8 | uint16(b[i+1])
			}
			units = append(units, v)
		}
		b = []byte(string(utf16.Decode(units)))
	}
	decoder := xml.NewDecoder(strings.NewReader(string(b)))
	decoder.CharsetReader = func(charset string, input io.Reader) (io.Reader, error) {
		if strings.HasPrefix(strings.ToUpper(charset), "UTF-16") {
			return input, nil
		}
		return nil, fmt.Errorf("неизвестная кодировка задачи: %s", charset)
	}
	var task struct {
		XMLName  xml.Name
		Settings struct {
			Enabled *bool `xml:"Enabled"`
		} `xml:"Settings"`
	}
	if err := decoder.Decode(&task); err != nil {
		return false, err
	}
	if task.XMLName.Local != "Task" {
		return false, errors.New("неожиданный формат задачи")
	}
	return task.Settings.Enabled == nil || *task.Settings.Enabled, nil
}

func (a *App) connectAtLogin(ctx context.Context) {
	a.settingsMu.Lock()
	s, err := readLaunchSettings(launchSettingsPath())
	a.settingsMu.Unlock()
	if err != nil {
		a.engine.consumeLogLine("Автозапуск: " + err.Error())
		return
	}
	if !s.AutoStart {
		return
	}
	// Opening Evasion at login should not close an already open Discord.
	s.Options.RestartDiscord = false
	for attempt := 0; attempt < 4; attempt++ {
		if ctx.Err() != nil {
			return
		}
		if err = a.startEngine(s.Options); err == nil && a.engine.waitReady() {
			return
		}
		if ctx.Err() != nil {
			return
		}
		_ = a.stopEngine()
		if attempt == 3 {
			break
		}
		timer := time.NewTimer(time.Duration(2<<attempt) * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
	a.engine.consumeLogLine("Автоподключение не удалось. Проверьте диагностику и нажмите кнопку подключения.")
}
