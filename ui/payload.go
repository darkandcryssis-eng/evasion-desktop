package main

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// payloadFS — файлы, которые оболочка несёт внутри себя: собранный движок,
// WinDivert и эталонный конфиг. Каталог payload/ наполняет скрипт сборки
// (build-and-run.bat); в репозитории лежит только README.md, поэтому шаблон
// embed совпадает всегда и `go build` проходит и без движка — тогда оболочка
// честно сообщает, что движок не встроен.
//
//go:embed all:payload
var payloadFS embed.FS

const (
	payloadXray        = "xray.exe"
	payloadXrayLicense = "Xray-LICENSE.txt"
	payloadEngine      = "evasion.exe"
	payloadConfig      = "config.json"
	payloadDivertDLL   = "WinDivert.dll"
	payloadDivertSys   = "WinDivert64.sys"
	payloadDivertLic   = "WinDivert-LICENSE.txt"

	// runtimeDirName — подкаталог рядом с Evasion.exe, куда распаковывается
	// пакет. WinDivert.dll обязана лежать рядом с evasion.exe: движок грузит
	// её через LazyDLL, поиск начинается с каталога бинарника.
	runtimeDirName = "runtime"
)

// payloadFile читает файл встроенного пакета; ok=false, если файла нет.
func payloadFile(name string) ([]byte, bool) {
	b, err := fs.ReadFile(payloadFS, "payload/"+name)
	if err != nil {
		return nil, false
	}
	return b, true
}

// payloadInfo — что именно встроено в эту сборку.
type payloadInfo struct {
	Engine    bool `json:"engine"`
	Config    bool `json:"config"`
	WinDivert bool `json:"windivert"`
}

func embeddedPayload() payloadInfo {
	has := func(n string) bool { _, ok := payloadFile(n); return ok }
	return payloadInfo{
		Engine:    has(payloadEngine),
		Config:    has(payloadConfig),
		WinDivert: has(payloadDivertDLL) && has(payloadDivertSys),
	}
}

// layout — пути, с которыми работает оболочка.
//
// Base — выделенная папка данных в профиле пользователя (dataDir():
// %LOCALAPPDATA%\Evasion на Windows). Она же рабочий каталог движка: движок в
// режиме intercept держит state\ (rtctrack.json, engine.lock, events.jsonl)
// относительно рабочего каталога. Фиксированная папка (а не каталог рядом с
// Evasion.exe) даёт детерминированное место для lock и памяти голоса: откуда бы
// exe ни запустили, движок видит ту же папку — повторный запуск находит свой
// lock и не плодит конфликты за WinDivert.
type layout struct {
	Base    string
	Runtime string
	Engine  string
	// Config — конфиг, с которым стартует движок: config.json рядом с
	// Evasion.exe, если пользователь его положил, иначе встроенный эталон.
	Config     string
	UserConfig bool
	State      string
}

func resolveLayout() (layout, error) {
	base := dataDir()
	if err := os.MkdirAll(base, 0o755); err != nil {
		return layout{}, fmt.Errorf("не удалось создать папку данных %s: %w", base, err)
	}
	rt := filepath.Join(base, runtimeDirName)
	l := layout{
		Base:    base,
		Runtime: rt,
		Engine:  filepath.Join(rt, payloadEngine),
		Config:  filepath.Join(rt, payloadConfig),
		State:   filepath.Join(base, "state"),
	}
	if st, err := os.Stat(filepath.Join(base, payloadConfig)); err == nil && !st.IsDir() {
		l.Config = filepath.Join(base, payloadConfig)
		l.UserConfig = true
	}
	return l, nil
}

// errNoEngine — сборка без встроенного движка (собрана голым `wails build`).
var errNoEngine = errors.New("движок не встроен в эту сборку: соберите Evasion.exe через ui\\build-and-run.bat")

// extractPayload раскладывает встроенный пакет в runtime\.
//
// Политика по файлам:
//   - evasion.exe и config.json перезаписываются, если отличаются: после
//     обновления Evasion.exe движок и эталонный конфиг должны быть его версии;
//   - WinDivert.dll/.sys пишутся только если их нет. Так файлы можно заменить
//     своей сборкой (LGPLv3 требует заменяемости), а занятый загруженным
//     драйвером .sys не мешает запуску.
func extractPayload(l layout) error {
	engine, ok := payloadFile(payloadEngine)
	if !ok {
		return errNoEngine
	}
	if err := os.MkdirAll(l.Runtime, 0o755); err != nil {
		return fmt.Errorf("не удалось создать %s: %w", l.Runtime, err)
	}
	if err := writeIfChanged(l.Engine, engine); err != nil {
		return fmt.Errorf("не удалось обновить %s (не запущен ли движок отдельно?): %w", l.Engine, err)
	}
	if cfg, ok := payloadFile(payloadConfig); ok {
		if err := writeIfChanged(filepath.Join(l.Runtime, payloadConfig), cfg); err != nil {
			return err
		}
	}
	for _, name := range []string{payloadXray, payloadXrayLicense} {
		if data, ok := payloadFile(name); ok {
			if err := writeIfChanged(filepath.Join(l.Runtime, name), data); err != nil {
				return err
			}
		}
	}
	for _, name := range []string{payloadDivertDLL, payloadDivertSys, payloadDivertLic} {
		data, ok := payloadFile(name)
		if !ok {
			continue
		}
		if err := writeIfMissing(filepath.Join(l.Runtime, name), data); err != nil {
			return err
		}
	}
	for _, name := range []string{payloadDivertDLL, payloadDivertSys} {
		if _, err := os.Stat(filepath.Join(l.Runtime, name)); err != nil {
			return fmt.Errorf("нет %s в %s: сборка без WinDivert, положите файл вручную", name, l.Runtime)
		}
	}
	return nil
}

func writeIfChanged(path string, data []byte) error {
	if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, data) {
		return nil
	}
	return writeAtomic(path, data)
}

func writeIfMissing(path string, data []byte) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	return writeAtomic(path, data)
}

func writeAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o755); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
