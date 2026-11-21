package main

import (
	"regexp"
	"strconv"
	"strings"
)

type driverService struct {
	ID              string `json:"id"`
	State           string `json:"state"`
	Start           string `json:"start"`
	PendingDeletion bool   `json:"pendingDeletion"`
	Code            uint32 `json:"code"`
}
type driverDiagnostic struct {
	Status   string          `json:"status"`
	Summary  string          `json:"summary"`
	Advice   string          `json:"advice"`
	Code     uint32          `json:"code"`
	Services []driverService `json:"services"`
}

var driverCodePattern = regexp.MustCompile(`(?i)WinDivert[^\r\n]{0,30}код (\d+)`)

func driverCode(text string) uint32 {
	m := driverCodePattern.FindStringSubmatch(text)
	if len(m) != 2 {
		return 0
	}
	v, _ := strconv.ParseUint(m[1], 10, 32)
	return uint32(v)
}
func summarizeDriver(services []driverService, code uint32) driverDiagnostic {
	d := driverDiagnostic{Status: "unknown", Summary: "Драйвер ещё не проверен", Advice: "Включите обход, чтобы проверить загрузку драйвера.", Code: code, Services: services}
	if code != 0 {
		d.Status = "warn"
		d.Summary = "Драйвер не запустился · код " + strconv.FormatUint(uint64(code), 10)
		d.Advice = "Проверьте службы ниже и сообщение об ошибке запуска."
		if code == 1058 || code == 1072 {
			d.Advice = "Перезагрузите Windows, затем запустите только Evasion от имени администратора. Если ошибка повторится, сохраните отчёт для проверки состояния служб."
		}
		return d
	}
	for _, s := range services {
		if s.ID == "bfe" && (s.State == "stopped" || s.Start == "disabled") {
			d.Status = "warn"
			d.Summary = "Недоступна базовая фильтрация Windows (BFE)"
			d.Advice = "Для сетевого драйвера требуется работающая служба BFE. Проверьте состояние Windows и её служб."
			return d
		}
	}
	for _, s := range services {
		if s.ID != "windivert" {
			continue
		}
		switch {
		case s.State == "running":
			d.Status = "ok"
			d.Summary = "Драйвер загружен"
			d.Advice = "Windows сообщает, что WinDivert работает. Это не проверка доступа к сайтам."
			return d
		case s.PendingDeletion:
			d.Status = "warn"
			d.Summary = "Драйвер ожидает удаления"
			d.Advice = "Завершите программы обхода и перезагрузите Windows."
			d.Code = 1072
			return d
		case s.Start == "disabled":
			d.Status = "warn"
			d.Summary = "Запуск драйвера отключён"
			d.Advice = "Перезагрузите Windows и повторите запуск Evasion. Если состояние сохранится, отправьте отчёт для проверки причины отключения службы."
			d.Code = 1058
			return d
		case s.Code != 0:
			d.Status = "unknown"
			d.Summary = "Не удалось прочитать состояние драйвера"
			d.Advice = "Откройте Evasion от имени администратора и повторите диагностику."
			return d
		}
	}
	return d
}
func (a *App) driverDiagnostic() driverDiagnostic {
	var code uint32
	for _, manager := range []*engineManager{a.engine, a.games} {
		if manager != nil {
			s := manager.snapshot()
			if s.Phase == phaseFailed {
				if n := driverCode(s.Error); n != 0 {
					code = n
				}
			}
		}
	}
	return summarizeDriver(readDriverServices(), code)
}
func driverDiagnosticItem(d driverDiagnostic) DiagnosticItem {
	tone := "neutral"
	if d.Status == "ok" {
		tone = "success"
	} else if d.Status == "warn" {
		tone = "warning"
	}
	return DiagnosticItem{Name: "Служба сетевого драйвера", Status: d.Summary, Tone: tone, Detail: strings.TrimSpace(d.Advice)}
}
