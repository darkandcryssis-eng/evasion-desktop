package main

import "strings"

// Сторонние средства обхода, которые держат свой перехват WinDivert на том же
// трафике. Два перехватчика применяют десинк друг поверх друга, и обход
// становится нестабильным, поэтому перед запуском движка они останавливаются.
var (
	conflictProcesses = []string{
		"winws.exe", "winws2.exe", "zapret.exe", // zapret
		"goodbyedpi.exe",
		"ciadpi.exe", "byedpi.exe", // byedpi
	}
	conflictServices = []string{"zapret", "zapret2", "winws", "winws1", "winws2", "goodbyedpi"}
)

// conflictReport — что сделала подготовка перед запуском движка.
type conflictReport struct {
	Stopped []string
	Failed  []string
}

func isConflictProcess(name string) bool {
	for _, known := range conflictProcesses {
		if strings.EqualFold(name, known) {
			return true
		}
	}
	return false
}

// isConflictService узнаёт службу по имени или по исполняемому файлу: сборки
// zapret регистрируют winws.exe под произвольными именами служб.
func isConflictService(name, imagePath string) bool {
	for _, known := range conflictServices {
		if strings.EqualFold(name, known) {
			return true
		}
	}
	return isConflictProcess(serviceBinary(imagePath))
}

// serviceBinary достаёт имя исполняемого файла из ImagePath службы
// (`"C:\dir with space\winws.exe" --args`, `C:\dir\winws.exe --args`).
func serviceBinary(imagePath string) string {
	path := servicePath(imagePath)
	if i := strings.LastIndexAny(path, `\/`); i >= 0 {
		path = path[i+1:]
	}
	return path
}

func servicePath(imagePath string) string {
	s := strings.TrimSpace(imagePath)
	if strings.HasPrefix(s, `"`) {
		if end := strings.Index(s[1:], `"`); end >= 0 {
			return strings.TrimPrefix(s[1:1+end], `\??\`)
		}
		return strings.TrimPrefix(s[1:], `\??\`)
	}
	s = strings.TrimPrefix(s, `\??\`)
	lower := strings.ToLower(s)
	for _, ext := range []string{".exe", ".sys"} {
		if i := strings.Index(lower, ext); i >= 0 {
			return s[:i+len(ext)]
		}
	}
	return s
}

// staleDriver сообщает, что остановленная запись службы WinDivert осталась от
// удалённой программы обхода: запуск отключён или файла драйвера уже нет. С
// такой записью WinDivertOpen пытается поднять старую службу и отказывает
// (коды 2, 1058), пока запись не удалить. Рабочую чужую запись не трогаем.
func staleDriver(imagePath string, disabled bool, systemRoot string, exists func(string) bool) bool {
	if disabled {
		return true
	}
	path := servicePath(imagePath)
	if path == "" {
		return false
	}
	lower := strings.ToLower(path)
	switch {
	case strings.HasPrefix(lower, `\systemroot\`):
		path = strings.TrimSuffix(systemRoot, `\`) + path[len(`\systemroot`):]
	case strings.HasPrefix(lower, `system32\`):
		path = strings.TrimSuffix(systemRoot, `\`) + `\` + path
	}
	return !exists(path)
}

func (r conflictReport) summary() string {
	var parts []string
	if len(r.Stopped) > 0 {
		parts = append(parts, "Остановлено перед запуском: "+strings.Join(r.Stopped, ", ")+".")
	}
	if len(r.Failed) > 0 {
		parts = append(parts, "Не удалось остановить: "+strings.Join(r.Failed, ", ")+" — закройте вручную, иначе обход будет нестабильным.")
	}
	return strings.Join(parts, " ")
}

func conflictItem(r conflictReport) (string, string, string, string) {
	const name = "Другие средства обхода"
	switch {
	case len(r.Failed) > 0:
		return name, "Мешают", "warning", r.summary()
	case len(r.Stopped) > 0:
		return name, "Остановлены", "success", r.summary()
	}
	return name, "Нет", "success", "zapret, GoodbyeDPI и byedpi останавливаются автоматически перед запуском."
}
