// Пакет repohygiene содержит только тесты и проверяет свойства самого
// репозитория, а не кода.
//
// Зачем существует: часть требований к файлам нельзя выразить ни типами, ни
// обычными тестами, потому что это требования к байтам файлов. Нарушить их легко
// и незаметно — особенно при правке скриптов сторонними средствами, которые
// молча меняют кодировку.
//
// Каждая проверка здесь появилась после настоящей поломки, а не из
// предусмотрительности. Проверка кодировки скриптов PowerShell добавлена после
// того, как потеря метки BOM дважды сделала скрипт проверок неработоспособным.
package repohygiene

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

// utf8BOM — метка порядка байт UTF-8.
var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// repoRoot возвращает корень репозитория.
//
// Поднимаемся от каталога теста до каталога с go.mod, а не берём путь из
// переменной окружения: тест должен работать при любом способе запуска.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("определение текущего каталога: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod не найден: тест запущен вне репозитория")
		}
		dir = parent
	}
}

// collectFiles собирает файлы с указанным расширением по всему репозиторию,
// пропуская каталоги служебных данных.
func collectFiles(t *testing.T, ext string) []string {
	t.Helper()
	root := repoRoot(t)
	var out []string
	// node_modules и vendor — сторонние деревья (npm-шимы, вендоренные пакеты):
	// их байты не наши, и требования к кодировке наших скриптов на них не
	// распространяются. Без пропуска тест ловил бы чужие .ps1-шимы npm из
	// каталога UI (он собирается отдельно, 2.1).
	skip := map[string]bool{
		".git": true, "bin": true, "dist": true, "reports": true, "testdata": true,
		"node_modules": true, "vendor": true,
	}

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skip[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.EqualFold(filepath.Ext(path), ext) {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("обход репозитория: %v", err)
	}
	return out
}

// TestPowerShellScriptsHaveBOM требует метку BOM у скриптов PowerShell.
//
// Windows PowerShell 5.1 читает файл .ps1 без метки в системной кодировке
// (cp1251 на русской Windows), а не в UTF-8. Русский текст в комментариях и
// строках превращается в мусор, вместе с ним ломаются кавычки и тире, и скрипт
// перестаёт разбираться целиком — ошибка выглядит как десяток непонятных
// жалоб на синтаксис в случайных местах.
//
// Проверка нужна именно автоматическая: глазами потеря метки не видна, а
// сломается скрипт только на машине с не-UTF-8 системной кодировкой.
func TestPowerShellScriptsHaveBOM(t *testing.T) {
	files := collectFiles(t, ".ps1")
	if len(files) == 0 {
		t.Skip("скриптов PowerShell в репозитории нет")
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("чтение %s: %v", f, err)
		}
		if !bytes.HasPrefix(data, utf8BOM) {
			t.Errorf("%s: нет метки BOM. Windows PowerShell 5.1 прочитает русский текст "+
				"в системной кодировке, и скрипт не разберётся", f)
		}
	}
}

// TestPowerShellScriptsAreValidUTF8 требует корректной кодировки содержимого.
//
// Отдельно от метки: файл может начинаться с метки и всё равно содержать
// испорченные байты, если его правили средством, перекодировавшим часть текста.
func TestPowerShellScriptsAreValidUTF8(t *testing.T) {
	for _, f := range collectFiles(t, ".ps1") {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("чтение %s: %v", f, err)
		}
		if !utf8.Valid(bytes.TrimPrefix(data, utf8BOM)) {
			t.Errorf("%s: содержимое не является корректным UTF-8", f)
		}
	}
}

// TestJSONFilesHaveNoBOM требует отсутствия метки BOM у файлов JSON.
//
// Требование прямо противоположно предыдущему, и в этом всё дело: строгий
// разбор JSON в Go на метке падает, поэтому конфиги обязаны быть без неё.
// Два противоположных правила в одном репозитории путают, и держать их в голове
// не нужно — пусть держит тест.
func TestJSONFilesHaveNoBOM(t *testing.T) {
	files := collectFiles(t, ".json")
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("чтение %s: %v", f, err)
		}
		if bytes.HasPrefix(data, utf8BOM) {
			t.Errorf("%s: есть метка BOM, строгий разбор JSON на ней падает", f)
		}
	}
}
