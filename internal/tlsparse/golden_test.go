package tlsparse

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Золотые эталоны ClientHello.
//
// Зачем они нужны отдельно от живой генерации через crypto/tls: тело
// фаззинг-цели выполняется в каждом рабочем процессе фаззера, и создание там
// сетевых соединений и рукопожатий останавливает фаззинг (замерено: со живыми
// затравками скорость падает до нуля, со статическими — 61 тыс. итераций в
// секунду). Затравки обязаны быть детерминированными и дешёвыми.
//
// Живая генерация остаётся в обычных тестах, где она быстра и безвредна, а
// TestGoldenMatchesLiveLibrary сверяет эталон с тем, что порождает библиотека
// прямо сейчас, — чтобы эталон не устарел незаметно.

// Имена файлов эталонов в testdata.
const (
	goldenWithSNIFile    = "clienthello_sni.hex"
	goldenWithoutSNIFile = "clienthello_nosni.hex"
	// goldenSNIName — имя сервера, записанное в эталоне с SNI.
	goldenSNIName = "www.example.com"
)

// goldenClientHello читает эталон из testdata и декодирует его из
// шестнадцатеричной записи.
//
// Эталоны хранятся текстом, а не двоичным файлом, намеренно: двоичный файл в
// обзоре изменений нечитаем, а шестнадцатеричная запись видна в диффе.
func goldenClientHello(t testing.TB, file string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", file))
	if err != nil {
		t.Fatalf("чтение эталона %s: %v", file, err)
	}
	// Пробелы и переводы строк в файле нужны для читаемости и значения не несут.
	clean := strings.Join(strings.Fields(string(raw)), "")
	data, err := hex.DecodeString(clean)
	if err != nil {
		t.Fatalf("разбор эталона %s: %v", file, err)
	}
	return data
}

func TestGoldenWithSNIParses(t *testing.T) {
	data := goldenClientHello(t, goldenWithSNIFile)

	ch, err := ParseClientHello(data)
	if err != nil {
		t.Fatalf("разбор эталона: %v", err)
	}
	sni, ok := ch.SNI(data)
	if !ok {
		t.Fatal("SNI не найден в эталоне")
	}
	if string(sni) != goldenSNIName {
		t.Fatalf("SNI = %q, ожидалось %q", sni, goldenSNIName)
	}
}

func TestGoldenWithoutSNIParses(t *testing.T) {
	data := goldenClientHello(t, goldenWithoutSNIFile)

	ch, err := ParseClientHello(data)
	if err != nil {
		t.Fatalf("разбор эталона: %v", err)
	}
	if ch.SNILen != 0 {
		t.Fatalf("в эталоне без SNI найдено имя длиной %d", ch.SNILen)
	}
	if ch.ExtensionsLen == 0 {
		t.Fatal("расширения должны присутствовать и без SNI")
	}
}

// TestGoldenMatchesLiveLibrary сверяет эталон с ClientHello, который
// стандартная библиотека порождает прямо сейчас.
//
// Побайтное сравнение невозможно: в сообщении есть случайные поля (random,
// ключевые доли). Сверяются структурные свойства, по которым работает движок:
// найденное имя, наличие расширений и то, что сообщение целиком умещается в
// одну запись. Если очередная версия Go начнёт формировать ClientHello так, что
// эталон перестанет быть представительным, тест это покажет.
func TestGoldenMatchesLiveLibrary(t *testing.T) {
	golden := goldenClientHello(t, goldenWithSNIFile)
	live := realClientHello(t, goldenSNIName)

	gch, err := ParseClientHello(golden)
	if err != nil {
		t.Fatalf("разбор эталона: %v", err)
	}
	lch, err := ParseClientHello(live)
	if err != nil {
		t.Fatalf("разбор живого сообщения: %v", err)
	}

	gsni, _ := gch.SNI(golden)
	lsni, _ := lch.SNI(live)
	if string(gsni) != string(lsni) {
		t.Fatalf("SNI эталона %q не совпадает с живым %q", gsni, lsni)
	}
	if gch.HasECH != lch.HasECH {
		t.Fatalf("признак ECH расходится: эталон %v, живое %v", gch.HasECH, lch.HasECH)
	}
	if (gch.ExtensionsLen == 0) != (lch.ExtensionsLen == 0) {
		t.Fatal("наличие расширений расходится между эталоном и живым сообщением")
	}
	if gch.Record.End() != len(golden) {
		t.Fatalf("эталон содержит %d байт при длине записи %d — он должен быть ровно одной записью",
			len(golden), gch.Record.End())
	}
}

// TestRegenerateGoldenVectors перезаписывает эталоны из текущей стандартной
// библиотеки. Обычным прогоном пропускается: эталон должен меняться осознанно,
// а не при каждом запуске тестов.
//
// Запуск:
//
//	EVASION_REGENERATE_GOLDEN=1 go test -run TestRegenerateGoldenVectors ./internal/tlsparse
func TestRegenerateGoldenVectors(t *testing.T) {
	if os.Getenv("EVASION_REGENERATE_GOLDEN") == "" {
		t.Skip("перезапись эталонов выключена; см. док-комментарий")
	}

	for file, name := range map[string]string{
		goldenWithSNIFile:    goldenSNIName,
		goldenWithoutSNIFile: "",
	} {
		data := realClientHello(t, name)

		// Разбиваем шестнадцатеричную запись на строки по 48 байт, чтобы файл
		// читался в обзоре изменений.
		h := hex.EncodeToString(data)
		var b strings.Builder
		for i := 0; i < len(h); i += 96 {
			end := min(i+96, len(h))
			b.WriteString(h[i:end])
			b.WriteByte('\n')
		}
		path := filepath.Join("testdata", file)
		if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
			t.Fatalf("запись %s: %v", path, err)
		}
		t.Logf("перезаписан %s (%d байт)", path, len(data))
	}
}
