package hosts

import (
	"bytes"
	"strings"
	"testing"
)

// TestParseRenderRoundtrip: Parse → Render возвращает содержимое без потери
// строк, только нормализует перевод строк в CRLF. Это свойство нужно, чтобы
// Apply/Remove не меняли ничего, кроме целевого блока.
func TestParseRenderRoundtrip(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "LF normalized to CRLF",
			in:   "# comment\n127.0.0.1 localhost\n",
			want: "# comment\r\n127.0.0.1 localhost\r\n",
		},
		{
			name: "CRLF preserved",
			in:   "# comment\r\n127.0.0.1 localhost\r\n",
			want: "# comment\r\n127.0.0.1 localhost\r\n",
		},
		{
			name: "no trailing newline preserved",
			in:   "# only line",
			want: "# only line",
		},
		{
			name: "empty file",
			in:   "",
			want: "",
		},
		{
			name: "cyrillic comment",
			in:   "# Привет\n1.2.3.4 example.com\n",
			want: "# Привет\r\n1.2.3.4 example.com\r\n",
		},
		{
			name: "BOM stripped",
			in:   "\xEF\xBB\xBF# with BOM\n",
			want: "# with BOM\r\n",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := Parse([]byte(c.in))
			got := string(h.Render())
			if got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}
}

// TestApplyAddsBlock: на пустом hosts (или на hosts без нашего блока) Apply
// добавляет блок с нужными маркерами, Render содержит все записи.
func TestApplyAddsBlock(t *testing.T) {
	h := Parse([]byte("# existing\n127.0.0.1 localhost\n"))
	changed, err := h.Apply(ManagedBlock{
		ID:      "cloudflare-fallback",
		Comment: []string{"test comment"},
		Entries: []Entry{
			{IP: "1.2.3.4", Host: "example.com"},
			{IP: "5.6.7.8", Host: "another.com"},
		},
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !changed {
		t.Fatal("добавление блока должно считаться изменением")
	}
	out := string(h.Render())
	for _, want := range []string{
		"# existing",
		"127.0.0.1 localhost",
		"# >>> evasion:cloudflare-fallback begin >>>",
		"# test comment",
		"1.2.3.4 example.com",
		"5.6.7.8 another.com",
		"# <<< evasion:cloudflare-fallback end <<<",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("ожидалось %q в выводе, не найдено:\n%s", want, out)
		}
	}
}

// TestApplyIdempotent: повторный Apply с тем же содержимым возвращает
// changed=false — это и есть смысл идемпотентности, по которому вызывающий
// решает не перезаписывать файл.
func TestApplyIdempotent(t *testing.T) {
	block := ManagedBlock{
		ID:      "test",
		Entries: []Entry{{IP: "1.2.3.4", Host: "example.com"}},
	}
	h := Parse(nil)
	if _, err := h.Apply(block); err != nil {
		t.Fatal(err)
	}
	changed, err := h.Apply(block)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("повторный Apply с тем же блоком не должен считаться изменением")
	}
}

// TestApplyReplacesExistingBlock: Apply с теми же маркерами, но другим
// содержимым заменяет блок, не трогая остальное.
func TestApplyReplacesExistingBlock(t *testing.T) {
	h := Parse([]byte("# header\r\n"))
	_, err := h.Apply(ManagedBlock{
		ID:      "test",
		Entries: []Entry{{IP: "1.2.3.4", Host: "old.com"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	changed, err := h.Apply(ManagedBlock{
		ID:      "test",
		Entries: []Entry{{IP: "5.6.7.8", Host: "new.com"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("замена содержимого — это изменение")
	}
	out := string(h.Render())
	if !strings.Contains(out, "# header") {
		t.Fatal("исходный header потерян при замене блока")
	}
	if strings.Contains(out, "old.com") {
		t.Fatal("старое содержимое блока должно быть вычищено")
	}
	if !strings.Contains(out, "5.6.7.8 new.com") {
		t.Fatal("новое содержимое блока не записано")
	}
}

// TestRemoveBlock: удаление блока оставляет остальное содержимое.
func TestRemoveBlock(t *testing.T) {
	h := Parse([]byte("# header\n"))
	_, err := h.Apply(ManagedBlock{
		ID:      "test",
		Entries: []Entry{{IP: "1.2.3.4", Host: "example.com"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	removed := h.Remove("test")
	if !removed {
		t.Fatal("Remove должен сообщить об удалении существующего блока")
	}
	out := string(h.Render())
	if strings.Contains(out, "evasion:test") {
		t.Fatalf("маркеры блока не удалены: %s", out)
	}
	if !strings.Contains(out, "# header") {
		t.Fatal("остальное содержимое потеряно при удалении")
	}
}

// TestRemoveMissingBlockNoop: Remove несуществующего блока — false, без
// изменений. Нужно для скриптов запуска: вызывать Remove безопасно.
func TestRemoveMissingBlockNoop(t *testing.T) {
	in := "# existing\n127.0.0.1 localhost\n"
	h := Parse([]byte(in))
	if removed := h.Remove("nonexistent"); removed {
		t.Fatal("Remove несуществующего блока должен вернуть false")
	}
	// Содержимое не поменялось, только CRLF-нормализация.
	want := "# existing\r\n127.0.0.1 localhost\r\n"
	if got := string(h.Render()); got != want {
		t.Fatalf("Remove-NOP изменил hosts: %q", got)
	}
}

// TestHasBlock: наличие обоих маркеров подтверждает блок, одного — нет.
func TestHasBlock(t *testing.T) {
	h := Parse(nil)
	if h.HasBlock("test") {
		t.Fatal("пустой hosts не может иметь блока")
	}
	_, err := h.Apply(ManagedBlock{
		ID:      "test",
		Entries: []Entry{{IP: "1.2.3.4", Host: "example.com"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !h.HasBlock("test") {
		t.Fatal("после Apply блок должен присутствовать")
	}
	// Полусиротский (без закрывающего) не считаем блоком.
	h2 := Parse([]byte("# >>> evasion:orphan begin >>>\n1.2.3.4 x\n"))
	if h2.HasBlock("orphan") {
		t.Fatal("без закрывающего маркера блок не существует")
	}
}

// TestZapretBlockNotTouched: блок с другим префиксом (`zapretgui`) не считается
// нашим и не трогается. Это граница с внешним инструментом.
func TestZapretBlockNotTouched(t *testing.T) {
	in := "# >>> zapretgui:hosts managed begin >>>\n" +
		"104.25.158.178 finland14021.discord.media\n" +
		"# <<< zapretgui:hosts managed end <<<\n"
	h := Parse([]byte(in))
	// Удаление нашего ID не должно затронуть Zapret-блок.
	h.Remove("hosts managed")
	out := h.Render()
	if !bytes.Contains(out, []byte("zapretgui:hosts managed begin")) {
		t.Fatal("Zapret-блок не наш; трогать нельзя")
	}
	if !bytes.Contains(out, []byte("104.25.158.178 finland14021.discord.media")) {
		t.Fatal("содержимое Zapret-блока не должно удаляться")
	}
}

// TestValidateBlock: нулевой блок и битые записи отвергаются; валидный
// проходит. Валидация — единственное место, где нельзя пропустить дефект,
// иначе он уедет в hosts.
func TestValidateBlock(t *testing.T) {
	cases := []struct {
		name    string
		block   ManagedBlock
		wantErr bool
	}{
		{
			name:  "valid simple",
			block: ManagedBlock{ID: "test", Entries: []Entry{{IP: "1.2.3.4", Host: "example.com"}}},
		},
		{
			name:    "empty ID",
			block:   ManagedBlock{Entries: []Entry{{IP: "1.2.3.4", Host: "example.com"}}},
			wantErr: true,
		},
		{
			name:    "ID with space",
			block:   ManagedBlock{ID: "has space", Entries: []Entry{{IP: "1.2.3.4", Host: "example.com"}}},
			wantErr: true,
		},
		{
			name:    "ID with > breaks marker",
			block:   ManagedBlock{ID: "evil>", Entries: []Entry{{IP: "1.2.3.4", Host: "example.com"}}},
			wantErr: true,
		},
		{
			name:    "empty entries",
			block:   ManagedBlock{ID: "test"},
			wantErr: true,
		},
		{
			name:    "empty IP",
			block:   ManagedBlock{ID: "test", Entries: []Entry{{Host: "example.com"}}},
			wantErr: true,
		},
		{
			name:    "space in IP",
			block:   ManagedBlock{ID: "test", Entries: []Entry{{IP: "1.2.3.4 bad", Host: "example.com"}}},
			wantErr: true,
		},
		{
			name:    "empty host",
			block:   ManagedBlock{ID: "test", Entries: []Entry{{IP: "1.2.3.4"}}},
			wantErr: true,
		},
		{
			name:    "newline in comment",
			block:   ManagedBlock{ID: "test", Comment: []string{"line1\nline2"}, Entries: []Entry{{IP: "1.2.3.4", Host: "example.com"}}},
			wantErr: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.block.Validate()
			if c.wantErr && err == nil {
				t.Fatal("ожидалась ошибка валидации")
			}
			if !c.wantErr && err != nil {
				t.Fatalf("валидация провалилась: %v", err)
			}
		})
	}
}

// TestParseKeepsRealWorldHosts: реалистичный hosts (с BOM, CRLF, кирилликой,
// пустыми строками) не теряется при Parse+Apply+Remove+Render. Это главный
// инвариант пакета: мы вмешиваемся только в наш блок.
func TestParseKeepsRealWorldHosts(t *testing.T) {
	original := "\xEF\xBB\xBF# Copyright (c) 1993-2009 Microsoft Corp.\r\n" +
		"\r\n" +
		"# localhost name resolution is handled within DNS itself.\r\n" +
		"#\t127.0.0.1       localhost\r\n" +
		"#\t::1             localhost\r\n" +
		"\r\n" +
		"# Телеграм\r\n" +
		"149.154.167.220 t.me\r\n"

	h := Parse([]byte(original))
	// Применяем, затем удаляем — должен получиться эквивалент оригинала
	// (вплоть до BOM и, возможно, одной лишней пустой строки на стыке).
	_, err := h.Apply(ManagedBlock{
		ID:      "test-roundtrip",
		Entries: []Entry{{IP: "1.2.3.4", Host: "x.com"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	h.Remove("test-roundtrip")

	// Все исходные содержательные строки должны присутствовать (BOM и
	// количество пустых строк на стыке могут отличаться — на них гарантий нет,
	// и это осознано: hosts не формат, в котором пустые строки значимы).
	out := string(h.Render())
	for _, want := range []string{
		"# Copyright (c) 1993-2009 Microsoft Corp.",
		"# localhost name resolution is handled within DNS itself.",
		"#\t127.0.0.1       localhost",
		"# Телеграм",
		"149.154.167.220 t.me",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("после Apply+Remove потеряна строка %q", want)
		}
	}
}
