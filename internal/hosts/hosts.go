package hosts

import (
	"bytes"
	"fmt"
	"strings"
)

// Hosts — разобранное содержимое hosts-файла.
//
// Хранится как плоский список строк, потому что hosts — построчный формат, и
// любое более умное представление (map доменов, парсинг IP) потеряло бы
// комментарии и порядок, которые владелец машины может иметь важными. Задача
// пакета — вставить и удалить именованный блок, не трогая прочее.
type Hosts struct {
	// lines хранится без терминаторов строк: мы читаем файл в byte-срез,
	// разделяем по '\n' c обрезанием '\r', собираем обратно с CRLF. Так проще
	// работать с индексами и не терять строки на границе.
	lines []string
	// Исходный разделитель последней строки — чтобы Render вернул файл без
	// лишнего \n, если его не было (мелочь, но hosts-файл редко оканчивается
	// переводом строки, и нам незачем добавлять).
	trailingNewline bool
}

// Parse разбирает содержимое hosts-файла. Переводы строк универсальные: LF и
// CRLF одинаково приемлемы на входе.
//
// BOM на входе игнорируется, если встретится: Windows PowerShell 5.1 без него
// читает hosts в cp1251, но системный DNS-ресолвер читает hosts байтово — так
// что BOM в начале просто портит первое имя. Мы его срезаем молча и на выходе
// не возвращаем: удаление BOM — не правка смысла, а привидение файла к той
// форме, которой ждёт сам Windows.
func Parse(data []byte) *Hosts {
	// Срезаем UTF-8 BOM: по RFC 3629 он не относится к данным.
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		data = data[3:]
	}
	trailing := len(data) > 0 && data[len(data)-1] == '\n'
	// Разбиваем, не теряя пустых строк в середине файла.
	raw := bytes.Split(data, []byte{'\n'})
	// Последний «кусок» после финального \n пуст — не учитываем его, иначе
	// каждый Render добавлял бы ещё одну пустую строку.
	if trailing && len(raw) > 0 && len(raw[len(raw)-1]) == 0 {
		raw = raw[:len(raw)-1]
	}
	lines := make([]string, len(raw))
	for i, l := range raw {
		// Срезаем '\r' на конце строки, если файл был в CRLF.
		if n := len(l); n > 0 && l[n-1] == '\r' {
			l = l[:n-1]
		}
		lines[i] = string(l)
	}
	return &Hosts{lines: lines, trailingNewline: trailing}
}

// Render собирает hosts-файл обратно в байты. Переводы строк — CRLF: это
// родной для Windows формат, и наши скрипты (`.gitattributes` + repohygiene) на
// него уже настроены. Трейлинг-перевод строки восстанавливается, если был на
// входе — чтобы наша правка не добавляла и не теряла его.
func (h *Hosts) Render() []byte {
	var buf bytes.Buffer
	for i, l := range h.lines {
		buf.WriteString(l)
		// Между строками — всегда CRLF. После последней — только если на входе
		// был trailing newline, или если файл изменился и мы хотим корректное
		// завершение (в hosts это безопаснее — часть DNS-ресолверов тихо
		// игнорируют последнюю строку без \n).
		if i < len(h.lines)-1 || h.trailingNewline {
			buf.WriteString("\r\n")
		}
	}
	return buf.Bytes()
}

// ManagedBlock — именованный блок, которым владеет движок.
type ManagedBlock struct {
	// ID — короткий токен, различающий блоки. Разрешены ASCII-буквы, цифры,
	// '-' и '_'. Валидация строгая — ID попадает прямо в текст маркера.
	ID string
	// Comment — одна или несколько строк комментариев, пишутся сразу после
	// открывающего маркера, перед собственно записями. Пустой — не пишется.
	Comment []string
	// Entries — записи вида «IP имя» (без комментария). Пустые имена и адреса
	// отвергаются валидацией — пустой блок не нужен, пустая запись опасна.
	Entries []Entry
}

// Entry — одна запись hosts: IP и имя.
type Entry struct {
	IP   string
	Host string
}

// validateID — ID должен быть короткий, ASCII, без пробелов и спецсимволов,
// которые ломают маркер (например, '>'). Иначе маркер можно было бы случайно
// слепить так, что он совпадёт с чужой строкой.
func validateID(id string) error {
	if id == "" {
		return fmt.Errorf("hosts: пустой ID управляемого блока")
	}
	if len(id) > 32 {
		return fmt.Errorf("hosts: ID управляемого блока длиннее 32 символов: %q", id)
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_' || r == ':':
		default:
			return fmt.Errorf("hosts: ID управляемого блока содержит недопустимый символ %q: %q", r, id)
		}
	}
	return nil
}

// Validate проверяет блок на согласованность: ID, непустые записи, допустимые
// IP (строго v4 или v6; валидация тут простая — проверка на не-пустоту и
// отсутствие пробелов). Жёсткая проверка форматов IP оставлена вызывающему
// (конфиг или команда), чтобы пакет не тащил net/netip ради этого.
func (b ManagedBlock) Validate() error {
	if err := validateID(b.ID); err != nil {
		return err
	}
	if len(b.Entries) == 0 {
		return fmt.Errorf("hosts: блок %q без записей", b.ID)
	}
	for i, e := range b.Entries {
		if e.IP == "" || strings.ContainsAny(e.IP, " \t") {
			return fmt.Errorf("hosts: блок %q запись %d: негодный IP %q", b.ID, i, e.IP)
		}
		if e.Host == "" || strings.ContainsAny(e.Host, " \t") {
			return fmt.Errorf("hosts: блок %q запись %d: негодный host %q", b.ID, i, e.Host)
		}
	}
	for _, c := range b.Comment {
		if strings.ContainsAny(c, "\r\n") {
			return fmt.Errorf("hosts: блок %q: комментарий содержит перевод строки", b.ID)
		}
	}
	return nil
}

// beginMarker возвращает открывающий маркер для блока с ID.
func beginMarker(id string) string { return "# >>> evasion:" + id + " begin >>>" }

// endMarker возвращает закрывающий маркер.
func endMarker(id string) string { return "# <<< evasion:" + id + " end <<<" }

// findBlock возвращает [start, end] — индексы строк открывающего и закрывающего
// маркеров блока с id. Если блока нет, возвращает -1, -1. Строки до/после
// блока вызывающий получает срезами h.lines.
func (h *Hosts) findBlock(id string) (start, end int) {
	begin := beginMarker(id)
	end2 := endMarker(id)
	start, end = -1, -1
	for i, line := range h.lines {
		if start == -1 && line == begin {
			start = i
			continue
		}
		if start != -1 && line == end2 {
			end = i
			return start, end
		}
	}
	// Открывающий найден, закрывающий нет — считаем, что блока нет: писать
	// поверх половинного было бы агрессивно. Вызывающий увидит, что HasBlock
	// == false, Apply добавит блок рядом; старая половина останется мусором,
	// это осознанная цена против затирания неизвестного содержимого.
	if start != -1 && end == -1 {
		return -1, -1
	}
	return start, end
}

// HasBlock сообщает, есть ли в hosts целый блок с id (оба маркера на месте).
func (h *Hosts) HasBlock(id string) bool {
	s, _ := h.findBlock(id)
	return s >= 0
}

// Apply вставляет или заменяет блок. Идемпотентен: Apply одного и того же
// блока дважды не меняет содержимое.
//
// Возвращает признак, что hosts изменился, — вызывающему удобно решить, нужна
// ли запись в файл. Запись нужна тогда, когда что-то поменялось: лишние
// переписывания файла — лишние шансы на гонку с системным DNS-резолвером.
//
// Ошибка возникает только при негодном блоке (валидация). Файловая система тут
// не затрагивается.
func (h *Hosts) Apply(block ManagedBlock) (changed bool, err error) {
	if err := block.Validate(); err != nil {
		return false, err
	}
	newLines := renderBlock(block)

	start, end := h.findBlock(block.ID)
	if start == -1 {
		// Нет блока — добавляем в конец. Перед блоком пустая строка, если
		// файл не оканчивается ею: отделение от предыдущего содержимого.
		var insert []string
		if len(h.lines) > 0 && h.lines[len(h.lines)-1] != "" {
			insert = append(insert, "")
		}
		insert = append(insert, newLines...)
		h.lines = append(h.lines, insert...)
		return true, nil
	}

	// Блок есть. Проверим идемпотентность: если содержимое совпадает, ничего
	// не делаем. Это упрощает скрипты запуска: Apply всегда безопасно.
	existing := h.lines[start : end+1]
	if equalStrings(existing, newLines) {
		return false, nil
	}

	// Заменяем диапазон start..end на newLines.
	h.lines = append(h.lines[:start], append(newLines, h.lines[end+1:]...)...)
	return true, nil
}

// Remove удаляет блок с id. Возвращает признак, что удалил.
//
// Если перед блоком была пустая строка-разделитель, добавленная при Apply, она
// остаётся. Это оставляет файл чуть «пустее», но не более того, и не ломает
// чужое содержимое — другие записи своё разделение держат сами.
func (h *Hosts) Remove(id string) bool {
	start, end := h.findBlock(id)
	if start == -1 {
		return false
	}
	h.lines = append(h.lines[:start], h.lines[end+1:]...)
	return true
}

// renderBlock собирает строки блока: открывающий маркер, комментарии, записи,
// закрывающий маркер. Отдельно от Apply, чтобы можно было проверить
// идемпотентность сравнением строк.
func renderBlock(b ManagedBlock) []string {
	out := make([]string, 0, 2+len(b.Comment)+len(b.Entries))
	out = append(out, beginMarker(b.ID))
	for _, c := range b.Comment {
		out = append(out, "# "+c)
	}
	for _, e := range b.Entries {
		out = append(out, e.IP+" "+e.Host)
	}
	out = append(out, endMarker(b.ID))
	return out
}

// equalStrings — покусковое сравнение срезов строк. Отдельно от bytes/strings,
// потому что компараторов срезов строк в stdlib нет (slices.Equal — да, но
// он не поддерживается в старой Go; у нас Go 1.27, можно было бы, но
// независимость от стандартной библиотеки за три строки стоит того).
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
