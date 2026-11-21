package packet

import "encoding/binary"

// Раскладка заголовка TCP (RFC 9293):
//
//	0–1    порт источника
//	2–3    порт назначения
//	4–7    номер последовательности
//	8–11   номер подтверждения
//	12     смещение данных в 32-битных словах (4 бита) | резерв (4 бита)
//	13     флаги
//	14–15  окно
//	16–17  контрольная сумма
//	18–19  указатель срочности
//	далее  опции, до границы смещения данных
const (
	tcpSrcPortOff    = 0
	tcpDstPortOff    = 2
	tcpSeqOff        = 4
	tcpAckOff        = 8
	tcpDataOffsetOff = 12
	tcpFlagsOff      = 13
	tcpWindowOff     = 14
	tcpChecksumOff   = 16
	tcpUrgentOff     = 18
	tcpMinHeaderLen  = 20
	tcpMaxHeaderLen  = 60 // смещение данных задаётся 4 битами в словах: 15 * 4
)

// Флаги TCP в порядке битов байта 13.
const (
	FlagFIN uint8 = 1 << 0
	FlagSYN uint8 = 1 << 1
	FlagRST uint8 = 1 << 2
	FlagPSH uint8 = 1 << 3
	FlagACK uint8 = 1 << 4
	FlagURG uint8 = 1 << 5
	FlagECE uint8 = 1 << 6
	FlagCWR uint8 = 1 << 7
)

// Виды опций TCP, которые умеет читать и править этот пакет.
const (
	TCPOptEnd       uint8 = 0  // конец списка опций
	TCPOptNop       uint8 = 1  // заполнитель
	TCPOptMSS       uint8 = 2  // максимальный размер сегмента, 2 байта значения
	TCPOptWindowScl uint8 = 3  // масштаб окна, 1 байт значения
	TCPOptMD5       uint8 = 19 // MD5 Signature (RFC 2385), 16 байт значения
)

// TCPHeader — представление заголовка TCP поверх чужого буфера.
type TCPHeader []byte

// ParseTCPHeader строит представление заголовка TCP, проверив границы и
// объявленное смещение данных.
func ParseTCPHeader(buf []byte) (TCPHeader, error) {
	if len(buf) < tcpMinHeaderLen {
		return nil, ErrShortBuffer
	}
	// Смещение данных объявлено в 32-битных словах — отсюда умножение на 4.
	hdrLen := int(buf[tcpDataOffsetOff]>>4) * 4
	if hdrLen < tcpMinHeaderLen || hdrLen > tcpMaxHeaderLen {
		return nil, ErrBadHeaderLen
	}
	if len(buf) < hdrLen {
		return nil, ErrShortBuffer
	}
	return TCPHeader(buf[:hdrLen]), nil
}

// HeaderLen возвращает длину заголовка в байтах, включая опции.
func (h TCPHeader) HeaderLen() int { return len(h) }

// SetDataOffset записывает смещение данных — длину заголовка TCP в байтах
// (обязана быть кратной 4) — в старшие 4 бита байта 12, сохраняя младшие
// (резерв). Нужен при вставке опций: область опций растёт, и смещение данных
// обязано это отразить, иначе сервер прочтёт опции как начало нагрузки.
func (h TCPHeader) SetDataOffset(headerLenBytes int) {
	words := headerLenBytes / 4
	h[tcpDataOffsetOff] = (h[tcpDataOffsetOff] & 0x0f) | byte(words<<4)
}

// SrcPort возвращает порт источника.
func (h TCPHeader) SrcPort() uint16 { return binary.BigEndian.Uint16(h[tcpSrcPortOff:]) }

// SetSrcPort записывает порт источника. Длина заголовка не меняется, поэтому
// пересобирать пакет не нужно — только пересчитать контрольную сумму TCP
// (порт входит в её покрытие).
func (h TCPHeader) SetSrcPort(v uint16) { binary.BigEndian.PutUint16(h[tcpSrcPortOff:], v) }

// DstPort возвращает порт назначения.
func (h TCPHeader) DstPort() uint16 { return binary.BigEndian.Uint16(h[tcpDstPortOff:]) }

// SetDstPort записывает порт назначения. См. оговорку у SetSrcPort о сумме.
func (h TCPHeader) SetDstPort(v uint16) { binary.BigEndian.PutUint16(h[tcpDstPortOff:], v) }

// Seq возвращает номер последовательности.
func (h TCPHeader) Seq() uint32 { return binary.BigEndian.Uint32(h[tcpSeqOff:]) }

// SetSeq записывает номер последовательности.
//
// Арифметика номеров циклическая по модулю 2^32, поэтому вызывающий код обязан
// считать смещения в uint32 и не полагаться на отсутствие переполнения: сложение
// в uint32 оборачивается именно так, как требует протокол.
func (h TCPHeader) SetSeq(v uint32) { binary.BigEndian.PutUint32(h[tcpSeqOff:], v) }

// Ack возвращает номер подтверждения.
func (h TCPHeader) Ack() uint32 { return binary.BigEndian.Uint32(h[tcpAckOff:]) }

// SetAck записывает номер подтверждения.
func (h TCPHeader) SetAck(v uint32) { binary.BigEndian.PutUint32(h[tcpAckOff:], v) }

// Flags возвращает байт флагов.
func (h TCPHeader) Flags() uint8 { return h[tcpFlagsOff] }

// SetFlags записывает байт флагов целиком.
func (h TCPHeader) SetFlags(v uint8) { h[tcpFlagsOff] = v }

// Window возвращает размер окна.
func (h TCPHeader) Window() uint16 { return binary.BigEndian.Uint16(h[tcpWindowOff:]) }

// SetWindow записывает размер окна.
func (h TCPHeader) SetWindow(v uint16) { binary.BigEndian.PutUint16(h[tcpWindowOff:], v) }

// Checksum возвращает записанную контрольную сумму.
func (h TCPHeader) Checksum() uint16 { return binary.BigEndian.Uint16(h[tcpChecksumOff:]) }

// SetChecksum записывает контрольную сумму как есть, без пересчёта: примитив
// порчи суммы обязан уметь записать заведомо неверное значение.
func (h TCPHeader) SetChecksum(v uint16) {
	binary.BigEndian.PutUint16(h[tcpChecksumOff:], v)
}

// Urgent возвращает указатель срочности.
func (h TCPHeader) Urgent() uint16 { return binary.BigEndian.Uint16(h[tcpUrgentOff:]) }

// SetUrgent записывает указатель срочности.
func (h TCPHeader) SetUrgent(v uint16) { binary.BigEndian.PutUint16(h[tcpUrgentOff:], v) }

// options возвращает срез байт области опций (между фиксированной частью
// заголовка и его концом).
func (h TCPHeader) options() []byte {
	if len(h) <= tcpMinHeaderLen {
		return nil
	}
	return h[tcpMinHeaderLen:]
}

// TCPOption — одна опция заголовка TCP. Value указывает в исходный буфер, то
// есть опцию можно править на месте, не меняя длину.
type TCPOption struct {
	// Kind — вид опции.
	Kind uint8
	// Value — байты значения опции без вида и без байта длины. У опций без
	// значения (конец списка, заполнитель) пуст.
	Value []byte
}

// Options перебирает опции заголовка в порядке следования.
//
// Перебор ленивый и не выделяет памяти: это итератор-функция, а не срез.
// Разбор останавливается на опции «конец списка». Некорректная длина опции
// прерывает перебор — вместо ошибки, потому что итератор не может её вернуть;
// такие заголовки отбраковывает ValidateOptions.
func (h TCPHeader) Options() func(yield func(TCPOption) bool) {
	return func(yield func(TCPOption) bool) {
		opts := h.options()
		for i := 0; i < len(opts); {
			kind := opts[i]
			switch kind {
			case TCPOptEnd:
				return
			case TCPOptNop:
				if !yield(TCPOption{Kind: kind}) {
					return
				}
				i++
				continue
			}
			// Остальные опции имеют формат «вид, длина, значение», где длина
			// включает оба служебных байта. Потому минимум — 2.
			if i+1 >= len(opts) {
				return
			}
			optLen := int(opts[i+1])
			if optLen < 2 || i+optLen > len(opts) {
				return
			}
			if !yield(TCPOption{Kind: kind, Value: opts[i+2 : i+optLen]}) {
				return
			}
			i += optLen
		}
	}
}

// ValidateOptions проверяет, что область опций корректна целиком: все объявленные
// длины умещаются в заголовок.
//
// Нужна отдельно от Options потому, что итератор при встрече битой опции просто
// прекращает перебор, а разбору пакета важно отличить «опций больше нет» от
// «заголовок некорректен».
func (h TCPHeader) ValidateOptions() error {
	opts := h.options()
	for i := 0; i < len(opts); {
		switch opts[i] {
		case TCPOptEnd:
			return nil
		case TCPOptNop:
			i++
			continue
		}
		if i+1 >= len(opts) {
			return ErrBadOption
		}
		optLen := int(opts[i+1])
		if optLen < 2 || i+optLen > len(opts) {
			return ErrBadOption
		}
		i += optLen
	}
	return nil
}

// MSS возвращает значение опции максимального размера сегмента.
func (h TCPHeader) MSS() (uint16, error) {
	var value uint16
	err := ErrOptionNotFound
	for opt := range h.Options() {
		if opt.Kind != TCPOptMSS {
			continue
		}
		if len(opt.Value) != 2 {
			return 0, ErrOptionSize
		}
		value = binary.BigEndian.Uint16(opt.Value)
		err = nil
		break
	}
	return value, err
}

// SetMSS записывает значение опции максимального размера сегмента на месте.
//
// Длина опции не меняется, поэтому заголовок не нужно перестраивать. Если опции
// нет — возвращается ошибка: добавление опции сдвинуло бы данные и потребовало
// пересчёта смещения, что относится к сборке пакета, а не к правке поля.
func (h TCPHeader) SetMSS(v uint16) error {
	for opt := range h.Options() {
		if opt.Kind != TCPOptMSS {
			continue
		}
		if len(opt.Value) != 2 {
			return ErrOptionSize
		}
		binary.BigEndian.PutUint16(opt.Value, v)
		return nil
	}
	return ErrOptionNotFound
}

// WindowScale возвращает значение опции масштаба окна.
func (h TCPHeader) WindowScale() (uint8, error) {
	var value uint8
	err := ErrOptionNotFound
	for opt := range h.Options() {
		if opt.Kind != TCPOptWindowScl {
			continue
		}
		if len(opt.Value) != 1 {
			return 0, ErrOptionSize
		}
		value = opt.Value[0]
		err = nil
		break
	}
	return value, err
}

// SetWindowScale записывает значение опции масштаба окна на месте.
func (h TCPHeader) SetWindowScale(v uint8) error {
	for opt := range h.Options() {
		if opt.Kind != TCPOptWindowScl {
			continue
		}
		if len(opt.Value) != 1 {
			return ErrOptionSize
		}
		opt.Value[0] = v
		return nil
	}
	return ErrOptionNotFound
}
