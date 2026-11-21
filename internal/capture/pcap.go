package capture

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"github.com/fitting-1c/evasion/internal/core"
)

var _ PacketSource = (*PCAPSource)(nil)

// Разбираемые типы канального уровня (поле network глобального заголовка).
//
// Поддержаны ровно два: сырой IP и Ethernet. Остальные — явная ошибка, а не
// молчаливый пропуск: прочесть запись в неизвестной инкапсуляции и выдать её
// за пакет значило бы скормить движку мусор под видом трафика.
const (
	linkTypeEthernet = 1
	linkTypeRaw      = 101
)

// ethernetHeaderLen — длина заголовка Ethernet II (6+6+2), который снимается
// перед выдачей пакета: движок работает с IP-уровня (packet.Dissect ждёт
// IP-заголовок). VLAN-теги не обрабатываются — это ограничение названо в
// NewPCAPSource.
const ethernetHeaderLen = 14

// pcapGlobalHeaderLen, pcapRecordHeaderLen — длины заголовков классического
// формата pcap. Глобальный: magic(4) + version(4) + thiszone(4) + sigfigs(4) +
// snaplen(4) + network(4). Запись: ts_sec(4) + ts_usec(4) + incl_len(4) +
// orig_len(4).
const (
	pcapGlobalHeaderLen = 24
	pcapRecordHeaderLen = 16
)

// maxPacketBytes — верхний предел длины одной записи. Файл pcap — недоверенный
// ввод (10.2): без предела запись с громадным incl_len заставила бы прочитать
// произвольный объём в память. 262144 с запасом перекрывает джамбо-кадр.
const maxPacketBytes = 256 << 10

// PCAPSource читает пакеты из файла в классическом формате pcap (не pcapng).
//
// Нужен для офлайн-воспроизведения (2.5, команда replay): даёт прогнать логику
// формирования пакетов на записанном потоке, без сети и без Windows. Проверяет
// он корректность формируемой ПОСЛЕДОВАТЕЛЬНОСТИ, а не реакцию цензора — её из
// записи получить нельзя (2.5), и источник на это не претендует.
//
// Не потокобезопасен: читается последовательно, по одному источнику на горутину
// (как и живой).
type PCAPSource struct {
	r        io.Reader
	closer   io.Closer
	bo       binary.ByteOrder
	linkType uint32
	// dir — направление, которым помечается каждый пакет. Классический pcap
	// направление не несёт, а движку оно нужно (разрез ClientHello — outbound,
	// RST — inbound). Выбор назван в NewPCAPSource.
	dir core.Direction
}

// OpenPCAP открывает файл pcap. Закрывать обязан вызывающий через Close.
func OpenPCAP(path string) (*PCAPSource, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("capture: открытие pcap %s: %w", path, err)
	}
	s, err := NewPCAPSource(f)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	s.closer = f
	return s, nil
}

// NewPCAPSource читает глобальный заголовок из r и готовит источник.
//
// Направление всех пакетов — Outbound. Это сознательное ограничение первой
// версии: классический pcap направление не хранит, а основной случай
// воспроизведения — исходящая последовательность ClientHello. Воспроизведение
// входящих (RST) и разбор направления из pcapng — отдельный последующий шаг;
// признан явно, а не выдан за полноту.
func NewPCAPSource(r io.Reader) (*PCAPSource, error) {
	hdr := make([]byte, pcapGlobalHeaderLen)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, fmt.Errorf("capture: глобальный заголовок pcap: %w", err)
	}

	bo, err := pcapByteOrder(hdr[:4])
	if err != nil {
		return nil, err
	}

	linkType := bo.Uint32(hdr[20:24])
	if linkType != linkTypeEthernet && linkType != linkTypeRaw {
		return nil, fmt.Errorf("capture: тип канала pcap %d не поддержан (только %d raw и %d ethernet)",
			linkType, linkTypeRaw, linkTypeEthernet)
	}

	return &PCAPSource{r: r, bo: bo, linkType: linkType, dir: core.DirectionOutbound}, nil
}

// pcapByteOrder определяет порядок байт по магическому числу.
//
// Вынесено отдельной функцией нарочно: это самая непрозрачная часть разбора, и
// проверяться она обязана без файла. Варианты наносекундных меток времени
// (a1b23c4d) различаются только разрешением времени, которое источник не
// использует, поэтому от микросекундных отличается лишь порядком байт.
func pcapByteOrder(magic []byte) (binary.ByteOrder, error) {
	switch {
	case magic[0] == 0xa1 && magic[1] == 0xb2 && magic[2] == 0xc3 && magic[3] == 0xd4,
		magic[0] == 0xa1 && magic[1] == 0xb2 && magic[2] == 0x3c && magic[3] == 0x4d:
		return binary.BigEndian, nil
	case magic[0] == 0xd4 && magic[1] == 0xc3 && magic[2] == 0xb2 && magic[3] == 0xa1,
		magic[0] == 0x4d && magic[1] == 0x3c && magic[2] == 0xb2 && magic[3] == 0xa1:
		return binary.LittleEndian, nil
	default:
		return nil, fmt.Errorf("capture: не pcap: магическое число %x", magic)
	}
}

// Recv возвращает очередной пакет либо io.EOF по концу файла.
func (s *PCAPSource) Recv() (Packet, error) {
	rec := make([]byte, pcapRecordHeaderLen)
	// Конец файла ровно на границе записи — это штатное завершение. io.EOF
	// отдаётся как есть, чтобы потребитель остановился тем же способом, что и
	// на синтетическом источнике.
	if _, err := io.ReadFull(s.r, rec); err != nil {
		if err == io.EOF {
			return Packet{}, io.EOF
		}
		return Packet{}, fmt.Errorf("capture: заголовок записи pcap: %w", err)
	}

	inclLen := s.bo.Uint32(rec[8:12])
	if inclLen == 0 {
		return Packet{}, fmt.Errorf("capture: пустая запись pcap")
	}
	if inclLen > maxPacketBytes {
		return Packet{}, fmt.Errorf("capture: запись pcap %d байт превышает предел %d", inclLen, maxPacketBytes)
	}

	data := make([]byte, inclLen)
	if _, err := io.ReadFull(s.r, data); err != nil {
		// Здесь io.EOF — уже порча: заголовок обещал inclLen байт, а их нет.
		// Поэтому io.ErrUnexpectedEOF не превращаем обратно в io.EOF.
		return Packet{}, fmt.Errorf("capture: тело записи pcap (%d байт): %w", inclLen, err)
	}

	if s.linkType == linkTypeEthernet {
		if len(data) < ethernetHeaderLen {
			return Packet{}, fmt.Errorf("capture: кадр ethernet короче заголовка: %d байт", len(data))
		}
		data = data[ethernetHeaderLen:]
	}

	return Packet{Data: data, Dir: s.dir}, nil
}

// Close закрывает нижележащий файл, если источник открыт из файла.
func (s *PCAPSource) Close() error {
	if s.closer != nil {
		return s.closer.Close()
	}
	return nil
}
