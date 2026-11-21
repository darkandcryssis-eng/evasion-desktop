package packetexec

import (
	"context"
	"errors"
	"fmt"

	"github.com/fitting-1c/evasion/internal/capture"
	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/desync"
	"github.com/fitting-1c/evasion/internal/executor"
	"github.com/fitting-1c/evasion/internal/packet"
	"github.com/fitting-1c/evasion/internal/strategy"
)

// ErrFrameUnsupported — запрошена IP-фрагментация, которой packetexec пока не
// умеет (появится отдельным куском). В норме сюда не доходит: стратегию с
// FragIP отвергает шлюз возможностей (CapFragmentIP не объявлена). Это защитная
// сетка — молчать о непосильном нельзя (4.7 п. 2).
var ErrFrameUnsupported = errors.New("packetexec: IP-фрагментация ещё не реализована")

// Conn реализует executor.Conn поверх приёмника пакетов.
//
// Строит исходящие пакеты из шаблона — перехваченного ClientHello — и
// отправляет их в sink. Отвечает только за ClientHello: освобождение потока и
// пропуск остального — дело flow (4.2).
type Conn struct {
	in       desync.Input
	sink     capture.PacketSink
	tmpl     []byte
	d        packet.Dissection
	baseSeq  uint32
	reinject any
	dir      core.Direction
	// sent — был ли отправлен хоть один пакет. Нужен вызывающему для
	// безопасного отката после ошибки: если ещё ничего не ушло, оригинальный
	// ClientHello можно пропустить как есть и соединение уцелеет; если ушло —
	// поток уже необратимо начат. Тот же смысл, что socketexec.Wrote.
	sent         bool
	segmentLimit int
	tailAligned  bool
}

// SetSegmentTailAligned makes the last piece of a split payload full-sized
// (the remainder goes first) instead of the first one.
func (c *Conn) SetSegmentTailAligned(on bool) { c.tailAligned = on }

// SetSegmentLimit bounds payloads when replaying a reassembled ClientHello.
// Zero preserves the original emission behavior.
func (c *Conn) SetSegmentLimit(limit int) { c.segmentLimit = limit }

// NewConnAt — как NewConn, но с явно заданным базовым номером последовательности
// baseSeq вместо взятого из шаблона.
//
// Нужен для сборки многосегментного ClientHello: когда десинкуется не первый
// сегмент потока, нагрузка начинается не с того байта, чей seq лежит в шаблоне.
// Смещения операций (op.StreamOffset) по-прежнему отсчитываются от начала
// нагрузки, а baseSeq задаёт её положение в потоке. Шаблон при этом годится
// любой из того же соединения (заголовки, адреса, реинъекция у них общие).
func NewConnAt(sink capture.PacketSink, in desync.Input, tmpl capture.Packet, baseSeq uint32) (*Conn, error) {
	c, err := NewConn(sink, in, tmpl)
	if err != nil {
		return nil, err
	}
	c.baseSeq = baseSeq
	return c, nil
}

// NewConn создаёт соединение исполнителя из события и пакета-шаблона.
//
// in описывает исходящий ClientHello (нагрузку, направление, точки разреза);
// tmpl — перехваченный пакет, из которого берутся заголовки, адреса и базовый
// номер последовательности. Разбор TLS выполняет вызывающий, как в socketexec:
// packetexec от tlsparse не зависит.
func NewConn(sink capture.PacketSink, in desync.Input, tmpl capture.Packet) (*Conn, error) {
	d, err := packet.Dissect(tmpl.Data)
	if err != nil {
		return nil, fmt.Errorf("packetexec: разбор шаблона: %w", err)
	}
	if d.Truncated {
		// Из усечённого шаблона строить нельзя: суммы считаются по всей длине,
		// а байт в буфере нет.
		return nil, errors.New("packetexec: шаблон усечён — строить из него нельзя")
	}
	tcp, ok := d.TCP(tmpl.Data)
	if !ok {
		return nil, errors.New("packetexec: шаблон не является пакетом TCP")
	}

	// Копируем буфер шаблона: по контракту capture.Packet.Data действителен
	// только до следующего Recv, а Conn живёт дольше.
	cp := append([]byte(nil), tmpl.Data...)
	reinject := tmpl.Reinject
	if address, ok := reinject.(interface{ WithFinalTCPChecksums() any }); ok {
		reinject = address.WithFinalTCPChecksums()
	}

	return &Conn{
		in:       in,
		sink:     sink,
		tmpl:     cp,
		d:        d,
		baseSeq:  tcp.Seq(),
		reinject: reinject,
		dir:      tmpl.Dir,
	}, nil
}

// Input возвращает событие, по которому строится план.
func (c *Conn) Input() desync.Input { return c.in }

// SendReal собирает и отправляет сегмент с куском реальной нагрузки.
//
// Номер последовательности — базовый плюс смещение операции в потоке
// (op.StreamOffset), а не накопленное по порядку отправки: при дублировании и
// обратном порядке порядок отправки не равен положению куска.
func (c *Conn) SendReal(ctx context.Context, op desync.Op) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if op.Frame != desync.FrameSegment {
		return ErrFrameUnsupported
	}
	return c.emit(op.Payload, op.StreamOffset, nil, false, false)
}

// SendFake собирает и отправляет фейковый пакет: как сегмент, но с правками
// полей заголовка, которые и делают его фейком (низкий TTL, порча суммы, иной
// номер последовательности).
func (c *Conn) SendFake(ctx context.Context, op desync.Op) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if op.Frame != desync.FrameSegment {
		return ErrFrameUnsupported
	}
	return c.emit(op.Payload, op.StreamOffset, op.Edits, op.InsertMD5Sig, op.InsertIPv6HopByHop)
}

// bogusMD5Digest — заведомо неверная подпись для приёма md5sig. Приём намеренно
// шлёт невалидную MD5: сервер отбросит сегмент (RFC 2385), DPI обычно подпись
// не проверяет. Значение фиксировано, не случайно: детерминизм обязателен
// золотым тестам и воспроизведению записи — тот же довод, что у synthFakePayload.
var bogusMD5Digest = [16]byte{
	0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
	0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
}

// emit собирает пакет, применяет правки и отправляет его.
//
// Порядок правок принципиален: правки полей заголовка — ДО пересчёта сумм,
// чтобы сумма их покрыла; правка самой суммы — ПОСЛЕ пересчёта, иначе
// намеренно неверное значение было бы затёрто корректным. Это ровно оговорка
// из packet/access.go, вынесенная в порядок вызовов.
func (c *Conn) emit(payload []byte, streamOffset int, edits []strategy.TamperParams, insertMD5, insertIPv6Ext bool) error {
	if c.segmentLimit <= 0 || len(payload) <= c.segmentLimit {
		return c.emitSegment(payload, streamOffset, edits, insertMD5, insertIPv6Ext)
	}
	first := c.segmentLimit
	if rem := len(payload) % c.segmentLimit; c.tailAligned && rem != 0 {
		first = rem
	}
	for start := 0; start < len(payload); {
		end := min(start+c.segmentLimit, len(payload))
		if start == 0 {
			end = first
		}
		if err := c.emitSegment(payload[start:end], streamOffset+start, edits, insertMD5, insertIPv6Ext); err != nil {
			return err
		}
		start = end
	}
	return nil
}

func (c *Conn) emitSegment(payload []byte, streamOffset int, edits []strategy.TamperParams, insertMD5, insertIPv6Ext bool) error {
	seq := c.baseSeq + uint32(streamOffset)
	out, d, err := assemble(c.tmpl, c.d, payload, seq)
	if err != nil {
		return err
	}

	// Вставки, расширяющие заголовок, — ДО правок полей и пересчёта сумм:
	// они двигают нагрузку и смещения, поэтому должны попасть в пакет раньше,
	// чем сумма его покроет. Каждая пересобирает буфер и разбор, дальше правки
	// идут уже по новой раскладке.
	if insertMD5 {
		out, d, err = d.InsertTCPOption(out, packet.MD5SignatureOption(bogusMD5Digest))
		if err != nil {
			return fmt.Errorf("packetexec: вставка MD5-опции: %w", err)
		}
	}
	if insertIPv6Ext {
		out, d, err = d.InsertIPv6HopByHop(out)
		if err != nil {
			return fmt.Errorf("packetexec: вставка Hop-by-Hop: %w", err)
		}
	}

	for i := range edits {
		if isChecksumField(edits[i].Field) {
			continue
		}
		if err := applyEdit(d, out, edits[i]); err != nil {
			return err
		}
	}

	if !d.RecomputeChecksums(out) {
		return fmt.Errorf("packetexec: пересчёт сумм собранного пакета не удался")
	}

	for i := range edits {
		if !isChecksumField(edits[i].Field) {
			continue
		}
		if err := applyEdit(d, out, edits[i]); err != nil {
			return err
		}
	}

	if err := c.sink.Send(capture.Packet{Data: out, Dir: c.dir, Reinject: c.reinject}); err != nil {
		return err
	}
	// Признак ставится после удачной отправки: отказ сборки или правки до
	// отправки поток не начинает, и такой случай остаётся безопасным для
	// отката.
	c.sent = true
	return nil
}

// Sent сообщает, ушёл ли хоть один пакет. По нему вызывающий решает, допустим
// ли откат к прозрачному пропуску оригинала после ошибки исполнения.
func (c *Conn) Sent() bool { return c.sent }

// статическая проверка соответствия интерфейсу.
var _ executor.Conn = (*Conn)(nil)
