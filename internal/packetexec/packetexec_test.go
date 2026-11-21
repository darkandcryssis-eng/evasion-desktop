package packetexec

import (
	"context"
	"encoding/binary"
	"net"
	"testing"

	"github.com/fitting-1c/evasion/internal/capture"
	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/desync"
	"github.com/fitting-1c/evasion/internal/packet"
	"github.com/fitting-1c/evasion/internal/strategy"
)

const baseSeq = uint32(1000)

// tlsPayload — похожая на ClientHello нагрузка (тип 0x16), длиной 20 байт.
var tlsPayload = []byte{
	0x16, 0x03, 0x01, 0x00, 0x0f,
	0x01, 0x00, 0x00, 0x0b, 0x03, 0x03, 0xaa, 0xbb, 0xcc, 0xdd,
	0xee, 0xff, 0x00, 0x11, 0x22,
}

// --- помощники построения дерева стратегии ---

func send() *strategy.Action { return &strategy.Action{Kind: core.ActionSend} }

func dup(l, r *strategy.Action) *strategy.Action {
	return &strategy.Action{Kind: core.ActionDuplicate, Left: l, Right: r}
}

func tamper(p strategy.TamperParams, child *strategy.Action) *strategy.Action {
	return &strategy.Action{Kind: core.ActionTamper, Params: &p, Left: child}
}

func frag(p strategy.FragmentParams, l, r *strategy.Action) *strategy.Action {
	return &strategy.Action{Kind: core.ActionFragment, Params: &p, Left: l, Right: r}
}

func helloRule(a *strategy.Action) *strategy.Strategy {
	return &strategy.Strategy{Rules: []strategy.Rule{{
		Direction: core.DirectionOutbound,
		Trigger:   strategy.Trigger{Match: strategy.MatchClientHello},
		Action:    a,
	}}}
}

// clientHelloPacketV4 собирает валидный пакет IPv4/TCP с TTL 64 и заданной
// нагрузкой. Суммы пересчитывает пакет packet.
func clientHelloPacketV4(t *testing.T, payload []byte, seq uint32) []byte {
	t.Helper()
	const ipLen, tcpLen = 20, 20
	buf := make([]byte, ipLen+tcpLen+len(payload))

	buf[0] = 0x45
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(buf)))
	buf[8] = 64 // TTL
	buf[9] = 6  // TCP
	copy(buf[12:16], net.ParseIP("10.0.0.1").To4())
	copy(buf[16:20], net.ParseIP("93.184.216.34").To4())

	binary.BigEndian.PutUint16(buf[20:22], 50000)
	binary.BigEndian.PutUint16(buf[22:24], 443)
	binary.BigEndian.PutUint32(buf[24:28], seq)
	buf[32] = 0x50 // смещение данных 5 слов (20 байт)
	buf[33] = 0x18 // PSH|ACK
	binary.BigEndian.PutUint16(buf[34:36], 65535)
	copy(buf[40:], payload)

	d, err := packet.Dissect(buf)
	if err != nil {
		t.Fatalf("разбор тестового пакета: %v", err)
	}
	if !d.RecomputeChecksums(buf) {
		t.Fatalf("пересчёт сумм тестового пакета не удался")
	}
	return buf
}

func newConn(t *testing.T, sink capture.PacketSink, reinject any) *Conn {
	t.Helper()
	pkt := clientHelloPacketV4(t, tlsPayload, baseSeq)
	in := desync.Input{Direction: core.DirectionOutbound, Payload: tlsPayload, Ordinal: 1, IsClientHello: true}
	conn, err := NewConn(sink, in, capture.Packet{Data: pkt, Dir: core.DirectionOutbound, Reinject: reinject})
	if err != nil {
		t.Fatalf("NewConn: %v", err)
	}
	return conn
}

// dissect разбирает собранный пакет для проверок.
func dissect(t *testing.T, p capture.Packet) (packet.Dissection, packet.TCPHeader, packet.IPv4Header) {
	t.Helper()
	d, err := packet.Dissect(p.Data)
	if err != nil {
		t.Fatalf("разбор сегмента: %v", err)
	}
	th, ok := d.TCP(p.Data)
	if !ok {
		t.Fatalf("сегмент не TCP")
	}
	ih, _ := d.IPv4(p.Data)
	return d, th, ih
}

// TestExecuteFragmentsAtPacketLevel — разрез TCP даёт два сегмента с верными
// нагрузками, seq и суммами; склейка равна исходной, реинъекция донесена.
func TestExecuteFragmentsAtPacketLevel(t *testing.T) {
	const cut = 5
	sink := &capture.SyntheticSink{}
	sentinel := struct{ id int }{id: 42}
	conn := newConn(t, sink, sentinel)

	s := helloRule(frag(strategy.FragmentParams{Proto: strategy.FragTCP, Offset: cut, Order: strategy.FragForward}, send(), send()))
	if err := New().Execute(context.Background(), s, conn); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	sent := sink.Sent()
	if len(sent) != 2 {
		t.Fatalf("ожидалось 2 сегмента, получено %d", len(sent))
	}

	d0, th0, _ := dissect(t, sent[0])
	if th0.Seq() != baseSeq || !d0.VerifyChecksums(sent[0].Data) {
		t.Errorf("сегмент 0: seq=%d, суммы верны=%v", th0.Seq(), d0.VerifyChecksums(sent[0].Data))
	}
	pl0, _ := d0.Payload(sent[0].Data)
	if string(pl0) != string(tlsPayload[:cut]) {
		t.Errorf("сегмент 0: нагрузка %x", pl0)
	}
	d1, th1, _ := dissect(t, sent[1])
	if th1.Seq() != baseSeq+cut || !d1.VerifyChecksums(sent[1].Data) {
		t.Errorf("сегмент 1: seq=%d, суммы верны=%v", th1.Seq(), d1.VerifyChecksums(sent[1].Data))
	}
	pl1, _ := d1.Payload(sent[1].Data)
	if string(pl1) != string(tlsPayload[cut:]) {
		t.Errorf("сегмент 1: нагрузка %x", pl1)
	}
	if got, ok := sent[0].Reinject.(struct{ id int }); !ok || got.id != 42 {
		t.Errorf("данные реинъекции потеряны: %+v", sent[0].Reinject)
	}
}

// TestFakeThenRealSamePosition — классический фейк: дубль, одной копии правим
// TTL (она фейк), вторая реальна. Обе на позиции 0, значит обе с seq = base —
// это и проверяет исправление номера по положению, а не по порядку отправки.
func TestFakeThenRealSamePosition(t *testing.T) {
	sink := &capture.SyntheticSink{}
	conn := newConn(t, sink, nil)

	s := helloRule(dup(
		tamper(strategy.TamperParams{Field: strategy.FieldIPv4TTL, Mode: strategy.TamperReplace, Value: 3}, send()),
		send(),
	))
	if err := New().Execute(context.Background(), s, conn); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	sent := sink.Sent()
	if len(sent) != 2 {
		t.Fatalf("ожидалось 2 пакета, получено %d", len(sent))
	}

	// Порядок: сначала левая ветвь (фейк), затем правая (реальные данные).
	d0, th0, ih0 := dissect(t, sent[0])
	if ih0.TTL() != 3 {
		t.Errorf("фейк: ожидался TTL 3, получено %d", ih0.TTL())
	}
	if th0.Seq() != baseSeq {
		t.Errorf("фейк: ожидался seq %d (позиция 0), получено %d", baseSeq, th0.Seq())
	}
	if !d0.VerifyChecksums(sent[0].Data) {
		t.Errorf("фейк с правкой TTL должен иметь верную сумму (порча не запрашивалась)")
	}

	_, th1, ih1 := dissect(t, sent[1])
	if ih1.TTL() != 64 {
		t.Errorf("реальный пакет: TTL шаблона 64 изменён на %d", ih1.TTL())
	}
	if th1.Seq() != baseSeq {
		t.Errorf("реальный пакет: ожидался seq %d (та же позиция 0), получено %d", baseSeq, th1.Seq())
	}
}

// TestChecksumCorruptFake — порча суммы даёт фейк с ЗАВЕДОМО неверной суммой
// TCP, тогда как реальная копия корректна.
func TestChecksumCorruptFake(t *testing.T) {
	sink := &capture.SyntheticSink{}
	conn := newConn(t, sink, nil)

	s := helloRule(dup(
		tamper(strategy.TamperParams{Field: strategy.FieldTCPChecksum, Mode: strategy.TamperCorrupt}, send()),
		send(),
	))
	if err := New().Execute(context.Background(), s, conn); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	sent := sink.Sent()
	d0, _, _ := dissect(t, sent[0])
	if d0.VerifyChecksums(sent[0].Data) {
		t.Errorf("фейк с порчей суммы не должен проходить проверку сумм")
	}
	d1, _, _ := dissect(t, sent[1])
	if !d1.VerifyChecksums(sent[1].Data) {
		t.Errorf("реальная копия должна иметь верные суммы")
	}
}

// TestReverseOrderSeqByPosition — обратный порядок: сегменты уходят в обратном
// порядке, но seq каждого — по его положению в потоке, а не по порядку отправки.
func TestReverseOrderSeqByPosition(t *testing.T) {
	const cut = 5
	sink := &capture.SyntheticSink{}
	conn := newConn(t, sink, nil)

	s := helloRule(frag(strategy.FragmentParams{Proto: strategy.FragTCP, Offset: cut, Order: strategy.FragReverse}, send(), send()))
	if err := New().Execute(context.Background(), s, conn); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	sent := sink.Sent()
	if len(sent) != 2 {
		t.Fatalf("ожидалось 2 сегмента, получено %d", len(sent))
	}
	// Первым ушёл правый кусок (позиция cut), вторым левый (позиция 0).
	_, th0, _ := dissect(t, sent[0])
	if th0.Seq() != baseSeq+cut {
		t.Errorf("первый отправленный (правый): ожидался seq %d, получено %d", baseSeq+cut, th0.Seq())
	}
	_, th1, _ := dissect(t, sent[1])
	if th1.Seq() != baseSeq {
		t.Errorf("второй отправленный (левый): ожидался seq %d, получено %d", baseSeq, th1.Seq())
	}
}

// TestMSSTamperWithoutOptionErrors — правка опции MSS на сегменте без опций
// отвергается явной ошибкой, а не исполняется наугад (4.7 п. 2).
func TestMSSTamperWithoutOptionErrors(t *testing.T) {
	sink := &capture.SyntheticSink{}
	conn := newConn(t, sink, nil)

	s := helloRule(tamper(strategy.TamperParams{Field: strategy.FieldTCPMSS, Mode: strategy.TamperReplace, Value: 1400}, send()))
	if err := New().Execute(context.Background(), s, conn); err == nil {
		t.Fatalf("ожидалась ошибка: опции MSS на сегменте ClientHello нет")
	}
}

// TestNewConnRejectsNonTCP — шаблон не-TCP отвергается явной ошибкой.
func TestNewConnRejectsNonTCP(t *testing.T) {
	buf := make([]byte, 20+8)
	buf[0] = 0x45
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(buf)))
	buf[8] = 64
	buf[9] = 17 // UDP
	copy(buf[12:16], net.ParseIP("10.0.0.1").To4())
	copy(buf[16:20], net.ParseIP("93.184.216.34").To4())
	binary.BigEndian.PutUint16(buf[20:22], 50000)
	binary.BigEndian.PutUint16(buf[22:24], 443)
	binary.BigEndian.PutUint16(buf[24:26], 8)

	if _, err := NewConn(&capture.SyntheticSink{}, desync.Input{}, capture.Packet{Data: buf}); err == nil {
		t.Fatalf("ожидалась ошибка на шаблоне не-TCP")
	}
}

// TestIPFragmentUnsupported — IP-фрагментация пока отвергается явно.
func TestIPFragmentUnsupported(t *testing.T) {
	conn := newConn(t, &capture.SyntheticSink{}, nil)
	err := conn.SendReal(context.Background(), desync.Op{Kind: desync.OpSendReal, Payload: tlsPayload, Frame: desync.FrameIPFragment})
	if err == nil {
		t.Fatalf("IP-фрагментация должна отвергаться")
	}
}

// TestCapabilities — объявлен набор этапа 1 без IP-фрагментации.
func TestCapabilities(t *testing.T) {
	caps := Capabilities()
	for _, want := range []core.Capability{
		core.CapFragmentTCP, core.CapDelay, core.CapTamper,
		core.CapTamperChecksumCorrupt, core.CapDuplicate, core.CapDrop, core.CapReorder,
	} {
		if !caps.Has(want) {
			t.Errorf("ожидалась возможность %s", want)
		}
	}
	if caps.Has(core.CapFragmentIP) {
		t.Errorf("IP-фрагментация пока не должна объявляться")
	}
}

func md5sig(child *strategy.Action) *strategy.Action {
	return &strategy.Action{Kind: core.ActionMD5Sig, Left: child}
}

// TestExecuteMD5SigInsertsOption — приём md5sig: исполнитель шлёт один фейковый
// сегмент, в котором заголовок TCP расширен опцией MD5 Signature (вид 19,
// 16 байт), смещение данных и длина IPv4 обновлены, нагрузка цела, суммы верны.
func TestExecuteMD5SigInsertsOption(t *testing.T) {
	sink := &capture.SyntheticSink{}
	conn := newConn(t, sink, nil)

	s := helloRule(md5sig(send()))
	if err := New().Execute(context.Background(), s, conn); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	sent := sink.Sent()
	if len(sent) != 1 {
		t.Fatalf("ожидался 1 пакет, получено %d", len(sent))
	}
	d, th, ih := dissect(t, sent[0])

	// Заголовок TCP вырос с 20 до 40 байт (опция 18 + 2 NOP выравнивания).
	if th.HeaderLen() != 40 {
		t.Errorf("длина заголовка TCP %d, ожидалось 40", th.HeaderLen())
	}
	if int(ih.TotalLen()) != len(sent[0].Data) {
		t.Errorf("total len %d, ожидалось %d", ih.TotalLen(), len(sent[0].Data))
	}

	var found bool
	for o := range th.Options() {
		if o.Kind == packet.TCPOptMD5 {
			found = true
			if len(o.Value) != 16 {
				t.Errorf("значение MD5 %d байт, ожидалось 16", len(o.Value))
			}
		}
	}
	if !found {
		t.Error("опция MD5 не найдена в отправленном фейке")
	}

	// Нагрузка не искажена, seq соответствует базовому, суммы сходятся.
	pay, _ := d.Payload(sent[0].Data)
	if string(pay) != string(tlsPayload) {
		t.Errorf("нагрузка искажена: %x", pay)
	}
	if th.Seq() != baseSeq {
		t.Errorf("seq=%d, ожидался %d", th.Seq(), baseSeq)
	}
	if !d.VerifyChecksums(sent[0].Data) {
		t.Error("контрольные суммы фейка неверны")
	}
}

func ipv6ext(child *strategy.Action) *strategy.Action {
	return &strategy.Action{Kind: core.ActionIPv6Ext, Left: child}
}

// TestExecuteIPv6ExtUnavailableOnIPv4 — ipv6_ext на IPv4-шаблоне неисполним:
// исполнитель обязан вернуть ошибку и НЕ отправить ничего (движок затем
// пропустит оригинал сырьём). Это тот же класс «поле/приём недоступны в этом
// пакете», что у правки IPv6-поля на IPv4.
func TestExecuteIPv6ExtUnavailableOnIPv4(t *testing.T) {
	sink := &capture.SyntheticSink{}
	conn := newConn(t, sink, nil) // шаблон IPv4

	s := helloRule(ipv6ext(send()))
	if err := New().Execute(context.Background(), s, conn); err == nil {
		t.Fatal("ожидалась ошибка: ipv6_ext на IPv4-пакете")
	}
	if conn.Sent() {
		t.Error("на неисполнимом приёме ничего отправлять нельзя")
	}
	if len(sink.Sent()) != 0 {
		t.Errorf("отправлено %d пакетов, ожидалось 0", len(sink.Sent()))
	}
}
