package intercept

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/fitting-1c/evasion/internal/capture"
	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/executor"
	"github.com/fitting-1c/evasion/internal/flow"
	"github.com/fitting-1c/evasion/internal/packet"
	"github.com/fitting-1c/evasion/internal/packetexec"
	"github.com/fitting-1c/evasion/internal/proxy"
	"github.com/fitting-1c/evasion/internal/strategy"
	"github.com/fitting-1c/evasion/internal/tlsparse"
)

const baseSeq = uint32(1000)

// helloPayload — нагрузка, которую тестовый детектор считает ClientHello.
var helloPayload = []byte{
	0x16, 0x03, 0x01, 0x00, 0x0f,
	0x01, 0x00, 0x00, 0x0b, 0x03, 0x03, 0xaa, 0xbb, 0xcc, 0xdd,
	0xee, 0xff, 0x00, 0x11, 0x22,
}

// testDetector распознаёт ClientHello по первому байту 0x16 — без tlsparse,
// чтобы проверять логику цикла, а не разбор TLS.
func testDetector(payload []byte) ([]byte, bool, bool) {
	if len(payload) > 0 && payload[0] == 0x16 {
		return payload, true, true
	}
	return nil, false, false
}

// fixedParser возвращает заданное имя сервера без разбора.
func fixedParser(sni string) HelloParser {
	return func([]byte) (string, []core.CutPoint, bool) { return sni, nil, true }
}

type fakeProvider struct {
	matchSNI string
	sel      proxy.Selection
}

type failureRecordingProvider struct {
	proxy.StrategyProvider
	failures []reportedFailure
}

type reportedFailure struct {
	sni string
	id  core.StrategyID
}

func (p *failureRecordingProvider) ReportFailure(sni string, failed core.StrategyID) {
	p.failures = append(p.failures, reportedFailure{sni: sni, id: failed})
}

func (p fakeProvider) Select(m proxy.ConnMeta) proxy.Selection {
	if m.SNI == p.matchSNI {
		return p.sel
	}
	return proxy.Selection{}
}

func fragStrategy(offset int) *strategy.Strategy {
	return &strategy.Strategy{Rules: []strategy.Rule{{
		Direction: core.DirectionOutbound,
		Trigger:   strategy.Trigger{Match: strategy.MatchClientHello},
		Action: &strategy.Action{
			Kind:   core.ActionFragment,
			Params: &strategy.FragmentParams{Proto: strategy.FragTCP, Offset: offset, Order: strategy.FragForward},
			Left:   &strategy.Action{Kind: core.ActionSend},
			Right:  &strategy.Action{Kind: core.ActionSend},
		},
	}}}
}

func delayedFragStrategy(offset, delayMs int) *strategy.Strategy {
	return &strategy.Strategy{Rules: []strategy.Rule{{
		Direction: core.DirectionOutbound,
		Trigger:   strategy.Trigger{Match: strategy.MatchClientHello},
		Action: &strategy.Action{
			Kind: core.ActionFragment,
			Params: &strategy.FragmentParams{
				Proto: strategy.FragTCP, Offset: offset, Order: strategy.FragForward, DelayMs: delayMs,
			},
			Left:  &strategy.Action{Kind: core.ActionSend},
			Right: &strategy.Action{Kind: core.ActionSend},
		},
	}}}
}

type timedPacket struct {
	port    uint16
	seq     uint32
	payload []byte
	at      time.Time
}

type timedSink struct {
	mu      sync.Mutex
	packets []timedPacket
}

func (s *timedSink) Send(pkt capture.Packet) error {
	d, err := packet.Dissect(pkt.Data)
	if err != nil {
		return err
	}
	tcp, ok := d.TCP(pkt.Data)
	if !ok {
		return nil
	}
	payload, _ := d.Payload(pkt.Data)
	record := timedPacket{
		port: tcp.SrcPort(), seq: tcp.Seq(),
		payload: append([]byte(nil), payload...), at: time.Now(),
	}
	s.mu.Lock()
	s.packets = append(s.packets, record)
	s.mu.Unlock()
	return nil
}

func (s *timedSink) snapshot() []timedPacket {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]timedPacket(nil), s.packets...)
}

type heldPacketSource struct {
	first   capture.Packet
	done    chan struct{}
	stopped chan struct{}
	once    sync.Once
}

func (s *heldPacketSource) Recv() (capture.Packet, error) {
	if s.first.Data != nil {
		pkt := s.first
		s.first = capture.Packet{}
		return pkt, nil
	}
	<-s.done
	return capture.Packet{}, io.EOF
}

func (s *heldPacketSource) ShutdownReceive() error {
	s.once.Do(func() {
		close(s.done)
		close(s.stopped)
	})
	return nil
}

type cancellationExecutor struct {
	started  chan struct{}
	release  chan struct{}
	finished chan struct{}
}

func (e *cancellationExecutor) Capabilities() core.PrimitiveSet {
	return core.PrimitiveSet(0).With(core.CapDelay)
}

func (e *cancellationExecutor) Execute(ctx context.Context, _ *strategy.Strategy, _ executor.Conn) error {
	close(e.started)
	<-ctx.Done()
	<-e.release
	close(e.finished)
	return ctx.Err()
}

// fragStrategyAt — стратегия разреза по структурной точке (а не числу), нужна
// для проверки сборки многосегментного ClientHello: имя сервера лежит во втором
// сегменте, и разрез «внутри имени» обязан попасть именно в него.
func fragStrategyAt(at core.CutKind) *strategy.Strategy {
	return &strategy.Strategy{Rules: []strategy.Rule{{
		Direction: core.DirectionOutbound,
		Trigger:   strategy.Trigger{Match: strategy.MatchClientHello},
		Action: &strategy.Action{
			Kind:   core.ActionFragment,
			Params: &strategy.FragmentParams{Proto: strategy.FragTCP, At: at, Order: strategy.FragForward},
			Left:   &strategy.Action{Kind: core.ActionSend},
			Right:  &strategy.Action{Kind: core.ActionSend},
		},
	}}}
}

// packetV4 собирает пакет IPv4/TCP с заданной нагрузкой, направлением и seq.
func packetV4(t *testing.T, payload []byte, dir core.Direction) capture.Packet {
	return packetV4Port(t, payload, dir, 50000)
}

// packetV4Port — то же, но с заданным исходным (локальным) портом. Нужен для
// проверки выбора стратегии по локальному порту (провайдер песочницы).
func packetV4Port(t *testing.T, payload []byte, dir core.Direction, srcPort uint16) capture.Packet {
	return packetV4Seq(t, payload, dir, srcPort, baseSeq)
}

// packetV4Seq — то же, но с заданным номером последовательности TCP. Нужен для
// проверки сборки многосегментного ClientHello: второй сегмент продолжает поток
// с seq первого плюс его длина.
func packetV4Seq(t *testing.T, payload []byte, dir core.Direction, srcPort uint16, seq uint32) capture.Packet {
	t.Helper()
	buf := make([]byte, 20+20+len(payload))
	buf[0] = 0x45
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(buf)))
	buf[8] = 64
	buf[9] = 6 // TCP
	copy(buf[12:16], net.ParseIP("10.0.0.1").To4())
	copy(buf[16:20], net.ParseIP("93.184.216.34").To4())
	binary.BigEndian.PutUint16(buf[20:22], srcPort)
	binary.BigEndian.PutUint16(buf[22:24], 443)
	binary.BigEndian.PutUint32(buf[24:28], seq)
	buf[32] = 0x50
	buf[33] = 0x18
	binary.BigEndian.PutUint16(buf[34:36], 65535)
	copy(buf[40:], payload)

	d, err := packet.Dissect(buf)
	if err != nil {
		t.Fatalf("разбор тестового пакета: %v", err)
	}
	if !d.RecomputeChecksums(buf) {
		t.Fatalf("пересчёт сумм не удался")
	}
	return capture.Packet{Data: buf, Dir: dir}
}

func buildEngine(t *testing.T, src capture.PacketSource, sink capture.PacketSink, parser HelloParser, prov proxy.StrategyProvider) *Engine {
	t.Helper()
	e, err := New(Options{
		Source:   src,
		Sink:     sink,
		Flows:    flow.NewTable(16, time.Minute, testDetector),
		Provider: prov,
		Exec:     packetexec.New(),
		Parse:    parser,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e
}

// TestAppliesStrategyAndDropsOriginal — на ClientHello в радиусе стратегия
// применяется (две части), а оригинал НЕ пропускается.
func TestAppliesStrategyAndDropsOriginal(t *testing.T) {
	const cut = 5
	src := capture.NewSyntheticSource(packetV4(t, helloPayload, core.DirectionOutbound))
	sink := &capture.SyntheticSink{}
	prov := fakeProvider{matchSNI: "blocked.example", sel: proxy.Selection{Strategy: fragStrategy(cut), ID: core.StrategyID("frag")}}

	e := buildEngine(t, src, sink, fixedParser("blocked.example"), prov)
	if err := e.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	sent := sink.Sent()
	if len(sent) != 2 {
		t.Fatalf("ожидалось 2 сегмента (оригинал заменён), получено %d", len(sent))
	}
	d0, _ := packet.Dissect(sent[0].Data)
	p0, _ := d0.Payload(sent[0].Data)
	if string(p0) != string(helloPayload[:cut]) {
		t.Errorf("сегмент 0: нагрузка %x", p0)
	}
	th0, _ := d0.TCP(sent[0].Data)
	if th0.Seq() != baseSeq || !d0.VerifyChecksums(sent[0].Data) {
		t.Errorf("сегмент 0: seq=%d суммы=%v", th0.Seq(), d0.VerifyChecksums(sent[0].Data))
	}
	d1, _ := packet.Dissect(sent[1].Data)
	th1, _ := d1.TCP(sent[1].Data)
	if th1.Seq() != baseSeq+cut {
		t.Errorf("сегмент 1: ожидался seq %d, получено %d", baseSeq+cut, th1.Seq())
	}
}

func TestSeparateDesyncSenderPreservesOrdinaryTraffic(t *testing.T) {
	for _, tc := range []struct {
		name, sni string
		dedicated bool
	}{{"youtube-dedicated", "youtube.com", true}, {"youtube-fallback", "youtube.com", false}, {"discord-default", "discord.com", true}} {
		t.Run(tc.name, func(t *testing.T) {
			hello := packetV4(t, helloPayload, core.DirectionOutbound)
			data := packetV4Seq(t, []byte("application data"), core.DirectionOutbound, 50000, baseSeq+uint32(len(helloPayload)))
			normal, modified := &capture.SyntheticSink{}, &capture.SyntheticSink{}
			selector := func(sni string) capture.PacketSink {
				if tc.dedicated && sni == "youtube.com" {
					return modified
				}
				return nil
			}
			e, err := New(Options{Source: capture.NewSyntheticSource(hello, data), Sink: normal, DesyncSink: selector, Flows: flow.NewTable(16, time.Minute, testDetector), Provider: fakeProvider{matchSNI: tc.sni, sel: proxy.Selection{Strategy: fragStrategy(5)}}, Exec: packetexec.New(), Parse: fixedParser(tc.sni)})
			if err != nil {
				t.Fatal(err)
			}
			if err := e.Run(context.Background()); err != nil {
				t.Fatal(err)
			}
			if tc.dedicated && tc.sni == "youtube.com" {
				if len(modified.Sent()) != 2 || len(normal.Sent()) != 1 || !bytes.Equal(normal.Sent()[0].Data, data.Data) {
					t.Fatal("dedicated sender changed normal traffic")
				}
			} else if len(normal.Sent()) != 3 || len(modified.Sent()) != 0 {
				t.Fatal("nil sender changed default behavior")
			}
		})
	}
}

// portProvider выбирает стратегию по локальному порту соединения — так же, как
// это делает провайдер песочницы (5.2). Проверяет, что движок доносит исходный
// порт до ConnMeta.
type portProvider struct {
	wantPort uint16
	sel      proxy.Selection
}

func (p portProvider) Select(m proxy.ConnMeta) proxy.Selection {
	if m.LocalPort == p.wantPort {
		return p.sel
	}
	return proxy.Selection{}
}

// TestSelectsByLocalPort — движок кладёт исходный порт в ConnMeta.LocalPort, и
// провайдер, выбирающий по порту, применяет стратегию к «своему» порту и
// пропускает чужой. Это основа изоляции песочницы: разные порты — разные
// кандидаты, при одной и той же цели и SNI.
func TestSelectsByLocalPort(t *testing.T) {
	const cut = 5
	prov := portProvider{wantPort: 40007, sel: proxy.Selection{Strategy: fragStrategy(cut), ID: core.StrategyID("cand")}}

	// Порт в диапазоне песочницы: стратегия применяется (оригинал заменён).
	{
		src := capture.NewSyntheticSource(packetV4Port(t, helloPayload, core.DirectionOutbound, 40007))
		sink := &capture.SyntheticSink{}
		e := buildEngine(t, src, sink, fixedParser("blocked.example"), prov)
		if err := e.Run(context.Background()); err != nil {
			t.Fatalf("Run: %v", err)
		}
		if sent := sink.Sent(); len(sent) != 2 {
			t.Fatalf("порт песочницы: ожидалось 2 сегмента, получено %d", len(sent))
		}
	}

	// Другой порт (вне привязки): тот же SNI, но стратегия не применяется —
	// выбор строго по порту.
	{
		pkt := packetV4Port(t, helloPayload, core.DirectionOutbound, 50000)
		src := capture.NewSyntheticSource(pkt)
		sink := &capture.SyntheticSink{}
		e := buildEngine(t, src, sink, fixedParser("blocked.example"), prov)
		if err := e.Run(context.Background()); err != nil {
			t.Fatalf("Run: %v", err)
		}
		if sent := sink.Sent(); len(sent) != 1 || string(sent[0].Data) != string(pkt.Data) {
			t.Fatalf("чужой порт должен пройти как есть, получено %d сегментов", len(sent))
		}
	}
}

// TestOnClientHelloHook — наблюдатель получает имя сервера на каждом
// распознанном исходящем ClientHello, в том числе вне радиуса (там выбор
// стратегии пуст). Нужен трекеру QUIC-only: TCP-хелло по имени — признак того,
// что приложение откатилось на TCP (3.3).
func TestOnClientHelloHook(t *testing.T) {
	// Вне радиуса: провайдер отдаёт стратегию для другого имени, но хук всё
	// равно обязан сработать — откат на TCP происходит независимо от радиуса.
	pkt := packetV4(t, helloPayload, core.DirectionOutbound)
	src := capture.NewSyntheticSource(pkt)
	sink := &capture.SyntheticSink{}
	prov := fakeProvider{matchSNI: "blocked.example", sel: proxy.Selection{Strategy: fragStrategy(5)}}

	var seen []string
	e, err := New(Options{
		Source:        src,
		Sink:          sink,
		Flows:         flow.NewTable(16, time.Minute, testDetector),
		Provider:      prov,
		Exec:          packetexec.New(),
		Parse:         fixedParser("youtube.com"),
		OnClientHello: func(sni string) { seen = append(seen, sni) },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := e.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(seen) != 1 || seen[0] != "youtube.com" {
		t.Fatalf("ожидался один вызов наблюдателя с youtube.com, получено %v", seen)
	}
	// Пакет вне радиуса прошёл как есть — хук выбора стратегии не меняет.
	if sent := sink.Sent(); len(sent) != 1 || string(sent[0].Data) != string(pkt.Data) {
		t.Fatalf("вне радиуса пакет должен пройти как есть, получено %d", len(sent))
	}
}

// TestForwardsInbound — входящий пакет пропускается без изменений.
func TestForwardsInbound(t *testing.T) {
	in := packetV4(t, helloPayload, core.DirectionInbound)
	src := capture.NewSyntheticSource(in)
	sink := &capture.SyntheticSink{}
	prov := fakeProvider{matchSNI: "blocked.example", sel: proxy.Selection{Strategy: fragStrategy(5)}}

	e := buildEngine(t, src, sink, fixedParser("blocked.example"), prov)
	if err := e.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	sent := sink.Sent()
	if len(sent) != 1 || string(sent[0].Data) != string(in.Data) {
		t.Fatalf("входящий должен пройти как есть одним пакетом, получено %d", len(sent))
	}
}

// TestForwardsOutOfRadius — ClientHello вне радиуса (провайдер пуст) проходит
// без изменений.
func TestForwardsOutOfRadius(t *testing.T) {
	pkt := packetV4(t, helloPayload, core.DirectionOutbound)
	src := capture.NewSyntheticSource(pkt)
	sink := &capture.SyntheticSink{}
	// Провайдер отдаёт стратегию только для другого имени.
	prov := fakeProvider{matchSNI: "blocked.example", sel: proxy.Selection{Strategy: fragStrategy(5)}}

	e := buildEngine(t, src, sink, fixedParser("allowed.example"), prov)
	if err := e.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if sent := sink.Sent(); len(sent) != 1 || string(sent[0].Data) != string(pkt.Data) {
		t.Fatalf("вне радиуса пакет должен пройти как есть, получено %d", len(sent))
	}
}

// TestForwardsSyn — пустой сегмент (без нагрузки) пропускается: решать не на чем.
func TestForwardsSyn(t *testing.T) {
	syn := packetV4(t, nil, core.DirectionOutbound)
	src := capture.NewSyntheticSource(syn)
	sink := &capture.SyntheticSink{}
	prov := fakeProvider{matchSNI: "blocked.example", sel: proxy.Selection{Strategy: fragStrategy(5)}}

	e := buildEngine(t, src, sink, fixedParser("blocked.example"), prov)
	if err := e.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if sent := sink.Sent(); len(sent) != 1 {
		t.Fatalf("SYN должен пройти как есть, получено %d", len(sent))
	}
}

// TestTransparentForwardsEverything — в прозрачном режиме даже ClientHello в
// радиусе проходит без изменений (killswitch сработал).
func TestTransparentForwardsEverything(t *testing.T) {
	pkt := packetV4(t, helloPayload, core.DirectionOutbound)
	src := capture.NewSyntheticSource(pkt)
	sink := &capture.SyntheticSink{}
	prov := fakeProvider{matchSNI: "blocked.example", sel: proxy.Selection{Strategy: fragStrategy(5)}}

	e := buildEngine(t, src, sink, fixedParser("blocked.example"), prov)
	e.SetTransparent(true)
	if err := e.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if sent := sink.Sent(); len(sent) != 1 || string(sent[0].Data) != string(pkt.Data) {
		t.Fatalf("в прозрачном режиме пакет должен пройти как есть, получено %d", len(sent))
	}
}

// TestGuardRaisesAndClearsTransparent — killswitch поднимает прозрачный режим
// при потере связности и снимает при восстановлении.
func TestGuardRaisesAndClearsTransparent(t *testing.T) {
	e := buildEngine(t, capture.NewSyntheticSource(), &capture.SyntheticSink{},
		fixedParser(""), fakeProvider{})

	healthy := make(chan bool, 1)
	check := func(context.Context) bool {
		select {
		case v := <-healthy:
			return v
		default:
			return false // по умолчанию связи нет
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Guard(ctx, check, 5*time.Millisecond, 2)

	// Связи нет — после порога прозрачный режим поднимается.
	waitFor(t, func() bool { return e.Transparent() }, time.Second, "killswitch должен включить прозрачный режим")

	// Подаём «связь есть» непрерывно — режим снимается.
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case healthy <- true:
			}
		}
	}()
	waitFor(t, func() bool { return !e.Transparent() }, time.Second, "killswitch должен снять прозрачный режим при восстановлении")
}

// waitFor ждёт выполнения условия до истечения срока.
func waitFor(t *testing.T, cond func() bool, within time.Duration, msg string) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal(msg)
}

// buildFullHello собирает целый ClientHello, в котором перед расширением
// server_name стоит крупное ведущее расширение (модель постквантового
// key_share, вытолкнувшего имя дальше по сообщению). Возвращает запись целиком
// и смещение начала расширения server_name в ней.
func buildFullHello(t *testing.T, name string, leadLen int) (rec []byte, sniExtStart int) {
	t.Helper()

	// Ведущее расширение (тип padding=21) до server_name.
	lead := binary.BigEndian.AppendUint16(nil, 21)
	lead = binary.BigEndian.AppendUint16(lead, uint16(leadLen))
	lead = append(lead, make([]byte, leadLen)...)

	// Расширение server_name.
	entry := []byte{0 /*host_name*/}
	entry = binary.BigEndian.AppendUint16(entry, uint16(len(name)))
	entry = append(entry, name...)
	sniData := binary.BigEndian.AppendUint16(nil, uint16(len(entry)))
	sniData = append(sniData, entry...)
	sniExt := binary.BigEndian.AppendUint16(nil, 0 /*server_name*/)
	sniExt = binary.BigEndian.AppendUint16(sniExt, uint16(len(sniData)))
	sniExt = append(sniExt, sniData...)

	exts := append(append([]byte{}, lead...), sniExt...)

	// Тело ClientHello.
	body := binary.BigEndian.AppendUint16(nil, 0x0303) // legacy_version
	body = append(body, make([]byte, 32)...)           // random
	body = append(body, 0)                             // session_id: пусто
	body = binary.BigEndian.AppendUint16(body, 2)      // cipher_suites len
	body = append(body, 0x13, 0x01)
	body = append(body, 1, 0) // compression_methods
	body = binary.BigEndian.AppendUint16(body, uint16(len(exts)))
	body = append(body, exts...)

	// Заголовок сообщения рукопожатия.
	hs := []byte{1 /*client_hello*/, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)

	// Заголовок записи TLS.
	rec = []byte{22 /*handshake*/, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
	rec = append(rec, hs...)

	return rec, len(rec) - len(sniExt)
}

// buildSplitHello делит целый ClientHello ровно по началу server_name: заголовок
// записи, рукопожатие и ведущее расширение попадают в первый сегмент, имя сервера
// целиком — во второй. Модель соединения, где имя уехало во второй TCP-сегмент.
func buildSplitHello(t *testing.T, name string, leadLen int) (seg1, seg2 []byte) {
	t.Helper()
	rec, split := buildFullHello(t, name, leadLen)
	return rec[:split], rec[split:]
}

func TestAssembledDomainSplitSendsTailBeforeHeaderWithinOriginalMSS(t *testing.T) {
	const name = "rr3---sn-jvhnu5g-n8vr.googlevideo.com"
	const mss = 1200
	for _, padding := range []int{1120, 1900, 3100} {
		full, _ := buildFullHello(t, name, padding)
		var packets []capture.Packet
		for start := 0; start < len(full); start += mss {
			end := min(start+mss, len(full))
			packets = append(packets, packetV4Seq(t, full[start:end], core.DirectionOutbound, 50000, baseSeq+uint32(start)))
		}
		s := fragStrategyAt(core.CutInsideSLD)
		s.Rules[0].Action.Params.(*strategy.FragmentParams).Order = strategy.FragReverse
		sink := &capture.SyntheticSink{}
		e, err := New(Options{Source: capture.NewSyntheticSource(packets...), Sink: sink, Flows: flow.NewTable(16, time.Minute, TLSHelloDetector), Provider: fakeProvider{matchSNI: name, sel: proxy.Selection{Strategy: s}}, Exec: packetexec.New(), Parse: TLSHelloParser})
		if err != nil {
			t.Fatal(err)
		}
		if err = e.Run(context.Background()); err != nil {
			t.Fatal(err)
		}
		rebuilt := make([]byte, len(full))
		sent := sink.Sent()
		for i, p := range sent {
			d, err := packet.Dissect(p.Data)
			if err != nil {
				t.Fatal(err)
			}
			h, _ := d.TCP(p.Data)
			payload, _ := d.Payload(p.Data)
			offset := int(h.Seq() - baseSeq)
			if i == 0 && offset == 0 {
				t.Fatal("TLS header leaked before SNI tail", padding)
			}
			if len(payload) > mss || offset < 0 || offset+len(payload) > len(full) || !d.VerifyChecksums(p.Data) {
				t.Fatal("invalid split geometry", padding, len(payload), offset)
			}
			if bytes.Contains(payload, []byte("googlevideo")) {
				t.Fatal("blocked label left intact", padding)
			}
			copy(rebuilt[offset:], payload)
		}
		if !bytes.Equal(rebuilt, full) {
			t.Fatal("ClientHello bytes changed", padding)
		}
	}
}

func TestOffloadedDomainSplitKeepsCoalescedTLSRecords(t *testing.T) {
	const name = "rr3---sn-jvhnu5g-n8vr.googlevideo.com"
	full, _ := buildFullHello(t, name, 1900)
	full = append(full, 20, 3, 3, 0, 1, 1) // TLS 1.3 compatibility CCS.
	s := fragStrategyAt(core.CutInsideSLD)
	s.Rules[0].Action.Params.(*strategy.FragmentParams).Order = strategy.FragReverse
	sink := &capture.SyntheticSink{}
	e, err := New(Options{Source: capture.NewSyntheticSource(packetV4(t, full, core.DirectionOutbound)), Sink: sink, Flows: flow.NewTable(16, time.Minute, TLSHelloDetector), Provider: fakeProvider{matchSNI: name, sel: proxy.Selection{Strategy: s}}, Exec: packetexec.New(), Parse: TLSHelloParser})
	if err != nil {
		t.Fatal(err)
	}
	if err = e.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	rebuilt := make([]byte, len(full))
	total := 0
	for _, p := range sink.Sent() {
		d, _ := packet.Dissect(p.Data)
		h, _ := d.TCP(p.Data)
		payload, _ := d.Payload(p.Data)
		offset := int(h.Seq() - baseSeq)
		if len(payload) > 1400 || offset+len(payload) > len(full) {
			t.Fatal("offloaded packet exceeded safe size")
		}
		copy(rebuilt[offset:], payload)
		total += len(payload)
	}
	if total != len(full) || !bytes.Equal(rebuilt, full) {
		t.Fatal("coalesced CCS record lost")
	}
}

// TestAssemblesSecondSegmentAndDesyncs — сквозная проверка сборки: имя сервера
// лежит во втором сегменте. Первый сегмент обязан пройти сырым, второй —
// десинкнуться разрезом «внутри имени», причём части должны получить верные
// номера последовательности (продолжение потока со второго сегмента) и в сумме
// восстановить второй сегмент. Детектор и разбор — настоящие (tlsparse): тест
// ловит ошибки перевода смещений и координат seq.
func TestAssemblesSecondSegmentAndDesyncs(t *testing.T) {
	const name = "v.googlevideo.example"
	seg1, seg2 := buildSplitHello(t, name, 300)

	// Контрольный разбор склейки: где имя и где ожидаемый разрез «внутри имени».
	full := append(append([]byte{}, seg1...), seg2...)
	ch, err := tlsparse.ParseClientHello(full)
	if err != nil {
		t.Fatalf("контрольный разбор склейки: %v", err)
	}
	if sni, _ := ch.SNI(full); string(sni) != name {
		t.Fatalf("контроль: SNI склейки = %q", sni)
	}
	wantCut := (ch.SNIOff + ch.SNILen/2) - len(seg1)
	if wantCut <= 0 || wantCut >= len(seg2) {
		t.Fatalf("контроль: разрез внутри имени (%d) не попал во второй сегмент [0,%d)", wantCut, len(seg2))
	}

	const s1seq = uint32(7000)
	s2seq := s1seq + uint32(len(seg1))
	p1 := packetV4Seq(t, seg1, core.DirectionOutbound, 50000, s1seq)
	p2 := packetV4Seq(t, seg2, core.DirectionOutbound, 50000, s2seq)

	src := capture.NewSyntheticSource(p1, p2)
	sink := &capture.SyntheticSink{}
	prov := fakeProvider{matchSNI: name, sel: proxy.Selection{Strategy: fragStrategyAt(core.CutInsideSNI), ID: core.StrategyID("inside-sni")}}

	e, err := New(Options{
		Source:   src,
		Sink:     sink,
		Flows:    flow.NewTable(16, time.Minute, TLSHelloDetector),
		Provider: prov,
		Exec:     packetexec.New(),
		Parse:    TLSHelloParser,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := e.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	sent := sink.Sent()
	if len(sent) != 3 {
		t.Fatalf("ожидалось 3 пакета (досланный сегмент 1 + 2 части сегмента 2), получено %d", len(sent))
	}

	// Пакет 0 — первый сегмент, досланный сырьём: та же нагрузка и seq, что у
	// оригинала (пересобран из удержанных байт, заголовки — из шаблона).
	d0, _ := packet.Dissect(sent[0].Data)
	th0, _ := d0.TCP(sent[0].Data)
	pay0, _ := d0.Payload(sent[0].Data)
	if th0.Seq() != s1seq {
		t.Errorf("сегмент 1: seq=%d, ожидался %d", th0.Seq(), s1seq)
	}
	if !bytes.Equal(pay0, seg1) {
		t.Errorf("сегмент 1: нагрузка должна совпасть с исходной (%d байт), получено %d", len(seg1), len(pay0))
	}
	if !d0.VerifyChecksums(sent[0].Data) {
		t.Errorf("сегмент 1: контрольные суммы неверны")
	}

	// Пакеты 1 и 2 — части второго сегмента с верными seq и нагрузкой.
	d1, _ := packet.Dissect(sent[1].Data)
	th1, _ := d1.TCP(sent[1].Data)
	pay1, _ := d1.Payload(sent[1].Data)
	if th1.Seq() != s2seq {
		t.Errorf("часть 1: seq=%d, ожидался %d", th1.Seq(), s2seq)
	}
	if !bytes.Equal(pay1, seg2[:wantCut]) {
		t.Errorf("часть 1: нагрузка %x, ожидалось %x", pay1, seg2[:wantCut])
	}
	if !d1.VerifyChecksums(sent[1].Data) {
		t.Errorf("часть 1: контрольные суммы неверны")
	}

	d2, _ := packet.Dissect(sent[2].Data)
	th2, _ := d2.TCP(sent[2].Data)
	pay2, _ := d2.Payload(sent[2].Data)
	if th2.Seq() != s2seq+uint32(wantCut) {
		t.Errorf("часть 2: seq=%d, ожидался %d", th2.Seq(), s2seq+uint32(wantCut))
	}
	if !bytes.Equal(pay2, seg2[wantCut:]) {
		t.Errorf("часть 2: нагрузка %x, ожидалось %x", pay2, seg2[wantCut:])
	}
	if !d2.VerifyChecksums(sent[2].Data) {
		t.Errorf("часть 2: контрольные суммы неверны")
	}

	// Части разреза в сумме восстанавливают второй сегмент — байты не потеряны.
	if !bytes.Equal(append(append([]byte{}, pay1...), pay2...), seg2) {
		t.Errorf("части разреза не восстанавливают второй сегмент")
	}
}

// TestAssemblesStraddlingSNIAndDesyncs — имя сервера РАСЩЕПЛЕНО ровно на границе
// сегментов: первые байты имени в первом сегменте, остальные во втором. Ни один
// сегмент сам по себе имя не несёт целиком, и фикс «десинк сегмента с именем» без
// удержания здесь не дотянулся бы до начала имени. Проверяем, что десинк
// накрывает кусок С НАЧАЛА имени (с первого сегмента), первый сегмент сырьём не
// уходит, а части разреза в сумме восстанавливают всю склейку.
func TestAssemblesStraddlingSNIAndDesyncs(t *testing.T) {
	const name = "v.googlevideo.example"
	full, _ := buildFullHello(t, name, 300)

	ch, err := tlsparse.ParseClientHello(full)
	if err != nil {
		t.Fatalf("контрольный разбор: %v", err)
	}
	// Делим внутри имени: несколько его байт — в первом сегменте, хвост — во втором.
	split := ch.SNIOff + 4
	if split <= ch.SNIOff || split >= ch.SNIOff+ch.SNILen {
		t.Fatalf("контроль: точка деления %d вне имени [%d,%d)", split, ch.SNIOff, ch.SNIOff+ch.SNILen)
	}
	seg1, seg2 := full[:split], full[split:]

	// Разрез «внутри имени» в координатах склейки (= координаты первого сегмента,
	// т.к. десинк начнётся с него).
	wantCut := ch.SNIOff + ch.SNILen/2
	if wantCut <= 0 || wantCut >= len(full) {
		t.Fatalf("контроль: разрез %d вне склейки", wantCut)
	}

	const s1seq = uint32(9000)
	s2seq := s1seq + uint32(len(seg1))
	p1 := packetV4Seq(t, seg1, core.DirectionOutbound, 50000, s1seq)
	p2 := packetV4Seq(t, seg2, core.DirectionOutbound, 50000, s2seq)

	src := capture.NewSyntheticSource(p1, p2)
	sink := &capture.SyntheticSink{}
	prov := fakeProvider{matchSNI: name, sel: proxy.Selection{Strategy: fragStrategyAt(core.CutInsideSNI), ID: core.StrategyID("inside-sni")}}

	e, err := New(Options{
		Source:   src,
		Sink:     sink,
		Flows:    flow.NewTable(16, time.Minute, TLSHelloDetector),
		Provider: prov,
		Exec:     packetexec.New(),
		Parse:    TLSHelloParser,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := e.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	sent := sink.Sent()
	// Префикса до имени нет (имя начинается в первом сегменте), поэтому только
	// две части разреза всей склейки.
	if len(sent) != 2 {
		t.Fatalf("ожидалось 2 части разреза склейки, получено %d", len(sent))
	}

	d0, _ := packet.Dissect(sent[0].Data)
	th0, _ := d0.TCP(sent[0].Data)
	pay0, _ := d0.Payload(sent[0].Data)
	if th0.Seq() != s1seq {
		t.Errorf("часть 1: seq=%d, ожидался %d (с начала склейки)", th0.Seq(), s1seq)
	}
	if !bytes.Equal(pay0, full[:wantCut]) {
		t.Errorf("часть 1: нагрузка не равна началу склейки до разреза")
	}
	if !d0.VerifyChecksums(sent[0].Data) {
		t.Errorf("часть 1: контрольные суммы неверны")
	}

	d1, _ := packet.Dissect(sent[1].Data)
	th1, _ := d1.TCP(sent[1].Data)
	pay1, _ := d1.Payload(sent[1].Data)
	if th1.Seq() != s1seq+uint32(wantCut) {
		t.Errorf("часть 2: seq=%d, ожидался %d", th1.Seq(), s1seq+uint32(wantCut))
	}
	if !bytes.Equal(pay1, full[wantCut:]) {
		t.Errorf("часть 2: нагрузка не равна хвосту склейки после разреза")
	}

	// Части в сумме восстанавливают всю склейку — ни байта не потеряно.
	if !bytes.Equal(append(append([]byte{}, pay0...), pay1...), full) {
		t.Errorf("части разреза не восстанавливают склейку")
	}
}

// TestAssemblyGiveUpFlushesHeldSegment — сборка начата, но следующий сегмент
// приходит с разрывом нумерации. Удержанный первый сегмент не должен пропасть:
// его обязаны дослать в сеть сырьём, а срывающий пакет — пропустить как есть.
func TestAssemblyGiveUpFlushesHeldSegment(t *testing.T) {
	const name = "v.googlevideo.example"
	full, _ := buildFullHello(t, name, 300)

	ch, err := tlsparse.ParseClientHello(full)
	if err != nil {
		t.Fatalf("контрольный разбор: %v", err)
	}
	// Первый сегмент обрезан ДО имени: TLS виден, имени нет — начнётся сборка.
	seg1 := full[:ch.SNIOff-2]

	const s1seq = uint32(11000)
	held := packetV4Seq(t, seg1, core.DirectionOutbound, 50000, s1seq)
	// Срывающий пакет: тот же поток, но seq с разрывом (не продолжает склейку).
	gapPayload := []byte("not a continuation")
	gap := packetV4Seq(t, gapPayload, core.DirectionOutbound, 50000, s1seq+9999)

	src := capture.NewSyntheticSource(held, gap)
	sink := &capture.SyntheticSink{}
	prov := fakeProvider{matchSNI: name, sel: proxy.Selection{Strategy: fragStrategyAt(core.CutInsideSNI)}}

	e, err := New(Options{
		Source:   src,
		Sink:     sink,
		Flows:    flow.NewTable(16, time.Minute, TLSHelloDetector),
		Provider: prov,
		Exec:     packetexec.New(),
		Parse:    TLSHelloParser,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := e.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	sent := sink.Sent()
	// Досланный удержанный сегмент + срывающий пакет.
	if len(sent) != 2 {
		t.Fatalf("ожидалось 2 пакета (досланный удержанный + срывающий), получено %d", len(sent))
	}

	d0, _ := packet.Dissect(sent[0].Data)
	th0, _ := d0.TCP(sent[0].Data)
	pay0, _ := d0.Payload(sent[0].Data)
	if th0.Seq() != s1seq {
		t.Errorf("досланный сегмент: seq=%d, ожидался %d", th0.Seq(), s1seq)
	}
	if !bytes.Equal(pay0, seg1) {
		t.Errorf("досланный сегмент: нагрузка не равна удержанному первому сегменту")
	}
	if !d0.VerifyChecksums(sent[0].Data) {
		t.Errorf("досланный сегмент: контрольные суммы неверны")
	}

	// Срывающий пакет прошёл как есть.
	if !bytes.Equal(sent[1].Data, gap.Data) {
		t.Errorf("срывающий пакет должен пройти сырым без изменений")
	}
}

// TestOnPassiveOnClientHelloRetransmit: повтор ClientHello (тот же seq) на уже
// решённом потоке поднимает пассивное наблюдение (5.10), атрибутированное
// стратегии и цели текущего выбора.
func TestOnPassiveOnClientHelloRetransmit(t *testing.T) {
	seq := uint32(1000)
	p1 := packetV4Seq(t, helloPayload, core.DirectionOutbound, 50000, seq)
	p2 := packetV4Seq(t, helloPayload, core.DirectionOutbound, 50000, seq) // повтор того же seq
	src := capture.NewSyntheticSource(p1, p2)
	sink := &capture.SyntheticSink{}
	prov := fakeProvider{matchSNI: "youtube.com", sel: proxy.Selection{
		Strategy: fragStrategy(5), ID: core.StrategyID("sid1"), Target: "youtube.com",
	}}

	var events []PassiveEvent
	e, err := New(Options{
		Source:    src,
		Sink:      sink,
		Flows:     flow.NewTable(16, time.Minute, testDetector),
		Provider:  prov,
		Exec:      packetexec.New(),
		Parse:     fixedParser("youtube.com"),
		OnPassive: func(ev PassiveEvent) { events = append(events, ev) },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := e.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(events) != 1 {
		t.Fatalf("ожидалось одно пассивное событие, получено %d", len(events))
	}
	ev := events[0]
	if ev.SNI != "youtube.com" || ev.Target != "youtube.com" || ev.StrategyID != core.StrategyID("sid1") {
		t.Fatalf("пассивное событие неверно атрибутировано: %+v", ev)
	}
}

func TestRetransmitReportsFailureAndPassesThrough(t *testing.T) {
	seq := uint32(1000)
	first := packetV4Seq(t, helloPayload, core.DirectionOutbound, 50000, seq)
	retransmit := packetV4Seq(t, helloPayload, core.DirectionOutbound, 50000, seq)
	sink := &capture.SyntheticSink{}
	provider := &failureRecordingProvider{StrategyProvider: fakeProvider{
		matchSNI: "youtube.com",
		sel:      proxy.Selection{Strategy: fragStrategy(5), ID: core.StrategyID("sid1"), Target: "youtube.com"},
	}}
	engine := buildEngine(t, capture.NewSyntheticSource(first, retransmit), sink, fixedParser("youtube.com"), provider)
	if err := engine.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(provider.failures) != 1 || provider.failures[0] != (reportedFailure{sni: "youtube.com", id: "sid1"}) {
		t.Fatalf("ReportFailure calls = %v", provider.failures)
	}
	rawSeen := 0
	for _, sent := range sink.Sent() {
		if bytes.Equal(sent.Data, retransmit.Data) {
			rawSeen++
		}
	}
	if rawSeen != 1 {
		t.Fatalf("retransmit passthrough count = %d, want 1", rawSeen)
	}
}

func TestOnInboundRSTReportsFreshDesyncOnce(t *testing.T) {
	for _, tc := range []struct {
		name       string
		advance    time.Duration
		wantReport bool
	}{
		{name: "within window", advance: 4 * time.Second, wantReport: true},
		{name: "expired", advance: 6 * time.Second},
		{name: "duplicate", advance: 0, wantReport: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
			provider := &failureRecordingProvider{StrategyProvider: fakeProvider{
				matchSNI: "youtube.com",
				sel:      proxy.Selection{Strategy: fragStrategy(5), ID: core.StrategyID("sid1")},
			}}
			engine, err := New(Options{
				Source:   capture.NewSyntheticSource(),
				Sink:     &capture.SyntheticSink{},
				Flows:    flow.NewTable(16, time.Minute, testDetector),
				Provider: provider,
				Exec:     packetexec.New(),
				Parse:    fixedParser("youtube.com"),
				Now:      func() time.Time { return now },
			})
			if err != nil {
				t.Fatal(err)
			}
			tmpl := packetV4(t, helloPayload, core.DirectionOutbound)
			if engine.execDesync(context.Background(), tmpl, helloPayload, nil, baseSeq, "youtube.com", 50000, 1, false, 0, func() {}) {
				t.Fatal("execDesync did not apply the strategy")
			}
			now = now.Add(tc.advance)
			remote := netip.MustParseAddrPort("93.184.216.34:443")
			engine.OnInboundRST(remote, 50000)
			if tc.name == "duplicate" {
				engine.OnInboundRST(remote, 50000)
			}
			want := 0
			if tc.wantReport {
				want = 1
			}
			if len(provider.failures) != want {
				t.Fatalf("ReportFailure calls = %v, want %d", provider.failures, want)
			}
			if want == 1 && provider.failures[0] != (reportedFailure{sni: "youtube.com", id: "sid1"}) {
				t.Fatalf("ReportFailure call = %+v", provider.failures[0])
			}
		})
	}
}

// TestOnPassiveSkippedOutOfRadius: повтор ClientHello по имени вне радиуса не
// атрибутируется — стратегия не выбрана, наказывать нечем.
func TestOnPassiveSkippedOutOfRadius(t *testing.T) {
	seq := uint32(1000)
	p1 := packetV4Seq(t, helloPayload, core.DirectionOutbound, 50000, seq)
	p2 := packetV4Seq(t, helloPayload, core.DirectionOutbound, 50000, seq)
	src := capture.NewSyntheticSource(p1, p2)
	sink := &capture.SyntheticSink{}
	// Провайдер отдаёт выбор только для другого имени: по youtube.com — пусто.
	prov := fakeProvider{matchSNI: "other.example", sel: proxy.Selection{
		Strategy: fragStrategy(5), ID: core.StrategyID("x"), Target: "other.example",
	}}

	var events []PassiveEvent
	e, err := New(Options{
		Source:    src,
		Sink:      sink,
		Flows:     flow.NewTable(16, time.Minute, testDetector),
		Provider:  prov,
		Exec:      packetexec.New(),
		Parse:     fixedParser("youtube.com"),
		OnPassive: func(ev PassiveEvent) { events = append(events, ev) },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := e.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("вне радиуса пассивных событий быть не должно, получено %d", len(events))
	}
}

// TestRetransmitForwardedRaw: повтор ClientHello в радиусе НЕ переприменяет
// десинк, а пропускается сырьём. Прежнее поведение (второй шанс через
// applySingle) создавало шторм ретрансмитов на многосегментных ClientHello
// (~1:1 с собранными в живом прогоне у владельца) и затуп AUTHENTICATING на
// 1-2 минуты (TCP RTO × экспоненциальный backoff до перехода на следующий
// RTC-сервер Discord). Сырой пропуск = DPI увидит SNI и RST'нёт поток, Discord
// быстро переходит к следующему серверу. Пассивный сигнал (OnPassive) всё
// равно записывается в оценку стратегии.
func TestRetransmitForwardedRaw(t *testing.T) {
	seq := uint32(1000)
	p1 := packetV4Seq(t, helloPayload, core.DirectionOutbound, 50000, seq)
	p2 := packetV4Seq(t, helloPayload, core.DirectionOutbound, 50000, seq) // повтор того же seq
	src := capture.NewSyntheticSource(p1, p2)
	sink := &capture.SyntheticSink{}
	prov := fakeProvider{matchSNI: "youtube.com", sel: proxy.Selection{
		Strategy: fragStrategy(5), ID: core.StrategyID("sid1"), Target: "youtube.com",
	}}

	e := buildEngine(t, src, sink, fixedParser("youtube.com"), prov)
	if err := e.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// Повтор ClientHello должен уйти сырьём ровно одной копией (как есть).
	rawSeen := 0
	for _, s := range sink.Sent() {
		if bytes.Equal(s.Data, p2.Data) {
			rawSeen++
		}
	}
	if rawSeen != 1 {
		t.Fatalf("повтор сырьём: ожидали 1, видно %d (sink.Sent=%d)", rawSeen, len(sink.Sent()))
	}
	// Первая попытка должна была десинкнуться (есть и другие пакеты).
	if len(sink.Sent()) < 2 {
		t.Fatalf("ожидали десинк первой попытки + сырой повтор, в sink %d пакетов", len(sink.Sent()))
	}
}

// overlapStrategy — стратегия tcp_overlap с штатным 681-байтным cover-пресетом.
// Та же, что в группе discord_cdn боевого конфига.
func overlapStrategy() *strategy.Strategy {
	return &strategy.Strategy{Rules: []strategy.Rule{{
		Direction: core.DirectionOutbound,
		Trigger:   strategy.Trigger{Match: strategy.MatchClientHello},
		Action: &strategy.Action{
			Kind:   core.ActionTCPOverlap,
			Params: &strategy.TCPOverlapParams{Preset: strategy.PresetTLSCover681},
		},
	}}}
}

// TestAssembledTCPOverlapDesyncsWholeHello — регрессия на загрузку GUI с
// cdn.discordapp.com. Крупный ClientHello приходит двумя сегментами (имя во
// втором). Прежде движок на сборке десинковал только хвост от имени, а он
// короче 681-байтного cover'а tcp_overlap → exec_failed → настоящий SNI уходил
// сырьём → TSPU рубил ресурс → GUI не отрисовывался. Теперь для tcp_overlap
// десинкуется ВЕСЬ собранный hello: ровно два пакета (cover 681 + реальный hello),
// оригинал не пропускается, суммы и seq верны.
func TestAssembledTCPOverlapDesyncsWholeHello(t *testing.T) {
	const name = "cdn.discordapp.example"
	// Большое ведущее расширение: полный ClientHello длиннее cover'а (681),
	// иначе tcp_overlap неприменим в принципе. Имя уезжает во второй сегмент.
	seg1, seg2 := buildSplitHello(t, name, 760)
	full := append(append([]byte{}, seg1...), seg2...)
	if len(full) <= 681 {
		t.Fatalf("контроль: полный hello %d байт, нужен >681", len(full))
	}
	// Хвост от имени (второй сегмент) заведомо короче cover'а — именно на нём
	// старый путь падал бы exec_failed. В этом и смысл теста.
	if len(seg2) >= 681 {
		t.Fatalf("контроль: второй сегмент %d байт, для смысла теста нужен <681", len(seg2))
	}

	const s1seq = uint32(7000)
	s2seq := s1seq + uint32(len(seg1))
	p1 := packetV4Seq(t, seg1, core.DirectionOutbound, 50000, s1seq)
	p2 := packetV4Seq(t, seg2, core.DirectionOutbound, 50000, s2seq)

	src := capture.NewSyntheticSource(p1, p2)
	sink := &capture.SyntheticSink{}
	prov := fakeProvider{matchSNI: name, sel: proxy.Selection{Strategy: overlapStrategy(), ID: core.StrategyID("overlap")}}

	e, err := New(Options{
		Source:   src,
		Sink:     sink,
		Flows:    flow.NewTable(16, time.Minute, TLSHelloDetector),
		Provider: prov,
		Exec:     packetexec.New(),
		Parse:    TLSHelloParser,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := e.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	sent := sink.Sent()
	// tcp_overlap на цельном hello = ровно два пакета: cover + реальный hello.
	// Если бы движок десинковал хвост, был бы exec_failed и досылка сырьём.
	if len(sent) != 2 {
		t.Fatalf("ожидалось 2 пакета (cover+реальный), получено %d", len(sent))
	}

	cover, _ := packet.Dissect(sent[0].Data)
	coverPay, _ := cover.Payload(sent[0].Data)
	realD, _ := packet.Dissect(sent[1].Data)
	realPay, _ := realD.Payload(sent[1].Data)

	if len(coverPay) != 681 {
		t.Errorf("cover: длина нагрузки %d, ожидалось 681", len(coverPay))
	}
	if len(coverPay) > 0 && coverPay[0] != 0x16 {
		t.Errorf("cover: первый байт 0x%02x, ожидался TLS handshake 0x16", coverPay[0])
	}
	if !bytes.Equal(realPay, full) {
		t.Errorf("реальный пакет: нагрузка %d байт, ожидался полный hello %d байт", len(realPay), len(full))
	}

	thReal, _ := realD.TCP(sent[1].Data)
	if thReal.Seq() != s1seq {
		t.Errorf("реальный: seq=%d, ожидался %d (начало потока)", thReal.Seq(), s1seq)
	}
	thCover, _ := cover.TCP(sent[0].Data)
	wantCoverSeq := s1seq + uint32(len(full)) - 681
	if thCover.Seq() != wantCoverSeq {
		t.Errorf("cover: seq=%d, ожидался %d (перекрытие хвоста)", thCover.Seq(), wantCoverSeq)
	}
	if !cover.VerifyChecksums(sent[0].Data) || !realD.VerifyChecksums(sent[1].Data) {
		t.Errorf("контрольные суммы собранных пакетов неверны")
	}
}

// Короткий ClientHello (клиент без постквантового обмена) не длиннее cover'а
// tcp_overlap. Сырьём он ушёл бы с открытым SNI; вместо этого имя режется.
func TestShortHelloUnderOverlapIsSplitNotRaw(t *testing.T) {
	const name = "gateway.discord.example"
	hello, _ := buildFullHello(t, name, 100)
	if len(hello) >= 681 {
		t.Fatalf("контроль: hello %d байт, нужен короче cover'а", len(hello))
	}
	const seq = uint32(9000)
	src := capture.NewSyntheticSource(packetV4Seq(t, hello, core.DirectionOutbound, 50000, seq))
	sink := &capture.SyntheticSink{}
	e, err := New(Options{
		Source:   src,
		Sink:     sink,
		Flows:    flow.NewTable(16, time.Minute, TLSHelloDetector),
		Provider: fakeProvider{matchSNI: name, sel: proxy.Selection{Strategy: overlapStrategy(), ID: core.StrategyID("overlap")}},
		Exec:     packetexec.New(),
		Parse:    TLSHelloParser,

		ShortHelloFallback: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := e.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	sent := sink.Sent()
	if len(sent) != 2 {
		t.Fatalf("ожидалось 2 части hello, получено %d", len(sent))
	}
	stream := make([]byte, len(hello))
	covered := 0
	for _, p := range sent {
		d, _ := packet.Dissect(p.Data)
		pay, _ := d.Payload(p.Data)
		th, _ := d.TCP(p.Data)
		if bytes.Contains(pay, []byte(name)) {
			t.Fatal("имя ушло целиком в одном пакете")
		}
		copy(stream[th.Seq()-seq:], pay)
		covered += len(pay)
	}
	if covered != len(hello) || !bytes.Equal(stream, hello) {
		t.Fatal("части не складываются в исходный hello")
	}
}

func TestRunDelayedFlowDoesNotBlockOtherFlowsAndQueuesSameFlow(t *testing.T) {
	const delayMs = 200
	a := packetV4Port(t, helloPayload, core.DirectionOutbound, 50000)
	b := packetV4Port(t, []byte("B"), core.DirectionOutbound, 50001)
	a2 := packetV4Seq(t, []byte("A2"), core.DirectionOutbound, 50000, baseSeq+uint32(len(helloPayload)))
	sink := &timedSink{}
	e := buildEngine(t, capture.NewSyntheticSource(a, b, a2), sink, fixedParser("slow.example"),
		fakeProvider{matchSNI: "slow.example", sel: proxy.Selection{
			Strategy: delayedFragStrategy(5, delayMs), ID: core.StrategyID("delayed"),
		}})
	if err := e.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	packets := sink.snapshot()
	bIndex, delayedIndex, a2Index := -1, -1, -1
	for i, sent := range packets {
		switch {
		case sent.port == 50001 && string(sent.payload) == "B":
			bIndex = i
		case sent.port == 50000 && sent.seq == baseSeq+5:
			delayedIndex = i
		case sent.port == 50000 && string(sent.payload) == "A2":
			a2Index = i
		}
	}
	if bIndex < 0 || delayedIndex < 0 || a2Index < 0 {
		t.Fatalf("missing expected packets: B=%d delayed A=%d queued A2=%d; packets=%+v",
			bIndex, delayedIndex, a2Index, packets)
	}
	if bIndex > delayedIndex {
		t.Fatalf("flow B was sent at %d after flow A delayed op at %d", bIndex, delayedIndex)
	}
	if a2Index < delayedIndex {
		t.Fatalf("same-flow packet A2 was sent at %d before delayed op at %d", a2Index, delayedIndex)
	}
}

func TestRunWaitsForDelayedWorkerOnCancellation(t *testing.T) {
	exec := &cancellationExecutor{
		started: make(chan struct{}), release: make(chan struct{}), finished: make(chan struct{}),
	}
	source := &heldPacketSource{
		first: packetV4(t, helloPayload, core.DirectionOutbound),
		done:  make(chan struct{}), stopped: make(chan struct{}),
	}
	e, err := New(Options{
		Source: source, Sink: &timedSink{},
		Flows: flow.NewTable(16, time.Minute, testDetector),
		Provider: fakeProvider{matchSNI: "slow.example", sel: proxy.Selection{
			Strategy: delayedFragStrategy(5, 200), ID: core.StrategyID("delayed"),
		}},
		Exec: exec, Parse: fixedParser("slow.example"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.Run(ctx) }()
	select {
	case <-exec.started:
	case <-time.After(time.Second):
		t.Fatal("delayed executor did not start")
	}
	cancel()
	select {
	case <-source.stopped:
	case <-time.After(time.Second):
		t.Fatal("Run did not stop the source")
	}
	select {
	case err := <-done:
		t.Fatalf("Run returned before worker finished: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(exec.release)
	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatalf("Run error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not return after worker finished")
	}
	select {
	case <-exec.finished:
	default:
		t.Fatal("Run returned before worker completion")
	}
}

func TestStallAfterHandshakeReportsFailureOnce(t *testing.T) {
	seq := uint32(1000)
	appData := []byte{0x17, 0x03, 0x03, 0x00, 0x08, 1, 2, 3, 4, 5, 6, 7, 8}
	dataSeq := seq + uint32(len(helloPayload))
	packets := []capture.Packet{packetV4Seq(t, helloPayload, core.DirectionOutbound, 50000, seq)}
	for i := 0; i < 5; i++ {
		packets = append(packets, packetV4Seq(t, appData, core.DirectionOutbound, 50000, dataSeq))
	}
	sink := &capture.SyntheticSink{}
	provider := &failureRecordingProvider{StrategyProvider: fakeProvider{
		matchSNI: "youtube.com",
		sel:      proxy.Selection{Strategy: fragStrategy(5), ID: core.StrategyID("sid1"), Target: "youtube.com"},
	}}
	engine := buildEngine(t, capture.NewSyntheticSource(packets...), sink, fixedParser("youtube.com"), provider)
	if err := engine.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(provider.failures) != 1 || provider.failures[0] != (reportedFailure{sni: "youtube.com", id: "sid1"}) {
		t.Fatalf("ReportFailure calls = %v", provider.failures)
	}
	passed := 0
	for _, sent := range sink.Sent() {
		if bytes.Equal(sent.Data, packets[1].Data) {
			passed++
		}
	}
	if passed != 5 {
		t.Fatalf("сегменты с данными должны пройти без изменений: %d из 5", passed)
	}
}
