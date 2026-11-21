package proxy

import (
	"errors"
	"io"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/strategy"
)

// timeoutErr — ошибка, которую сеть выдаёт при истечении срока.
type timeoutErr struct{}

func (timeoutErr) Error() string   { return "таймаут" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

var _ net.Error = timeoutErr{}

// TestClassifyConn проверяет главное суждение прокси о стратегии на всех
// ветвях сразу. Суждение вынесено в чистую функцию именно для этого.
func TestClassifyConn(t *testing.T) {
	for _, tc := range []struct {
		name    string
		applied bool
		rr      relayResult
		outcome core.Outcome
		reason  core.Reason
	}{
		{
			// Главное правило классификации всего проекта: не применилась —
			// значит не проверялась, независимо от причины (вес 0, 5.7).
			name:    "стратегия не применялась",
			applied: false,
			rr:      relayResult{gotDown: true, firstDownByte: tlsRecordHandshake},
			outcome: core.OutcomeInconclusive,
			reason:  core.ReasonStrategyNotApplied,
		},
		{
			name:    "сервер начал рукопожатие",
			applied: true,
			rr:      relayResult{gotDown: true, firstDownByte: tlsRecordHandshake, down: 1500},
			outcome: core.OutcomeOK,
			reason:  core.ReasonHandshakeDone,
		},
		{
			// До сервера дошли, DPI обманут; чем недоволен сервер — не про
			// стратегию.
			name:    "сервер отказал предупреждением TLS",
			applied: true,
			rr:      relayResult{gotDown: true, firstDownByte: tlsRecordAlert, down: 7},
			outcome: core.OutcomeInconclusive,
			reason:  core.ReasonTLSRejected,
		},
		{
			name:    "ответ не похож на TLS, но он есть",
			applied: true,
			rr:      relayResult{gotDown: true, firstDownByte: 'H', down: 100},
			outcome: core.OutcomeOK,
			reason:  core.ReasonHandshakeDone,
		},
		{
			name:    "ответа нет, сервер сбросил",
			applied: true,
			rr:      relayResult{serverEndedFirst: true, downErr: syscall.ECONNRESET},
			outcome: core.OutcomeFail,
			reason:  core.ReasonReset,
		},
		{
			name:    "ответа нет, сервер закрыл тихо",
			applied: true,
			rr:      relayResult{serverEndedFirst: true, downErr: io.EOF},
			outcome: core.OutcomeFail,
			reason:  core.ReasonReset,
		},
		{
			name:    "ответа нет, истёк срок",
			applied: true,
			rr:      relayResult{serverEndedFirst: true, downErr: timeoutErr{}},
			outcome: core.OutcomeFail,
			reason:  core.ReasonTimeout,
		},
		{
			// Пользователь закрыл вкладку. Винить в этом стратегию нельзя —
			// иначе каждый передумавший человек портил бы ей оценку.
			name:    "ответа нет, но первым ушёл клиент",
			applied: true,
			rr:      relayResult{serverEndedFirst: false, up: 517},
			outcome: core.OutcomeInconclusive,
			reason:  core.ReasonCanceled,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			outcome, reason := classifyConn(tc.applied, tc.rr)
			if outcome != tc.outcome || reason != tc.reason {
				t.Fatalf("исход = %v/%q, ожидался %v/%q", outcome, reason, tc.outcome, tc.reason)
			}
		})
	}
}

// TestDownstreamWatcherRecordsFirstByte: исход определяется первым ответом
// сервера, поэтому запомнить его обязательно — и ровно один раз.
func TestDownstreamWatcherRecordsFirstByte(t *testing.T) {
	w := &downstreamWatcher{r: newChunkReader([][]byte{{tlsRecordHandshake, 0x03}, {0x01, 0x02}}), start: time.Now()}

	buf := make([]byte, 8)
	if _, err := w.Read(buf); err != nil {
		t.Fatalf("первое чтение: %v", err)
	}
	if !w.got || w.firstByte != tlsRecordHandshake {
		t.Fatalf("первый байт = %#x, признак %v", w.firstByte, w.got)
	}
	if !w.measured {
		t.Fatal("признак измерения обязан быть выставлен: нулевая задержка законна")
	}

	if _, err := w.Read(buf); err != nil {
		t.Fatalf("второе чтение: %v", err)
	}
	if w.firstByte != tlsRecordHandshake {
		t.Fatal("первый байт не должен переписываться следующими чтениями")
	}
}

// TestDownstreamWatcherSilentServer: сервер, не ответивший ничего, не должен
// оставлять признака измерения — иначе нулевая задержка читалась бы как
// мгновенный ответ.
func TestDownstreamWatcherSilentServer(t *testing.T) {
	w := &downstreamWatcher{r: newChunkReader(nil), start: time.Now()}
	buf := make([]byte, 8)
	if _, err := w.Read(buf); !errors.Is(err, io.EOF) {
		t.Fatalf("ошибка = %v, ожидался io.EOF", err)
	}
	if w.got || w.measured {
		t.Fatal("без ответа сервера ни признака ответа, ни признака измерения быть не должно")
	}
}

// chunkReader отдаёт заранее заданные порции, затем io.EOF.
type chunkReader struct {
	chunks [][]byte
}

func newChunkReader(chunks [][]byte) *chunkReader { return &chunkReader{chunks: chunks} }

func (r *chunkReader) Read(p []byte) (int, error) {
	if len(r.chunks) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.chunks[0])
	r.chunks = r.chunks[1:]
	return n, nil
}

// recordingSink — приёмник исходов для тестов.
type recordingSink struct {
	mu   sync.Mutex
	list []ConnOutcome
}

func (s *recordingSink) ConnOutcome(o ConnOutcome) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.list = append(s.list, o)
}

func (s *recordingSink) wait(t *testing.T, n int) []ConnOutcome {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		s.mu.Lock()
		got := len(s.list)
		s.mu.Unlock()
		if got >= n {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("исходов получено %d, ожидалось %d", got, n)
		}
		time.Sleep(5 * time.Millisecond)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ConnOutcome, len(s.list))
	copy(out, s.list)
	return out
}

// TestServerReportsSuccessOutcome — сквозная проверка: соединение прошло через
// настоящий SOCKS, стратегия применилась, сервер ответил рукопожатием, и
// исход дошёл до приёмника с целью радиуса и признаком применения.
func TestServerReportsSuccessOutcome(t *testing.T) {
	sink := &recordingSink{}
	s := splitStrategy(5)
	id := mustComputeID(t, s)

	addr, up := startServer(t, Config{
		Provider: fixedProvider{sel: Selection{
			Strategy: s, ID: id, Target: "youtube.com", Trial: true,
		}},
		Outcomes: sink,
	})

	client, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	socksConnect(t, client, "www.youtube.com", 443)

	hello := fakeClientHello("www.youtube.com")
	if _, err := client.Write(hello); err != nil {
		t.Fatalf("отправка ClientHello: %v", err)
	}
	// Начало потока вычерпывается ЦЕЛИКОМ, а не первой порцией. Стратегия
	// режет ClientHello на части, а подставной апстрим — net.Pipe, то есть
	// синхронная труба без буфера: не прочитав вторую часть, тест заблокирует
	// прокси на записи, а сам заблокируется на ответе. Первая версия теста
	// именно так и зависла.
	readWithTimeout(t, up.serverSide, len(hello))
	if _, err := up.serverSide.Write([]byte{tlsRecordHandshake, 0x03, 0x03, 0x00, 0x01, 0x00}); err != nil {
		t.Fatalf("ответ сервера: %v", err)
	}
	// Закрываем обе стороны, чтобы соединение завершилось.
	_ = up.serverSide.Close()
	_ = client.Close()

	got := sink.wait(t, 1)[0]
	if got.Outcome != core.OutcomeOK || got.Reason != core.ReasonHandshakeDone {
		t.Fatalf("исход = %v/%q, ожидался ok/handshake_done", got.Outcome, got.Reason)
	}
	if got.Target != "youtube.com" {
		t.Fatalf("цель = %q, ожидалась youtube.com (цель радиуса, а не имя соединения)", got.Target)
	}
	if got.StrategyID != id || !got.StrategyApplied || !got.Trial {
		t.Fatalf("исход не связан со стратегией: %+v", got)
	}
	if !got.FirstByteMeasured {
		t.Fatal("задержка первого байта обязана быть измерена при полученном ответе")
	}
}

// TestServerReportsNotAppliedOutcome: соединение без ClientHello стратегию не
// проверяет, и исход обязан быть «не определено» — иначе обычный HTTP через
// прокси портил бы оценку стратегии.
func TestServerReportsNotAppliedOutcome(t *testing.T) {
	sink := &recordingSink{}
	s := splitStrategy(5)

	addr, up := startServer(t, Config{
		Provider: fixedProvider{sel: Selection{
			Strategy: s, ID: mustComputeID(t, s), Target: "youtube.com",
		}},
		Outcomes:     sink,
		HelloTimeout: 150 * time.Millisecond,
	})

	client, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	socksConnect(t, client, "www.youtube.com", 443)

	// Не TLS: обычный текст. Он проходит без изменений, одной записью.
	plain := []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	if _, err := client.Write(plain); err != nil {
		t.Fatalf("отправка: %v", err)
	}
	readWithTimeout(t, up.serverSide, len(plain))
	_ = up.serverSide.Close()
	_ = client.Close()

	got := sink.wait(t, 1)[0]
	if got.Outcome != core.OutcomeInconclusive || got.Reason != core.ReasonStrategyNotApplied {
		t.Fatalf("исход = %v/%q, ожидался inconclusive/strategy_not_applied", got.Outcome, got.Reason)
	}
	if got.StrategyApplied {
		t.Fatal("признак применения не должен быть выставлен")
	}
}

// TestServerWithoutSinkWorks: прокси обязан работать и без приёмника исходов —
// так он и работал весь этап 0 до появления контура.
func TestServerWithoutSinkWorks(t *testing.T) {
	s := splitStrategy(5)
	addr, up := startServer(t, Config{
		Provider: fixedProvider{sel: Selection{Strategy: s, ID: mustComputeID(t, s)}},
	})

	client, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	socksConnect(t, client, "www.youtube.com", 443)
	hello := fakeClientHello("www.youtube.com")
	if _, err := client.Write(hello); err != nil {
		t.Fatalf("отправка: %v", err)
	}
	readWithTimeout(t, up.serverSide, len(hello))
	_ = client.Close()
	_ = up.serverSide.Close()
}

// mustComputeID считает идентификатор стратегии для теста.
func mustComputeID(t *testing.T, s *strategy.Strategy) core.StrategyID {
	t.Helper()
	id, err := strategy.ComputeID(s)
	if err != nil {
		t.Fatalf("ComputeID: %v", err)
	}
	return id
}

// fixedProvider отдаёт заранее заданный выбор всем соединениям.
type fixedProvider struct{ sel Selection }

func (p fixedProvider) Select(ConnMeta) Selection { return p.sel }
