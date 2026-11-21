package probe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/socketexec"
	"github.com/fitting-1c/evasion/internal/strategy"
)

// selfSignedCert создаёт самоподписанный сертификат для локального сервера.
//
// Нужен потому, что проба измеряется на настоящем рукопожатии TLS: подделать
// его нечем, а внешняя сеть в тестах недопустима. Подлинность пробы не
// проверяют (см. doc.go), поэтому самоподписанный сертификат здесь не
// упрощение, а ровно то, с чем проба и работает.
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("генерация ключа: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "probe.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"probe.test"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("создание сертификата: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// serverBehaviour задаёт, как подставной сервер ведёт себя после рукопожатия.
type serverBehaviour int

const (
	// serveEcho отвечает минимальным ответом HTTP заданного размера.
	serveEcho serverBehaviour = iota
	// serveDropBeforeHandshake закрывает соединение, не отвечая на
	// ClientHello: так выглядит молчаливое отбрасывание цензором.
	serveDropBeforeHandshake
	// serveSilent принимает соединение и ничего не делает до закрытия теста:
	// так выглядит зависание.
	serveSilent
	// serveTrickle отдаёт тело порциями с паузами, растягивая передачу на
	// измеримое время. Нужен медленному уровню: мгновенный ответ по петле
	// укладывается в разрешение таймера, и скорость по нему не вычислить.
	serveTrickle
)

// trickleChunks, trickleChunkSize, trickleDelay задают форму медленной
// передачи. Произведение числа порций на паузу должно заметно превышать
// minThroughputWindow, иначе окно снова окажется неизмеримым.
const (
	trickleChunks    = 10
	trickleChunkSize = 8 << 10
	trickleDelay     = 20 * time.Millisecond
)

// startServer поднимает локальный сервер и возвращает его адрес.
func startServer(t *testing.T, behaviour serverBehaviour, bodySize int) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	cert := selfSignedCert(t)
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}

	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				switch behaviour {
				case serveDropBeforeHandshake:
					// Закрываем сразу: клиент увидит обрыв на рукопожатии.
					return
				case serveSilent:
					// Держим соединение открытым, не отвечая.
					<-time.After(30 * time.Second)
					return
				}

				tc := tls.Server(c, cfg)
				if err := tc.Handshake(); err != nil {
					return
				}
				// Дочитываем запрос до конца заголовков и отвечаем телом
				// заданного размера.
				buf := make([]byte, 4096)
				_ = tc.SetReadDeadline(time.Now().Add(5 * time.Second))
				_, _ = tc.Read(buf)

				size := bodySize
				if behaviour == serveTrickle {
					size = trickleChunks * trickleChunkSize
				}
				body := make([]byte, size)
				for i := range body {
					body[i] = 'x'
				}
				hdr := "HTTP/1.1 200 OK\r\nContent-Length: " +
					itoa(len(body)) + "\r\nConnection: close\r\n\r\n"
				_ = tc.SetWriteDeadline(time.Now().Add(30 * time.Second))
				_, _ = io.WriteString(tc, hdr)

				if behaviour != serveTrickle {
					_, _ = tc.Write(body)
					return
				}
				for off := 0; off < len(body); off += trickleChunkSize {
					end := off + trickleChunkSize
					if end > len(body) {
						end = len(body)
					}
					if _, err := tc.Write(body[off:end]); err != nil {
						return
					}
					time.Sleep(trickleDelay)
				}
			}(raw)
		}
	}()
	return ln.Addr().String()
}

// itoa — перевод числа в строку без обращения к strconv, чтобы не тащить
// импорт ради одной строки заголовка.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// splitInsideSNI — стратегия с разрезом внутри имени сервера.
func splitInsideSNI() *strategy.Strategy {
	return &strategy.Strategy{Rules: []strategy.Rule{{
		Direction: core.DirectionOutbound,
		Trigger:   strategy.Trigger{Match: strategy.MatchClientHello},
		Action: &strategy.Action{
			Kind:   core.ActionFragment,
			Params: &strategy.FragmentParams{Proto: strategy.FragTCP, At: core.CutInsideSNI},
			Left:   &strategy.Action{Kind: core.ActionSend},
			Right:  &strategy.Action{Kind: core.ActionSend},
		},
	}}}
}

// newProber создаёт пробник с исполнителем режима прокси.
func newProber(t *testing.T, cfg Config) *Prober {
	t.Helper()
	cfg.Executor = socketexec.New()
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

func TestNewRequiresExecutor(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("пробник без исполнителя должен отвергаться")
	}
}

func TestFastHandshakeSucceedsWithStrategy(t *testing.T) {
	addr := startServer(t, serveEcho, 1024)
	p := newProber(t, Config{})

	res := p.Fast(context.Background(), Request{
		Target:     addr,
		SNI:        "probe.test",
		Strategy:   splitInsideSNI(),
		StrategyID: core.StrategyID("test"),
	})

	if res.Outcome != core.OutcomeOK {
		t.Fatalf("исход %v, причина %q, ошибка %q", res.Outcome, res.Reason, res.Err)
	}
	if res.Reason != core.ReasonHandshakeDone {
		t.Fatalf("причина %q", res.Reason)
	}
	if !res.StrategyApplied {
		t.Fatal("стратегия помечена как не применённая, хотя рукопожатие прошло")
	}
	if res.Phase != core.PhaseFast {
		t.Fatalf("уровень %v", res.Phase)
	}
	// Проверяется ПРИЗНАК установки соединения, а не его длительность.
	//
	// Требовать ConnectRTT > 0 нельзя: на Windows разрешение таймера грубое, и
	// петлевое соединение устанавливается быстрее, чем таймер успевает это
	// заметить. Прежняя проверка была плавающей — падала через прогон.
	if !res.Connected {
		t.Fatal("соединение не отмечено как установленное, хотя рукопожатие прошло")
	}
	if res.ConnectRTT < 0 || res.HandshakeTime < 0 {
		t.Fatalf("отрицательные тайминги: рукопожатие %v, соединение %v",
			res.HandshakeTime, res.ConnectRTT)
	}
}

func TestFastHandshakeSucceedsWithoutStrategy(t *testing.T) {
	// Проба без стратегии измеряет только доступность цели. Признак
	// применения обязан быть ложным: иначе наблюдение приписалось бы
	// стратегии, которой не было.
	addr := startServer(t, serveEcho, 128)
	p := newProber(t, Config{})

	res := p.Fast(context.Background(), Request{Target: addr, SNI: "probe.test"})
	if res.Outcome != core.OutcomeOK {
		t.Fatalf("исход %v, ошибка %q", res.Outcome, res.Err)
	}
	if res.StrategyApplied {
		t.Fatal("стратегия помечена применённой при её отсутствии")
	}
}

func TestFastDropBeforeHandshakeIsFail(t *testing.T) {
	// Сервер закрывает соединение, не ответив на ClientHello — так выглядит
	// вмешательство. Это полноценный провал: ClientHello отправлен, значит
	// стратегия проверена.
	addr := startServer(t, serveDropBeforeHandshake, 0)
	p := newProber(t, Config{})

	res := p.Fast(context.Background(), Request{
		Target:   addr,
		SNI:      "probe.test",
		Strategy: splitInsideSNI(),
	})
	if res.Outcome != core.OutcomeFail {
		t.Fatalf("исход %v, причина %q, ошибка %q", res.Outcome, res.Reason, res.Err)
	}
	if !res.StrategyApplied {
		t.Fatal("стратегия должна считаться применённой: ClientHello был отправлен")
	}
}

func TestFastHangIsFailByTimeout(t *testing.T) {
	// Зависание: сервер принял соединение и молчит. Вердикт должен прийти по
	// сроку ожидания, а не через минуты.
	addr := startServer(t, serveSilent, 0)
	p := newProber(t, Config{MinTimeout: 300 * time.Millisecond})

	start := time.Now()
	res := p.Fast(context.Background(), Request{Target: addr, SNI: "probe.test"})
	elapsed := time.Since(start)

	if res.Outcome != core.OutcomeFail {
		t.Fatalf("исход %v, причина %q", res.Outcome, res.Reason)
	}
	if res.Reason != core.ReasonTimeout {
		t.Fatalf("причина %q, ожидалось %q", res.Reason, core.ReasonTimeout)
	}
	// Срок ожидания соблюдён: вердикт не позже него с разумным запасом.
	if elapsed > 3*time.Second {
		t.Fatalf("вердикт пришёл через %v при сроке 300мс", elapsed)
	}
}

func TestFastDialFailureIsInconclusive(t *testing.T) {
	// Главное правило классификации: если ClientHello не отправлялся,
	// стратегия не проверялась, и наблюдение не должно считаться провалом.
	p := newProber(t, Config{MinTimeout: 500 * time.Millisecond})

	res := p.Fast(context.Background(), Request{
		Target:   "нет-такого-имени.invalid:443",
		SNI:      "нет-такого-имени.invalid",
		Strategy: splitInsideSNI(),
	})
	if res.Outcome != core.OutcomeInconclusive {
		t.Fatalf("исход %v, причина %q", res.Outcome, res.Reason)
	}
	if res.Reason != core.ReasonResolveFailed && res.Reason != core.ReasonConnectFailed && res.Reason != core.ReasonTimeout {
		t.Fatalf("неожиданная причина %q", res.Reason)
	}
	if res.StrategyApplied {
		t.Fatal("стратегия помечена применённой, хотя соединение не установилось")
	}
}

func TestFastUnappliedStrategyIsInconclusive(t *testing.T) {
	// Цель задана адресом, поэтому crypto/tls не отправляет имя сервера, и
	// точка разреза «внутри имени» недоступна. Стратегия не применяется, и
	// наблюдение обязано стать неопределённым: про цензора оно не говорит
	// ничего.
	addr := startServer(t, serveDropBeforeHandshake, 0)
	p := newProber(t, Config{MinTimeout: time.Second})

	res := p.Fast(context.Background(), Request{
		Target:   addr,
		SNI:      "127.0.0.1",
		Strategy: splitInsideSNI(),
	})
	if res.StrategyApplied {
		t.Fatal("стратегия помечена применённой при недоступной точке разреза")
	}
	if res.Outcome != core.OutcomeInconclusive {
		t.Fatalf("исход %v, причина %q, ошибка %q", res.Outcome, res.Reason, res.Err)
	}
	if res.Reason != core.ReasonStrategyNotApplied {
		t.Fatalf("причина %q, ожидалось %q", res.Reason, core.ReasonStrategyNotApplied)
	}
}

func TestSlowMeasuresThroughput(t *testing.T) {
	// Передача растянута порциями, поэтому окно наблюдения измеримо.
	addr := startServer(t, serveTrickle, 0)
	p := newProber(t, Config{SlowWindow: 10 * time.Second})

	res := p.Slow(context.Background(), Request{
		Target:   addr,
		SNI:      "probe.test",
		Strategy: splitInsideSNI(),
	})
	if res.Outcome != core.OutcomeOK {
		t.Fatalf("исход %v, причина %q, ошибка %q", res.Outcome, res.Reason, res.Err)
	}
	if res.Phase != core.PhaseSlow {
		t.Fatalf("уровень %v", res.Phase)
	}
	if want := int64(trickleChunks * trickleChunkSize); res.BytesDown < want {
		t.Fatalf("принято %d байт, ожидалось не меньше %d", res.BytesDown, want)
	}
	if !res.ThroughputMeasured {
		t.Fatal("скорость не измерена при растянутой передаче")
	}
	if res.Throughput <= 0 {
		t.Fatalf("скорость %d при измеренном окне", res.Throughput)
	}
}

func TestSlowBelowThresholdIsThrottled(t *testing.T) {
	// Передача растянута, скорость измерима, порог заведомо выше неё.
	addr := startServer(t, serveTrickle, 0)
	p := newProber(t, Config{SlowWindow: 10 * time.Second, MinThroughput: 1 << 30})

	res := p.Slow(context.Background(), Request{Target: addr, SNI: "probe.test"})
	if !res.ThroughputMeasured {
		t.Fatal("скорость не измерена: проверка порога ничего не доказывает")
	}
	if res.Outcome != core.OutcomeThrottled {
		t.Fatalf("исход %v, причина %q, скорость %d", res.Outcome, res.Reason, res.Throughput)
	}
	if res.Reason != core.ReasonThroughputLow {
		t.Fatalf("причина %q", res.Reason)
	}
}

// TestSlowFastResponseIsNotThrottled — защита от дефекта, найденного прогоном
// на Windows.
//
// Ответ приходит мгновенно, окно наблюдения оказывается короче разрешения
// таймера. Прежде скорость считалась делением на это окно и выходила нулевой,
// а ноль ниже любого порога — и мгновенный ответ объявлялся замедлением.
// Рабочая стратегия получала бы штраф за то, что сработала слишком хорошо.
//
// Правильное поведение: скорость не измерена, вердикта о замедлении нет.
func TestSlowFastResponseIsNotThrottled(t *testing.T) {
	addr := startServer(t, serveEcho, 512)
	p := newProber(t, Config{SlowWindow: 5 * time.Second, MinThroughput: 1 << 30})

	res := p.Slow(context.Background(), Request{Target: addr, SNI: "probe.test"})
	if res.Outcome == core.OutcomeThrottled {
		t.Fatalf("мгновенный ответ объявлен замедлением: скорость %d, измерена=%t",
			res.Throughput, res.ThroughputMeasured)
	}
	if res.Outcome != core.OutcomeOK {
		t.Fatalf("исход %v, причина %q, ошибка %q", res.Outcome, res.Reason, res.Err)
	}
	if res.ThroughputMeasured {
		t.Skip("окно оказалось измеримым: на этой машине таймер точнее, проверка неприменима")
	}
	if res.Throughput != 0 {
		t.Fatalf("скорость %d при неизмеренном окне", res.Throughput)
	}
}

func TestTimeoutDerivedFromBaseRTT(t *testing.T) {
	p := newProber(t, Config{
		MinTimeout: 100 * time.Millisecond,
		MaxTimeout: 2 * time.Second,
		RTTFactor:  10,
	})

	// Без измеренного RTT берётся нижняя граница: догадываться не о чем.
	if got := p.timeout(); got != 100*time.Millisecond {
		t.Fatalf("без базового RTT срок %v", got)
	}

	// Кратность применяется.
	p.SetBaseRTT(50 * time.Millisecond)
	if got := p.timeout(); got != 500*time.Millisecond {
		t.Fatalf("при RTT 50мс и кратности 10 срок %v", got)
	}

	// Нижняя граница держит: на очень быстром канале срок не должен падать
	// до микросекунд, иначе рабочая стратегия объявлялась бы провалом.
	p.SetBaseRTT(time.Millisecond)
	if got := p.timeout(); got != 100*time.Millisecond {
		t.Fatalf("при RTT 1мс срок %v, ожидалась нижняя граница", got)
	}

	// Верхняя граница держит: единственный выброс в измерении не должен
	// растягивать каждую последующую пробу.
	p.SetBaseRTT(10 * time.Second)
	if got := p.timeout(); got != 2*time.Second {
		t.Fatalf("при RTT 10с срок %v, ожидалась верхняя граница", got)
	}
}

func TestSetBaseRTTIgnoresNonPositive(t *testing.T) {
	p := newProber(t, Config{})
	p.SetBaseRTT(40 * time.Millisecond)
	p.SetBaseRTT(0)
	p.SetBaseRTT(-time.Second)
	if p.BaseRTT() != 40*time.Millisecond {
		t.Fatalf("базовый RTT испорчен нулём или отрицательным значением: %v", p.BaseRTT())
	}
}

func TestMeasureBaseRTTTakesMinimum(t *testing.T) {
	// Берётся наименьшее из удачных измерений: единственная задержка из-за
	// занятости сервера завысила бы среднее и растянула бы сроки всех
	// последующих проб.
	fast := startServer(t, serveEcho, 0)
	slowAddr := startServer(t, serveEcho, 0)

	var delays = map[string]time.Duration{slowAddr: 200 * time.Millisecond}
	p := newProber(t, Config{Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		if d, ok := delays[address]; ok {
			select {
			case <-time.After(d):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		var dl net.Dialer
		return dl.DialContext(ctx, network, address)
	}})

	rtt, err := p.MeasureBaseRTT(context.Background(), []string{slowAddr, fast})
	if err != nil {
		t.Fatalf("MeasureBaseRTT: %v", err)
	}
	if rtt >= 200*time.Millisecond {
		t.Fatalf("взято не наименьшее измерение: %v", rtt)
	}
	// Ноль здесь законен: по петле соединение устанавливается быстрее
	// разрешения таймера на Windows. Главное, что ошибки нет и значение не
	// равно задержанному измерению.
	if rtt > 0 && p.BaseRTT() != rtt {
		t.Fatalf("измерение не сохранено: %v против %v", p.BaseRTT(), rtt)
	}
}

func TestMeasureBaseRTTNoTargets(t *testing.T) {
	p := newProber(t, Config{})
	if _, err := p.MeasureBaseRTT(context.Background(), nil); err == nil {
		t.Fatal("измерение без целей должно давать ошибку")
	}
}

func TestMeasureBaseRTTAllUnreachable(t *testing.T) {
	p := newProber(t, Config{MaxTimeout: 300 * time.Millisecond})
	_, err := p.MeasureBaseRTT(context.Background(), []string{"нет-такого.invalid:443"})
	if err == nil {
		t.Fatal("при недоступных целях ожидалась ошибка")
	}
	if p.BaseRTT() != 0 {
		t.Fatalf("базовый RTT изменён при неудачном измерении: %v", p.BaseRTT())
	}
}

func TestCanceledContextIsInconclusive(t *testing.T) {
	// Отмена извне — не свойство стратегии, и провалом считаться не должна.
	addr := startServer(t, serveSilent, 0)
	p := newProber(t, Config{MinTimeout: 5 * time.Second})

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	res := p.Fast(ctx, Request{Target: addr, SNI: "probe.test", Strategy: splitInsideSNI()})
	if res.Outcome != core.OutcomeInconclusive {
		t.Fatalf("исход %v, причина %q, ошибка %q", res.Outcome, res.Reason, res.Err)
	}
	if res.Reason != core.ReasonCanceled {
		t.Fatalf("причина %q, ожидалось %q", res.Reason, core.ReasonCanceled)
	}
}

func TestOutcomeAndPhaseTokens(t *testing.T) {
	for _, o := range []core.Outcome{core.OutcomeInconclusive, core.OutcomeOK, core.OutcomeThrottled, core.OutcomeFail} {
		text, err := o.MarshalText()
		if err != nil {
			t.Fatalf("MarshalText(%v): %v", o, err)
		}
		var back core.Outcome
		if err := back.UnmarshalText(text); err != nil {
			t.Fatalf("UnmarshalText(%q): %v", text, err)
		}
		if back != o {
			t.Fatalf("круговой перенос %v дал %v", o, back)
		}
	}

	var o core.Outcome
	if err := o.UnmarshalText([]byte("не-такой-исход")); err == nil {
		t.Fatal("неизвестное обозначение исхода должно отвергаться")
	} else {
		var ute *core.UnknownTokenError
		if !errors.As(err, &ute) {
			t.Fatalf("ожидалась UnknownTokenError, получено %T", err)
		}
	}

	if core.PhaseFast.String() != "fast" || core.PhaseSlow.String() != "slow" {
		t.Fatal("обозначения уровней неверны")
	}
}

func TestZeroOutcomeIsInconclusive(t *testing.T) {
	// Незаполненный результат не должен выглядеть успехом.
	var res Result
	if res.Outcome != core.OutcomeInconclusive {
		t.Fatalf("нулевой исход %v", res.Outcome)
	}
}

// TestPickMinRTTHandlesZero — проверка дефекта, найденного прогоном на Windows.
//
// Там разрешение таймера грубое, и соединение по петле измеряется ровно нулём.
// Прежде ноль служил признаком «измерений не было», и быстрый канал выглядел
// как недоступная цель: MeasureBaseRTT возвращал ошибку при полностью удачных
// измерениях.
//
// Через настоящие соединения это проверяется только на Windows, поэтому
// проверяется чистая функция выбора минимума.
func TestPickMinRTTHandlesZero(t *testing.T) {
	cases := []struct {
		name         string
		samples      []time.Duration
		wantBest     time.Duration
		wantMeasured bool
	}{
		{"измерений нет", nil, 0, false},
		{"единственный ноль — законное измерение", []time.Duration{0}, 0, true},
		{"ноль наименьший среди прочих", []time.Duration{200 * time.Millisecond, 0}, 0, true},
		{"обычный минимум", []time.Duration{200 * time.Millisecond, 30 * time.Millisecond}, 30 * time.Millisecond, true},
		{"порядок не важен", []time.Duration{30 * time.Millisecond, 200 * time.Millisecond}, 30 * time.Millisecond, true},
		{"отрицательное отбрасывается", []time.Duration{-time.Second, 50 * time.Millisecond}, 50 * time.Millisecond, true},
		{"только отрицательное", []time.Duration{-time.Second}, 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			best, measured := pickMinRTT(c.samples)
			if measured != c.wantMeasured {
				t.Fatalf("признак измерения %t, ожидался %t", measured, c.wantMeasured)
			}
			if best != c.wantBest {
				t.Fatalf("минимум %v, ожидался %v", best, c.wantBest)
			}
		})
	}
}

// TestConnectedDistinguishesFastFromFailed — третий случай того же класса
// ошибки, что ThroughputMeasured и StrategyApplied.
//
// Мгновенная установка соединения и её отсутствие дают одинаковый ConnectRTT,
// равный нулю, когда разрешение таймера грубое. Различает их только признак
// Connected, и потребителю (scoring, control) без него пришлось бы гадать.
func TestConnectedDistinguishesFastFromFailed(t *testing.T) {
	addr := startServer(t, serveEcho, 128)
	p := newProber(t, Config{MinTimeout: time.Second})

	ok := p.Fast(context.Background(), Request{Target: addr, SNI: "probe.test"})
	if !ok.Connected {
		t.Fatal("удачная проба: соединение не отмечено установленным")
	}

	bad := p.Fast(context.Background(), Request{
		Target: "нет-такого-имени.invalid:443",
		SNI:    "нет-такого-имени.invalid",
	})
	if bad.Connected {
		t.Fatal("неудачная проба: соединение отмечено установленным")
	}
	if bad.ConnectRTT != 0 {
		t.Fatalf("время установки %v при неустановленном соединении", bad.ConnectRTT)
	}
}
