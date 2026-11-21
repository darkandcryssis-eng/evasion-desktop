package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/fitting-1c/evasion/internal/capture"
	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/discordvoice"
	"github.com/fitting-1c/evasion/internal/packet"
	"github.com/fitting-1c/evasion/internal/quicfake"
	"github.com/fitting-1c/evasion/internal/windivert"
)

// maxStrictEndpoints — сколько первых адресов «куда ушёл строгий 74-байтный»
// запоминать для вывода в логе. Ограничено сознательно: нужно подтверждение
// «идёт к серверу Discord», а не список-ведро.
const maxStrictEndpoints = 10

// shapedCount — результат разбора UDP-датаграммы на предмет формы Discord IP
// discovery. Поля намеренно независимые: мягкий счётчик (`len==74`) оставлен
// как было ради диагностики — он даёт верхнюю оценку, а строгий
// (`IsIPDiscoveryRequest`) отвечает на вопрос «это точно начало голоса».
// Их расхождение сразу показывает, сколько шума в мягком счётчике.
type shapedCount struct {
	loose    bool   // полезная нагрузка UDP ровно 74 байта (любая форма)
	strict   bool   // строгая форма: тип 0x0001, поле длины 70
	endpoint string // dstIP:port — куда ушла строгая датаграмма (пусто при loose без strict)
}

// tallyUDPShaped классифицирует UDP-датаграмму по форме Discord IP discovery.
//
// Чистая функция без состояния — проверяется офлайн без WinDivert, без петли.
// Если пакет не UDP или разбор не прошёл, возвращает нулевое значение (ни
// мягкого, ни строгого попадания): отсутствие сигнала, а не ошибка.
// Диссекция принимается параметром, чтобы вызывающий не делал двойной разбор:
// на горячем пути он уже есть.
func tallyUDPShaped(buf []byte, d packet.Dissection) shapedCount {
	if d.Protocol != packet.ProtoUDP {
		return shapedCount{}
	}
	pl, ok := d.Payload(buf)
	if !ok {
		return shapedCount{}
	}
	var out shapedCount
	if len(pl) == 74 {
		out.loose = true
	}
	if discordvoice.IsIPDiscoveryRequest(pl) {
		out.strict = true
		out.endpoint = udpDstEndpoint(buf, d)
	}
	return out
}

// udpDstEndpoint возвращает строку "ip:port" адресата UDP-датаграммы.
// Пустая строка — если разбор заголовков не сложился (вызывающий тогда просто
// не логирует точку назначения, не теряя сам факт попадания).
func udpDstEndpoint(buf []byte, d packet.Dissection) string {
	uh, ok := d.UDP(buf)
	if !ok {
		return ""
	}
	var ip net.IP
	switch d.Version {
	case packet.Version4:
		if h, ok := d.IPv4(buf); ok {
			ip = net.IP(h.Dst()).To4()
		}
	case packet.Version6:
		if h, ok := d.IPv6(buf); ok {
			ip = net.IP(h.Dst()).To16()
		}
	}
	if ip == nil {
		return ""
	}
	return net.JoinHostPort(ip.String(), fmt.Sprintf("%d", uh.DstPort()))
}

// appendStrictEndpoint добавляет адрес к набору первых maxStrictEndpoints
// строгих хитов, если ещё есть место и адрес не пустой. Возвращает обновлённый
// срез. Выделено отдельной функцией, чтобы и UDP-скан, и QUIC-петля вели набор
// одинаково — одно место правит правила один раз на оба счётчика.
func appendStrictEndpoint(dst []string, ep string) []string {
	if ep == "" || len(dst) >= maxStrictEndpoints {
		return dst
	}
	return append(dst, ep)
}

// voiceFilter captures only Discord IP discovery requests on any non-QUIC port.
// RTP, ordinary UDP and DNS stay in the kernel rather than making a userspace
// round trip. buildVoiceDecoys validates the discovery signature again.
const voiceFilter = "outbound and udp and udp.DstPort != 443 and udp.PayloadLength == 74 and udp.Payload16[0] == 0x0001 and udp.Payload16[1] == 70 and not impostor"

const (
	// voiceDecoyRepeats — сколько decoy слать перед настоящим пакетом. Шесть,
	// как в рабочих конфигах аналогов (--dpi-desync-repeats=6): DPI классифицирует
	// UDP-поток по первым нескольким пакетам, и чем больше decoy он увидит ПЕРЕД
	// настоящим началом голоса, тем вернее закроет поток как посторонний и не
	// тронет ни настоящий IP discovery, ни последующий RTP.
	voiceDecoyRepeats = 6
	// voiceDecoyTTL — TTL/hop limit живого decoy: доходит до DPI, умирает до
	// сервера. Малое значение; точное — предмет живого подбора (2.5).
	voiceDecoyTTL = 6
	// voiceBadsumTTL — TTL decoy с битой суммой: ему нужно дойти до DPI на любом
	// расстоянии, а сервер отбросит его по сумме.
	voiceBadsumTTL = 64
	// voiceReportEvery — не чаще этого срока пишется сводка десинка голоса.
	voiceReportEvery = 30 * time.Second
)

// voicePayload — выбор нагрузки UDP-decoy голоса.
//
// Исторически decoy нёс нейтральные байты (не 0x0001, тип не Discord IP
// discovery) — DPI видел «посторонний» первый пакет. С добавлением QUIC-пресета
// decoy вместо нейтральных байт несёт байты, похожие на QUIC v1 Initial
// long-header: DPI классифицирует UDP-поток как QUIC к постороннему хосту, что
// точнее уводит его от классификации «голос Discord».
type voicePayload uint8

const (
	// voicePayloadNeutral — исторический decoy: детерминированный узор, не
	// начинающийся с 0x0001.
	voicePayloadNeutral voicePayload = iota
	// voicePayloadQUIC — QUIC v1 Initial long-header с нейтральным DCID.
	// Срабатывает на DPI, который классифицирует UDP-потоки по форме первого
	// пакета (большинство современных).
	voicePayloadQUIC
)

// voiceMode — настройка десинка голоса: включён ли, каким приёмом, с какой
// нагрузкой decoy, либо режим сканирования портов (диагностика).
type voiceMode struct {
	enabled bool
	fool    discordvoice.Fooling
	payload voicePayload
	// probe — режим сканера: ничего не десинкуем, только смотрим, на какие
	// порты и какого размера идёт исходящий UDP. Нужен, чтобы НАЙТИ, где у
	// конкретного провайдера живёт голосовой UDP Discord, прежде чем его
	// десинкать (мерить, потом чинить, 8.1).
	probe bool
}

// parseVoiceMode разбирает значение флага --voice.
//
// Форматы:
//
//	off | ""        выключен
//	ttl             живой decoy с коротким TTL, нейтральная нагрузка
//	badsum          decoy с битой UDP-суммой, нейтральная нагрузка
//	ttl-quic        TTL + QUIC v1 Initial-подобная нагрузка (benign-QUIC)
//	badsum-quic     badsum + benign-QUIC
//	probe           сканер UDP-портов (ничего не десинкуем, диагностика)
//
// По умолчанию (пустая строка) выключено: приём экспериментальный и трогает
// UDP, поэтому включается осознанно. Неизвестное значение — внятная ошибка, а
// не молчаливое выключение.
func parseVoiceMode(s string) (voiceMode, error) {
	switch s {
	case "", "off":
		return voiceMode{enabled: false}, nil
	case "ttl":
		return voiceMode{enabled: true, fool: discordvoice.FoolTTL, payload: voicePayloadNeutral}, nil
	case "ttl-quic":
		return voiceMode{enabled: true, fool: discordvoice.FoolTTL, payload: voicePayloadQUIC}, nil
	case "badsum":
		return voiceMode{enabled: true, fool: discordvoice.FoolBadChecksum, payload: voicePayloadNeutral}, nil
	case "badsum-quic":
		return voiceMode{enabled: true, fool: discordvoice.FoolBadChecksum, payload: voicePayloadQUIC}, nil
	case "probe":
		return voiceMode{probe: true}, nil
	default:
		return voiceMode{}, fmt.Errorf("неизвестный режим --voice %q: доступны off, ttl, badsum, ttl-quic, badsum-quic, probe", s)
	}
}

// udpScanFilterNo443 — фильтр сканера для работы вместе с движком: весь
// исходящий UDP, кроме порта 443 (там свой дескриптор QUIC — два на одних
// пакетах конфликтовали бы). 74-байтные пакеты на 443 считает петля QUIC.
// Широкий намеренно: задача — найти, на какие порты идёт голос, а не угадать их.
const udpScanFilterNo443 = "outbound and udp and udp.DstPort != 443 and not impostor"

// runUDPScan наблюдает исходящий UDP и периодически печатает, на какие порты и
// какого размера идут датаграммы. Ничего не модифицирует: каждый пакет
// пропускается как есть. Нужен разово, чтобы найти голосовой UDP Discord.
//
// Счётчиков формы два: мягкий (длина нагрузки ровно 74 байта) и строгий
// (`discordvoice.IsIPDiscoveryRequest`: длина + тип 0x0001 + поле длины 70).
// Расхождение между ними сразу говорит, сколько шума в мягком — любые
// 74-байтные QUIC retry / короткие ACK-подобные фреймы попадают только в него.
// Решение «переключить фильтр на этот порт» принимается по СТРОГОМУ.
func runUDPScan(ctx context.Context, conn quicConn, logger *slog.Logger) {
	// На порт: сколько всего, сколько 74 байт по длине (мягко) и сколько
	// строгих IP discovery.
	type stat struct{ total, shapedLoose, discovery int }
	ports := map[uint16]*stat{}
	var total int
	// Первые адреса, куда ушёл строгий IP discovery, — для вывода в логе:
	// по ним глазами подтверждается, что идёт к серверу Discord.
	var strictEndpoints []string
	var lastReport time.Time

	report := func(tag string) {
		var loose, strict, top []string
		type pc struct {
			port uint16
			s    *stat
		}
		all := make([]pc, 0, len(ports))
		for p, s := range ports {
			all = append(all, pc{p, s})
		}
		sort.Slice(all, func(i, j int) bool { return all[i].s.total > all[j].s.total })
		for i, e := range all {
			if i < 15 {
				top = append(top, fmt.Sprintf("%d:%d", e.port, e.s.total))
			}
			if e.s.shapedLoose > 0 {
				loose = append(loose, fmt.Sprintf("%d(74б×%d)", e.port, e.s.shapedLoose))
			}
			if e.s.discovery > 0 {
				strict = append(strict, fmt.Sprintf("%d(disc×%d)", e.port, e.s.discovery))
			}
		}
		logger.Info("UDP-скан: "+tag,
			"всего_датаграмм", total,
			"портов", len(ports),
			"топ_порт:кол", strings.Join(top, " "),
			"порты_74байт_форма", strings.Join(loose, " "),
			"порты_discovery_строго", strings.Join(strict, " "),
			"куда_строгие", strings.Join(strictEndpoints, " "))
	}

	for {
		pkt, err := conn.Recv()
		if err != nil {
			report("итог")
			return
		}
		total++
		if d, e := packet.Dissect(pkt.Data); e == nil && d.Protocol == packet.ProtoUDP {
			if u, ok := d.UDP(pkt.Data); ok {
				dp := u.DstPort()
				s := ports[dp]
				if s == nil {
					s = &stat{}
					ports[dp] = s
				}
				s.total++
				c := tallyUDPShaped(pkt.Data, d)
				if c.loose {
					s.shapedLoose++
				}
				if c.strict {
					s.discovery++
					strictEndpoints = appendStrictEndpoint(strictEndpoints, c.endpoint)
				}
			}
		}
		// Наблюдаем, не трогаем: пропускаем пакет как есть.
		if err := conn.Send(pkt); err != nil {
			logger.Warn("UDP-скан: не удалось пропустить пакет", "ошибка", err)
		}
		if total > 0 && time.Since(lastReport) >= voiceReportEvery {
			report("промежуточно")
			lastReport = time.Now()
		}
		if ctx.Err() != nil {
			report("итог")
			return
		}
	}
}

// startUDPScan поднимает сканер UDP (диагностика) в своей горутине и возвращает
// функцию остановки. filter — строка фильтра WinDivert. На не-Windows
// windivert.Open вернёт ошибку (стаб).
func startUDPScan(ctx context.Context, filter string, logger *slog.Logger) (func(), error) {
	handle, err := windivert.Open(filter)
	if err != nil {
		return nil, err
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		runUDPScan(ctx, handle, logger)
	}()
	logger.Info("UDP-скан запущен: зайди в голосовой канал Discord (движок обхода работает), затем Ctrl+C",
		"фильтр", filter)
	return func() {
		_ = handle.Close() // разблокирует зависший на приёме Recv
		<-done
	}, nil
}

// buildVoiceDecoys решает, что отправить для исходящего UDP-пакета pkt. Если это
// пакет начала голоса Discord (IP discovery), возвращает decoy'и ПЕРЕД настоящим
// пакетом и applied=true; иначе (nil, false), и вызывающий шлёт пакет как есть.
//
// Чистая и без состояния: Discord шлёт IP discovery только в начале соединения
// (и ретрансмитит при молчании), поэтому decoy на каждый такой пакет корректен —
// повтор это свежая попытка, которой decoy тоже нужен. Вынесено отдельно, чтобы
// проверять решение без WinDivert (тот же приём разделения, что у quicDesyncPacket).
func buildVoiceDecoys(pkt capture.Packet, fool discordvoice.Fooling, ttl uint8, repeats int, payload voicePayload) ([]capture.Packet, bool) {
	if pkt.Dir != core.DirectionOutbound {
		return nil, false
	}
	d, err := packet.Dissect(pkt.Data)
	if err != nil || d.Protocol != packet.ProtoUDP {
		return nil, false
	}
	payloadBytes, ok := d.Payload(pkt.Data)
	if !ok || !discordvoice.IsIPDiscoveryRequest(payloadBytes) {
		return nil, false
	}

	// Нагрузка decoy — НЕ копия настоящего IP discovery, а подменные байты той
	// же длины. В этом вся суть: decoy идёт первым, и если бы он нёс ту же форму
	// (тип 0x0001, длина 70), DPI увидел бы характерную подпись начала голоса в
	// первом же пакете — ровно то, что мы прячем.
	//
	// Два варианта нагрузки:
	//
	//   - neutral: детерминированный узор, не начинающийся с 0x0001. DPI видит
	//     «посторонний» первый пакет; настоящий IP discovery идёт последним и
	//     единственным доходит до сервера (decoy умирают по TTL/битой сумме).
	//     Та же логика, что у fake-пакетов TCP-аналогов: подделка несёт не
	//     целевое содержимое, а безобидное.
	//
	//   - quic: байты, похожие на QUIC v1 Initial long-header (benign-QUIC).
	//     Первый байт 0xc0, версия 0x00000001 — явная сигнатура QUIC. DPI
	//     классифицирует UDP-поток как QUIC-соединение к постороннему хосту, а
	//     не как «голос Discord». Усиление приёма: на DPI, которые решают
	//     класс потока по форме первого пакета, QUIC-подобный decoy вернее
	//     уводит классификацию.
	fake := voiceFakePayload(len(payloadBytes), payload)

	// Оба приёма подряд, выбранный первым. Какой из них сработает, зависит от
	// сети, а не от пользователя: decoy с коротким TTL не доходит до DPI, если
	// тот дальше voiceDecoyTTL переходов, а decoy с битой суммой отбрасывают
	// некоторые домашние роутеры и NAT. Лишний decoy безвреден — до сервера не
	// доживает ни тот, ни другой.
	type step struct {
		fool discordvoice.Fooling
		ttl  uint8
	}
	steps := []step{{discordvoice.FoolTTL, ttl}, {discordvoice.FoolBadChecksum, voiceBadsumTTL}}
	if fool == discordvoice.FoolBadChecksum {
		steps[0], steps[1] = steps[1], steps[0]
	}
	out := make([]capture.Packet, 0, 2*repeats+1)
	for _, step := range steps {
		for range repeats {
			decoy, err := discordvoice.BuildDecoy(pkt.Data, step.fool, step.ttl, fake)
			if err != nil {
				// Собрать decoy не вышло — честно отказываемся от приёма и шлём
				// оригинал как есть (1.6), а не рвём голос.
				return nil, false
			}
			out = append(out, capture.Packet{Data: decoy, Dir: pkt.Dir, Reinject: pkt.Reinject})
		}
	}
	// Настоящий пакет — последним, после decoy'ев.
	out = append(out, pkt)
	return out, true
}

// voiceFakePayload строит нагрузку decoy длины n — той же, что у настоящего
// IP discovery (иначе BuildDecoy откажет: смена длины потребовала бы правки
// полей длины IP и UDP).
//
// Содержимое выбирается по voicePayload:
//
//	voicePayloadNeutral — детерминированный узор, НЕ начинающийся с 0x0001 (не
//	    форма Discord IP discovery). Байт 0 = 0x2b, узор циклический.
//	voicePayloadQUIC    — QUIC v1 Initial long-header. При n == 74 (размер
//	    настоящего IP discovery) — ровно то, что собирает quicfake.BenignInitial74.
//	    При другом n — узор neutral, потому что QUIC-пресета фиксированной
//	    длины 74 в нашем реестре; делать строгое соответствие формы при чужой
//	    длине значило бы собрать невалидный QUIC и приём бы не сработал по
//	    технической причине.
func voiceFakePayload(n int, kind voicePayload) []byte {
	if n <= 0 {
		return nil
	}
	if kind == voicePayloadQUIC && n == 74 {
		return quicfake.BenignInitial74()
	}
	b := make([]byte, n)
	for i := range b {
		// Узор, заведомо не начинающийся с 0x00 0x01: байт 0 будет 0x2b.
		b[i] = byte(0x2b + i%0x53)
	}
	return b
}

// startVoiceDesync поднимает десинк голоса Discord, если он включён.
//
// Обратимо и опционально (1.6): по умолчанию выключен; в наблюдении не
// запускается; при остановке дескриптор закрывается — приём снимается
// полностью. На не-Windows windivert.Open вернёт ошибку (стаб), и вызывающий
// честно откажет. Возвращает функцию остановки, признак активности и ошибку.
func startVoiceDesync(ctx context.Context, mode voiceMode, observe bool, logger *slog.Logger) (stop func(), active bool, err error) {
	if !mode.enabled || observe {
		return func() {}, false, nil
	}
	handle, err := windivert.Open(voiceFilter)
	if err != nil {
		return nil, false, err
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		runVoiceDesync(ctx, handle, mode.fool, mode.payload, logger)
	}()
	stop = func() {
		_ = handle.Close() // разблокирует зависший на приёме Recv
		<-done
	}
	return stop, true, nil
}

// runVoiceDesync ведёт цикл десинка голоса до закрытия дескриптора или отмены.
//
// На пакете начала голоса (IP discovery) шлёт decoy'и, затем настоящий пакет;
// прочий UDP диапазона пропускает как есть. Переиспользует quicConn (Recv/Send).
func runVoiceDesync(ctx context.Context, conn quicConn, fool discordvoice.Fooling, payload voicePayload, logger *slog.Logger) {
	// Счётчики наблюдаемости (принадлежат циклу, без синхронизации): всего
	// исходящих UDP-датаграмм на фильтре и сколько из них — пакеты начала
	// голоса, к которым приём применён. По ним на живом прогоне видно, ловит ли
	// фильтр голос вообще: датаграмм=0 значит исходящего UDP (кроме 443) нет
	// совсем (голосовой канал не подключён); датаграмм>0, применено=0 — UDP
	// есть, но форму IP discovery не распознаём.
	var acted, dgrams int
	var lastReport time.Time
	for {
		pkt, err := conn.Recv()
		if err != nil {
			// Финальная сводка печатается всегда, даже при нулях: ноль датаграмм
			// — это ответ (голос не на этих портах / канал не подключался), а не
			// отсутствие данных.
			logger.Info("десинк голоса остановлен",
				"применено", acted, "датаграмм_udp", dgrams)
			return
		}
		dgrams++

		if pkts, applied := buildVoiceDecoys(pkt, fool, voiceDecoyTTL, voiceDecoyRepeats, payload); applied {
			for _, p := range pkts {
				if err := conn.Send(p); err != nil {
					logger.Warn("десинк голоса: не удалось отправить пакет", "ошибка", err)
				}
			}
			acted++
			if acted == 1 || time.Since(lastReport) >= voiceReportEvery {
				logger.Info("десинк голоса применён (Discord IP discovery)",
					"применено", acted, "датаграмм_udp", dgrams)
				lastReport = time.Now()
			}
			if ctx.Err() != nil {
				return
			}
			continue
		}

		if err := conn.Send(pkt); err != nil {
			logger.Warn("десинк голоса: не удалось пропустить пакет", "ошибка", err)
		}
		// Периодическая сводка, даже когда ничего не применяем: без неё молчание
		// петли не отличить от «голос не идёт». Печатается не чаще
		// voiceReportEvery и только когда датаграммы вообще были.
		if dgrams > 0 && time.Since(lastReport) >= voiceReportEvery {
			logger.Info("десинк голоса: сводка",
				"датаграмм_udp", dgrams, "применено", acted)
			lastReport = time.Now()
		}
		if ctx.Err() != nil {
			return
		}
	}
}
