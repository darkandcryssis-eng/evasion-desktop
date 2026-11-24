package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/fitting-1c/evasion/internal/capture"
	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/discordvoice"
	"github.com/fitting-1c/evasion/internal/hops"
	"github.com/fitting-1c/evasion/internal/netbind"
	"github.com/fitting-1c/evasion/internal/packet"
	"github.com/fitting-1c/evasion/internal/windivert"
)

// voiceObservePorts — диапазоны портов голосовых серверов Discord.
const voiceObservePorts = "((%[1]s >= 19294 and %[1]s <= 19344) or %[1]s >= 50000)"

// voiceObserveFilter — начало голоса Discord (запрос и ответ IP discovery на
// любом порту) и сам голос на портах голосовых серверов, на всех интерфейсах.
// Наблюдение пассивное (sniff): пакеты идут своим путём.
var voiceObserveFilter = "udp and not impostor and ((udp.PayloadLength == 74 and udp.Payload16[1] == 70 and " +
	"(udp.Payload16[0] == 0x0001 or udp.Payload16[0] == 0x0002)) or (outbound and " +
	fmt.Sprintf(voiceObservePorts, "udp.DstPort") + ") or (inbound and " + fmt.Sprintf(voiceObservePorts, "udp.SrcPort") + "))"

// voiceObserveLogLimit — сколько событий голоса пишется в журнал поштучно.
const voiceObserveLogLimit = 40

type voiceDiscovery struct {
	src, dst netip.AddrPort
	response bool
}

// parseVoiceDiscovery разбирает IPv4-пакет IP discovery: запрос клиента (тип 1)
// или ответ сервера (тип 2), длина тела 70.
func parseVoiceDiscovery(buf []byte) (voiceDiscovery, bool) {
	d, err := packet.Dissect(buf)
	if err != nil || d.Version != packet.Version4 {
		return voiceDiscovery{}, false
	}
	ip, ok := d.IPv4(buf)
	if !ok {
		return voiceDiscovery{}, false
	}
	udp, ok := d.UDP(buf)
	if !ok {
		return voiceDiscovery{}, false
	}
	payload, _ := d.Payload(buf)
	if len(payload) != 74 || payload[0] != 0 || (payload[1] != 1 && payload[1] != 2) || payload[2] != 0 || payload[3] != 70 {
		return voiceDiscovery{}, false
	}
	src, okSrc := netip.AddrFromSlice(ip.Src())
	dst, okDst := netip.AddrFromSlice(ip.Dst())
	if !okSrc || !okDst {
		return voiceDiscovery{}, false
	}
	return voiceDiscovery{
		src:      netip.AddrPortFrom(src.Unmap(), udp.SrcPort()),
		dst:      netip.AddrPortFrom(dst.Unmap(), udp.DstPort()),
		response: payload[1] == 2,
	}, true
}

// udpEndpoints возвращает адреса отправителя и получателя IPv4-датаграммы.
func udpEndpoints(buf []byte) (src, dst netip.Addr, ok bool) {
	d, err := packet.Dissect(buf)
	if err != nil || d.Version != packet.Version4 {
		return src, dst, false
	}
	ip, okIP := d.IPv4(buf)
	if _, okUDP := d.UDP(buf); !okIP || !okUDP {
		return src, dst, false
	}
	src, okSrc := netip.AddrFromSlice(ip.Src())
	dst, okDst := netip.AddrFromSlice(ip.Dst())
	return src.Unmap(), dst.Unmap(), okSrc && okDst
}

// voiceControl связывает наблюдение, заслон в туннеле и выбор пути голоса.
type voiceControl struct {
	route    netbind.Route
	router   *voiceRouter
	sessions voiceSessions
	logger   *slog.Logger
	// reconnect обрывает сигнальные соединения голосовых серверов: клиент
	// Discord сразу подключается к голосу заново, уже по новому пути.
	reconnect func() int
}

// report пишет итог завершившегося сеанса и снимает маршруты, когда голос
// переведён в туннель: оставшийся маршрут увёл бы новый сеанс мимо VPN.
func (c *voiceControl) report(v *voiceVerdict) {
	if v == nil {
		return
	}
	result := "работал"
	if !v.alive {
		result = "СОРВАН: сервер не отвечал голосом"
	}
	c.logger.Info("голос Discord: сеанс завершён", "сервер", v.server, "путь", v.path.String(),
		"отправлено_пакетов", v.out, "получено_пакетов", v.in, "итог", result)
	if !v.switched {
		return
	}
	c.logger.Warn("голос Discord: сеансы срываются подряд, следующий пойдёт другим путём", "путь", v.next.String())
	if v.next == voiceTunnel {
		c.router.Close()
	}
}

// reportStalled разбирает сеанс, сорванный на месте: клиент сам сервер не
// сменит, поэтому его голосовое подключение обрывается принудительно.
func (c *voiceControl) reportStalled(v *voiceVerdict) {
	if v == nil {
		return
	}
	c.report(v)
	if c.reconnect != nil {
		c.logger.Warn("голос Discord: сервер молчит, подключение к голосу перезапущено", "соединений", c.reconnect())
	}
}

// startVoiceObserver следит за голосом Discord при стороннем VPN и ведёт счёт
// пакетов сеанса: по нему выбирается путь голоса, а журнал показывает, куда
// голос уходит и отвечает ли сервер.
func startVoiceObserver(ctx context.Context, route netbind.Route, router *voiceRouter, reconnect func() int, logger *slog.Logger) func() {
	control := &voiceControl{route: route, router: router, logger: logger, reconnect: reconnect}
	handle, err := windivert.Observe(voiceObserveFilter)
	if err != nil {
		logger.Warn("голос Discord: наблюдение недоступно, голос останется в VPN", "err", err)
		return func() {}
	}
	var once sync.Once
	closeHandle := func() { once.Do(func() { _ = handle.Close() }) }
	stopWatch := context.AfterFunc(ctx, closeHandle)
	done := make(chan struct{})
	go func() {
		defer close(done)
		logged := 0
		var lastSummary time.Time
		var lastIn, lastOut int
		for {
			pkt, err := handle.Recv()
			if err != nil {
				return
			}
			addr, _ := pkt.Reinject.(windivert.Address)
			onTunnel := addr.IfIdx() == route.Default.Index
			if event, ok := parseVoiceDiscovery(pkt.Data); ok {
				via := "другой интерфейс"
				switch addr.IfIdx() {
				case route.Default.Index:
					via = "VPN"
				case route.Physical.Index:
					via = "физический адаптер"
				}
				kind := "запрос"
				if event.response {
					kind = "ОТВЕТ сервера"
				}
				if logged < voiceObserveLogLimit {
					logged++
					logger.Info("голос Discord: IP discovery", "что", kind, "интерфейс", via, "откуда", event.src, "куда", event.dst)
				}
				// Запросы в туннель разбирает заслон; здесь — те, что уже идут
				// мимо VPN по стоящему маршруту.
				if !event.response && addr.Outbound() && !onTunnel {
					_, verdict := control.sessions.begin(event.dst.Addr(), false)
					control.report(verdict)
				}
				continue
			}
			src, dst, ok := udpEndpoints(pkt.Data)
			if !ok {
				continue
			}
			if addr.Outbound() {
				control.sessions.count(dst, false)
				control.reportStalled(control.sessions.stalled())
			} else {
				control.sessions.count(src, true)
			}
			if now := time.Now(); now.Sub(lastSummary) >= 10*time.Second {
				lastSummary = now
				if server, path, in, out, active := control.sessions.snapshot(); active && (in != lastIn || out != lastOut) {
					lastIn, lastOut = in, out
					logger.Info("голос Discord: сеанс", "сервер", server, "путь", path.String(),
						"отправлено_пакетов", out, "получено_пакетов", in)
				}
			}
		}
	}()
	stopGate := startVoiceGate(ctx, control)
	return func() {
		stopGate()
		stopWatch()
		closeHandle()
		<-done
	}
}

// redirectVoiceDiscovery пересобирает запрос IP discovery, пойманный в туннеле,
// для отправки через физический адаптер: адрес отправителя заменяется адресом
// адаптера, перед запросом ставятся те же подделки, что и в обычном голосовом
// десинке (сам десинк этот пакет уже не увидит). Пустой результат — пересобрать
// нельзя.
func redirectVoiceDiscovery(pkt capture.Packet, physical netbind.Adapter) []capture.Packet {
	addr, ok := pkt.Reinject.(windivert.Address)
	if !ok || !physical.Addr.Is4() || physical.Index == 0 {
		return nil
	}
	d, err := packet.Dissect(pkt.Data)
	if err != nil || d.Version != packet.Version4 || len(pkt.Data) < 20 {
		return nil
	}
	data := append([]byte(nil), pkt.Data...)
	own := physical.Addr.As4()
	copy(data[12:16], own[:])
	if !d.RecomputeChecksums(data) {
		return nil
	}
	direct := capture.Packet{Data: data, Dir: core.DirectionOutbound, Reinject: addr.WithInterface(physical.Index)}
	ttl := hops.Default.FakeTTL(voicePacketDestination(direct), 1, voiceDecoyTTL)
	decoys, applied := buildVoiceDecoys(direct, discordvoice.FoolTTL, ttl, voiceDecoyRepeats, voicePayloadQUIC)
	if !applied {
		return nil
	}
	return append(buildVoiceCovers(direct, voiceDecoyRepeats), decoys...)
}

// voiceGatePriority ставит заслон раньше остальных обработчиков движка.
const voiceGatePriority = 1000

// startVoiceGate перехватывает запросы IP discovery, уходящие в туннель VPN, и
// решает путь сеанса. Для прямого пути на адрес сервера ставится маршрут мимо
// VPN, а сам запрос отбрасывается: ответ через туннель сообщил бы клиенту
// внешний адрес VPN-сервера, и голос, который дальше пойдёт мимо туннеля,
// пришёл бы к серверу с другого адреса. Клиент повторяет запрос, и повтор
// уходит через физический адаптер — весь сеанс идёт одним путём. Для пути
// через VPN запрос пропускается как есть.
func startVoiceGate(ctx context.Context, control *voiceControl) func() {
	logger := control.logger
	filter := fmt.Sprintf("outbound and udp and ifIdx == %d and udp.PayloadLength == 74 and "+
		"udp.Payload16[0] == 0x0001 and udp.Payload16[1] == 70 and not impostor", control.route.Default.Index)
	handle, err := windivert.OpenPriority(filter, voiceGatePriority)
	if err != nil {
		logger.Warn("голос Discord: заслон в туннеле недоступен, голос останется в VPN", "err", err)
		return func() {}
	}
	var once sync.Once
	closeHandle := func() { once.Do(func() { _ = handle.Close() }) }
	stopWatch := context.AfterFunc(ctx, closeHandle)
	done := make(chan struct{})
	go func() {
		defer close(done)
		held := 0
		for {
			pkt, err := handle.Recv()
			if err != nil {
				return
			}
			if event, ok := parseVoiceDiscovery(pkt.Data); ok && !event.response {
				server := event.dst.Addr()
				path, verdict := control.sessions.begin(server, true)
				control.report(verdict)
				if path == voiceDirect {
					if control.router.Route(server) {
						// Запрос сразу уходит мимо VPN от адреса физического
						// адаптера, вместе с подделками: ждать секунду, пока
						// клиент сам его повторит, не нужно. Если пересобрать
						// пакет нельзя, он отбрасывается, и уйдёт повтор.
						redirected := redirectVoiceDiscovery(pkt, control.route.Physical)
						for _, out := range redirected {
							if err := handle.Send(out); err != nil {
								logger.Warn("голос Discord: запрос мимо VPN не отправлен, уйдёт повтор клиента", "err", err)
								break
							}
						}
						held++
						if held <= voiceObserveLogLimit {
							what := "запрос в туннель отброшен, повтор уйдёт мимо VPN"
							if len(redirected) > 0 {
								what = "запрос перенаправлен мимо VPN"
							}
							logger.Info("голос Discord: "+what, "куда", event.dst)
						}
						continue
					}
					control.sessions.keepTunnel(server)
				}
			}
			if err := handle.Send(pkt); err != nil {
				logger.Warn("голос Discord: пакет не пропущен", "err", err)
			}
		}
	}()
	return func() {
		stopWatch()
		closeHandle()
		<-done
	}
}
