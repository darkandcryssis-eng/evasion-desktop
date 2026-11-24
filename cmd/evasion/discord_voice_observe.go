package main

import (
	"context"
	"log/slog"
	"net/netip"
	"sync"

	"github.com/fitting-1c/evasion/internal/netbind"
	"github.com/fitting-1c/evasion/internal/packet"
	"github.com/fitting-1c/evasion/internal/windivert"
)

// voiceObserveFilter — запрос и ответ IP discovery голоса Discord на любом
// интерфейсе. Наблюдение пассивное (sniff): пакеты идут своим путём.
const voiceObserveFilter = "udp and udp.PayloadLength == 74 and udp.Payload16[1] == 70 and " +
	"(udp.Payload16[0] == 0x0001 or udp.Payload16[0] == 0x0002) and not impostor"

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

// startVoiceObserver следит за началом голоса Discord при стороннем VPN. Запрос
// IP discovery, ушедший в туннель, выдаёт адрес голосового сервера: на него
// ставится маршрут мимо VPN. Каждое событие пишется в журнал с интерфейсом, так
// что по журналу видно, куда уходит голос и приходит ли на него ответ.
func startVoiceObserver(ctx context.Context, route netbind.Route, router *voiceRouter, logger *slog.Logger) func() {
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
		for {
			pkt, err := handle.Recv()
			if err != nil {
				return
			}
			event, ok := parseVoiceDiscovery(pkt.Data)
			if !ok {
				continue
			}
			addr, _ := pkt.Reinject.(windivert.Address)
			ifIndex := addr.IfIdx()
			via := "другой интерфейс"
			switch ifIndex {
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
			if !event.response && addr.Outbound() && ifIndex == route.Default.Index {
				router.Route(event.dst.Addr())
			}
		}
	}()
	return func() {
		stopWatch()
		closeHandle()
		<-done
	}
}
