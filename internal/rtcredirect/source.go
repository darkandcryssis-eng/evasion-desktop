package rtcredirect

import (
	"github.com/fitting-1c/evasion/internal/capture"
	"github.com/fitting-1c/evasion/internal/core"
)

// Source оборачивает источник пакетов и применяет переклейку портов на каждом
// принятом пакете. Это декоратор: ядро движка его не видит и не меняется —
// движку отдаётся уже исправленный пакет (исходящие на живом порту, входящие с
// восстановленным исходным портом), и дальше он работает как обычно.
//
// Приёмник (Sink) оборачивать НЕ нужно: исходящие пакеты, которые движок строит
// (десинк) или пропускает, собираются из уже переклеенного шаблона и уходят на
// живой порт сами; входящие движок пропускает как есть — а их порт уже
// восстановлен здесь, на приёме.
type Source struct {
	inner capture.PacketSource
	r     *Redirector
}

// NewSource оборачивает inner переклейщиком r. Если переклейка не настроена
// (r.Active() == false), пакеты проходят без изменений — обёртка безвредна.
func NewSource(inner capture.PacketSource, r *Redirector) *Source {
	return &Source{inner: inner, r: r}
}

// Recv принимает пакет от нижнего источника и применяет переклейку на месте.
// Буфер действителен до следующего Recv — ровно тот же контракт, что у
// нижнего источника, а правка идёт по месту, без копий.
func (s *Source) Recv() (capture.Packet, error) {
	pkt, err := s.inner.Recv()
	if err != nil {
		return pkt, err
	}
	s.r.Apply(pkt.Data, pkt.Dir == core.DirectionOutbound)
	return pkt, nil
}
