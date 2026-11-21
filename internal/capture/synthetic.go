package capture

import "io"

// Проверка во время компиляции, что синтетические реализации удовлетворяют шов.
var (
	_ PacketSource = (*SyntheticSource)(nil)
	_ PacketSink   = (*SyntheticSink)(nil)
)

// SyntheticSource отдаёт заранее заданную последовательность пакетов.
//
// Нужен тестам flow и packetexec: позволяет прогнать логику на выдуманном
// потоке без сети и без Windows. По исчерпании возвращает io.EOF — тот же
// признак конца, что у файлового источника, чтобы потребитель, написанный под
// один, работал и с другим.
//
// Не потокобезопасен: источник предполагается по одному на читающую горутину,
// как и живой (у WinDivert это один handle на поток приёма).
type SyntheticSource struct {
	packets []Packet
	i       int
}

// NewSyntheticSource создаёт источник из заданных пакетов. Порядок сохраняется:
// на нём и держится проверка последовательностей, формируемых десинком.
func NewSyntheticSource(packets ...Packet) *SyntheticSource {
	return &SyntheticSource{packets: packets}
}

// Recv возвращает очередной пакет либо io.EOF, когда они кончились.
func (s *SyntheticSource) Recv() (Packet, error) {
	if s.i >= len(s.packets) {
		return Packet{}, io.EOF
	}
	p := s.packets[s.i]
	s.i++
	return p, nil
}

// SyntheticSink записывает отправленные пакеты для последующей проверки.
//
// Send копирует Data нарочно. По контракту владения (doc.go) источник вправе
// переиспользовать буфер после Recv, поэтому приёмник, который пакет
// удерживает, обязан скопировать — и синтетический приёмник делает это, во-
// первых, чтобы записанное не искажалось позднейшей перезаписью буфера, во-
// вторых, чтобы служить примером правильного удерживающего потребителя.
type SyntheticSink struct {
	sent []Packet
}

// Send записывает копию пакета.
func (s *SyntheticSink) Send(p Packet) error {
	cp := Packet{Dir: p.Dir, Reinject: p.Reinject}
	if p.Data != nil {
		cp.Data = append([]byte(nil), p.Data...)
	}
	s.sent = append(s.sent, cp)
	return nil
}

// Sent возвращает отправленные пакеты в порядке отправки.
func (s *SyntheticSink) Sent() []Packet { return s.sent }
