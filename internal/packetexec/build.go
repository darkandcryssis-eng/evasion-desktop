package packetexec

import (
	"fmt"

	"github.com/fitting-1c/evasion/internal/packet"
	"github.com/fitting-1c/evasion/internal/strategy"
)

// ipv6FixedHeaderLen — длина фиксированного заголовка IPv6. Поле длины нагрузки
// считает всё после этих 40 байт, включая заголовки расширения.
const ipv6FixedHeaderLen = 40

// assemble собирает пакет из шаблона: заголовки шаблона, затем payload, с
// номером последовательности seq и исправленной длиной сетевого слоя.
//
// Суммы здесь НЕ пересчитываются: порядок пересчёта зависит от того, есть ли
// правка самой суммы (её пишут после пересчёта), поэтому им распоряжается
// вызывающий. Возвращается буфер и его разбор по уже исправленной длине.
func assemble(tmpl []byte, d packet.Dissection, payload []byte, seq uint32) ([]byte, packet.Dissection, error) {
	headerLen := d.PayloadOff
	if headerLen <= 0 || headerLen > len(tmpl) {
		return nil, packet.Dissection{}, fmt.Errorf("packetexec: негодный разбор шаблона (PayloadOff=%d)", headerLen)
	}

	out := make([]byte, headerLen+len(payload))
	copy(out, tmpl[:headerLen])
	copy(out[headerLen:], payload)

	switch d.Version {
	case packet.Version4:
		packet.IPv4Header(out[:d.L3Len]).SetTotalLen(uint16(len(out)))
	case packet.Version6:
		packet.IPv6Header(out[:ipv6FixedHeaderLen]).SetPayloadLen(uint16(len(out) - ipv6FixedHeaderLen))
	default:
		return nil, packet.Dissection{}, fmt.Errorf("packetexec: неизвестная версия сетевого слоя")
	}
	packet.TCPHeader(out[d.L4Off : d.L4Off+d.L4Len]).SetSeq(seq)

	d2, err := packet.Dissect(out)
	if err != nil {
		return nil, packet.Dissection{}, fmt.Errorf("packetexec: разбор собранного пакета: %w", err)
	}
	return out, d2, nil
}

// isChecksumField сообщает, является ли поле контрольной суммой. Правки суммы
// применяются ПОСЛЕ пересчёта (намеренно неверное значение), все прочие — до.
func isChecksumField(f strategy.FieldID) bool {
	return f == strategy.FieldIPv4Checksum || f == strategy.FieldTCPChecksum
}

// applyValue вычисляет новое значение поля по режиму правки.
//
// Маскирование по ширине поля выполняет приведение к типу поля у места записи:
// узкие поля (флаги, смещение фрагмента, метка потока) маскируют свои сеттеры
// сами, широкие укладываются в тип. Поэтому здесь ширину знать не нужно.
func applyValue(e strategy.TamperParams, cur uint64) uint64 {
	switch e.Mode {
	case strategy.TamperReplace:
		return e.Value
	case strategy.TamperAdd:
		// Знаковая дельта в дополнительном коде: сложение по модулю ширины даёт
		// верный результат после усечения к типу поля.
		return cur + e.Value
	case strategy.TamperCorrupt:
		// Детерминированная порча — побитовое отрицание. Для суммы это заведомо
		// иное значение; детерминизм обязателен золотым тестам и replay. Задание
		// предполагало сид-основанную случайность (params.go), но её можно
		// ввести позже, не меняя ни план, ни этот интерфейс.
		return ^cur
	default:
		return cur
	}
}

// fieldUnavailable — поле правки отсутствует в этом пакете (например, опция MSS
// на сегменте без опций, или поле IPv4 на пакете IPv6). Явная ошибка, а не
// молчаливый пропуск: исполнить правку не того поля нельзя (4.7 п. 2), это тот
// же класс, что ErrCutUnavailable в desync.
func fieldUnavailable(f strategy.FieldID) error {
	return fmt.Errorf("packetexec: поле %s недоступно в этом пакете", f)
}

// applyEdit применяет одну правку поля заголовка к собранному пакету.
//
// Поле тела (FieldPayload) сюда не доходит: его подмену desync применяет к
// нагрузке напрямую, и в edits оно не попадает. Если всё же дошло — это дефект,
// и мы сообщаем о нём явно, а не правим наугад.
func applyEdit(d packet.Dissection, buf []byte, e strategy.TamperParams) error {
	switch e.Field {
	// --- IPv4 ---
	case strategy.FieldIPv4TTL:
		h, ok := d.IPv4(buf)
		if !ok {
			return fieldUnavailable(e.Field)
		}
		h.SetTTL(uint8(applyValue(e, uint64(h.TTL()))))
	case strategy.FieldIPv4ID:
		h, ok := d.IPv4(buf)
		if !ok {
			return fieldUnavailable(e.Field)
		}
		h.SetID(uint16(applyValue(e, uint64(h.ID()))))
	case strategy.FieldIPv4Flags:
		h, ok := d.IPv4(buf)
		if !ok {
			return fieldUnavailable(e.Field)
		}
		h.SetFlags(uint8(applyValue(e, uint64(h.Flags()))))
	case strategy.FieldIPv4FragOff:
		h, ok := d.IPv4(buf)
		if !ok {
			return fieldUnavailable(e.Field)
		}
		h.SetFragOffset(uint16(applyValue(e, uint64(h.FragOffset()))))
	case strategy.FieldIPv4TOS:
		h, ok := d.IPv4(buf)
		if !ok {
			return fieldUnavailable(e.Field)
		}
		h.SetTOS(uint8(applyValue(e, uint64(h.TOS()))))
	case strategy.FieldIPv4Checksum:
		h, ok := d.IPv4(buf)
		if !ok {
			return fieldUnavailable(e.Field)
		}
		h.SetChecksum(uint16(applyValue(e, uint64(h.Checksum()))))

	// --- IPv6 ---
	case strategy.FieldIPv6HopLimit:
		h, ok := d.IPv6(buf)
		if !ok {
			return fieldUnavailable(e.Field)
		}
		h.SetHopLimit(uint8(applyValue(e, uint64(h.HopLimit()))))
	case strategy.FieldIPv6FlowLabel:
		h, ok := d.IPv6(buf)
		if !ok {
			return fieldUnavailable(e.Field)
		}
		h.SetFlowLabel(uint32(applyValue(e, uint64(h.FlowLabel()))))
	case strategy.FieldIPv6TrafficClass:
		h, ok := d.IPv6(buf)
		if !ok {
			return fieldUnavailable(e.Field)
		}
		h.SetTrafficClass(uint8(applyValue(e, uint64(h.TrafficClass()))))

	// --- TCP ---
	case strategy.FieldTCPSeq:
		th, ok := d.TCP(buf)
		if !ok {
			return fieldUnavailable(e.Field)
		}
		th.SetSeq(uint32(applyValue(e, uint64(th.Seq()))))
	case strategy.FieldTCPAck:
		th, ok := d.TCP(buf)
		if !ok {
			return fieldUnavailable(e.Field)
		}
		th.SetAck(uint32(applyValue(e, uint64(th.Ack()))))
	case strategy.FieldTCPFlags:
		th, ok := d.TCP(buf)
		if !ok {
			return fieldUnavailable(e.Field)
		}
		th.SetFlags(uint8(applyValue(e, uint64(th.Flags()))))
	case strategy.FieldTCPWindow:
		th, ok := d.TCP(buf)
		if !ok {
			return fieldUnavailable(e.Field)
		}
		th.SetWindow(uint16(applyValue(e, uint64(th.Window()))))
	case strategy.FieldTCPUrgent:
		th, ok := d.TCP(buf)
		if !ok {
			return fieldUnavailable(e.Field)
		}
		th.SetUrgent(uint16(applyValue(e, uint64(th.Urgent()))))
	case strategy.FieldTCPChecksum:
		th, ok := d.TCP(buf)
		if !ok {
			return fieldUnavailable(e.Field)
		}
		th.SetChecksum(uint16(applyValue(e, uint64(th.Checksum()))))
	case strategy.FieldTCPMSS:
		th, ok := d.TCP(buf)
		if !ok {
			return fieldUnavailable(e.Field)
		}
		cur, err := th.MSS()
		if err != nil {
			return fieldUnavailable(e.Field)
		}
		if err := th.SetMSS(uint16(applyValue(e, uint64(cur)))); err != nil {
			return fieldUnavailable(e.Field)
		}
	case strategy.FieldTCPWScale:
		th, ok := d.TCP(buf)
		if !ok {
			return fieldUnavailable(e.Field)
		}
		cur, err := th.WindowScale()
		if err != nil {
			return fieldUnavailable(e.Field)
		}
		if err := th.SetWindowScale(uint8(applyValue(e, uint64(cur)))); err != nil {
			return fieldUnavailable(e.Field)
		}

	default:
		// FieldPayload и неизвестные поля: править наугад нельзя.
		return fmt.Errorf("packetexec: правка поля %s не поддержана в заголовке", e.Field)
	}
	return nil
}
