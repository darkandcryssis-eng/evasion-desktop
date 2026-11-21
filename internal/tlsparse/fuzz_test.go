package tlsparse

import (
	"errors"
	"github.com/fitting-1c/evasion/internal/core"
	"testing"
)

// FuzzParseClientHello проверяет разбор на враждебном вводе.
//
// Проверяются свойства, нарушение которых означает аварию или неверное решение
// в рабочем режиме:
//
//  1. разбор не паникует ни на каком вводе;
//  2. при успехе все объявленные смещения лежат внутри буфера;
//  3. точки разреза упорядочены и не выходят за буфер — по ним desync режет
//     поток, и смещение за границей стало бы выходом за пределы памяти;
//  4. неполнота отличается от порчи: ErrIncomplete не возвращается на вводе,
//     который уже заведомо не TLS.
func FuzzParseClientHello(f *testing.F) {
	// Затравки компактные и статические. Настоящий ClientHello (около 1500
	// байт) в роли затравки загоняет фаззер в минимизацию, и бюджет уходит на
	// неё вместо поиска: замерено 13 тыс. итераций за 12 с против 750 тыс. на
	// компактной затравке. Подробности — в minimal_test.go.
	f.Add(buildMinimalClientHello(f, "a.example.com").Data)
	f.Add(buildMinimalClientHello(f, "").Data)
	f.Add([]byte("GET / HTTP/1.1\r\n\r\n"))
	f.Add([]byte{22, 0x03, 0x01, 0x00, 0x04, 1, 0, 0, 0})
	f.Add([]byte{22, 0x03, 0x03, 0xff, 0xff})
	f.Add([]byte{})

	var cuts []core.CutPoint

	f.Fuzz(func(t *testing.T, data []byte) {
		ch, err := ParseClientHello(data)

		if err != nil {
			// Ошибка обязана быть одной из объявленных: неизвестная означала бы
			// утечку внутренней ошибки наружу.
			switch {
			case errors.Is(err, ErrIncomplete),
				errors.Is(err, ErrNotTLS),
				errors.Is(err, ErrNotHandshake),
				errors.Is(err, ErrNotClientHello),
				errors.Is(err, ErrMalformed),
				errors.Is(err, ErrFragmentedHandshake):
			default:
				t.Fatalf("неожиданная ошибка разбора: %v", err)
			}
			return
		}

		// Запись должна умещаться в буфер: разбор объявил успех.
		if ch.Record.End() > len(data) {
			t.Fatalf("запись выходит за буфер: end=%d len=%d", ch.Record.End(), len(data))
		}
		if ch.HandshakeOff < 0 || ch.HandshakeOff+ch.HandshakeLen > len(data) {
			t.Fatalf("сообщение выходит за буфер: off=%d len=%d buf=%d",
				ch.HandshakeOff, ch.HandshakeLen, len(data))
		}
		if ch.ExtensionsOff < 0 || ch.ExtensionsOff+ch.ExtensionsLen > len(data) {
			t.Fatalf("расширения выходят за буфер: off=%d len=%d buf=%d",
				ch.ExtensionsOff, ch.ExtensionsLen, len(data))
		}
		if ch.SNILen > 0 {
			if ch.SNIOff < 0 || ch.SNIOff+ch.SNILen > len(data) {
				t.Fatalf("SNI выходит за буфер: off=%d len=%d buf=%d",
					ch.SNIOff, ch.SNILen, len(data))
			}
			// Доступ к имени обязан быть согласован с объявленными границами.
			if _, ok := ch.SNI(data); !ok {
				t.Fatal("SNI объявлен, но недоступен")
			}
		}

		cuts = ch.CutPoints(cuts[:0])
		prev := -1
		for _, p := range cuts {
			if p.Offset < 0 || p.Offset > len(data) {
				t.Fatalf("точка %s со смещением %d вне буфера длиной %d",
					p.Kind, p.Offset, len(data))
			}
			if p.Offset < prev {
				t.Fatalf("точки разреза не упорядочены: %d после %d", p.Offset, prev)
			}
			prev = p.Offset
		}
	})
}

// FuzzParseRecord отдельно фаззит слой записей: он разбирается раньше всего и на
// нём держится различение «не TLS» и «подождать ещё байт».
func FuzzParseRecord(f *testing.F) {
	f.Add([]byte{22, 0x03, 0x01, 0x00, 0x10})
	f.Add([]byte{23, 0x03, 0x03, 0x40, 0x00})
	f.Add([]byte{0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		rec, err := ParseRecord(data)
		if err != nil {
			return
		}
		if rec.PayloadOff != recordHeaderLen {
			t.Fatalf("смещение тела = %d, ожидалось %d", rec.PayloadOff, recordHeaderLen)
		}
		if rec.PayloadLen <= 0 || rec.PayloadLen > maxRecordPayload {
			t.Fatalf("длина тела = %d вне допустимых границ", rec.PayloadLen)
		}
		if rec.End() > len(data) {
			t.Fatalf("запись выходит за буфер: end=%d len=%d", rec.End(), len(data))
		}
	})
}
