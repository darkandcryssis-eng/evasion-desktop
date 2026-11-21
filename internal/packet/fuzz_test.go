package packet

import "testing"

// FuzzDissect — главный фаззер проекта: здесь обрабатываются данные из сети,
// то есть заведомо враждебные. Проверяется не корректность разбора, а два
// свойства, нарушение которых означает аварию в рабочем режиме:
//
//  1. разбор не паникует ни на каком вводе;
//  2. если разбор удался, объявленные им смещения лежат внутри буфера —
//     иначе последующее обращение к слоям вышло бы за границы.
func FuzzDissect(f *testing.F) {
	// Затравки: корректные пакеты обоих семейств, пакет с опциями, цепочка
	// расширений, усечённый пакет и явный мусор.
	f.Add(buildIPv4TCP(f))
	f.Add(buildIPv6TCP(f))
	f.Add(buildIPv4UDP(f))
	f.Add(buildIPv6ExtTCP(f))
	f.Add(buildIPv4TCPWithOptions(f))
	f.Add(buildIPv4TCP(f)[:25])
	f.Add([]byte{0x45, 0, 0, 20})
	f.Add([]byte{0x60})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		d, err := Dissect(data)
		if err != nil {
			return
		}

		// Смещения обязаны быть неотрицательны и не выходить за буфер.
		if d.L3Len < 0 || d.L3Len > len(data) {
			t.Fatalf("L3Len=%d вне буфера длиной %d", d.L3Len, len(data))
		}
		if d.L4Off < 0 || d.L4Len < 0 || d.L4Off+d.L4Len > len(data) {
			t.Fatalf("L4 off=%d len=%d вне буфера длиной %d", d.L4Off, d.L4Len, len(data))
		}
		if d.PayloadOff < 0 || d.PayloadLen < 0 || d.PayloadOff+d.PayloadLen > len(data) {
			t.Fatalf("тело off=%d len=%d вне буфера длиной %d",
				d.PayloadOff, d.PayloadLen, len(data))
		}

		// Доступ к слоям не должен паниковать и не должен отдавать срезы за
		// границами буфера.
		if h, ok := d.IPv4(data); ok && len(h) > len(data) {
			t.Fatal("представление IPv4 длиннее буфера")
		}
		if h, ok := d.IPv6(data); ok && len(h) > len(data) {
			t.Fatal("представление IPv6 длиннее буфера")
		}
		if th, ok := d.TCP(data); ok {
			if len(th) > len(data) {
				t.Fatal("представление TCP длиннее буфера")
			}
			// Перебор опций обязан завершаться на любом вводе.
			count := 0
			for range th.Options() {
				count++
				if count > tcpMaxHeaderLen {
					t.Fatal("перебор опций не завершается")
				}
			}
			_, _ = th.MSS()
			_, _ = th.WindowScale()
		}
		if uh, ok := d.UDP(data); ok && len(uh) != udpHeaderLen {
			t.Fatalf("представление UDP длиной %d", len(uh))
		}
		_, _ = d.Payload(data)

		// Пересчёт и проверка сумм на произвольном вводе тоже не должны
		// паниковать. Результат не проверяем: на мусоре он произволен.
		_ = d.RecomputeChecksums(data)
		_ = d.VerifyChecksums(data)
	})
}

// FuzzUpdateChecksum16 проверяет эквивалентность инкрементального пересчёта
// полному на случайных значениях: это свойство, от которого зависит
// корректность правки любого поля заголовка.
func FuzzUpdateChecksum16(f *testing.F) {
	f.Add([]byte{0x00, 0x00, 0x00, 0x00})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{0x40, 0x06, 0x03, 0x06})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 4 {
			return
		}
		// Берём два 16-битных слова: старое и новое значение поля.
		oldWord := uint16(data[0])<<8 | uint16(data[1])
		newWord := uint16(data[2])<<8 | uint16(data[3])

		pkt := buildIPv4TCP(t)
		h, err := ParseIPv4Header(pkt)
		if err != nil {
			t.Fatal(err)
		}
		// Записываем старое слово в поле идентификатора (оно не участвует ни в
		// каких проверках) и считаем сумму полностью.
		h.SetID(oldWord)
		h.RecomputeChecksum()
		before := h.Checksum()

		incremental := UpdateChecksum16(before, oldWord, newWord)

		h.SetID(newWord)
		h.RecomputeChecksum()
		full := h.Checksum()

		if incremental != full {
			t.Fatalf("old=0x%04x new=0x%04x: инкрементально 0x%04x, полностью 0x%04x",
				oldWord, newWord, incremental, full)
		}
	})
}
