package packet

// Доступ к слоям разобранного пакета и пересчёт контрольных сумм.
//
// Эти функции принимают буфер и результат его разбора. Связь между ними
// компилятором не проверяется (см. оговорку у Dissection), поэтому каждая из
// них перепроверяет границы: цена — несколько сравнений, выгода — отсутствие
// паник при рассогласовании.

// IPv4 возвращает представление заголовка IPv4 разобранного пакета.
// Второе значение — false, если пакет не IPv4 либо буфер короче разбора.
func (d Dissection) IPv4(buf []byte) (IPv4Header, bool) {
	if d.Version != Version4 || d.L3Len < ipv4MinHeaderLen || len(buf) < d.L3Len {
		return nil, false
	}
	return IPv4Header(buf[:d.L3Len]), true
}

// IPv6 возвращает представление основного заголовка IPv6 разобранного пакета.
//
// Заголовки расширения в представление не входят: оно покрывает только
// фиксированные 40 байт, поля которых и правит десинк.
func (d Dissection) IPv6(buf []byte) (IPv6Header, bool) {
	if d.Version != Version6 || len(buf) < ipv6HeaderLen {
		return nil, false
	}
	return IPv6Header(buf[:ipv6HeaderLen]), true
}

// TCP возвращает представление заголовка TCP разобранного пакета.
func (d Dissection) TCP(buf []byte) (TCPHeader, bool) {
	if d.Protocol != ProtoTCP || d.L4Len < tcpMinHeaderLen || len(buf) < d.L4Off+d.L4Len {
		return nil, false
	}
	return TCPHeader(buf[d.L4Off : d.L4Off+d.L4Len]), true
}

// UDP возвращает представление заголовка UDP разобранного пакета.
func (d Dissection) UDP(buf []byte) (UDPHeader, bool) {
	if d.Protocol != ProtoUDP || d.L4Len < udpHeaderLen || len(buf) < d.L4Off+d.L4Len {
		return nil, false
	}
	return UDPHeader(buf[d.L4Off : d.L4Off+d.L4Len]), true
}

// Payload возвращает полезную нагрузку разобранного пакета.
//
// Для исходящего TLS-соединения это и есть байты записи TLS, которые затем
// разбирает tlsparse.
func (d Dissection) Payload(buf []byte) ([]byte, bool) {
	if d.PayloadLen <= 0 {
		return nil, false
	}
	end := d.PayloadOff + d.PayloadLen
	if d.PayloadOff < 0 || end > len(buf) {
		return nil, false
	}
	return buf[d.PayloadOff:end], true
}

// srcDst возвращает адреса источника и назначения сетевого слоя.
func (d Dissection) srcDst(buf []byte) (src, dst []byte, ok bool) {
	switch d.Version {
	case Version4:
		h, ok := d.IPv4(buf)
		if !ok {
			return nil, nil, false
		}
		return h.Src(), h.Dst(), true
	case Version6:
		h, ok := d.IPv6(buf)
		if !ok {
			return nil, nil, false
		}
		return h.Src(), h.Dst(), true
	default:
		return nil, nil, false
	}
}

// RecomputeChecksums пересчитывает контрольные суммы сетевого слоя и слоя
// протокола для разобранного пакета.
//
// Вызывается после любой правки полей или тела. Единственное исключение —
// примитив намеренной порчи суммы: он пишет значение через SetChecksum уже
// ПОСЛЕ пересчёта, иначе порча была бы затёрта.
//
// Возвращает false, если разбор не согласуется с буфером настолько, что считать
// нечего. Усечённый пакет пересчёту не подлежит: сумма считается по всей длине
// протокола, а её байт в буфере нет, и результат был бы неверным — молча
// записать такую сумму хуже, чем отказаться.
func (d Dissection) RecomputeChecksums(buf []byte) bool {
	if d.Truncated {
		return false
	}

	// Сетевой слой: только IPv4, у IPv6 контрольной суммы заголовка нет —
	// целостность там возложена на протоколы верхнего уровня.
	if h, ok := d.IPv4(buf); ok {
		h.RecomputeChecksum()
	}

	if d.L4Off == 0 || d.L4Len == 0 {
		// Заголовка верхнего уровня нет (фрагмент или прочий протокол) —
		// сетевая сумма уже пересчитана, больше делать нечего.
		return true
	}

	src, dst, ok := d.srcDst(buf)
	if !ok {
		return false
	}

	// Длина данных протокола верхнего уровня: заголовок плюс тело. Именно она
	// входит в псевдозаголовок, и ошибка в ней — классический источник
	// «пакет уходит, но молча отбрасывается».
	l4Len := d.L4Len + d.PayloadLen
	end := d.L4Off + l4Len
	if end > len(buf) || l4Len < 0 {
		return false
	}
	l4 := buf[d.L4Off:end]

	var pseudo uint32
	switch d.Version {
	case Version4:
		pseudo = pseudoSumIPv4(src, dst, uint8(d.Protocol), l4Len)
	case Version6:
		pseudo = pseudoSumIPv6(src, dst, uint8(d.Protocol), l4Len)
	default:
		return false
	}

	switch d.Protocol {
	case ProtoTCP:
		th, ok := d.TCP(buf)
		if !ok {
			return false
		}
		th.SetChecksum(l4Checksum(pseudo, l4, tcpChecksumOff))
	case ProtoUDP:
		uh, ok := d.UDP(buf)
		if !ok {
			return false
		}
		sum := l4Checksum(pseudo, l4, udpChecksumOff)
		// Нулевая сумма в UDP означает «не вычислялась», поэтому вычисленный
		// ноль передаётся как 0xFFFF: в арифметике дополнения до единицы это
		// то же значение, но не спутается с признаком отсутствия суммы.
		if sum == 0 {
			sum = 0xffff
		}
		uh.SetChecksum(sum)
	}
	return true
}

// VerifyChecksums проверяет контрольные суммы разобранного пакета.
//
// Нужна тестам и офлайн-воспроизведению: это независимая от RecomputeChecksums
// проверка свойства «сумма по всем словам, включая поле суммы, даёт нули».
// Поэтому ошибка в одной из двух функций не маскируется другой.
func (d Dissection) VerifyChecksums(buf []byte) bool {
	if d.Truncated {
		return false
	}
	if h, ok := d.IPv4(buf); ok {
		// Свойство суммы в дополнении до единицы: если просуммировать весь
		// заголовок вместе с полем суммы, свёрнутый результат равен 0xFFFF,
		// а его инверсия — нулю.
		if foldChecksum(onesComplementSum(h, 0)) != 0 {
			return false
		}
	}
	if d.L4Off == 0 || d.L4Len == 0 {
		return true
	}
	src, dst, ok := d.srcDst(buf)
	if !ok {
		return false
	}
	l4Len := d.L4Len + d.PayloadLen
	end := d.L4Off + l4Len
	if end > len(buf) {
		return false
	}
	l4 := buf[d.L4Off:end]

	var pseudo uint32
	switch d.Version {
	case Version4:
		pseudo = pseudoSumIPv4(src, dst, uint8(d.Protocol), l4Len)
	case Version6:
		pseudo = pseudoSumIPv6(src, dst, uint8(d.Protocol), l4Len)
	default:
		return false
	}
	switch d.Protocol {
	case ProtoTCP, ProtoUDP:
		return foldChecksum(onesComplementSum(l4, pseudo)) == 0
	default:
		return true
	}
}
