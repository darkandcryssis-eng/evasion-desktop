package discordvoice

import (
	"errors"
	"fmt"

	"github.com/fitting-1c/evasion/internal/packet"
)

// Fooling — способ «обмана» DPI в decoy-пакете. Это UDP-аналоги TCP-фейков из
// стартового портфеля: приём общего назначения, а какой берёт конкретный
// цензор — решает живая проверка, а не предположение.
type Fooling uint8

const (
	// FoolTTL — живой decoy с низким TTL (IPv4) либо hop limit (IPv6): доходит
	// до DPI, но умирает до сервера. Контрольные суммы верные, иначе пакет
	// отбросит первый же маршрутизатор и до DPI он не дойдёт.
	FoolTTL Fooling = iota
	// FoolBadChecksum — decoy с битой контрольной суммой UDP: DPI впитывает его
	// (сумму UDP на пути обычно не проверяют), а сервер отбрасывает. IP-заголовок
	// и его сумма при этом верны, чтобы пакет дошёл до DPI.
	FoolBadChecksum
)

// BuildDecoy строит decoy-пакет из шаблона raw — полного буфера исходящего
// UDP-пакета (IP + UDP + нагрузка). Шаблон не изменяется: результат — новый
// буфер.
//
// Назначение: отправить decoy ПЕРЕД настоящим первым пакетом голоса (IP
// discovery), чтобы испортить DPI представление о начале UDP-потока, не меняя
// того, что увидит сервер. Отсюда два приёма: короткий TTL (не доходит до
// сервера) и битая сумма UDP (сервер отбрасывает). Оба — механика общего
// назначения; действенность решает живой прогон (2.5), как у TCP-фейков.
//
// replacePayload, если не nil, замещает нагрузку decoy — ТОЙ ЖЕ длины, иначе
// ошибка: смена длины потребовала бы правки полей длины IP и UDP, это отдельный
// путь. nil оставляет нагрузку шаблона, и тогда decoy — копия настоящего пакета
// с укороченным TTL или битой суммой.
func BuildDecoy(raw []byte, fool Fooling, ttl uint8, replacePayload []byte) ([]byte, error) {
	d, err := packet.Dissect(raw)
	if err != nil {
		return nil, err
	}
	if _, ok := d.UDP(raw); !ok {
		return nil, errors.New("discordvoice: шаблон decoy не UDP")
	}

	// Смещения в d не зависят от самого буфера, поэтому их можно применять к
	// копии с той же раскладкой.
	out := make([]byte, len(raw))
	copy(out, raw)

	if replacePayload != nil {
		pl, ok := d.Payload(out)
		if !ok {
			return nil, errors.New("discordvoice: у шаблона нет нагрузки")
		}
		if len(pl) != len(replacePayload) {
			return nil, fmt.Errorf("discordvoice: длина decoy %d не равна длине нагрузки шаблона %d",
				len(replacePayload), len(pl))
		}
		copy(pl, replacePayload)
	}

	// Короткий TTL/hop limit: decoy не доживёт до сервера.
	if h, ok := d.IPv4(out); ok {
		h.SetTTL(ttl)
	} else if h, ok := d.IPv6(out); ok {
		h.SetHopLimit(ttl)
	}

	// Верные суммы обязательны: иначе decoy отбросит первый маршрутизатор, и до
	// DPI он не дойдёт — приём не сработает по технической причине, а не по сути.
	if !d.RecomputeChecksums(out) {
		return nil, errors.New("discordvoice: не удалось пересчитать суммы decoy")
	}

	if fool == FoolBadChecksum {
		u, _ := d.UDP(out)
		// Инвертируем верную сумму — получаем заведомо битую.
		corrupt := u.Checksum() ^ 0xFFFF
		if corrupt == 0 {
			// Ноль у UDP поверх IPv4 означает «сумма не вычислялась» — это
			// валидно, а нам нужна именно БИТАЯ. Берём заведомо ненулевое.
			corrupt = 0x0001
		}
		u.SetChecksum(corrupt)
	}

	return out, nil
}
