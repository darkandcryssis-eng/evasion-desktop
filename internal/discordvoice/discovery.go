package discordvoice

import "encoding/binary"

// Раскладка пакета обнаружения внешнего IP (IP discovery) Discord. Пакет
// фиксированной длины 74 байта, порядок байт сетевой (big-endian):
//
//	0–1   тип (0x0001 — запрос клиента, 0x0002 — ответ сервера)
//	2–3   длина оставшейся части пакета, всегда 70 (0x0046)
//	4–7   SSRC
//	8–71  адрес (64 байта; у запроса клиента — нули)
//	72–73 порт
//
// Клиент шлёт запрос (тип 0x0001) первым пакетом голосового соединения — по
// нему и опознаём начало голоса. Длина поля (70) не включает первые 4 байта
// (тип и длину), поэтому 4 + 70 = 74 суммарно.
const (
	discoveryLen      = 74
	discoveryBodyLen  = 70 // значение поля длины: всё после типа и длины
	discoveryTypeOff  = 0
	discoveryLenOff   = 2
	discoveryTypeReq  = 0x0001 // запрос клиента
	discoveryTypeResp = 0x0002 // ответ сервера
)

// IsIPDiscoveryRequest сообщает, что полезная нагрузка UDP — это запрос
// обнаружения внешнего IP, которым клиент Discord открывает голосовое
// соединение.
//
// Проверяется строго: точная длина 74 байта, тип 0x0001 и поле длины 70.
// Строгость намеренная — это и есть опознание голоса «по форме», и принять за
// него что-то постороннее нельзя (1.6): ложная цель повела бы десинк по чужому
// UDP. Поэтому любое расхождение — false, и вызывающий поток не трогает.
func IsIPDiscoveryRequest(payload []byte) bool {
	if len(payload) != discoveryLen {
		return false
	}
	if binary.BigEndian.Uint16(payload[discoveryTypeOff:]) != discoveryTypeReq {
		return false
	}
	return binary.BigEndian.Uint16(payload[discoveryLenOff:]) == discoveryBodyLen
}

// IsIPDiscovery сообщает, что нагрузка — пакет обнаружения внешнего IP Discord
// любого направления (запрос клиента или ответ сервера).
//
// Нужна наблюдению за обоими концами обмена: ответ сервера (тип 0x0002)
// подтверждает, что голосовое соединение установилось. Для выбора момента
// десинка служит именно запрос клиента (IsIPDiscoveryRequest) — он исходящий и
// первый; ответ сервера входящий и к применению десинка отношения не имеет.
func IsIPDiscovery(payload []byte) bool {
	if len(payload) != discoveryLen {
		return false
	}
	if binary.BigEndian.Uint16(payload[discoveryLenOff:]) != discoveryBodyLen {
		return false
	}
	t := binary.BigEndian.Uint16(payload[discoveryTypeOff:])
	return t == discoveryTypeReq || t == discoveryTypeResp
}

// Заголовок STUN/TURN (RFC 5389 / RFC 5766): тип, длина атрибутов, magic
// cookie, 12 байт идентификатора транзакции.
const (
	stunHeaderLen               = 20
	stunBindingRequest          = 0x0001
	stunAllocateRequest         = 0x0003
	stunRefreshRequest          = 0x0004
	stunCreatePermissionRequest = 0x0008
	stunChannelBindRequest      = 0x0009
	stunMagicCookie             = 0x2112A442
)

// IsSTUNBindingRequest сообщает, что нагрузка UDP — запрос STUN Binding.
//
// Им открывается медиа-соединение WebRTC: демонстрация экрана и клиенты
// Discord, которые идут через WebRTC, начинают поток не с IP discovery, а с
// него. Проверка строгая: тип, magic cookie и поле длины, равное остатку
// пакета и кратное четырём.
func IsSTUNBindingRequest(payload []byte) bool {
	if len(payload) < stunHeaderLen {
		return false
	}
	if binary.BigEndian.Uint16(payload[0:]) != stunBindingRequest {
		return false
	}
	if binary.BigEndian.Uint32(payload[4:]) != stunMagicCookie {
		return false
	}
	n := int(binary.BigEndian.Uint16(payload[2:]))
	return n%4 == 0 && n == len(payload)-stunHeaderLen
}

// IsSTUNOrTURNRequest сообщает, что нагрузка UDP — запрос STUN Binding или
// TURN (Allocate, Refresh, CreatePermission, ChannelBind), используемый
// WebRTC и звонками Telegram.
func IsSTUNOrTURNRequest(payload []byte) bool {
	if len(payload) < stunHeaderLen {
		return false
	}
	switch binary.BigEndian.Uint16(payload[0:]) {
	case stunBindingRequest, stunAllocateRequest, stunRefreshRequest, stunCreatePermissionRequest, stunChannelBindRequest:
	default:
		return false
	}
	if binary.BigEndian.Uint32(payload[4:]) != stunMagicCookie {
		return false
	}
	n := int(binary.BigEndian.Uint16(payload[2:]))
	return n%4 == 0 && n == len(payload)-stunHeaderLen
}
