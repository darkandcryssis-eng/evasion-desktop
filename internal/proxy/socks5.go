package proxy

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

// Минимальная реализация серверной стороны SOCKS5 (RFC 1928): согласование
// метода «без аутентификации» и команда CONNECT. Этого достаточно браузерам и
// curl. Аутентификация, BIND и UDP ASSOCIATE не поддерживаются: прокси
// локальный, а UDP (QUIC) обрабатывается не здесь (3.3).

const (
	socksVersion5 = 0x05

	// методы аутентификации
	socksMethodNoAuth       = 0x00
	socksMethodNoAcceptable = 0xff

	// команды
	socksCmdConnect = 0x01

	// типы адреса
	socksAddrIPv4   = 0x01
	socksAddrDomain = 0x03
	socksAddrIPv6   = 0x04

	// коды ответа
	socksReplySuccess             = 0x00
	socksReplyGeneralFailure      = 0x01
	socksReplyCommandNotSupported = 0x07
	socksReplyAddrNotSupported    = 0x08
)

// ErrSOCKS — обобщённая ошибка протокола SOCKS5. Детали в обёрнутой ошибке; код
// ответа клиенту выбирает вызывающий.
var ErrSOCKS = errors.New("proxy: ошибка протокола SOCKS5")

// socksNegotiate выполняет согласование метода аутентификации.
//
// Клиент присылает версию, число методов и список методов. Отвечаем выбором
// «без аутентификации», если клиент его предлагает, иначе — отказом.
func socksNegotiate(c net.Conn) error {
	// [версия][число методов]
	header := make([]byte, 2)
	if _, err := io.ReadFull(c, header); err != nil {
		return fmt.Errorf("%w: чтение приветствия: %v", ErrSOCKS, err)
	}
	if header[0] != socksVersion5 {
		return fmt.Errorf("%w: версия %d не поддерживается", ErrSOCKS, header[0])
	}
	n := int(header[1])
	if n == 0 {
		return fmt.Errorf("%w: пустой список методов", ErrSOCKS)
	}
	methods := make([]byte, n)
	if _, err := io.ReadFull(c, methods); err != nil {
		return fmt.Errorf("%w: чтение методов: %v", ErrSOCKS, err)
	}

	for _, m := range methods {
		if m == socksMethodNoAuth {
			_, err := c.Write([]byte{socksVersion5, socksMethodNoAuth})
			return err
		}
	}
	// Приемлемого метода нет: сообщаем отказ и прекращаем.
	_, _ = c.Write([]byte{socksVersion5, socksMethodNoAcceptable})
	return fmt.Errorf("%w: клиент не предлагает метод без аутентификации", ErrSOCKS)
}

// socksTarget — цель, разобранная из запроса CONNECT.
type socksTarget struct {
	host string // доменное имя или строковый IP-адрес
	port uint16
}

// addr возвращает цель в форме host:port для диалера.
func (t socksTarget) addr() string {
	return net.JoinHostPort(t.host, strconv.Itoa(int(t.port)))
}

// socksReadConnect читает запрос CONNECT и возвращает цель.
//
// Формат запроса: [версия][команда][резерв][тип адреса][адрес][порт]. Длина
// адреса зависит от типа: 4 байта для IPv4, 16 для IPv6, для домена — байт
// длины и затем имя. Каждое чтение ограничено заявленной длиной, поэтому
// враждебный клиент не заставит читать за пределы.
func socksReadConnect(c net.Conn) (socksTarget, error) {
	var t socksTarget

	header := make([]byte, 4)
	if _, err := io.ReadFull(c, header); err != nil {
		return t, fmt.Errorf("%w: чтение запроса: %v", ErrSOCKS, err)
	}
	if header[0] != socksVersion5 {
		return t, fmt.Errorf("%w: версия запроса %d", ErrSOCKS, header[0])
	}
	if header[1] != socksCmdConnect {
		// Поддерживаем только CONNECT; об отказе сообщит вызывающий кодом ответа.
		return t, fmt.Errorf("%w: команда %d не поддерживается", ErrSOCKS, header[1])
	}
	// header[2] — зарезервированный байт, игнорируется.

	switch header[3] {
	case socksAddrIPv4:
		buf := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(c, buf); err != nil {
			return t, fmt.Errorf("%w: чтение IPv4: %v", ErrSOCKS, err)
		}
		t.host = net.IP(buf).String()
	case socksAddrIPv6:
		buf := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(c, buf); err != nil {
			return t, fmt.Errorf("%w: чтение IPv6: %v", ErrSOCKS, err)
		}
		t.host = net.IP(buf).String()
	case socksAddrDomain:
		lenByte := make([]byte, 1)
		if _, err := io.ReadFull(c, lenByte); err != nil {
			return t, fmt.Errorf("%w: чтение длины домена: %v", ErrSOCKS, err)
		}
		name := make([]byte, int(lenByte[0]))
		if _, err := io.ReadFull(c, name); err != nil {
			return t, fmt.Errorf("%w: чтение домена: %v", ErrSOCKS, err)
		}
		t.host = string(name)
	default:
		return t, fmt.Errorf("%w: тип адреса %d не поддерживается", ErrSOCKS, header[3])
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(c, portBuf); err != nil {
		return t, fmt.Errorf("%w: чтение порта: %v", ErrSOCKS, err)
	}
	// Порт в сетевом порядке байт.
	t.port = uint16(portBuf[0])<<8 | uint16(portBuf[1])
	return t, nil
}

// socksReply отправляет клиенту ответ на запрос CONNECT.
//
// Поле связанного адреса заполняем нулевым IPv4-адресом и портом: клиенту он не
// нужен (соединение уже установлено прокси), а подставлять настоящий локальный
// адрес незачем.
func socksReply(c net.Conn, code byte) error {
	resp := []byte{
		socksVersion5, code, 0x00, socksAddrIPv4,
		0, 0, 0, 0, // связанный адрес 0.0.0.0
		0, 0, // связанный порт 0
	}
	_, err := c.Write(resp)
	return err
}
