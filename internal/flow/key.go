package flow

import (
	"bytes"
	"net"
)

// Endpoint — одна сторона соединения: адрес и порт.
//
// Адрес хранится 16 байтами всегда: IPv4 приводится к виду IPv4-в-IPv6
// (net.IP.To16), поэтому одна структура годится для обоих протоколов (3.2), и
// сравнение ключей единообразно.
type Endpoint struct {
	IP   [16]byte
	Port uint16
}

// Key — соединение, нормализованное так, что пакеты обеих сторон дают один
// ключ. Структура сравнима, поэтому служит ключом карты напрямую, без строковой
// сериализации в горячем пути.
type Key struct {
	A, B Endpoint
}

// NewKey строит нормализованный ключ из двух концов соединения.
//
// Порядок концов не важен: меньший кладётся в A. Благодаря этому исходящий
// пакет (src=приложение, dst=сервер) и входящий (наоборот) дают один ключ, и
// обе стороны находят один поток.
func NewKey(ip1 net.IP, port1 uint16, ip2 net.IP, port2 uint16) Key {
	e1 := endpointOf(ip1, port1)
	e2 := endpointOf(ip2, port2)
	if lessEndpoint(e1, e2) {
		return Key{A: e1, B: e2}
	}
	return Key{A: e2, B: e1}
}

// endpointOf собирает Endpoint, приводя адрес к 16 байтам.
func endpointOf(ip net.IP, port uint16) Endpoint {
	var e Endpoint
	// To16 возвращает nil для негодного адреса; copy тогда оставит нули — это
	// лучше паники в горячем пути, а негодный адрес сюда прийти не должен
	// (ключ строится из разобранного пакета).
	copy(e.IP[:], ip.To16())
	e.Port = port
	return e
}

// lessEndpoint задаёт устойчивый порядок концов: сначала по адресу, затем по
// порту.
func lessEndpoint(x, y Endpoint) bool {
	if c := bytes.Compare(x.IP[:], y.IP[:]); c != 0 {
		return c < 0
	}
	return x.Port < y.Port
}
