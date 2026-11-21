package vantage

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"sort"
	"strings"
)

// fingerprintBytes — длина отпечатка в байтах до перевода в шестнадцатеричную
// запись. Шестнадцати байт достаточно: отпечаток различает сети, а не защищает
// от подбора.
const fingerprintBytes = 8

// InterfaceSource отдаёт сетевые интерфейсы машины.
//
// Интерфейс, а не прямой вызов net.Interfaces, нужен тестам: отпечаток обязан
// быть проверяем на заданном наборе интерфейсов, иначе тест зависел бы от
// машины, на которой запущен, и в песочнице проверял бы не то же, что на
// рабочем компьютере.
type InterfaceSource interface {
	// Interfaces возвращает интерфейсы и их адреса.
	Interfaces() ([]Iface, error)
}

// Iface — сетевой интерфейс в виде, нужном для отпечатка.
type Iface struct {
	// Name — имя интерфейса. В отпечаток НЕ входит: имена на Windows меняются
	// при переустановке драйвера, и сеть при этом остаётся той же.
	Name string
	// HardwareAddr — аппаратный адрес.
	HardwareAddr net.HardwareAddr
	// Up — интерфейс поднят.
	Up bool
	// Loopback — интерфейс петлевой.
	Loopback bool
	// Addrs — адреса интерфейса вместе с маской.
	Addrs []net.IPNet
}

// systemInterfaces — источник на основе стандартной библиотеки.
type systemInterfaces struct{}

// Interfaces возвращает интерфейсы машины.
func (systemInterfaces) Interfaces() ([]Iface, error) {
	list, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]Iface, 0, len(list))
	for _, in := range list {
		f := Iface{
			Name:         in.Name,
			HardwareAddr: in.HardwareAddr,
			Up:           in.Flags&net.FlagUp != 0,
			Loopback:     in.Flags&net.FlagLoopback != 0,
		}
		addrs, err := in.Addrs()
		if err != nil {
			// Интерфейс мог исчезнуть между перечислением и запросом адресов.
			// Это не повод прерывать определение: пропускаем его адреса.
			out = append(out, f)
			continue
		}
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP != nil {
				f.Addrs = append(f.Addrs, *ipnet)
			}
		}
		out = append(out, f)
	}
	return out, nil
}

// SystemInterfaces возвращает источник интерфейсов машины.
func SystemInterfaces() InterfaceSource { return systemInterfaces{} }

// Fingerprint вычисляет отпечаток локальных сетевых признаков.
//
// В отпечаток входят аппаратные адреса поднятых непетлевых интерфейсов и
// НОМЕРА СЕТЕЙ их адресов, а не сами адреса. Это существенно: при повторном
// получении адреса по DHCP конкретный адрес меняется, а сеть остаётся той же,
// и отпечаток по адресам давал бы ложное срабатывание смены сети при каждом
// продлении аренды.
//
// Что отпечаток НЕ различает, и это надо знать:
//
//   - одну и ту же сеть у разных операторов (например, при смене провайдера с
//     тем же оборудованием и той же адресацией) — поэтому основной способ
//     задания точки наблюдения всё равно метка из конфига (6.2 п. 1);
//   - он МЕНЯЕТСЯ при поднятии или опускании виртуального адаптера (VPN,
//     гипервизор). Формально это и есть изменение условий наблюдения, поэтому
//     поведение считается верным, но всплывать оно будет чаще, чем смена сети.
//
// Отпечаток устойчив к порядку перечисления интерфейсов: признаки сортируются
// перед хешированием, иначе значение менялось бы от запуска к запуску.
func Fingerprint(src InterfaceSource) (string, error) {
	// Источник обязан быть задан. Проверка здесь, а не в доверии к
	// вызывающему, потому что nil даёт панику при первом же обращении, а
	// случается это на старте движка — то есть там, где внятная ошибка нужнее
	// всего. Найдено собственным промахом при подключении контура к CLI.
	if src == nil {
		return "", errors.New("vantage: источник интерфейсов не задан")
	}
	list, err := src.Interfaces()
	if err != nil {
		return "", err
	}

	parts := make([]string, 0, len(list))
	for _, f := range list {
		if !f.Up || f.Loopback {
			continue
		}
		var b strings.Builder
		b.WriteString(f.HardwareAddr.String())
		nets := make([]string, 0, len(f.Addrs))
		for _, a := range f.Addrs {
			// Маскируем адрес его же маской: получаем номер сети.
			n := net.IPNet{IP: a.IP.Mask(a.Mask), Mask: a.Mask}
			nets = append(nets, n.String())
		}
		sort.Strings(nets)
		for _, n := range nets {
			b.WriteString("|")
			b.WriteString(n)
		}
		parts = append(parts, b.String())
	}
	sort.Strings(parts)

	sum := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return hex.EncodeToString(sum[:fingerprintBytes]), nil
}
