//go:build windows

package netbind

import (
	"encoding/binary"
	"errors"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	ifTypeEthernet  = 6
	ifTypeWiFi      = 71
	ifOperStatusUp  = 1
	ipUnicastIF     = 31
	gaaIncludeGates = 0x80
)

// Detect читает адаптеры Windows и маршрут по умолчанию.
func Detect() (Route, error) {
	adapters, err := listAdapters()
	if err != nil {
		return Route{}, err
	}
	var best uint32
	probe := &windows.SockaddrInet4{Addr: [4]byte{1, 1, 1, 1}}
	if err := windows.GetBestInterfaceEx(probe, &best); err != nil {
		return Route{}, err
	}
	return Classify(adapters, best), nil
}

func listAdapters() ([]Adapter, error) {
	size := uint32(16 * 1024)
	for attempt := 0; attempt < 4; attempt++ {
		buf := make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_INET, gaaIncludeGates|windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST|windows.GAA_FLAG_SKIP_DNS_SERVER, 0, first, &size)
		if errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			continue
		}
		if err != nil {
			return nil, err
		}
		var out []Adapter
		for a := first; a != nil; a = a.Next {
			out = append(out, Adapter{
				Index:       a.IfIndex,
				Name:        windows.UTF16PtrToString(a.FriendlyName),
				Description: windows.UTF16PtrToString(a.Description),
				Hardware:    a.IfType == ifTypeEthernet || a.IfType == ifTypeWiFi,
				Up:          a.OperStatus == ifOperStatusUp,
				Gateway:     a.FirstGatewayAddress != nil,
				Metric:      a.Ipv4Metric,
			})
		}
		return out, nil
	}
	return nil, windows.ERROR_BUFFER_OVERFLOW
}

// bindControl ставит IP_UNICAST_IF: исходящие пакеты сокета уходят через
// заданный интерфейс независимо от таблицы маршрутов. Для IPv4 индекс
// передаётся в сетевом порядке байт.
func bindControl(index uint32) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var raw [4]byte
		binary.BigEndian.PutUint32(raw[:], index)
		value := *(*uint32)(unsafe.Pointer(&raw[0]))
		var sockErr error
		if err := c.Control(func(fd uintptr) {
			sockErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, ipUnicastIF, int(value))
		}); err != nil {
			return err
		}
		return sockErr
	}
}
