//go:build windows

package netbind

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
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
			var gateway netip.Addr
			if a.FirstGatewayAddress != nil {
				if ip, ok := netip.AddrFromSlice(a.FirstGatewayAddress.Address.IP()); ok {
					gateway = ip.Unmap()
				}
			}
			out = append(out, Adapter{
				GatewayIP:   gateway,
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

var (
	iphlpapi                 = windows.NewLazySystemDLL("iphlpapi.dll")
	procCreateIpForwardEntry = iphlpapi.NewProc("CreateIpForwardEntry")
	procDeleteIpForwardEntry = iphlpapi.NewProc("DeleteIpForwardEntry")
)

// mibIPForwardRow — MIB_IPFORWARDROW. Адреса лежат в сетевом порядке байт.
type mibIPForwardRow struct {
	Dest, Mask, Policy, NextHop, IfIndex uint32
	Type, Proto, Age, NextHopAS          uint32
	Metric1, Metric2, Metric3            uint32
	Metric4, Metric5                     uint32
}

const (
	mibIPRouteTypeIndirect = 4
	mibIPProtoNetMgmt      = 3
	metricUnused           = 0xFFFFFFFF
)

func rawIPv4(addr netip.Addr) uint32 {
	raw := addr.As4()
	return *(*uint32)(unsafe.Pointer(&raw[0]))
}

func (r HostRoute) row() mibIPForwardRow {
	return mibIPForwardRow{
		Dest: rawIPv4(r.Dest), Mask: 0xFFFFFFFF, NextHop: rawIPv4(r.Gateway), IfIndex: r.IfIndex,
		Type: mibIPRouteTypeIndirect, Proto: mibIPProtoNetMgmt,
		// Метрика не меньше метрики интерфейса, иначе Windows отвергает строку.
		Metric1: r.Metric, Metric2: metricUnused, Metric3: metricUnused, Metric4: metricUnused, Metric5: metricUnused,
	}
}

// Add ставит маршрут. Уже существующий маршрут ошибкой не считается. Если
// системный вызов отвергнут, маршрут ставится через route.exe.
func (r HostRoute) Add() error {
	row := r.row()
	code, _, _ := procCreateIpForwardEntry.Call(uintptr(unsafe.Pointer(&row)))
	if code == 0 || windows.Errno(code) == windows.ERROR_OBJECT_ALREADY_EXISTS {
		return nil
	}
	if out, err := r.routeExe("ADD", "METRIC", "1"); err != nil {
		return fmt.Errorf("CreateIpForwardEntry: %w; route.exe: %v (%s)", windows.Errno(code), err, out)
	}
	return nil
}

// Delete снимает маршрут; отсутствующий маршрут ошибкой не считается.
func (r HostRoute) Delete() error {
	row := r.row()
	code, _, _ := procDeleteIpForwardEntry.Call(uintptr(unsafe.Pointer(&row)))
	if code == 0 || windows.Errno(code) == windows.ERROR_NOT_FOUND {
		return nil
	}
	if out, err := r.routeExe("DELETE"); err != nil {
		return fmt.Errorf("DeleteIpForwardEntry: %w; route.exe: %v (%s)", windows.Errno(code), err, out)
	}
	return nil
}

func (r HostRoute) routeExe(verb string, extra ...string) (string, error) {
	args := []string{verb, r.Dest.String(), "MASK", "255.255.255.255", r.Gateway.String()}
	args = append(args, extra...)
	args = append(args, "IF", strconv.FormatUint(uint64(r.IfIndex), 10))
	cmd := exec.Command("route.exe", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	out, err := cmd.CombinedOutput()
	return string(out), err
}
