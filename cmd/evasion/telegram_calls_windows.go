//go:build windows

package main

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var tgIPHelper = windows.NewLazySystemDLL("iphlpapi.dll")

const (
	tgOwnerCacheTTL     = 250 * time.Millisecond
	tgOwnerUnknownFloor = 50 * time.Millisecond
)

type windowsTelegramUDPOwner struct {
	mu   sync.Mutex
	last time.Time
	snap udpOwnerSnapshot
}

func newTelegramUDPOwner() telegramUDPOwner {
	return &windowsTelegramUDPOwner{}
}

func (o *windowsTelegramUDPOwner) OwnsUDP(localIP netip.Addr, localPort uint16) bool {
	if !localIP.IsValid() || localPort == 0 {
		return false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	age := time.Since(o.last)
	owned := o.snap.Owns(localIP, localPort)
	if age > tgOwnerCacheTTL || (!owned && age > tgOwnerUnknownFloor) {
		o.refresh()
		owned = o.snap.Owns(localIP, localPort)
	}
	return owned
}

func (o *windowsTelegramUDPOwner) refresh() {
	o.last = time.Now()
	pids := telegramProcessPIDs()
	if len(pids) == 0 {
		o.snap = udpOwnerSnapshot{}
		return
	}
	tg := make(map[udpEndpoint]bool)
	other := make(map[udpEndpoint]bool)
	for _, ipv6 := range []bool{false, true} {
		for _, row := range readUDPOwnerTable(ipv6) {
			if row.port == 0 || !row.addr.IsValid() {
				continue
			}
			ep := udpEndpoint{addr: row.addr.Unmap(), port: row.port}
			if pids[row.pid] {
				tg[ep] = true
			} else {
				other[ep] = true
			}
		}
	}
	o.snap = udpOwnerSnapshot{tg: tg, other: other}
}

func telegramProcessPIDs() map[uint32]bool {
	h, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(h)
	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	out := make(map[uint32]bool)
	for err = windows.Process32First(h, &entry); err == nil; err = windows.Process32Next(h, &entry) {
		if entry.ProcessID > 4 && isTelegramProcessName(windows.UTF16ToString(entry.ExeFile[:])) {
			out[entry.ProcessID] = true
		}
	}
	return out
}

type udpOwnerRow struct {
	addr netip.Addr
	port uint16
	pid  uint32
}

func readUDPOwnerTable(ipv6 bool) []udpOwnerRow {
	proc := tgIPHelper.NewProc("GetExtendedUdpTable")
	family := uintptr(windows.AF_INET)
	if ipv6 {
		family = windows.AF_INET6
	}
	const udpTableOwnerPID = uintptr(1)
	var size uint32
	res, _, _ := proc.Call(0, uintptr(unsafe.Pointer(&size)), 0, family, udpTableOwnerPID, 0)
	if res != 0 && res != 122 {
		return nil
	}
	for range 3 {
		if size < 4 || size > 4<<20 {
			return nil
		}
		buf := make([]byte, size)
		res, _, _ = proc.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, family, udpTableOwnerPID, 0)
		if res == 0 {
			return decodeUDPOwnerRows(buf[:min(int(size), len(buf))], ipv6)
		}
		if res != 122 {
			break
		}
	}
	return nil
}

func decodeUDPOwnerRows(data []byte, ipv6 bool) []udpOwnerRow {
	size, portOff, pidOff := 12, 4, 8
	if ipv6 {
		size, portOff, pidOff = 28, 20, 24
	}
	if len(data) < 4 {
		return nil
	}
	count := int(binary.LittleEndian.Uint32(data))
	if count > (len(data)-4)/size {
		return nil
	}
	out := make([]udpOwnerRow, 0, count)
	for i := 0; i < count; i++ {
		row := data[4+i*size : 4+(i+1)*size]
		var addr netip.Addr
		if ipv6 {
			addr = netip.AddrFrom16([16]byte(row[0:16]))
		} else {
			addr = netip.AddrFrom4([4]byte(row[0:4]))
		}
		out = append(out, udpOwnerRow{
			addr: addr,
			port: binary.BigEndian.Uint16(row[portOff : portOff+2]),
			pid:  binary.LittleEndian.Uint32(row[pidOff : pidOff+4]),
		})
	}
	return out
}
