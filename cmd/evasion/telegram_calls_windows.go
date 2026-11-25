//go:build windows

package main

import (
	"encoding/binary"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var tgIPHelper = windows.NewLazySystemDLL("iphlpapi.dll")

const (
	tgOwnerCacheTTL      = 250 * time.Millisecond
	tgOwnerUnknownFloor  = 50 * time.Millisecond
)

type windowsTelegramUDPOwner struct {
	mu    sync.Mutex
	last  time.Time
	ports map[uint16]bool
}

func newTelegramUDPOwner() telegramUDPOwner {
	return &windowsTelegramUDPOwner{ports: map[uint16]bool{}}
}

func (o *windowsTelegramUDPOwner) OwnsUDP(localPort uint16) bool {
	if localPort == 0 {
		return false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	age := time.Since(o.last)
	owned, known := o.ports[localPort]
	if age > tgOwnerCacheTTL || (!known && age > tgOwnerUnknownFloor) {
		o.refresh()
		owned = o.ports[localPort]
	}
	return owned
}

func (o *windowsTelegramUDPOwner) refresh() {
	o.last = time.Now()
	pids := telegramProcessPIDs()
	if len(pids) == 0 {
		o.ports = map[uint16]bool{}
		return
	}
	ports := make(map[uint16]bool)
	for _, ipv6 := range []bool{false, true} {
		for _, row := range readUDPOwnerTable(ipv6) {
			if row.port != 0 && pids[row.pid] {
				ports[row.port] = true
			}
		}
	}
	o.ports = ports
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
		out = append(out, udpOwnerRow{
			port: binary.BigEndian.Uint16(row[portOff : portOff+2]),
			pid:  binary.LittleEndian.Uint32(row[pidOff : pidOff+4]),
		})
	}
	return out
}
