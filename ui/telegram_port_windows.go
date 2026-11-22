//go:build windows

package main

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procGetExtendedTcpTable = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetExtendedTcpTable")

func addrInUse(err error) bool { return errors.Is(err, windows.WSAEADDRINUSE) }

func findPortHolder(port int) (portHolder, bool) {
	const tcpTableOwnerPIDListener = 3
	var size uint32
	procGetExtendedTcpTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, windows.AF_INET, tcpTableOwnerPIDListener, 0)
	for range 3 {
		if size < 4 || size > 4<<20 {
			return portHolder{}, false
		}
		buf := make([]byte, size)
		r, _, _ := procGetExtendedTcpTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, windows.AF_INET, tcpTableOwnerPIDListener, 0)
		if r == uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
			continue
		}
		if r != 0 {
			return portHolder{}, false
		}
		rows, err := decodeTCPListeners(buf)
		if err != nil {
			return portHolder{}, false
		}
		pid, ok := loopbackHolder(rows, port)
		if !ok {
			return portHolder{}, false
		}
		return portHolder{PID: pid, Image: processImagePath(pid)}, true
	}
	return portHolder{}, false
}

func processImagePath(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, 32768)
	size := uint32(len(buf))
	if windows.QueryFullProcessImageName(h, 0, &buf[0], &size) != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:size])
}

func retireProcess(pid uint32) {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, pid)
	if err != nil {
		return
	}
	defer windows.CloseHandle(h)
	if windows.TerminateProcess(h, 0) == nil {
		_, _ = windows.WaitForSingleObject(h, 3000)
	}
}
