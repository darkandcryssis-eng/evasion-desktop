//go:build windows

package main

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// runningProcessNames — имена исполняемых файлов всех процессов (Toolhelp).
func runningProcessNames() ([]string, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)
	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err = windows.Process32First(snap, &entry); err != nil {
		return nil, err
	}
	var names []string
	for {
		names = append(names, windows.UTF16ToString(entry.ExeFile[:]))
		if err = windows.Process32Next(snap, &entry); err != nil {
			break
		}
	}
	return names, nil
}
