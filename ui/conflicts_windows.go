//go:build windows

package main

import (
	"os"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const servicesKey = `SYSTEM\CurrentControlSet\Services`

// clearConflicts останавливает сторонние средства обхода и убирает битую
// запись драйвера WinDivert. Службы идут первыми: иначе диспетчер служб
// поднимет убитый процесс заново.
func clearConflicts() conflictReport {
	var r conflictReport
	stopConflictServices(&r)
	killConflictProcesses(&r)
	dropStaleDriver(&r)
	return r
}

func serviceImagePath(name string) string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, servicesKey+`\`+name, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	path, _, _ := k.GetStringValue("ImagePath")
	return path
}

func stopConflictServices(r *conflictReport) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, servicesKey, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return
	}
	names, _ := key.ReadSubKeyNames(-1)
	key.Close()
	var m *mgr.Mgr
	for _, name := range names {
		if driverServiceName.MatchString(name) || !isConflictService(name, serviceImagePath(name)) {
			continue
		}
		if m == nil {
			if m, err = mgr.Connect(); err != nil {
				return
			}
			defer m.Disconnect()
		}
		s, err := m.OpenService(name)
		if err != nil {
			continue
		}
		st, err := s.Query()
		if err == nil && st.State != svc.Stopped {
			if stopService(s) {
				r.Stopped = append(r.Stopped, "служба "+name)
			} else {
				r.Failed = append(r.Failed, "служба "+name)
			}
		}
		s.Close()
	}
}

func stopService(s *mgr.Service) bool {
	_, _ = s.Control(svc.Stop)
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if st, err := s.Query(); err != nil || st.State == svc.Stopped {
			return err == nil
		}
	}
	return false
}

func killConflictProcesses(r *conflictReport) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return
	}
	defer windows.CloseHandle(snapshot)
	seen := map[string]bool{}
	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	for err = windows.Process32First(snapshot, &entry); err == nil; err = windows.Process32Next(snapshot, &entry) {
		name := windows.UTF16ToString(entry.ExeFile[:])
		if !isConflictProcess(name) || entry.ProcessID == uint32(os.Getpid()) {
			continue
		}
		name = strings.ToLower(name)
		h, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, entry.ProcessID)
		if err != nil {
			if !seen[name] {
				r.Failed = append(r.Failed, name)
				seen[name] = true
			}
			continue
		}
		// Ждём выхода: дескриптор WinDivert освобождается только с процессом.
		if windows.TerminateProcess(h, 0) == nil {
			_, _ = windows.WaitForSingleObject(h, 2000)
			if !seen[name] {
				r.Stopped = append(r.Stopped, name)
				seen[name] = true
			}
		}
		windows.CloseHandle(h)
	}
}

func dropStaleDriver(r *conflictReport) {
	const name = "WinDivert"
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, servicesKey+`\`+name, registry.QUERY_VALUE)
	if err != nil {
		return
	}
	path, _, _ := k.GetStringValue("ImagePath")
	start, _, startErr := k.GetIntegerValue("Start")
	k.Close()
	exists := func(p string) bool { _, err := os.Stat(p); return err == nil }
	if !staleDriver(path, startErr == nil && start == 4, os.Getenv("SystemRoot"), exists) {
		return
	}
	m, err := mgr.Connect()
	if err != nil {
		return
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return
	}
	defer s.Close()
	if st, err := s.Query(); err != nil || st.State != svc.Stopped {
		return
	}
	if s.Delete() == nil {
		r.Stopped = append(r.Stopped, "устаревшая запись драйвера WinDivert")
	}
}
