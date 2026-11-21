//go:build windows

package main

import (
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"regexp"
	"sort"
	"strings"
)

var driverServiceName = regexp.MustCompile(`(?i)^WinDivert[0-9.]*$`)

func readDriverServices() []driverService {
	names := []string{"BFE", "WinDivert", "BEService", "BEService_x64"}
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services`, registry.ENUMERATE_SUB_KEYS)
	if err == nil {
		found, _ := key.ReadSubKeyNames(-1)
		key.Close()
		for _, name := range found {
			if !strings.EqualFold(name, "WinDivert") && driverServiceName.MatchString(name) && len(names) < 10 {
				names = append(names, name)
			}
		}
	}
	sort.Strings(names)
	scm, scmErr := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if scmErr == nil {
		defer windows.CloseServiceHandle(scm)
	}
	result := []driverService{}
	for _, name := range names {
		id := "windivert"
		if name == "BFE" {
			id = "bfe"
		} else if strings.HasPrefix(name, "BEService") {
			id = "battleye"
		}
		s := driverService{ID: id, State: "unknown", Start: "unknown"}
		k, e := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\`+name, registry.QUERY_VALUE)
		if e == registry.ErrNotExist {
			s.State = "missing"
		} else if e == nil {
			start, _, e := k.GetIntegerValue("Start")
			if e == nil {
				switch start {
				case 0:
					s.Start = "boot"
				case 1:
					s.Start = "system"
				case 2:
					s.Start = "auto"
				case 3:
					s.Start = "demand"
				case 4:
					s.Start = "disabled"
				}
			}
			deleted, _, _ := k.GetIntegerValue("DeleteFlag")
			s.PendingDeletion = deleted != 0
			k.Close()
		}
		if scmErr == nil {
			ptr, _ := windows.UTF16PtrFromString(name)
			h, e := windows.OpenService(scm, ptr, windows.SERVICE_QUERY_STATUS)
			if e == nil {
				var st windows.SERVICE_STATUS
				e = windows.QueryServiceStatus(h, &st)
				windows.CloseServiceHandle(h)
				if e == nil {
					switch st.CurrentState {
					case windows.SERVICE_RUNNING:
						s.State = "running"
					case windows.SERVICE_STOPPED:
						s.State = "stopped"
					case windows.SERVICE_START_PENDING:
						s.State = "start_pending"
					case windows.SERVICE_STOP_PENDING:
						s.State = "stop_pending"
					}
				}
			}
			if e != nil {
				if e == windows.ERROR_SERVICE_DOES_NOT_EXIST {
					s.State = "missing"
				} else if code, ok := e.(windows.Errno); ok {
					s.Code = uint32(code)
				}
			}
		} else if code, ok := scmErr.(windows.Errno); ok {
			s.Code = uint32(code)
		}
		result = append(result, s)
	}
	return result
}
