//go:build windows

package gamefilter

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type Owners struct {
	mu        sync.Mutex
	options   Options
	last      time.Time
	ports     map[string]owner
	targets   []string
	lastError string
	processes []ProcessState
}

var ipHelper = windows.NewLazySystemDLL("iphlpapi.dll")

func NewOwners(o Options) *Owners { return &Owners{options: o, ports: map[string]owner{}} }
func (o *Owners) Owns(protocol string, port uint16) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if time.Since(o.last) > 100*time.Millisecond {
		o.refresh()
	}
	v := o.ports[ownerKey(protocol, port)]
	return v.selected && !v.ambiguous
}
func (o *Owners) Status() ([]string, string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if time.Since(o.last) > 250*time.Millisecond {
		o.refresh()
	}
	return append([]string{}, o.targets...), o.lastError
}

func table(protocol string, ipv6 bool) ([]socketRow, error) {
	name, class := "GetExtendedUdpTable", uintptr(1)
	if protocol == "tcp" {
		name, class = "GetExtendedTcpTable", 5
	}
	proc := ipHelper.NewProc(name)
	family := uintptr(windows.AF_INET)
	if ipv6 {
		family = windows.AF_INET6
	}
	var size uint32
	result, _, _ := proc.Call(0, uintptr(unsafe.Pointer(&size)), 0, family, class, 0)
	if result == 50 {
		return nil, nil
	}
	if result != 0 && result != 122 {
		return nil, errors.New("socket table unavailable")
	}
	for range 3 {
		if size < 4 || size > 4<<20 {
			return nil, errors.New("socket table too large")
		}
		buf := make([]byte, size)
		result, _, _ = proc.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, family, class, 0)
		if result == 0 {
			return decodeRows(buf[:min(int(size), len(buf))], protocol, ipv6)
		}
		if result != 122 {
			break
		}
	}
	return nil, errors.New("socket table unavailable")
}

type processInfo struct {
	pid, parent uint32
	name        string
}

func processList() ([]processInfo, error) {
	h, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(h)
	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	out := []processInfo{}
	for err = windows.Process32First(h, &entry); err == nil; err = windows.Process32Next(h, &entry) {
		out = append(out, processInfo{entry.ProcessID, entry.ParentProcessID, windows.UTF16ToString(entry.ExeFile[:])})
	}
	if err != windows.ERROR_NO_MORE_FILES {
		return nil, err
	}
	return out, nil
}
func processImage(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	buffer := make([]uint16, 32768)
	size := uint32(len(buffer))
	if windows.QueryFullProcessImageName(h, 0, &buffer[0], &size) != nil {
		return ""
	}
	return windows.UTF16ToString(buffer[:size])
}
func (o *Owners) refresh() {
	o.last = time.Now()
	o.lastError = ""
	o.processes = []ProcessState{}
	processes, err := processList()
	if err != nil {
		o.ports = map[string]owner{}
		o.targets = nil
		o.lastError = "не удалось определить игровые процессы"
		return
	}
	selected := map[uint32]string{}
	images := map[uint32]string{}
	for _, p := range processes {
		if p.pid <= 4 || Protected(p.name) {
			continue
		}
		candidate := o.options.Match(p.name) != ""
		for _, path := range o.options.Executables {
			if strings.EqualFold(filepath.Base(path), p.name) {
				candidate = true
			}
		}
		if !candidate {
			continue
		}
		image := processImage(p.pid)
		if !strings.EqualFold(filepath.Base(image), p.name) {
			continue
		}
		images[p.pid] = image
		if target := o.options.Match(image); target != "" {
			selected[p.pid] = target
		}
	}
	// Ubisoft launches games through helper processes. Limit descendants to that
	// family and reject browsers and Windows processes before granting ownership.
	for range 8 {
		changed := false
		for _, p := range processes {
			if selected[p.pid] != "" || (selected[p.parent] != "ubisoft" && selected[p.parent] != "albion") || Protected(p.name) {
				continue
			}
			image := images[p.pid]
			if image == "" {
				image = processImage(p.pid)
				images[p.pid] = image
			}
			if image == "" || !strings.EqualFold(filepath.Base(image), p.name) || strings.Contains(strings.ToLower(image), "\\windows\\") {
				continue
			}
			selected[p.pid] = selected[p.parent]
			changed = true
		}
		if !changed {
			break
		}
	}
	o.processes = summarizeProcesses(selected, images)
	if len(selected) == 0 {
		o.ports = map[string]owner{}
		o.targets = []string{}
		return
	}
	var rows []socketRow
	for _, protocol := range []string{"tcp", "udp"} {
		for _, ipv6 := range []bool{false, true} {
			r, e := table(protocol, ipv6)
			if e != nil {
				o.lastError = "не удалось прочитать игровые подключения"
				o.ports = map[string]owner{}
				o.targets = nil
				return
			}
			rows = append(rows, r...)
		}
	}
	o.ports = resolveRows(rows, selected)
	seen := map[string]bool{}
	o.targets = []string{}
	for _, label := range selected {
		if !seen[label] {
			seen[label] = true
			o.targets = append(o.targets, label)
		}
	}
}

// Filter captures only unambiguous local ports owned by selected applications.
func (o *Owners) Filter() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	if time.Since(o.last) > 100*time.Millisecond {
		o.refresh()
	}
	parts := []string{}
	for key, v := range o.ports {
		if !v.selected || v.ambiguous {
			continue
		}
		var protocol string
		var port int
		split := strings.Split(key, ":")
		if len(split) != 2 {
			continue
		}
		protocol = split[0]
		if protocol == "tcp" && !o.options.TCP() || protocol == "udp" && !o.options.UDP() {
			continue
		}
		if _, err := fmt.Sscan(split[1], &port); err != nil {
			continue
		}
		parts = append(parts, fmt.Sprintf("(%s and ((outbound and %s.SrcPort == %d) or (inbound and %s.DstPort == %d)))", protocol, protocol, port, protocol, port))
	}
	sort.Strings(parts)
	if len(parts) == 0 || len(parts) > 256 {
		return ""
	}
	return "not impostor and not loopback and (" + strings.Join(parts, " or ") + ")"
}

// Identity correlates reconnects of the same process to the same endpoint.
func (o *Owners) Identity(protocol string, port uint16) uint32 {
	o.mu.Lock()
	defer o.mu.Unlock()
	if time.Since(o.last) > 100*time.Millisecond {
		o.refresh()
	}
	v := o.ports[ownerKey(protocol, port)]
	if !v.selected || v.ambiguous {
		return 0
	}
	return v.pid
}

func (o *Owners) Processes() []ProcessState {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]ProcessState{}, o.processes...)
}

// A just-created TCP socket can be newer than the periodic table snapshot.
func (o *Owners) OwnsCurrent(protocol string, port uint16) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.refresh()
	v := o.ports[ownerKey(protocol, port)]
	return v.selected && !v.ambiguous
}
