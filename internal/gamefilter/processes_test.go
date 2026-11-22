package gamefilter

import (
	"strings"
	"testing"
)

func TestStartedProcessesCountAsHelpers(t *testing.T) {
	if s := summarizeProcesses(map[uint32]string{}, nil); len(s) != 0 {
		t.Fatal(s)
	}
	s := summarizeProcesses(map[uint32]string{1: "custom", 2: "custom", 3: "custom"}, map[uint32]bool{1: true})
	if len(s) != 1 || s[0].Family != "custom" || s[0].Clients != 1 || s[0].Helpers != 2 || s[0].Launchers != 0 {
		t.Fatal(s)
	}
}

func TestCaptureStaysWithinDriverFilterLimit(t *testing.T) {
	owners := map[string]owner{ownerKey("tcp", 50000): {pid: 1, selected: true}, ownerKey("udp", 5055): {pid: 1, selected: true}, ownerKey("tcp", 50001): {pid: 2}, ownerKey("tcp", 50002): {pid: 1, selected: false, ambiguous: true}}
	c := buildCapture(owners, true, true)
	want := "not impostor and not loopback and ((outbound and (tcp.SrcPort == 50000)) or (inbound and (tcp.DstPort == 50000)) or (outbound and (udp.SrcPort == 5055)) or (inbound and (udp.DstPort == 5055)))"
	if c.Filter != want {
		t.Fatal(c.Filter)
	}
	if c := buildCapture(owners, true, false); strings.Contains(c.Filter, "udp") {
		t.Fatal(c.Filter)
	}
	if c := buildCapture(map[string]owner{}, true, true); c.Filter != "" {
		t.Fatal(c.Filter)
	}
	for port := 40000; port < 40400; port += 2 {
		owners[ownerKey("tcp", uint16(port))] = owner{pid: 1, selected: true}
	}
	c = buildCapture(owners, true, true)
	if !strings.Contains(c.Filter, "tcp.SrcPort >= 40000 and tcp.SrcPort <= 50000") || !strings.Contains(c.Filter, "udp.SrcPort == 5055") {
		t.Fatal(c.Filter)
	}
	if tests := strings.Count(c.Filter, " and ") + strings.Count(c.Filter, " or "); tests > 200 {
		t.Fatal("filter too large for the driver", tests)
	}
}
