package gamefilter

import (
	"fmt"
	"sort"
	"strings"
)

// WinDivert compiles a filter into at most 256 tests; each listed port costs
// two. Above capturePortLimit the ports of a protocol collapse into one range.
const capturePortLimit = 48

// Capture describes what the selected applications' filter diverts.
type Capture struct {
	Filter         string
	tcp            map[uint16]bool
	tcpLow, tcpTop uint16
	tcpRange       bool
}

// CoversTCP reports whether a local TCP port is diverted by Filter.
func (c Capture) CoversTCP(port uint16) bool {
	if c.tcpRange {
		return port >= c.tcpLow && port <= c.tcpTop
	}
	return c.tcp[port]
}

func buildCapture(owners map[string]owner, tcp, udp bool) Capture {
	ports := map[string][]int{}
	for key, v := range owners {
		if !v.selected || v.ambiguous {
			continue
		}
		var protocol string
		var port int
		if _, err := fmt.Sscanf(strings.Replace(key, ":", " ", 1), "%s %d", &protocol, &port); err != nil || port <= 0 || port > 65535 {
			continue
		}
		if protocol == "tcp" && tcp || protocol == "udp" && udp {
			ports[protocol] = append(ports[protocol], port)
		}
	}
	c := Capture{tcp: map[uint16]bool{}}
	parts := []string{}
	for _, protocol := range []string{"tcp", "udp"} {
		list := ports[protocol]
		if len(list) == 0 {
			continue
		}
		sort.Ints(list)
		var out, in string
		if len(list) > capturePortLimit {
			// Other applications inside the range are forwarded unchanged:
			// ownership is checked again for every packet.
			low, top := list[0], list[len(list)-1]
			out = fmt.Sprintf("%s.SrcPort >= %d and %s.SrcPort <= %d", protocol, low, protocol, top)
			in = fmt.Sprintf("%s.DstPort >= %d and %s.DstPort <= %d", protocol, low, protocol, top)
			if protocol == "tcp" {
				c.tcpRange, c.tcpLow, c.tcpTop = true, uint16(low), uint16(top)
			}
		} else {
			src, dst := make([]string, len(list)), make([]string, len(list))
			for i, port := range list {
				src[i] = fmt.Sprintf("%s.SrcPort == %d", protocol, port)
				dst[i] = fmt.Sprintf("%s.DstPort == %d", protocol, port)
				if protocol == "tcp" {
					c.tcp[uint16(port)] = true
				}
			}
			out, in = strings.Join(src, " or "), strings.Join(dst, " or ")
		}
		parts = append(parts, fmt.Sprintf("(outbound and (%s)) or (inbound and (%s))", out, in))
	}
	if len(parts) > 0 {
		c.Filter = "not impostor and not loopback and (" + strings.Join(parts, " or ") + ")"
	}
	return c
}
