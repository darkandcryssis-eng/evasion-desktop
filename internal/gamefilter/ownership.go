package gamefilter

import (
	"encoding/binary"
	"errors"
	"fmt"
)

type socketRow struct {
	protocol string
	port     uint16
	pid      uint32
}
type owner struct {
	pid       uint32
	selected  bool
	ambiguous bool
}

func decodeRows(data []byte, protocol string, ipv6 bool) ([]socketRow, error) {
	size, portOff, pidOff := 12, 4, 8
	if protocol == "tcp" {
		size, portOff, pidOff = 24, 8, 20
	}
	if ipv6 {
		size, portOff, pidOff = 28, 20, 24
		if protocol == "tcp" {
			size, pidOff = 56, 52
		}
	}
	if len(data) < 4 {
		return nil, errors.New("socket table truncated")
	}
	count := int(binary.LittleEndian.Uint32(data))
	if count > (len(data)-4)/size {
		return nil, errors.New("socket row count invalid")
	}
	out := make([]socketRow, 0, count)
	for i := 0; i < count; i++ {
		row := data[4+i*size : 4+(i+1)*size]
		out = append(out, socketRow{protocol, binary.BigEndian.Uint16(row[portOff : portOff+2]), binary.LittleEndian.Uint32(row[pidOff : pidOff+4])})
	}
	return out, nil
}
func ownerKey(protocol string, port uint16) string { return fmt.Sprintf("%s:%d", protocol, port) }
func resolveRows(rows []socketRow, selected map[uint32]string) map[string]owner {
	out := map[string]owner{}
	for _, r := range rows {
		if r.port == 0 {
			continue
		}
		key := ownerKey(r.protocol, r.port)
		if v, ok := out[key]; ok {
			if v.pid != r.pid {
				v.ambiguous = true
				v.selected = false
				out[key] = v
			}
			continue
		}
		out[key] = owner{pid: r.pid, selected: selected[r.pid] != ""}
	}
	return out
}
