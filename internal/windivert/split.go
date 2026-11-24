package windivert

import (
	"encoding/binary"
	"fmt"
)

func splitPacketBatch(data []byte) ([][]byte, error) {
	var packets [][]byte
	for offset := 0; offset < len(data); {
		remaining := data[offset:]
		if len(remaining) < 1 {
			return packets, fmt.Errorf("windivert: empty packet tail")
		}

		var packetLen int
		switch remaining[0] >> 4 {
		case 4:
			if len(remaining) < 20 {
				return packets, fmt.Errorf("windivert: truncated IPv4 header")
			}
			headerLen := int(remaining[0]&0x0f) * 4
			packetLen = int(binary.BigEndian.Uint16(remaining[2:4]))
			if headerLen < 20 || packetLen < headerLen {
				return packets, fmt.Errorf("windivert: invalid IPv4 length")
			}
		case 6:
			if len(remaining) < 40 {
				return packets, fmt.Errorf("windivert: truncated IPv6 header")
			}
			packetLen = 40 + int(binary.BigEndian.Uint16(remaining[4:6]))
		default:
			return packets, fmt.Errorf("windivert: unknown IP version")
		}

		if packetLen > len(remaining) {
			return packets, fmt.Errorf("windivert: truncated IP packet")
		}
		packets = append(packets, data[offset:offset+packetLen])
		offset += packetLen
	}
	return packets, nil
}
