package main

import "encoding/binary"

// iconImage returns the nearest image resource, not the ICO directory itself.
// ICONDIRENTRY has length at +8 and offset at +12 (after planes/bit depth).
func iconImage(data []byte, size int) []byte {
	if len(data) < 6 || binary.LittleEndian.Uint16(data[2:]) != 1 {
		return nil
	}
	count := int(binary.LittleEndian.Uint16(data[4:]))
	if count == 0 || 6+count*16 > len(data) {
		return nil
	}
	best, distance := -1, int(^uint(0)>>1)
	for i := 0; i < count; i++ {
		at := 6 + i*16
		width := int(data[at])
		if width == 0 {
			width = 256
		}
		d := width - size
		if d < 0 {
			d = -d
		}
		if d < distance {
			best, distance = at, d
		}
	}
	length := uint64(binary.LittleEndian.Uint32(data[best+8:]))
	offset := uint64(binary.LittleEndian.Uint32(data[best+12:]))
	if length == 0 || offset < uint64(6+count*16) || offset+length > uint64(len(data)) {
		return nil
	}
	return data[offset : offset+length]
}
