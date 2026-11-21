package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"
)

func TestCatIconResourcesAreReadable(t *testing.T) {
	data, err := os.ReadFile("assets/tray.ico")
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{16, 20, 24, 32, 48, 64, 256} {
		image := iconImage(data, size)
		if len(image) < 8 || !(bytes.HasPrefix(image, []byte("\x89PNG\r\n\x1a\n")) || binary.LittleEndian.Uint32(image) == 40) {
			t.Fatalf("invalid ICO resource at size %d", size)
		}
	}
	for _, broken := range [][]byte{nil, data[:5], data[:20], append([]byte(nil), data...)} {
		if len(broken) == len(data) {
			binary.LittleEndian.PutUint32(broken[18:], 0xffffffff)
		}
		if iconImage(broken, 16) != nil {
			t.Fatal("invalid ICO accepted")
		}
	}
}
