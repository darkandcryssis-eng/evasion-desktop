package main

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

func TestWSFrameHelpers(t *testing.T) {
	for _, size := range []int{17, 125, 126, 4000} {
		text := strings.Repeat("x", size)
		var wire bytes.Buffer
		if err := writeWSText(&wire, text); err != nil {
			t.Fatal(err)
		}
		raw := wire.Bytes()
		if raw[0] != 0x81 || raw[1]&0x80 == 0 {
			t.Fatalf("size %d: кадр клиента должен быть текстовым и с маской: %x", size, raw[:2])
		}
		// Сервер шлёт то же без маски: снимаем её и читаем обратно.
		header := 2
		if size >= 126 {
			header = 4
		}
		mask := raw[header : header+4]
		body := append([]byte(nil), raw[header+4:]...)
		for i := range body {
			body[i] ^= mask[i%4]
		}
		unmasked := append(append([]byte{raw[0]}, raw[1:header]...), body...)
		unmasked[1] &^= 0x80
		opcode, payload, err := readWSFrame(bufio.NewReader(bytes.NewReader(unmasked)))
		if err != nil || opcode != 0x1 || string(payload) != text {
			t.Fatalf("size %d: opcode=%d err=%v совпало=%v", size, opcode, err, string(payload) == text)
		}
	}
}
