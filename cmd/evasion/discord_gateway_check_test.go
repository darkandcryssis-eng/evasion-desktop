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

func TestDiscordDirectGate(t *testing.T) {
	var gate discordDirectGate
	steps := []struct{ ok, proven, changed bool }{
		{true, false, false}, // одной проверки мало
		{true, true, true},   // вторая подряд — прямой путь доказан
		{true, true, false},
		{false, false, true}, // первый срыв снимает сразу
		{true, false, false},
		{false, false, false}, // счёт подряд идущих сбрасывается
		{true, false, false},
		{true, true, true},
	}
	for i, step := range steps {
		proven, changed := gate.observe(step.ok)
		if proven != step.proven || changed != step.changed {
			t.Fatalf("шаг %d: proven=%v changed=%v", i, proven, changed)
		}
	}
}
