package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/fitting-1c/evasion/internal/netbind"
)

const discordGatewayHost = "gateway.discord.gg"

// discordGatewayViaDefault включается самопроверкой, когда обмен с gateway
// через физический адаптер не проходит, а по маршруту по умолчанию (VPN)
// проходит. Тогда локальный прокси ведёт gateway через VPN.
var discordGatewayViaDefault atomic.Bool

// discordGatewayExchange повторяет начало сессии клиента: WebSocket, приём
// Hello, пинг с ожиданием ответа, вход с заведомо неверным токеном и ожидание
// отказа 4004. Одного рукопожатия мало: соединение может умирать сразу после.
func discordGatewayExchange(ctx context.Context, dial netbind.DialContextFunc) error {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	conn, err := dial(ctx, "tcp4", net.JoinHostPort(discordGatewayHost, "443"))
	if err != nil {
		return fmt.Errorf("TCP: %w", err)
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	tlsConn := tls.Client(conn, &tls.Config{ServerName: discordGatewayHost, MinVersion: tls.VersionTLS12})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("TLS: %w", err)
	}
	request := "GET /?v=10&encoding=json HTTP/1.1\r\nHost: " + discordGatewayHost + "\r\n" +
		"Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nOrigin: https://discord.com\r\n\r\n"
	if _, err := io.WriteString(tlsConn, request); err != nil {
		return fmt.Errorf("WebSocket: %w", err)
	}
	reader := bufio.NewReader(tlsConn)
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		return fmt.Errorf("WebSocket: %w", err)
	}
	if response.StatusCode != http.StatusSwitchingProtocols {
		return fmt.Errorf("WebSocket: HTTP %d", response.StatusCode)
	}
	if err := expectGatewayOp(reader, 10); err != nil {
		return fmt.Errorf("Hello не пришёл: %w", err)
	}
	if err := writeWSText(tlsConn, `{"op":1,"d":null}`); err != nil {
		return fmt.Errorf("пинг не отправлен: %w", err)
	}
	if err := expectGatewayOp(reader, 11); err != nil {
		return fmt.Errorf("на пинг нет ответа: %w", err)
	}
	identify := `{"op":2,"d":{"token":"evasion-selfcheck","intents":0,"properties":{"os":"windows","browser":"evasion","device":"evasion"}}}`
	if err := writeWSText(tlsConn, identify); err != nil {
		return fmt.Errorf("вход не отправлен: %w", err)
	}
	for {
		opcode, payload, err := readWSFrame(reader)
		if err != nil {
			return fmt.Errorf("на вход нет ответа: %w", err)
		}
		if opcode == 0x8 {
			if len(payload) >= 2 && binary.BigEndian.Uint16(payload) == 4004 {
				return nil
			}
			return fmt.Errorf("на вход пришёл неожиданный отказ: %x", payload)
		}
	}
}

func expectGatewayOp(reader *bufio.Reader, want int) error {
	for {
		opcode, payload, err := readWSFrame(reader)
		if err != nil {
			return err
		}
		switch opcode {
		case 0x1:
			var message struct {
				Op int `json:"op"`
			}
			if json.Unmarshal(payload, &message) == nil && message.Op == want {
				return nil
			}
		case 0x8:
			return errors.New("сервер закрыл соединение")
		}
	}
}

// readWSFrame читает один нефрагментированный кадр сервера (без маски).
func readWSFrame(reader *bufio.Reader) (byte, []byte, error) {
	var header [2]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return 0, nil, err
	}
	length := uint64(header[1] & 0x7f)
	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(reader, ext[:]); err != nil {
			return 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(reader, ext[:]); err != nil {
			return 0, nil, err
		}
		length = binary.BigEndian.Uint64(ext[:])
	}
	if header[1]&0x80 != 0 || length > 1<<20 {
		return 0, nil, errors.New("некорректный кадр WebSocket")
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return 0, nil, err
	}
	return header[0] & 0x0f, payload, nil
}

// writeWSText отправляет текстовый кадр клиента (с маской, до 64 КБ).
func writeWSText(w io.Writer, text string) error {
	if len(text) > 0xffff {
		return errors.New("кадр слишком велик")
	}
	frame := []byte{0x81}
	if len(text) < 126 {
		frame = append(frame, 0x80|byte(len(text)))
	} else {
		frame = append(frame, 0x80|126, byte(len(text)>>8), byte(len(text)))
	}
	var mask [4]byte
	if _, err := rand.Read(mask[:]); err != nil {
		return err
	}
	frame = append(frame, mask[:]...)
	for i := 0; i < len(text); i++ {
		frame = append(frame, text[i]^mask[i%4])
	}
	_, err := w.Write(frame)
	return err
}
