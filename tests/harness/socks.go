package harness

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os/exec"
	"runtime"
	"strconv"
	"syscall"
)

// Константы протокола SOCKS5, нужные клиенту прогона.
const (
	socksVersion5     = 0x05
	socksMethodNoAuth = 0x00
	socksCmdConnect   = 0x01
	socksAddrDomain   = 0x03
	socksReplyOK      = 0x00
)

// socksDial устанавливает соединение с адресом через SOCKS5-прокси движка.
//
// Имя цели передаётся прокси как имя, а не как адрес: движку нужно имя, чтобы
// сопоставить соединение с радиусом поражения, а разрешать имя самому прогону
// незачем — и незачем вдвойне, потому что разрешение имени не через прокси
// выдало бы запрос DNS мимо измеряемого пути.
func socksDial(ctx context.Context, proxyAddr, target string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("цель %q: %w", target, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("порт в %q: %w", target, err)
	}
	if len(host) > 255 {
		return nil, fmt.Errorf("имя %q длиннее 255 байт: в SOCKS5 оно не поместится", host)
	}

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("прокси %s: %w", proxyAddr, err)
	}

	// Приветствие: версия 5, единственный метод — без аутентификации.
	if _, err := conn.Write([]byte{socksVersion5, 1, socksMethodNoAuth}); err != nil {
		conn.Close()
		return nil, err
	}
	greet := make([]byte, 2)
	if _, err := io.ReadFull(conn, greet); err != nil {
		conn.Close()
		return nil, err
	}
	if greet[0] != socksVersion5 || greet[1] != socksMethodNoAuth {
		conn.Close()
		return nil, fmt.Errorf("прокси не согласовал метод: %v", greet)
	}

	req := []byte{socksVersion5, socksCmdConnect, 0x00, socksAddrDomain, byte(len(host))}
	req = append(req, host...)
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}

	// Ответ на CONNECT с адресом IPv4 занимает 10 байт.
	resp := make([]byte, 10)
	if _, err := io.ReadFull(conn, resp); err != nil {
		conn.Close()
		return nil, err
	}
	if resp[1] != socksReplyOK {
		conn.Close()
		return nil, fmt.Errorf("прокси отказал в CONNECT: код %d", resp[1])
	}
	return conn, nil
}

// terminate просит процесс завершиться.
//
// Движку нужно корректное завершение: он дописывает журнал наблюдений, и
// убийство потеряло бы последнюю пачку. Способ зависит от платформы, и на
// Windows он хуже: консольному процессу без окна нечего закрывать, поэтому
// taskkill без /F часто не срабатывает, а с /F это уже убийство. Прогоны,
// которым важен журнал, ждут срока дописывания пачки до остановки — иначе
// пришлось бы полагаться на удачу.
func terminate(cmd *exec.Cmd) error {
	if runtime.GOOS == "windows" {
		kill := exec.Command("taskkill", "/PID", strconv.Itoa(cmd.Process.Pid), "/T", "/F")
		return kill.Run()
	}
	return cmd.Process.Signal(syscall.SIGTERM)
}
