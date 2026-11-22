package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// portHolder — процесс, который слушает локальный порт Telegram-прокси.
type portHolder struct {
	PID   uint32
	Image string
}

// tcpListener — строка таблицы TCP-слушателей Windows (MIB_TCPROW_OWNER_PID).
type tcpListener struct {
	Addr [4]byte
	Port int
	PID  uint32
}

var (
	telegramPortHolder = findPortHolder
	retireEvasionCopy  = retireProcess
	telegramPortWait   = 5 * time.Second
	telegramPortStep   = 250 * time.Millisecond
)

// startOnTelegramPort открывает порт Telegram. Порт может быть ещё занят
// прежней копией Evasion (обновление, зависшее завершение): её Evasion
// закрывает сам, а чужую программу называет в ошибке.
func startOnTelegramPort(port int, start func() error) error {
	err := start()
	deadline := time.Now().Add(telegramPortWait)
	retired := map[uint32]bool{}
	for err != nil && addrInUse(err) {
		holder, found := telegramPortHolder(port)
		if found && holder.PID != uint32(os.Getpid()) && !retired[holder.PID] && isEvasionImage(holder.Image) {
			retired[holder.PID] = true
			retireEvasionCopy(holder.PID)
		} else if time.Now().After(deadline) {
			return telegramPortBusy(port, holder, found)
		}
		time.Sleep(telegramPortStep)
		err = start()
	}
	return err
}

func telegramPortBusy(port int, holder portHolder, found bool) error {
	hint := "закройте её или укажите другой локальный порт в настройках Telegram"
	if found && holder.Image != "" {
		return fmt.Errorf("локальный порт Telegram %d занят программой %s (PID %d): %s", port, filepath.Base(holder.Image), holder.PID, hint)
	}
	if found {
		return fmt.Errorf("локальный порт Telegram %d занят процессом с PID %d: %s", port, holder.PID, hint)
	}
	return fmt.Errorf("локальный порт Telegram %d занят другой программой: %s", port, hint)
}

// isEvasionImage — exe оболочки Evasion (текущий файл, его .old после
// обновления или другая копия Evasion*.exe), но не движок из папки данных.
func isEvasionImage(image string) bool {
	if image == "" {
		return false
	}
	if exe, err := currentExecutable(); err == nil {
		if strings.EqualFold(image, exe+".old") || sameFilePath(image, exe) {
			return true
		}
	}
	if rel, err := filepath.Rel(dataDir(), image); err == nil && !strings.HasPrefix(rel, "..") && !filepath.IsAbs(rel) {
		return false
	}
	name := strings.ToLower(filepath.Base(image))
	return strings.HasPrefix(name, "evasion") && (strings.HasSuffix(name, ".exe") || strings.HasSuffix(name, ".exe.old"))
}

func sameFilePath(a, b string) bool {
	x, err := os.Stat(a)
	if err != nil {
		return false
	}
	y, err := os.Stat(b)
	return err == nil && os.SameFile(x, y)
}

func decodeTCPListeners(buf []byte) ([]tcpListener, error) {
	if len(buf) < 4 {
		return nil, errors.New("таблица TCP пуста")
	}
	n := int(uint32(buf[0]) | uint32(buf[1])<<8 | uint32(buf[2])<<16 | uint32(buf[3])<<24)
	const row = 24
	if n < 0 || n > (len(buf)-4)/row {
		return nil, errors.New("таблица TCP повреждена")
	}
	out := make([]tcpListener, 0, n)
	for i := 0; i < n; i++ {
		r := buf[4+i*row : 4+(i+1)*row]
		var l tcpListener
		copy(l.Addr[:], r[4:8])
		l.Port = int(r[8])<<8 | int(r[9])
		l.PID = uint32(r[20]) | uint32(r[21])<<8 | uint32(r[22])<<16 | uint32(r[23])<<24
		out = append(out, l)
	}
	return out, nil
}

// loopbackHolder — кто слушает 127.0.0.1:port или 0.0.0.0:port.
func loopbackHolder(rows []tcpListener, port int) (uint32, bool) {
	for _, r := range rows {
		if r.Port == port && (r.Addr == [4]byte{127, 0, 0, 1} || r.Addr == [4]byte{}) {
			return r.PID, true
		}
	}
	return 0, false
}
