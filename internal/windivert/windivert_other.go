//go:build !windows

package windivert

import (
	"errors"

	"github.com/fitting-1c/evasion/internal/capture"
)

// ErrUnsupported — WinDivert доступен только на Windows. Стаб существует, чтобы
// команда запуска компоновалась и проверялась на любой ОС, а при попытке
// открыть перехват вне Windows получала внятный отказ, а не ошибку компоновки.
var ErrUnsupported = errors.New("windivert: перехват пакетов доступен только на Windows")

// Handle — заглушка дескриптора вне Windows.
type Handle struct{}

var (
	_ capture.PacketSource = (*Handle)(nil)
	_ capture.PacketSink   = (*Handle)(nil)
)

// Open вне Windows всегда возвращает ошибку.
func Open(string) (*Handle, error) { return nil, ErrUnsupported }

// Recv вне Windows всегда возвращает ошибку.
func (*Handle) Recv() (capture.Packet, error) { return capture.Packet{}, ErrUnsupported }

// Send вне Windows всегда возвращает ошибку.
func (*Handle) Send(capture.Packet) error { return ErrUnsupported }

// Close вне Windows безвреден.
func (*Handle) Close() error { return nil }

func (*Handle) ShutdownReceive() error { return ErrUnsupported }

func Observe(string) (*Handle, error) { return nil, ErrUnsupported }

func OpenPriority(string, int16) (*Handle, error) { return nil, ErrUnsupported }
