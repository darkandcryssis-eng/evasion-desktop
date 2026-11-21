//go:build windows

package windivert

import (
	"fmt"
	"unsafe"

	"github.com/fitting-1c/evasion/internal/capture"
	"github.com/fitting-1c/evasion/internal/core"
	"golang.org/x/sys/windows"
)

const (
	// layerNetwork — сетевой слой WinDivert (WINDIVERT_LAYER_NETWORK): перехват
	// пакетов IP, которые можно изменять и инъектировать обратно.
	layerNetwork = 0
	// WINDIVERT_MTU_MAX includes the 40-byte IPv6 header plus its payload.
	maxPacketLen = 40 + 0xFFFF
	// invalidHandle — признак неудачи WinDivertOpen (INVALID_HANDLE_VALUE).
	invalidHandle = ^uintptr(0)
)

var (
	dll       = windows.NewLazyDLL("WinDivert.dll")
	procOpen  = dll.NewProc("WinDivertOpen")
	procRecv  = dll.NewProc("WinDivertRecv")
	procSend  = dll.NewProc("WinDivertSend")
	procClose = dll.NewProc("WinDivertClose")
)

var (
	_ capture.PacketSource = (*Handle)(nil)
	_ capture.PacketSink   = (*Handle)(nil)
)

// Handle — открытый дескриптор WinDivert, он же источник и приёмник пакетов.
//
// Не потокобезопасен: один дескриптор ведёт одна горутина цикла (приём), а
// отправка идёт из неё же. Так же устроен и буфер приёма — один на дескриптор.
type Handle struct {
	h   uintptr
	buf []byte
}

// Open открывает WinDivert с заданным фильтром на сетевом слое.
//
// Фильтр — строка языка WinDivert (например, "outbound and tcp.DstPort == 443").
// Узкий фильтр — часть правила «уйти с пути» (4.2): движок видит только нужные
// пакеты. Флаги нулевые: обычный режим перехвата с возможностью инъекции (не
// sniff и не drop).
func Open(filter string) (*Handle, error) { return openNetwork(filter, 0, 0) }

// Observe copies packets without delaying or suppressing originals.
func OpenPriority(filter string, priority int16) (*Handle, error) {
	return openNetwork(filter, priority, 0)
}
func Observe(filter string) (*Handle, error) { return openNetwork(filter, 100, 1) }

func openNetwork(filter string, priority int16, flags uint64) (*Handle, error) {
	if err := dll.Load(); err != nil {
		return nil, newOpenError(err)
	}
	f, err := windows.BytePtrFromString(filter)
	if err != nil {
		return nil, fmt.Errorf("windivert: негодный фильтр: %w", err)
	}
	r, _, callErr := procOpen.Call(
		uintptr(unsafe.Pointer(f)),
		uintptr(layerNetwork),
		uintptr(priority), // приоритет
		uintptr(flags),    // флаги
	)
	if r == invalidHandle {
		return nil, newOpenError(callErr)
	}
	return &Handle{h: r, buf: make([]byte, maxPacketLen)}, nil
}

// Recv принимает очередной пакет.
//
// Data действителен только до следующего Recv: буфер приёма переиспользуется
// (контракт capture). Направление берётся из адреса; сам адрес кладётся в
// Reinject непрозрачно и обязан вернуться в Send.
func (h *Handle) Recv() (capture.Packet, error) {
	var addr Address
	var recvLen uint32
	r, _, callErr := procRecv.Call(
		h.h,
		uintptr(unsafe.Pointer(&h.buf[0])),
		uintptr(len(h.buf)),
		uintptr(unsafe.Pointer(&recvLen)),
		uintptr(unsafe.Pointer(&addr)),
	)
	if r == 0 {
		return capture.Packet{}, fmt.Errorf("windivert: WinDivertRecv: %w", callErr)
	}
	dir := core.DirectionInbound
	if addr.Outbound() {
		dir = core.DirectionOutbound
	}
	return capture.Packet{Data: h.buf[:recvLen], Dir: dir, Reinject: addr}, nil
}

// Send инъектирует пакет обратно в стек, используя сохранённый адрес.
//
// Контрольные суммы к этому моменту уже пересчитаны (packetexec): Windows
// отвергает пакеты с неверной суммой. Пустой пакет не отправляется.
func (h *Handle) Send(p capture.Packet) error {
	addr, ok := p.Reinject.(Address)
	if !ok {
		return fmt.Errorf("windivert: пакет без адреса реинъекции WinDivert")
	}
	if len(p.Data) == 0 {
		return nil
	}
	var sendLen uint32
	r, _, callErr := procSend.Call(
		h.h,
		uintptr(unsafe.Pointer(&p.Data[0])),
		uintptr(len(p.Data)),
		uintptr(unsafe.Pointer(&sendLen)),
		uintptr(unsafe.Pointer(&addr)),
	)
	if r == 0 {
		return fmt.Errorf("windivert: WinDivertSend: %w", callErr)
	}
	return nil
}

// Close закрывает дескриптор. Закрытие разблокирует зависший на приёме Recv
// ошибкой — так цикл перехвата и останавливают.
func (h *Handle) Close() error {
	r, _, callErr := procClose.Call(h.h)
	if r == 0 {
		return fmt.Errorf("windivert: WinDivertClose: %w", callErr)
	}
	return nil
}

// ShutdownReceive stops capture while allowing queued originals to be drained.
func (h *Handle) ShutdownReceive() error {
	r, _, err := dll.NewProc("WinDivertShutdown").Call(h.h, 0x1)
	if r == 0 {
		return fmt.Errorf("windivert: stop capture: %w", err)
	}
	return nil
}
