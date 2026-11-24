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
	maxBatchSize = 32
	// invalidHandle — признак неудачи WinDivertOpen (INVALID_HANDLE_VALUE).
	invalidHandle = ^uintptr(0)

	queueLengthParam = 0
	queueTimeParam   = 1
	queueSizeParam   = 2
)

var (
	dll          = windows.NewLazyDLL("WinDivert.dll")
	procOpen     = dll.NewProc("WinDivertOpen")
	procRecv     = dll.NewProc("WinDivertRecv")
	procRecvEx   = dll.NewProc("WinDivertRecvEx")
	procSend     = dll.NewProc("WinDivertSend")
	procClose    = dll.NewProc("WinDivertClose")
	procSetParam = dll.NewProc("WinDivertSetParam")
)

var (
	_ capture.PacketSource = (*Handle)(nil)
	_ capture.PacketSink   = (*Handle)(nil)
)

// Handle — открытый дескриптор WinDivert, он же источник и приёмник пакетов.
//
// Приём и его буфер принадлежат одной горутине; отправка может идти параллельно.
type Handle struct {
	h           uintptr
	buf         []byte
	addresses   []Address
	packets     [][]byte
	packetAddrs []Address
	nextPacket  int
	batch       bool
}

// Open открывает WinDivert с заданным фильтром на сетевом слое.
//
// Фильтр — строка языка WinDivert (например, "outbound and tcp.DstPort == 443").
// Узкий фильтр — часть правила «уйти с пути» (4.2): движок видит только нужные
// пакеты. Флаги нулевые: обычный режим перехвата с возможностью инъекции (не
// sniff и не drop).
func Open(filter string) (*Handle, error) { return openNetwork(scopeFilter(filter), 0, 0) }

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
	handle := &Handle{
		h:         r,
		buf:       make([]byte, maxBatchSize*maxPacketLen),
		addresses: make([]Address, maxBatchSize),
		batch:     true,
	}
	procSetParam.Call(r, uintptr(queueLengthParam), 8192)
	procSetParam.Call(r, uintptr(queueTimeParam), 2000)
	procSetParam.Call(r, uintptr(queueSizeParam), 8388608)
	return handle, nil
}

// Recv принимает очередной пакет.
//
// Data действителен только до следующего Recv: буфер приёма переиспользуется
// (контракт capture). Направление берётся из адреса; сам адрес кладётся в
// Reinject непрозрачно и обязан вернуться в Send.
func (h *Handle) Recv() (capture.Packet, error) {
	for {
		if h.nextPacket < len(h.packets) {
			i := h.nextPacket
			h.nextPacket++
			addr := h.packetAddrs[i]
			dir := core.DirectionInbound
			if addr.Outbound() {
				dir = core.DirectionOutbound
			}
			return capture.Packet{Data: h.packets[i], Dir: dir, Reinject: addr}, nil
		}
		h.packets = nil
		h.packetAddrs = nil
		h.nextPacket = 0

		if h.batch {
			if err := h.recvBatch(); err != nil {
				return capture.Packet{}, err
			}
			continue
		}

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
}

func (h *Handle) recvBatch() error {
	var recvLen uint32
	addrLen := uint32(len(h.addresses)) * uint32(unsafe.Sizeof(Address{}))
	r, _, callErr := procRecvEx.Call(
		h.h,
		uintptr(unsafe.Pointer(&h.buf[0])),
		uintptr(len(h.buf)),
		uintptr(unsafe.Pointer(&recvLen)),
		0,
		uintptr(unsafe.Pointer(&h.addresses[0])),
		uintptr(unsafe.Pointer(&addrLen)),
		0,
	)
	if r == 0 {
		return fmt.Errorf("windivert: WinDivertRecvEx: %w", callErr)
	}
	if int(recvLen) > len(h.buf) {
		h.batch = false
		return fmt.Errorf("windivert: WinDivertRecvEx returned oversized packet buffer")
	}

	packets, splitErr := splitPacketBatch(h.buf[:recvLen])
	addrSize := uint32(unsafe.Sizeof(Address{}))
	addrCount := int(addrLen / addrSize)
	if splitErr != nil {
		h.batch = false
		if addrCount == 1 && recvLen > 0 {
			packets = [][]byte{h.buf[:recvLen]}
		}
	}
	if addrLen%addrSize != 0 || addrCount > len(h.addresses) || len(packets) != addrCount {
		h.batch = false
	}

	count := min(len(packets), addrCount, len(h.addresses))
	h.packets = packets[:count]
	h.packetAddrs = h.addresses[:count]
	return nil
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
