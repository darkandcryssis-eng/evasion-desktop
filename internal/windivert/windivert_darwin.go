//go:build darwin

package windivert

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/fitting-1c/evasion/internal/capture"
	"github.com/fitting-1c/evasion/internal/core"
	"golang.org/x/sys/unix"
)

// На macOS нет WinDivert, поэтому тот же интерфейс собран из штатных средств
// системы: правило pf `route-to` уводит исходящие пакеты нужных портов в
// интерфейс utun, движок читает их оттуда, а отправляет кадрами Ethernet через
// BPF на физическом интерфейсе. Кадры BPF мимо pf, поэтому собственные инъекции
// повторно не перехватываются (аналог "not impostor").
//
// Ограничения: только исходящий IPv4 и только когда маршрут по умолчанию идёт
// через Ethernet или Wi-Fi. Пакеты, не подошедшие ни одному фильтру, hub сразу
// отправляет дальше без изменений.

const (
	pfAnchor  = "com.apple/evasion"
	tokenFile = "/var/run/evasion-pf.token"
	lockFile  = "/var/run/evasion-pf.lock"
	utunLocal = "10.211.77.1"
	utunPeer  = "10.211.77.2"
	queueLen  = 4096
	maxPacket = 0xffff
)

// ErrNoEthernet — маршрут по умолчанию идёт не через Ethernet/Wi-Fi (например,
// поверх включён VPN) либо сети нет.
var ErrNoEthernet = errors.New("windivert: перехват на macOS требует сети Ethernet или Wi-Fi без VPN поверх неё")

var errClosed = errors.New("windivert: дескриптор закрыт")

// Handle — источник и приёмник пакетов поверх общего hub.
type Handle struct {
	filter   *Filter
	priority int16
	tcp, udp []PortRange
	queue    chan []byte
	done     chan struct{}
	stopped  atomic.Bool
	once     sync.Once
	last     []byte
}

var (
	_ capture.PacketSource = (*Handle)(nil)
	_ capture.PacketSink   = (*Handle)(nil)
)

var bufPool = sync.Pool{New: func() any { b := make([]byte, 0, 2048); return &b }}

type link struct {
	iface   string
	gateway string
	mtu     int
	header  [14]byte
	bpf     int
}

type hub struct {
	mu      sync.Mutex
	handles []*Handle
	list    atomic.Pointer[[]*Handle]
	utun    *os.File
	utunIf  string
	link    atomic.Pointer[link]
	rules   string
	token   string
	stop    chan struct{}
}

var (
	hubMu  sync.Mutex
	theHub *hub
)

func Open(filter string) (*Handle, error) { return OpenPriority(filter, 0) }

// Observe на macOS не поддержан: копию пакета без задержки оригинала pf не даёт.
func Observe(string) (*Handle, error) {
	return nil, errors.New("windivert: режим наблюдения на macOS не поддержан")
}

func OpenPriority(filter string, priority int16) (*Handle, error) {
	f, err := ParseFilter(filter)
	if err != nil {
		return nil, err
	}
	h := &Handle{
		filter: f, priority: priority,
		tcp: f.OutboundPorts(true), udp: f.OutboundPorts(false),
		queue: make(chan []byte, queueLen), done: make(chan struct{}),
	}
	hubMu.Lock()
	defer hubMu.Unlock()
	if theHub == nil {
		hb, err := startHub()
		if err != nil {
			return nil, err
		}
		theHub = hb
	}
	if err := theHub.add(h); err != nil {
		if len(theHub.handles) == 0 {
			theHub.close()
			theHub = nil
		}
		return nil, err
	}
	return h, nil
}

func (h *Handle) Recv() (capture.Packet, error) {
	if h.last != nil {
		b := h.last[:0]
		bufPool.Put(&b)
		h.last = nil
	}
	var data []byte
	select {
	case data = <-h.queue:
	default:
		select {
		case data = <-h.queue:
		case <-h.done:
			return capture.Packet{}, errClosed
		}
	}
	h.last = data
	var addr Address
	addr[flagsOffset] = flagOutbound
	return capture.Packet{Data: data, Dir: core.DirectionOutbound, Reinject: addr}, nil
}

// Send отправляет пакет в сеть как есть. Контрольная сумма заголовка IPv4
// пересчитывается; суммы TCP/UDP остаются такими, какими их задал исполнитель.
func (h *Handle) Send(p capture.Packet) error {
	if len(p.Data) == 0 {
		return nil
	}
	hubMu.Lock()
	hb := theHub
	hubMu.Unlock()
	if hb == nil {
		return errClosed
	}
	return hb.send(p.Data)
}

func (h *Handle) ShutdownReceive() error {
	if h.stopped.CompareAndSwap(false, true) {
		hubMu.Lock()
		if theHub != nil {
			_ = theHub.remove(h)
		}
		hubMu.Unlock()
		close(h.done)
	}
	return nil
}

func (h *Handle) Close() error {
	_ = h.ShutdownReceive()
	h.once.Do(func() {
		// Пакеты, оставшиеся в очереди, уходят в сеть нетронутыми.
		for {
			select {
			case b := <-h.queue:
				_ = h.Send(capture.Packet{Data: b})
			default:
				hubMu.Lock()
				if theHub != nil && len(theHub.handles) == 0 {
					theHub.close()
					theHub = nil
				}
				hubMu.Unlock()
				return
			}
		}
	})
	return nil
}

func run(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func field(text, key string) string {
	for _, line := range strings.Split(text, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), ":"); ok && k == key {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func defaultRoute() (iface, gateway string) {
	out, err := run("/sbin/route", "-n", "get", "default")
	if err != nil {
		return "", ""
	}
	return field(out, "interface"), field(out, "gateway")
}

func gatewayMAC(gateway string) (net.HardwareAddr, bool) {
	for try := 0; try < 3; try++ {
		out, _ := run("/usr/sbin/arp", "-n", gateway)
		if _, rest, ok := strings.Cut(out, " at "); ok {
			// arp печатает октеты без ведущих нулей: 2:44:45:56:0:0.
			parts := strings.Split(strings.Fields(rest)[0], ":")
			if len(parts) == 6 {
				mac := make(net.HardwareAddr, 6)
				good := true
				for i, p := range parts {
					x, err := strconv.ParseUint(p, 16, 8)
					good = good && err == nil
					mac[i] = byte(x)
				}
				if good {
					return mac, true
				}
			}
		}
		_, _ = run("/sbin/ping", "-c", "1", "-t", "1", gateway)
	}
	return nil, false
}

func openLink() (*link, error) {
	iface, gateway := defaultRoute()
	if iface == "" || net.ParseIP(gateway).To4() == nil {
		return nil, ErrNoEthernet
	}
	ifi, err := net.InterfaceByName(iface)
	if err != nil || len(ifi.HardwareAddr) != 6 {
		return nil, ErrNoEthernet
	}
	gw, ok := gatewayMAC(gateway)
	if !ok {
		return nil, ErrNoEthernet
	}
	fd := -1
	for i := 0; i < 256; i++ {
		fd, err = unix.Open("/dev/bpf"+strconv.Itoa(i), unix.O_RDWR|unix.O_CLOEXEC, 0)
		if err == nil || !errors.Is(err, unix.EBUSY) {
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("windivert: bpf: %w", err)
	}
	fail := func(err error) (*link, error) {
		_ = unix.Close(fd)
		return nil, err
	}
	if err := syscall.SetBpfInterface(fd, iface); err != nil {
		return fail(fmt.Errorf("windivert: bpf %s: %w", iface, err))
	}
	if dlt, err := syscall.BpfDatalink(fd); err != nil || dlt != unix.DLT_EN10MB {
		return fail(ErrNoEthernet)
	}
	if err := syscall.SetBpfHeadercmpl(fd, 1); err != nil {
		return fail(fmt.Errorf("windivert: bpf: %w", err))
	}
	// Дескриптор только пишет: входящие кадры в его буфер не копируются.
	reject := []syscall.BpfInsn{{Code: syscall.BPF_RET | syscall.BPF_K, K: 0}}
	_ = syscall.SetBpf(fd, reject)
	l := &link{iface: iface, gateway: gateway, mtu: ifi.MTU, bpf: fd}
	copy(l.header[0:6], gw)
	copy(l.header[6:12], ifi.HardwareAddr)
	l.header[12], l.header[13] = 0x08, 0x00
	return l, nil
}

func openUtun() (*os.File, string, error) {
	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, 2 /* SYSPROTO_CONTROL */)
	if err != nil {
		return nil, "", fmt.Errorf("windivert: utun: %w", err)
	}
	info := &unix.CtlInfo{}
	copy(info.Name[:], "com.apple.net.utun_control")
	if err := unix.IoctlCtlInfo(fd, info); err != nil {
		_ = unix.Close(fd)
		return nil, "", fmt.Errorf("windivert: utun: %w", err)
	}
	// Unit 0 — система сама выбирает свободный номер utun.
	if err := unix.Connect(fd, &unix.SockaddrCtl{ID: info.Id, Unit: 0}); err != nil {
		_ = unix.Close(fd)
		if errors.Is(err, unix.EPERM) {
			return nil, "", errors.New("windivert: перехват на macOS требует прав администратора")
		}
		return nil, "", fmt.Errorf("windivert: utun: %w", err)
	}
	name, err := unix.GetsockoptString(fd, 2, 2 /* UTUN_OPT_IFNAME */)
	if err != nil {
		_ = unix.Close(fd)
		return nil, "", fmt.Errorf("windivert: utun: %w", err)
	}
	return os.NewFile(uintptr(fd), name), name, nil
}

func startHub() (*hub, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("windivert: перехват на macOS требует прав администратора")
	}
	if err := lockPF(); err != nil {
		return nil, err
	}
	releasePF()
	l, err := openLink()
	if err != nil {
		return nil, err
	}
	utun, name, err := openUtun()
	if err != nil {
		_ = unix.Close(l.bpf)
		return nil, err
	}
	hb := &hub{utun: utun, utunIf: name, stop: make(chan struct{})}
	hb.link.Store(l)
	empty := []*Handle{}
	hb.list.Store(&empty)
	if _, err := run("/sbin/ifconfig", name, utunLocal, utunPeer, "netmask", "255.255.255.255", "mtu", strconv.Itoa(l.mtu), "up"); err != nil {
		hb.close()
		return nil, err
	}
	// Своя ссылка на включённый pf нужна всегда: если pf держит чужая программа
	// и она его отпустит, без нашей ссылки правила перестали бы работать.
	out, _ := run("/sbin/pfctl", "-E")
	if _, tok, ok := strings.Cut(out, "Token : "); ok {
		hb.token = strings.TrimSpace(strings.SplitN(tok, "\n", 2)[0])
		_ = os.WriteFile(tokenFile, []byte(hb.token), 0o600)
	}
	watchdogOnce.Do(startWatchdog)
	go hb.readLoop()
	go hb.watchRoute()
	return hb, nil
}

var (
	pfLock       *os.File
	watchdogOnce sync.Once
)

// lockPF делает процесс единственным владельцем якоря pf и файла токена: два
// движка с общим якорем снимали бы правила друг друга. Блокировку наследует
// сторожевой процесс, поэтому она держится, пока он не уберёт правила.
func lockPF() error {
	if pfLock != nil {
		return nil
	}
	f, err := os.OpenFile(lockFile, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("windivert: %w", err)
	}
	for try := 0; ; try++ {
		if err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err == nil {
			pfLock = f
			return nil
		}
		if try >= 30 {
			_ = f.Close()
			return errors.New("windivert: перехват уже занят другим процессом Evasion")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// startWatchdog снимает правила pf, если движок умер, не успев убрать их сам:
// иначе трафик перехваченных портов уходил бы в исчезнувший utun.
func startWatchdog() {
	script := `while kill -0 "$0" 2>/dev/null; do sleep 0.3; done
/sbin/pfctl -a "$1" -F all >/dev/null 2>&1
if [ -s "$2" ]; then /sbin/pfctl -X "$(cat "$2")" >/dev/null 2>&1; rm -f "$2"; fi`
	cmd := exec.Command("/bin/sh", "-c", script, strconv.Itoa(os.Getpid()), pfAnchor, tokenFile)
	cmd.SysProcAttr = &unix.SysProcAttr{Setsid: true}
	cmd.ExtraFiles = []*os.File{pfLock}
	if cmd.Start() == nil {
		go func() { _ = cmd.Wait() }()
	}
}

func releasePF() {
	_, _ = run("/sbin/pfctl", "-a", pfAnchor, "-F", "all")
	if tok, err := os.ReadFile(tokenFile); err == nil {
		if t := strings.TrimSpace(string(tok)); t != "" {
			_, _ = run("/sbin/pfctl", "-X", t)
		}
		_ = os.Remove(tokenFile)
	}
}

func portList(sets ...[]PortRange) string {
	seen := map[PortRange]bool{}
	var parts []string
	for _, set := range sets {
		for _, r := range set {
			if seen[r] {
				continue
			}
			seen[r] = true
			if r.Lo == r.Hi {
				parts = append(parts, strconv.Itoa(int(r.Lo)))
			} else {
				parts = append(parts, fmt.Sprintf("%d:%d", r.Lo, r.Hi))
			}
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

// reload пересобирает правила pf по текущим дескрипторам. Вызывается под mu.
func (hb *hub) reload() error {
	var tcp, udp [][]PortRange
	for _, h := range hb.handles {
		tcp, udp = append(tcp, h.tcp), append(udp, h.udp)
	}
	var b strings.Builder
	l := hb.link.Load()
	if l != nil {
		for proto, ports := range map[string]string{"tcp": portList(tcp...), "udp": portList(udp...)} {
			if ports != "" {
				// Адреса локальной сети не трогаем: кадр ушёл бы шлюзу, а не соседу.
				fmt.Fprintf(&b, "pass out quick on %s route-to (%s %s) inet proto %s from any to ! (%s:network) port { %s } no state\n",
					l.iface, hb.utunIf, utunPeer, proto, l.iface, ports)
			}
		}
	}
	rules := b.String()
	if rules == hb.rules {
		return nil
	}
	cmd := exec.Command("/sbin/pfctl", "-a", pfAnchor, "-f", "-")
	cmd.Stdin = strings.NewReader(rules)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("windivert: pfctl: %w: %s", err, bytes.TrimSpace(out))
	}
	hb.rules = rules
	return nil
}

func (hb *hub) publish() {
	list := append([]*Handle(nil), hb.handles...)
	sort.SliceStable(list, func(i, j int) bool { return list[i].priority > list[j].priority })
	hb.list.Store(&list)
}

func (hb *hub) add(h *Handle) error {
	hb.mu.Lock()
	defer hb.mu.Unlock()
	hb.handles = append(hb.handles, h)
	hb.publish()
	if err := hb.reload(); err != nil {
		hb.handles = hb.handles[:len(hb.handles)-1]
		hb.publish()
		return err
	}
	return nil
}

func (hb *hub) remove(h *Handle) error {
	hb.mu.Lock()
	defer hb.mu.Unlock()
	for i, x := range hb.handles {
		if x == h {
			hb.handles = append(hb.handles[:i], hb.handles[i+1:]...)
			break
		}
	}
	hb.publish()
	return hb.reload()
}

func (hb *hub) close() {
	close(hb.stop)
	releasePF()
	_ = hb.utun.Close()
	if l := hb.link.Swap(nil); l != nil {
		_ = unix.Close(l.bpf)
	}
}

func (hb *hub) readLoop() {
	buf := make([]byte, 4+maxPacket)
	for {
		n, err := hb.utun.Read(buf)
		if err != nil {
			return
		}
		if n <= 4 {
			continue
		}
		pkt := buf[4:n]
		taken := false
		for _, h := range *hb.list.Load() {
			if h.stopped.Load() || !h.filter.Match(pkt, true) {
				continue
			}
			bp := bufPool.Get().(*[]byte)
			cp := append((*bp)[:0], pkt...)
			select {
			case h.queue <- cp:
				taken = true
			default:
				// Очередь полна: пакет уходит нетронутым, соединение не рвётся.
				bufPool.Put(bp)
			}
			break
		}
		if !taken {
			_ = hb.send(pkt)
		}
	}
}

func ipChecksum(h []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(h); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(h[i:]))
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func (hb *hub) send(pkt []byte) error {
	l := hb.link.Load()
	if l == nil {
		return ErrNoEthernet
	}
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return errors.New("windivert: на macOS отправляется только IPv4")
	}
	if len(pkt) > l.mtu {
		return fmt.Errorf("windivert: пакет %d байт больше MTU %d", len(pkt), l.mtu)
	}
	frame := make([]byte, 14+len(pkt))
	copy(frame, l.header[:])
	copy(frame[14:], pkt)
	ip := frame[14:]
	ihl := int(ip[0]&0x0f) * 4
	if ihl >= 20 && ihl <= len(ip) {
		ip[10], ip[11] = 0, 0
		binary.BigEndian.PutUint16(ip[10:], ipChecksum(ip[:ihl]))
	}
	_, err := unix.Write(l.bpf, frame)
	return err
}

// watchRoute следит за сменой сети: новый интерфейс или шлюз требуют нового
// адреса кадра и новых правил pf.
func (hb *hub) watchRoute() {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-hb.stop:
			return
		case <-t.C:
		}
		iface, gateway := defaultRoute()
		cur := hb.link.Load()
		if cur != nil && cur.iface == iface && cur.gateway == gateway {
			// Другая сеть с тем же адресом шлюза: меняется только его MAC.
			mac, ok := gatewayMAC(gateway)
			if !ok || bytes.Equal(mac, cur.header[0:6]) {
				continue
			}
		}
		next, _ := openLink()
		hb.mu.Lock()
		select {
		case <-hb.stop:
			hb.mu.Unlock()
			if next != nil {
				_ = unix.Close(next.bpf)
			}
			return
		default:
		}
		var old *link
		if next != nil {
			old = hb.link.Swap(next)
		} else {
			// Сети нет или она не Ethernet: правила снимаются, трафик идёт мимо.
			old = hb.link.Swap(nil)
		}
		_ = hb.reload()
		hb.mu.Unlock()
		if old != nil {
			_ = unix.Close(old.bpf)
		}
	}
}
