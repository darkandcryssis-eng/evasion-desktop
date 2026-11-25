package tunnel

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/fitting-1c/evasion/internal/warp"
)

// DefaultMTU — размер MTU WireGuard-интерфейса по умолчанию.
//
// WireGuard добавляет 60 байт служебной информации (20 IPv4 + 8 UDP + 32 WG),
// плюс заметный запас на фрагментацию. 1280 — безопасное значение, минимум
// IPv6 (RFC 2460), с которым нигде не споткнёмся. Можно поднять до 1420 на
// большинстве сетей, но ради предсказуемости держим низкий.
const DefaultMTU = 1280

// DefaultDNS — DNS-серверы для резолвинга имён ВНУТРИ туннеля.
//
// Задаются именно внутри: системный DNS у владельца подменён провайдером
// (мы это выяснили, когда `nslookup finland14021.discord.media` возвращал
// `104.25.158.178` вместо реальных IP). Через туннель запросы идут в
// Cloudflare 1.1.1.1 чистыми, провайдер их не видит.
var DefaultDNS = []netip.Addr{
	netip.MustParseAddr("1.1.1.1"),
	netip.MustParseAddr("1.0.0.1"),
}

// Tunnel — активный WireGuard-туннель.
//
// Безопасно использовать параллельно: `*netstack.Net` под капотом держит
// gVisor netstack, который рассчитан на одновременные соединения. Закрытие
// не ждёт активных Dial — закрывается устройство, активные соединения
// получат ошибку чтения/записи.
type Tunnel struct {
	device   *device.Device
	stack    *netstack.Net
	logger   *slog.Logger
	endpoint string
	ipv4     netip.Addr
	ipv6     netip.Addr
}

// Endpoint возвращает адрес пира ("IP:порт"), с которым поднят туннель.
func (t *Tunnel) Endpoint() string { return t.endpoint }

// Options — настройки открытия туннеля.
type Options struct {
	// Account — зарегистрированный аккаунт WARP. Обязателен.
	Account *warp.Account
	// MTU — размер MTU WireGuard-интерфейса. 0 означает DefaultMTU.
	MTU int
	// DNS — DNS-серверы ВНУТРИ туннеля. nil означает DefaultDNS. Пустой
	// срез отключает резолвинг через туннель (имена нужно резолвить снаружи
	// и дёргать `DialContext` с IP).
	DNS []netip.Addr
	// Logger — журнал. nil допустим (пишет в никуда).
	Logger *slog.Logger
	// LogLevel — уровень логов WireGuard. Пустая строка = Error (минимум).
	// `verbose` печатает хендшейки и статусы (нужно для диагностики).
	LogLevel string
}

// Open поднимает туннель.
//
// Это полная последовательность: сборка UAPI-конфига из account, создание
// netstack-TUN на наших WARP-адресах, запуск WireGuard-устройства, настройка
// peer-а (WARP). После Open туннель готов принимать Dial-ы.
//
// Ошибка возвращается, если:
//   - account битый (не прошёл Validate)
//   - UAPI-конфиг отвергнут wireguard-go (битые ключи, формат)
//   - netstack не стартует (аллокация адресов)
//
// Проблемы с сетью (peer не отвечает) здесь не всплывают — WireGuard
// подключается лениво, по первому пакету. DialContext с таймаутом покажет,
// что peer недоступен.
func Open(opts Options) (*Tunnel, error) {
	if opts.Account == nil {
		return nil, fmt.Errorf("tunnel: не задан account")
	}
	if err := opts.Account.Validate(); err != nil {
		return nil, err
	}
	mtu := opts.MTU
	if mtu == 0 {
		mtu = DefaultMTU
	}
	dns := opts.DNS
	if dns == nil {
		dns = DefaultDNS
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	// netstack-TUN привязан к НАШИМ адресам из WARP: пакеты, попадающие на
	// него, идут от этих IP. Так Cloudflare распознаёт сессию.
	tun, netStack, err := netstack.CreateNetTUN(
		[]netip.Addr{opts.Account.IPv4, opts.Account.IPv6},
		dns,
		mtu,
	)
	if err != nil {
		return nil, fmt.Errorf("tunnel: netstack: %w", err)
	}

	// Логгер WireGuard: уровень по умолчанию минимальный (ошибки). Verbose
	// печатает каждый хендшейк — нужен для диагностики, когда WG молчит.
	//
	// Verbose логи печатаются на уровне Info (не Debug): slog по умолчанию
	// режет Debug и прогон --verbose выглядел бы как молчание. На Info их
	// точно видно без настройки handler-ов. В «тихой» работе movok они
	// подавлены на нашей стороне (функция возвращается без вывода).
	verbose := opts.LogLevel == "verbose"
	wgLogger := &device.Logger{
		Verbosef: func(f string, args ...any) {
			if verbose {
				logger.Info("wg", "msg", fmt.Sprintf(f, args...))
			}
		},
		Errorf: func(f string, args ...any) {
			logger.Error("wg", "msg", fmt.Sprintf(f, args...))
		},
	}

	dev := device.NewDevice(tun, conn.NewDefaultBind(), wgLogger)

	// Endpoint peer-а: wireguard-go внутри делает net.ResolveUDPAddr, он
	// идёт через системный DNS. У владельца системный DNS режется провайдером,
	// и `engage.cloudflareclient.com` не резолвится — IpcSet упадёт с
	// "No such host is known". Резолвим сами, с фоллбэком на известный IP
	// WARP-endpoint (стабильный, Cloudflare держит его годами).
	endpoint, err := resolveEndpoint(opts.Account.PeerEndpoint)
	if err != nil {
		dev.Close()
		return nil, err
	}

	// UAPI-конфиг: WireGuard принимает текстовое описание пира с ключами в
	// HEX-формате. Base64 из wg-quick конфига сюда не подходит; конвертируем.
	uapi, err := buildUAPI(opts.Account, endpoint)
	if err != nil {
		dev.Close()
		return nil, err
	}
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		return nil, fmt.Errorf("tunnel: IpcSet: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("tunnel: Up: %w", err)
	}

	return &Tunnel{
		device:   dev,
		stack:    netStack,
		logger:   logger,
		endpoint: endpoint,
		ipv4:     opts.Account.IPv4,
		ipv6:     opts.Account.IPv6,
	}, nil
}

// ListenUDP открывает несвязанный UDP-сокет внутри туннеля для IPv4 или IPv6.
// Один сокет обслуживает все удалённые направления с сохранением внешнего
// порта (Cone NAT), что нужно для STUN/TURN/DTLS/SRTP в звонках Telegram.
func (t *Tunnel) ListenUDP(ipv6 bool) (net.PacketConn, error) {
	ip := t.ipv4
	if ipv6 {
		ip = t.ipv6
	}
	if !ip.IsValid() {
		return nil, fmt.Errorf("tunnel: адрес для UDP (ipv6=%v) не задан", ipv6)
	}
	return t.stack.ListenUDPAddrPort(netip.AddrPortFrom(ip, 0))
}

// DialContext открывает TCP-соединение через туннель.
//
// Поддерживает `network` = `tcp`, `tcp4`, `tcp6`. UDP пока не экспонирован:
// voice-гейтвеи Discord сначала поднимают TCP WebSocket, UDP приходит после
// (Phase 2.3+ обработает). Если понадобится UDP, добавится `DialUDP`.
//
// `addr` — "host:port" формат. host — имя или IP. Имя резолвится через
// `netstack.Net` своим DNS (DefaultDNS: 1.1.1.1 через туннель), а не
// системным — это и было нужно против DNS-подмены ISP.
func (t *Tunnel) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("tunnel: сеть %q не поддерживается (пока только tcp*)", network)
	}
	return t.stack.DialContext(ctx, network, addr)
}

// LookupHost резолвит имя через туннель. Возвращает IPv4 и IPv6 адреса,
// отданные DNS внутри туннеля.
//
// Удобно для SNI-прокси: получить реальный адрес `finland14035.discord.media`
// без обращения к системному DNS (который у провайдера может быть
// подменён).
func (t *Tunnel) LookupHost(ctx context.Context, host string) ([]netip.Addr, error) {
	ips, err := t.stack.LookupContextHost(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("tunnel: резолвинг %q: %w", host, err)
	}
	out := make([]netip.Addr, 0, len(ips))
	for _, s := range ips {
		if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("tunnel: имя %q резолвится в пустой список", host)
	}
	return out, nil
}

// Close останавливает туннель и освобождает ресурсы. Безопасно вызывать
// повторно (идемпотентно) и из любой горутины.
func (t *Tunnel) Close() error {
	t.device.Close()
	return nil
}

// WaitHandshake блокируется до успешного WireGuard-рукопожатия с peer-ом или
// отмены контекста. Проверка — через UAPI (`last_handshake_time_sec`): если
// значение > 0, рукопожатие прошло.
//
// Нужен для перебора portов: WireGuard сам не отдаёт событие «peer ответил»,
// а ждать 10 с на DialContext слишком долго для перебора 40 портов.
func (t *Tunnel) WaitHandshake(ctx context.Context) error {
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for {
		if t.hasHandshake() {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}

// hasHandshake читает состояние peer-а через UAPI и сообщает, был ли уже
// успешный хендшейк (last_handshake_time_sec > 0).
func (t *Tunnel) hasHandshake() bool {
	var buf strings.Builder
	if err := t.device.IpcGetOperation(&buf); err != nil {
		return false
	}
	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.HasPrefix(line, "last_handshake_time_sec=") {
			val := strings.TrimPrefix(line, "last_handshake_time_sec=")
			if n, _ := strconv.ParseInt(val, 10, 64); n > 0 {
				return true
			}
		}
	}
	return false
}

// OpenWithFallback пытается открыть туннель с перебором портов endpoint-а.
//
// Нужен когда провайдер режет основной порт WARP (2408). Cloudflare держит
// сервис на десятках нестандартных портов (WARPFallbackPorts), и часть из
// них у разных провайдеров открыта.
//
// Для каждого порта: открывается туннель, ждём рукопожатие perPortTimeout,
// при успехе — возвращаем, при неудаче — закрываем и пробуем следующий.
// Если все провалились, возвращаем ошибку с перечислением попыток.
func OpenWithFallback(opts Options, ports []int, perPortTimeout time.Duration) (*Tunnel, error) {
	return OpenWithFallbackContext(context.Background(), opts, ports, perPortTimeout)
}

// OpenWithFallbackContext — как OpenWithFallback, но немедленно прерывает
// перебор портов при отмене ctx.
func OpenWithFallbackContext(ctx context.Context, opts Options, ports []int, perPortTimeout time.Duration) (*Tunnel, error) {
	if opts.Account == nil {
		return nil, fmt.Errorf("tunnel: не задан account")
	}
	if len(ports) == 0 {
		return nil, fmt.Errorf("tunnel: пустой список портов для перебора")
	}
	origEndpoint := opts.Account.PeerEndpoint
	host, _, err := net.SplitHostPort(origEndpoint)
	if err != nil {
		return nil, fmt.Errorf("tunnel: endpoint %q не разбирается: %w", origEndpoint, err)
	}
	// Для перебора нужен IP (не DNS-имя): WARPFallbackPorts применяются к
	// anycast-IP, а имя мы и так подменяем через fallback в resolveEndpoint.
	if _, err := netip.ParseAddr(host); err != nil {
		resolved, rerr := resolveEndpoint(origEndpoint)
		if rerr != nil {
			return nil, rerr
		}
		host, _, _ = net.SplitHostPort(resolved)
	}

	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	var lastErr error
	for i, port := range ports {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		candidateAcc := *opts.Account
		candidateAcc.PeerEndpoint = fmt.Sprintf("%s:%d", host, port)
		candidateOpts := opts
		candidateOpts.Account = &candidateAcc

		logger.Info("tunnel: пробую порт", "port", port, "попытка", i+1, "всего", len(ports))
		tn, err := Open(candidateOpts)
		if err != nil {
			lastErr = err
			logger.Warn("tunnel: Open не прошёл", "port", port, "ошибка", err)
			continue
		}

		pctx, cancel := context.WithTimeout(ctx, perPortTimeout)
		err = tn.WaitHandshake(pctx)
		cancel()
		if err == nil {
			logger.Info("tunnel: рукопожатие прошло", "port", port, "попыток", i+1)
			return tn, nil
		}
		tn.Close()
		lastErr = err
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		logger.Debug("tunnel: порт не ответил", "port", port, "ошибка", err)
	}
	return nil, fmt.Errorf("tunnel: ни один из %d портов не ответил рукопожатием: %w", len(ports), lastErr)
}

// OpenWithFallbackParallel перебирает порты endpoint-а батчами по batchSize
// одновременно: первый порт, ответивший WireGuard-рукопожатием, выигрывает,
// остальные в батче немедленно закрываются. Укладывает перебор всех 41 портов
// WARP в несколько секунд вместо минуты.
func OpenWithFallbackParallel(ctx context.Context, opts Options, ports []int, perPortTimeout time.Duration, batchSize int) (*Tunnel, error) {
	if batchSize <= 1 {
		return OpenWithFallbackContext(ctx, opts, ports, perPortTimeout)
	}
	if opts.Account == nil {
		return nil, fmt.Errorf("tunnel: не задан account")
	}
	if len(ports) == 0 {
		return nil, fmt.Errorf("tunnel: пустой список портов для перебора")
	}
	origEndpoint := opts.Account.PeerEndpoint
	host, _, err := net.SplitHostPort(origEndpoint)
	if err != nil {
		return nil, fmt.Errorf("tunnel: endpoint %q не разбирается: %w", origEndpoint, err)
	}
	if _, err := netip.ParseAddr(host); err != nil {
		resolved, rerr := resolveEndpoint(origEndpoint)
		if rerr != nil {
			return nil, rerr
		}
		host, _, _ = net.SplitHostPort(resolved)
	}

	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	var lastErr error
	for start := 0; start < len(ports); start += batchSize {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		end := start + batchSize
		if end > len(ports) {
			end = len(ports)
		}
		batch := ports[start:end]

		bctx, bcancel := context.WithTimeout(ctx, perPortTimeout)
		var (
			mu       sync.Mutex
			winner   *Tunnel
			batchErr error
			wg       sync.WaitGroup
		)
		for _, port := range batch {
			wg.Add(1)
			go func(p int) {
				defer wg.Done()
				if bctx.Err() != nil {
					return
				}
				candidateAcc := *opts.Account
				candidateAcc.PeerEndpoint = fmt.Sprintf("%s:%d", host, p)
				candidateOpts := opts
				candidateOpts.Account = &candidateAcc

				tn, oerr := Open(candidateOpts)
				if oerr != nil {
					mu.Lock()
					if batchErr == nil {
						batchErr = oerr
					}
					mu.Unlock()
					return
				}
				werr := tn.WaitHandshake(bctx)
				if werr == nil {
					mu.Lock()
					if winner == nil {
						winner = tn
						bcancel()
						mu.Unlock()
						logger.Info("tunnel: рукопожатие прошло", "port", p)
						return
					}
					mu.Unlock()
					_ = tn.Close()
					return
				}
				_ = tn.Close()
				mu.Lock()
				if batchErr == nil {
					batchErr = werr
				}
				mu.Unlock()
			}(port)
		}
		wg.Wait()
		bcancel()

		if winner != nil {
			return winner, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if batchErr != nil {
			lastErr = batchErr
		}
	}
	return nil, fmt.Errorf("tunnel: ни один из %d портов не ответил рукопожатием: %w", len(ports), lastErr)
}

// WARPFallbackPorts — альтернативные UDP-порты, на которых Cloudflare держит
// WARP WireGuard-endpoint на том же anycast-IP (162.159.192.*).
//
// Задокументированы в wgcf и прочих клиентах WARP. Главный порт 2408 часто
// режется провайдерами, альтернативы живы с разным шансом. Перебираем по
// очереди, начиная с 2408 (обычно работает) и далее уменьшая вероятность.
var WARPFallbackPorts = []int{
	2408, 500, 1701, 4500,
	854, 859, 864, 878, 880, 890, 894, 903, 908, 928, 934, 939, 942,
	945, 955, 987, 1002, 1010, 1018, 1074, 1180,
	2371, 3138, 3476, 3581, 4177, 4198, 4233,
	5279, 5956, 7103, 7156, 7281, 7559, 8742, 8854, 8886,
}

// resolveEndpoint приводит endpoint к форме "IP:port".
//
// Если endpoint уже IP:port — возвращается как есть. Если это имя:port —
// пробуем системный DNS, при неудаче (у владельца провайдер режет DNS)
// подставляем известный IP WARP endpoint. Это стабильные IP Cloudflare
// (162.159.192.1 и т.п.), которые Cloudflare держит годами и которые
// попадают в тот же anycast-пул, что DNS-имя `engage.cloudflareclient.com`.
//
// Запасной IP жёсткий — на случай редкого будущего ремапа Cloudflare у нас
// есть одна правка в одном месте. Альтернатива (DoH до 1.1.1.1 как fallback)
// красивее, но тащит зависимость DNS-клиента ради одного DNS-запроса.
func resolveEndpoint(endpoint string) (string, error) {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return "", fmt.Errorf("tunnel: endpoint %q не разбирается: %w", endpoint, err)
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return endpoint, nil // уже IP
	}
	// Пытаемся системным резолвером с коротким таймаутом: висеть на DNS
	// минутами мы не можем, обвалилось — обвалилось, идём в fallback.
	resolver := &net.Resolver{}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ips, err := resolver.LookupIPAddr(ctx, host)
	if err == nil && len(ips) > 0 {
		return net.JoinHostPort(ips[0].IP.String(), port), nil
	}
	// Fallback: известный IP WARP endpoint. Актуален, пока Cloudflare не
	// переназначит сервис — за годы существования WARP не менялся.
	if host == "engage.cloudflareclient.com" {
		return "162.159.192.1:" + port, nil
	}
	return "", fmt.Errorf("tunnel: endpoint %q не резолвится и не в fallback-таблице: %w", endpoint, err)
}

// buildUAPI собирает текст UAPI-конфига из account.
//
// Формат документирован WireGuard (`src/uapi/wg-netlink.c`): ключи в HEX,
// endpoint host:port, allowed_ip в CIDR. Значения построчно, разделитель `\n`.
//
// AllowedIPs = 0.0.0.0/0 + ::/0 — весь v4/v6 через туннель, НО это
// применяется только к пакетам, попавшим на наш netstack-интерфейс. На
// системную маршрутизацию никак не влияет (netstack userspace). См. doc.go.
//
// endpoint передаётся УЖЕ резолвленным в IP:port — wireguard-go внутри
// делает ResolveUDPAddr, который у владельца с подменённым DNS падает.
func buildUAPI(a *warp.Account, endpoint string) (string, error) {
	privHex, err := b64ToHex(a.Keypair.Private)
	if err != nil {
		return "", fmt.Errorf("tunnel: приватный ключ в hex: %w", err)
	}
	pubHex, err := b64ToHex(a.PeerPublicKey)
	if err != nil {
		return "", fmt.Errorf("tunnel: публичный ключ peer в hex: %w", err)
	}
	// WireGuard UAPI требует именно такой порядок: сначала наш ключ, затем
	// peer с его параметрами. Нарушение порядка — ошибка на IpcSet.
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", privHex)
	fmt.Fprintf(&b, "public_key=%s\n", pubHex)
	fmt.Fprintf(&b, "endpoint=%s\n", endpoint)
	// PersistentKeepalive против NAT: держит UDP-сессию до peer-а живой,
	// иначе роутер пользователя через минуту обрезает «неиспользуемую»
	// сессию, и туннель молча умирает.
	fmt.Fprintf(&b, "persistent_keepalive_interval=25\n")
	// AllowedIPs — пара строк для v4 и v6 (так требует UAPI).
	fmt.Fprintln(&b, "allowed_ip=0.0.0.0/0")
	fmt.Fprintln(&b, "allowed_ip=::/0")
	return b.String(), nil
}

// b64ToHex конвертирует ключ из base64 (формат wg-quick/warp API) в hex
// (формат UAPI). Строгая проверка длины — 32 байта: иначе wireguard-go
// отдаст маловразумительную ошибку, а наш слой уже знает что именно сломано.
func b64ToHex(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("негодный base64: %w", err)
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("длина ключа %d байт, ожидалось 32", len(raw))
	}
	return hex.EncodeToString(raw), nil
}
