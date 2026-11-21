// Package rtcredirect прозрачно переклеивает исходящие TCP-соединения с
// «душимых» портов на живой порт того же сервера.
//
// Зачем. Голос Discord (control-socket WSS к *.discord.media) на части портов
// Cloudflare (2053/2083/2087/2096) у провайдера с TSPU душится уже ПОСЛЕ
// рукопожатия: соединение доходит до HELLO, затем входящие данные затыкаются,
// канал виснет на AUTHENTICATING и валится в цикл 1006/4801. На 443 и 8443 те же
// серверы работают стабильно. Discord сам порт не меняет — прилипает к
// выданному серверу и долбится в тот же порт. Значит лечить надо за него: увести
// соединение с душимого порта на живой.
//
// Как. Cloudflare отдаёт одну и ту же зону (discord.media) на всех «дружественных»
// портах, поэтому тот же сервер на :8443 обслужит голос так же, как на :2083.
// Переклейка идёт на уровне пакетов: у исходящих на душимый порт подменяем порт
// назначения на живой и запоминаем соответствие по локальному порту; у входящих
// с живого порта возвращаем исходный порт назначения, чтобы сокет приложения
// (он подключался к :2083) принял ответ. Приложение подмены не видит.
//
// Безопасность границ (1.6). Трогаются ТОЛЬКО соединения, НАЧАВШИЕСЯ на душимый
// порт. Нативные соединения на 443/8443 не затрагиваются: их локальный порт в
// карту не попадает, а свежий SYN на не-душимый порт сбрасывает возможную
// устаревшую запись по этому локальному порту (защита от переиспользования
// эфемерных портов). Движок и его десинк не меняются: для них переклеенное
// соединение выглядит как обычное 8443 — тот самый поток, что и так стабилен.
package rtcredirect

import "github.com/fitting-1c/evasion/internal/packet"

// Redirector хранит карту переклейки и решает судьбу одного пакета.
//
// Не потокобезопасен: им владеет одна горутина приёма (как таблицей потоков).
type Redirector struct {
	from map[uint16]bool   // душимые порты назначения, которые уводим
	to   uint16            // живой порт, на который уводим
	nat  map[uint16]uint16 // локальный (эфемерный) порт -> исходный порт назначения

	redirected int // сколько исходящих уведено на живой порт
	restored   int // сколько входящих возвращено на исходный порт
}

// New создаёт переклейщик: соединения на любой из портов from уводятся на порт
// to. Пустой from или нулевой to делают переклейку бездействующей (Apply всегда
// вернёт false) — это валидный «выключенный» режим.
func New(from []uint16, to uint16) *Redirector {
	set := make(map[uint16]bool, len(from))
	for _, p := range from {
		if p != 0 && p != to {
			set[p] = true
		}
	}
	return &Redirector{from: set, to: to, nat: make(map[uint16]uint16)}
}

// Active сообщает, настроена ли переклейка (есть ли куда и откуда уводить).
func (r *Redirector) Active() bool { return r.to != 0 && len(r.from) > 0 }

// Stats возвращает счётчики переклеек для наблюдаемости.
func (r *Redirector) Stats() (redirected, restored, tracked int) {
	return r.redirected, r.restored, len(r.nat)
}

// Apply разбирает один пакет (buf с IP-заголовка) и, если он относится к
// переклеиваемому соединению, правит порт на месте и пересчитывает контрольные
// суммы. Возвращает true, если пакет изменён.
//
// Чистая по отношению к сети: работает только с буфером и внутренней картой,
// поэтому проверяется на синтетических пакетах без WinDivert.
func (r *Redirector) Apply(buf []byte, outbound bool) bool {
	if !r.Active() {
		return false
	}
	d, err := packet.Dissect(buf)
	if err != nil || d.Protocol != packet.ProtoTCP {
		return false
	}
	th, ok := d.TCP(buf)
	if !ok {
		return false
	}

	if outbound {
		return r.applyOutbound(d, buf, th)
	}
	return r.applyInbound(d, buf, th)
}

// applyOutbound уводит исходящий пакет с душимого порта на живой и запоминает
// соответствие. На свежем SYN к не-душимому порту чистит устаревшую запись по
// этому локальному порту.
func (r *Redirector) applyOutbound(d packet.Dissection, buf []byte, th packet.TCPHeader) bool {
	dst := th.DstPort()
	if r.from[dst] {
		r.nat[th.SrcPort()] = dst
		th.SetDstPort(r.to)
		d.RecomputeChecksums(buf)
		r.redirected++
		return true
	}
	// Начало нового соединения (чистый SYN) на не-душимый порт: локальный порт
	// мог раньше принадлежать переклеенному соединению. Снимаем устаревшую
	// запись, иначе входящие живого порта для этого нативного соединения
	// переклеились бы ошибочно.
	if isSyn(th) {
		delete(r.nat, th.SrcPort())
	}
	return false
}

// applyInbound возвращает входящему пакету с живого порта исходный порт
// назначения, если его локальный порт — переклеенное соединение. На FIN/RST
// соединение забывается.
func (r *Redirector) applyInbound(d packet.Dissection, buf []byte, th packet.TCPHeader) bool {
	if th.SrcPort() != r.to {
		return false
	}
	local := th.DstPort()
	orig, ok := r.nat[local]
	if !ok {
		return false
	}
	th.SetSrcPort(orig)
	d.RecomputeChecksums(buf)
	r.restored++
	if th.Flags()&(packet.FlagFIN|packet.FlagRST) != 0 {
		delete(r.nat, local)
	}
	return true
}

// isSyn сообщает, что сегмент открывает соединение: SYN без ACK.
func isSyn(th packet.TCPHeader) bool {
	return th.Flags()&packet.FlagSYN != 0 && th.Flags()&packet.FlagACK == 0
}
