package windivert

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Filter — разобранное подмножество языка фильтров WinDivert. Нужен там, где
// самого WinDivert нет (macOS): пакеты отбирает движок, а не драйвер.
type Filter struct{ root node }

type tri int8

const (
	triFalse tri = iota
	triTrue
	triUnknown
)

type node interface {
	eval(v *view) bool
	// may — трёхзначная оценка для исходящего пакета, о котором известны
	// только протокол и порт назначения.
	may(tcp bool, port uint16) tri
}

type view struct {
	v6       bool
	proto    uint8
	src, dst netip.Addr
	sport    uint16
	dport    uint16
	flags    uint8
	payload  []byte
	outbound bool
}

const (
	protoTCP = 6
	protoUDP = 17
)

func parseView(b []byte, outbound bool) (view, bool) {
	v := view{outbound: outbound}
	var l4 []byte
	switch {
	case len(b) >= 20 && b[0]>>4 == 4:
		ihl := int(b[0]&0x0f) * 4
		total := int(binary.BigEndian.Uint16(b[2:]))
		if ihl < 20 || total < ihl || total > len(b) {
			return v, false
		}
		if binary.BigEndian.Uint16(b[6:])&0x1fff != 0 {
			return v, false
		}
		v.proto = b[9]
		v.src, _ = netip.AddrFromSlice(b[12:16])
		v.dst, _ = netip.AddrFromSlice(b[16:20])
		l4 = b[ihl:total]
	case len(b) >= 40 && b[0]>>4 == 6:
		plen := int(binary.BigEndian.Uint16(b[4:]))
		if 40+plen > len(b) {
			return v, false
		}
		v.v6 = true
		v.proto = b[6]
		v.src, _ = netip.AddrFromSlice(b[8:24])
		v.dst, _ = netip.AddrFromSlice(b[24:40])
		l4 = b[40 : 40+plen]
	default:
		return v, false
	}
	switch v.proto {
	case protoTCP:
		if len(l4) < 20 {
			return v, false
		}
		off := int(l4[12]>>4) * 4
		if off < 20 || off > len(l4) {
			return v, false
		}
		v.flags = l4[13]
		v.payload = l4[off:]
	case protoUDP:
		if len(l4) < 8 {
			return v, false
		}
		v.payload = l4[8:]
	default:
		return v, true
	}
	v.sport = binary.BigEndian.Uint16(l4)
	v.dport = binary.BigEndian.Uint16(l4[2:])
	return v, true
}

// Match сообщает, подходит ли пакет (с IP-заголовка) под фильтр.
func (f *Filter) Match(pkt []byte, outbound bool) bool {
	v, ok := parseView(pkt, outbound)
	return ok && f.root.eval(&v)
}

// PortRange — закрытый диапазон портов назначения.
type PortRange struct{ Lo, Hi uint16 }

// OutboundPorts возвращает порты назначения, исходящие пакеты на которые
// фильтр может захватить. Оценка сверху: условия на содержимое пакета считаются
// неизвестными.
func (f *Filter) OutboundPorts(tcp bool) []PortRange {
	var out []PortRange
	open := false
	for p := 0; p <= 0xffff; p++ {
		if f.root.may(tcp, uint16(p)) != triFalse {
			if open {
				out[len(out)-1].Hi = uint16(p)
			} else {
				out = append(out, PortRange{uint16(p), uint16(p)})
				open = true
			}
		} else {
			open = false
		}
	}
	return out
}

type constNode bool

func (c constNode) eval(*view) bool { return bool(c) }
func (c constNode) may(bool, uint16) tri {
	if c {
		return triTrue
	}
	return triFalse
}

type notNode struct{ x node }

func (n notNode) eval(v *view) bool { return !n.x.eval(v) }
func (n notNode) may(tcp bool, p uint16) tri {
	switch n.x.may(tcp, p) {
	case triTrue:
		return triFalse
	case triFalse:
		return triTrue
	}
	return triUnknown
}

type binNode struct {
	and  bool
	l, r node
}

func (n binNode) eval(v *view) bool {
	if n.and {
		return n.l.eval(v) && n.r.eval(v)
	}
	return n.l.eval(v) || n.r.eval(v)
}

func (n binNode) may(tcp bool, p uint16) tri {
	a, b := n.l.may(tcp, p), n.r.may(tcp, p)
	stop := triTrue
	if n.and {
		stop = triFalse
	}
	switch {
	case a == stop || b == stop:
		return stop
	case a == triUnknown || b == triUnknown:
		return triUnknown
	}
	return a
}

type fieldNode struct {
	field string // в нижнем регистре
	index int
	op    string // "" — проверка на истинность
	num   uint64
	addr  netip.Addr
}

func cmp(op string, a, b uint64) bool {
	switch op {
	case "==":
		return a == b
	case "!=":
		return a != b
	case "<":
		return a < b
	case "<=":
		return a <= b
	case ">":
		return a > b
	case ">=":
		return a >= b
	}
	return a != 0
}

func b2u(b bool) uint64 {
	if b {
		return 1
	}
	return 0
}

func (n fieldNode) value(v *view) (uint64, bool) {
	l4, name, _ := strings.Cut(n.field, ".")
	switch l4 {
	case "outbound":
		return b2u(v.outbound), true
	case "inbound":
		return b2u(!v.outbound), true
	case "impostor", "loopback":
		return 0, true
	case "ip":
		if name == "" {
			return b2u(!v.v6), true
		}
		return 0, !v.v6
	case "ipv6":
		if name == "" {
			return b2u(v.v6), true
		}
		return 0, v.v6
	case "tcp", "udp":
		want := uint8(protoTCP)
		if l4 == "udp" {
			want = protoUDP
		}
		if v.proto != want {
			return 0, false
		}
		switch name {
		case "":
			return 1, true
		case "dstport":
			return uint64(v.dport), true
		case "srcport":
			return uint64(v.sport), true
		case "payloadlength":
			return uint64(len(v.payload)), true
		case "syn":
			return b2u(v.flags&0x02 != 0), true
		case "fin":
			return b2u(v.flags&0x01 != 0), true
		case "rst":
			return b2u(v.flags&0x04 != 0), true
		case "psh":
			return b2u(v.flags&0x08 != 0), true
		case "ack":
			return b2u(v.flags&0x10 != 0), true
		case "payload":
			if n.index < len(v.payload) {
				return uint64(v.payload[n.index]), true
			}
		case "payload16":
			if o := n.index * 2; o+2 <= len(v.payload) {
				return uint64(binary.BigEndian.Uint16(v.payload[o:])), true
			}
		case "payload32":
			if o := n.index * 4; o+4 <= len(v.payload) {
				return uint64(binary.BigEndian.Uint32(v.payload[o:])), true
			}
		}
	}
	return 0, false
}

func (n fieldNode) eval(v *view) bool {
	if n.addr.IsValid() {
		a := v.dst
		if strings.HasSuffix(n.field, ".srcaddr") {
			a = v.src
		}
		if v.v6 != strings.HasPrefix(n.field, "ipv6.") {
			return false
		}
		return (a.Unmap() == n.addr.Unmap()) == (n.op == "==")
	}
	x, ok := n.value(v)
	if !ok {
		return false
	}
	return cmp(n.op, x, n.num)
}

func (n fieldNode) may(tcp bool, p uint16) tri {
	t := func(b bool) tri {
		if b {
			return triTrue
		}
		return triFalse
	}
	switch n.field {
	case "outbound":
		return triTrue
	case "inbound", "impostor", "loopback":
		return triFalse
	case "tcp":
		return t(tcp)
	case "udp":
		return t(!tcp)
	case "tcp.dstport", "udp.dstport":
		if tcp != (n.field == "tcp.dstport") {
			return triFalse
		}
		return t(cmp(n.op, uint64(p), n.num))
	}
	if strings.HasPrefix(n.field, "tcp.") && !tcp || strings.HasPrefix(n.field, "udp.") && tcp {
		return triFalse
	}
	return triUnknown
}

// ParseFilter разбирает строку фильтра.
func ParseFilter(s string) (*Filter, error) {
	p := &parser{toks: tokenize(s)}
	n, err := p.or()
	if err != nil {
		return nil, fmt.Errorf("windivert: негодный фильтр: %w", err)
	}
	if p.pos != len(p.toks) {
		return nil, fmt.Errorf("windivert: негодный фильтр: лишнее %q", p.toks[p.pos])
	}
	return &Filter{root: n}, nil
}

func tokenize(s string) []string {
	var out []string
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '(' || c == ')':
			out = append(out, string(c))
			i++
		case strings.ContainsRune("=!<>", rune(c)):
			j := i + 1
			if j < len(s) && s[j] == '=' {
				j++
			}
			out = append(out, s[i:j])
			i = j
		default:
			j := i
			for j < len(s) && !strings.ContainsRune(" \t\n\r()=!<>", rune(s[j])) {
				j++
			}
			out = append(out, s[i:j])
			i = j
		}
	}
	return out
}

type parser struct {
	toks []string
	pos  int
}

func (p *parser) peek() string {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return ""
}

func (p *parser) or() (node, error) {
	l, err := p.and()
	for err == nil && (p.peek() == "or" || p.peek() == "||") {
		p.pos++
		var r node
		if r, err = p.and(); err == nil {
			l = binNode{false, l, r}
		}
	}
	return l, err
}

func (p *parser) and() (node, error) {
	l, err := p.unary()
	for err == nil && (p.peek() == "and" || p.peek() == "&&") {
		p.pos++
		var r node
		if r, err = p.unary(); err == nil {
			l = binNode{true, l, r}
		}
	}
	return l, err
}

var boolFields = map[string]bool{
	"outbound": true, "inbound": true, "impostor": true, "loopback": true,
	"ip": true, "ipv6": true, "tcp": true, "udp": true,
	"tcp.syn": true, "tcp.fin": true, "tcp.rst": true, "tcp.psh": true, "tcp.ack": true,
}

var numFields = map[string]bool{
	"tcp.dstport": true, "tcp.srcport": true, "tcp.payloadlength": true,
	"udp.dstport": true, "udp.srcport": true, "udp.payloadlength": true,
	"tcp.payload": true, "tcp.payload16": true, "tcp.payload32": true,
	"udp.payload": true, "udp.payload16": true, "udp.payload32": true,
}

func (p *parser) unary() (node, error) {
	tok := p.peek()
	p.pos++
	switch tok {
	case "":
		return nil, fmt.Errorf("неожиданный конец")
	case "not", "!":
		x, err := p.unary()
		if err != nil {
			return nil, err
		}
		return notNode{x}, nil
	case "(":
		x, err := p.or()
		if err != nil {
			return nil, err
		}
		if p.peek() != ")" {
			return nil, fmt.Errorf("нет закрывающей скобки")
		}
		p.pos++
		return x, nil
	case "true", "false":
		return constNode(tok == "true"), nil
	}
	n := fieldNode{field: strings.ToLower(tok)}
	if i := strings.IndexByte(n.field, '['); i >= 0 && strings.HasSuffix(n.field, "]") {
		idx, err := strconv.Atoi(n.field[i+1 : len(n.field)-1])
		if err != nil || idx < 0 {
			return nil, fmt.Errorf("негодный индекс в %q", tok)
		}
		n.index, n.field = idx, n.field[:i]
	}
	isAddr := strings.HasSuffix(n.field, ".dstaddr") || strings.HasSuffix(n.field, ".srcaddr")
	if isAddr && !strings.HasPrefix(n.field, "ip.") && !strings.HasPrefix(n.field, "ipv6.") {
		return nil, fmt.Errorf("неизвестное поле %q", tok)
	}
	if !isAddr && !boolFields[n.field] && !numFields[n.field] {
		return nil, fmt.Errorf("неизвестное поле %q", tok)
	}
	switch op := p.peek(); op {
	case "==", "!=", "<", "<=", ">", ">=":
		p.pos++
		val := p.peek()
		p.pos++
		n.op = op
		if isAddr {
			a, err := netip.ParseAddr(val)
			if err != nil || (op != "==" && op != "!=") {
				return nil, fmt.Errorf("негодный адрес %q", val)
			}
			n.addr = a
			return n, nil
		}
		x, err := strconv.ParseUint(val, 0, 64)
		if err != nil {
			return nil, fmt.Errorf("негодное число %q", val)
		}
		n.num = x
	default:
		if isAddr || !boolFields[n.field] {
			return nil, fmt.Errorf("поле %q требует сравнения", tok)
		}
	}
	return n, nil
}
