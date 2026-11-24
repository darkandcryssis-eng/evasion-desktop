package desync

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/strategy"
	"github.com/fitting-1c/evasion/internal/tlsfake"
)

// Помощники построения деревьев. Строим структуры напрямую, а не из JSON:
// тесты проверяют семантику обхода, а не разбор.

func send() *strategy.Action { return &strategy.Action{Kind: core.ActionSend} }
func drop() *strategy.Action { return &strategy.Action{Kind: core.ActionDrop} }

func tamper(p strategy.TamperParams, child *strategy.Action) *strategy.Action {
	return &strategy.Action{Kind: core.ActionTamper, Params: &p, Left: child}
}

func fragment(p strategy.FragmentParams, left, right *strategy.Action) *strategy.Action {
	return &strategy.Action{Kind: core.ActionFragment, Params: &p, Left: left, Right: right}
}

func duplicate(left, right *strategy.Action) *strategy.Action {
	return &strategy.Action{Kind: core.ActionDuplicate, Left: left, Right: right}
}

// clientHelloRule оборачивает действие в правило по исходящему ClientHello.
func clientHelloRule(a *strategy.Action) *strategy.Strategy {
	return &strategy.Strategy{Rules: []strategy.Rule{{
		Direction: core.DirectionOutbound,
		Trigger:   strategy.Trigger{Match: strategy.MatchClientHello},
		Action:    a,
	}}}
}

// outboundHello — типовое исходящее событие с ClientHello.
func outboundHello(payload string) Input {
	return Input{
		Direction:     core.DirectionOutbound,
		Payload:       []byte(payload),
		Ordinal:       1,
		IsClientHello: true,
	}
}

// dumpPlan приводит план к построчной текстовой форме для золотого сравнения.
//
// Форма читаема в обзоре изменений: каждая операция — вид, обрамление,
// содержимое и правки заголовка. Содержимое печатается как строка в кавычках,
// потому что тестовые нагрузки состоят из печатаемых ASCII-символов.
func dumpPlan(p Plan) string {
	var b strings.Builder
	for i, op := range p.Ops {
		fmt.Fprintf(&b, "%d: %s %s %q", i, op.Kind, op.Frame, string(op.Payload))
		if len(op.Edits) > 0 {
			parts := make([]string, len(op.Edits))
			for j, e := range op.Edits {
				parts[j] = fmt.Sprintf("%s:%s:%d", e.Field, e.Mode, e.Value)
			}
			fmt.Fprintf(&b, " edits=[%s]", strings.Join(parts, ","))
		}
		b.WriteByte('\n')
	}
	return b.String()
}

func TestBuildPlanGolden(t *testing.T) {
	ttl3 := strategy.TamperParams{Field: strategy.FieldIPv4TTL, Mode: strategy.TamperReplace, Value: 3}

	cases := []struct {
		name     string
		strategy *strategy.Strategy
		input    Input
		want     string
	}{
		{
			// Ни одно правило не относится к событию (направление не то) —
			// сквозной пропуск целой нагрузки.
			name:     "passthrough при несовпадении направления",
			strategy: clientHelloRule(send()),
			input: Input{
				Direction:     core.DirectionInbound,
				Payload:       []byte("0123456789"),
				IsClientHello: true,
			},
			want: `0: send_real segment "0123456789"
`,
		},
		{
			// Сегментация TCP по прямому порядку: две части потока.
			name:     "фрагментация TCP вперёд",
			strategy: clientHelloRule(fragment(strategy.FragmentParams{Proto: strategy.FragTCP, Offset: 3, Order: strategy.FragForward}, send(), send())),
			input:    outboundHello("0123456789"),
			want: `0: send_real segment "012"
1: send_real segment "3456789"
`,
		},
		{
			// Обратный порядок выражается перестановкой операций: сначала
			// вторая часть, затем первая.
			name:     "фрагментация TCP назад",
			strategy: clientHelloRule(fragment(strategy.FragmentParams{Proto: strategy.FragTCP, Offset: 3, Order: strategy.FragReverse}, send(), send())),
			input:    outboundHello("0123456789"),
			want: `0: send_real segment "3456789"
1: send_real segment "012"
`,
		},
		{
			// Классический фейк: дублируем, одной копии правим TTL (она станет
			// фейком), вторую шлём как есть.
			name:     "фейк по низкому TTL плюс реальные данные",
			strategy: clientHelloRule(duplicate(tamper(ttl3, send()), send())),
			input:    outboundHello("ABCD"),
			want: `0: send_fake segment "ABCD" edits=[ipv4_ttl:replace:3]
1: send_real segment "ABCD"
`,
		},
		{
			// Drop обрывает ветвь: вторая копия уничтожается, остаётся одна
			// операция.
			name:     "drop уничтожает ветвь",
			strategy: clientHelloRule(duplicate(send(), drop())),
			input:    outboundHello("ABCD"),
			want: `0: send_real segment "ABCD"
`,
		},
		{
			// Фрагментация на уровне IP: части получают обрамление ip_fragment,
			// по которому packetexec соберёт один фрагментированный пакет.
			name:     "фрагментация IP помечает обрамление",
			strategy: clientHelloRule(fragment(strategy.FragmentParams{Proto: strategy.FragIP, Offset: 2, Order: strategy.FragForward}, send(), send())),
			input:    outboundHello("ABCD"),
			want: `0: send_real ip_fragment "AB"
1: send_real ip_fragment "CD"
`,
		},
		{
			// Подмена тела без правки заголовка НЕ делает кусок фейком: это
			// осознанная семантика. Такой кусок уйдёт как реальные данные с
			// подменённым содержимым (вероятно, во вред — ловится оценкой
			// побочного вреда). Фейком кусок становится только от правки поля.
			name:     "подмена тела без правки заголовка остаётся реальной",
			strategy: clientHelloRule(tamper(strategy.TamperParams{Field: strategy.FieldPayload, Mode: strategy.TamperReplace, Length: 4}, send())),
			input:    outboundHello("XY"),
			want: `0: send_real segment "XYXY"
`,
		},
		{
			// Полноценный фейк с подменённым телом: правка TTL делает кусок
			// фейком, подмена тела задаёт его содержимое и длину.
			name: "фейк с подменённым телом",
			strategy: clientHelloRule(duplicate(
				tamper(ttl3, tamper(strategy.TamperParams{Field: strategy.FieldPayload, Mode: strategy.TamperReplace, Length: 4}, send())),
				send(),
			)),
			input: outboundHello("HELLO"),
			want: `0: send_fake segment "HELL" edits=[ipv4_ttl:replace:3]
1: send_real segment "HELLO"
`,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			plan, err := BuildPlan(c.strategy, c.input)
			if err != nil {
				t.Fatalf("BuildPlan: %v", err)
			}
			got := dumpPlan(plan)
			if got != c.want {
				t.Fatalf("план расходится с эталоном\n--- получено ---\n%s--- ожидалось ---\n%s", got, c.want)
			}
		})
	}
}

// TestBuildPlanFakePreset: подмена тела по имени пресета кладёт в фейк
// конкретную нагрузку (безобидный ClientHello), а не синтетический узор. Это
// суть исправления: фейк несёт SNI безобидного домена, иначе DPI видит
// настоящее имя в фейке открытым текстом и не обманывается.
func TestBuildPlanFakePreset(t *testing.T) {
	ttl3 := strategy.TamperParams{Field: strategy.FieldIPv4TTL, Mode: strategy.TamperReplace, Value: 3}
	s := clientHelloRule(duplicate(
		tamper(ttl3, tamper(strategy.TamperParams{
			Field:  strategy.FieldPayload,
			Mode:   strategy.TamperReplace,
			Preset: strategy.PresetTLSGoogle,
		}, send())),
		send(),
	))
	plan, err := BuildPlan(s, outboundHello("REAL-CLIENT-HELLO-TO-DISCORD"))
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if len(plan.Ops) != 2 {
		t.Fatalf("ожидалось 2 операции, получено %s", dumpPlan(plan))
	}
	fake := plan.Ops[0]
	if fake.Kind != OpSendFake {
		t.Fatalf("первая операция = %s, ожидался send_fake", fake.Kind)
	}
	want, ok := strategy.FakePreset(strategy.PresetTLSGoogle)
	if !ok {
		t.Fatal("пресет tls_clienthello_google не найден в реестре")
	}
	if !tlsfake.EqualIgnoringRandom(fake.Payload, want) {
		t.Fatalf("нагрузка фейка не равна пресету: %d байт против %d", len(fake.Payload), len(want))
	}
	// Фейк не должен нести настоящую нагрузку (SNI discord) — проверяем, что
	// содержимое пришло от пресета, а не от исходного ClientHello.
	if bytes.Contains(fake.Payload, []byte("DISCORD")) {
		t.Fatal("фейк несёт байты настоящего ClientHello — пресет не применился")
	}
	// Вторая ветвь — реальные данные, без правок.
	if plan.Ops[1].Kind != OpSendReal {
		t.Fatalf("вторая операция = %s, ожидался send_real", plan.Ops[1].Kind)
	}
}

// TestBuildPlanStreamOffset фиксирует положение каждой операции в потоке. Это
// опора пакетного исполнителя: номер последовательности TCP считается по
// StreamOffset, а не по порядку отправки, иначе дубль и обратный порядок дали
// бы сегменту чужой номер.
func TestBuildPlanStreamOffset(t *testing.T) {
	// Разрез вперёд: части на позициях 0 и cut.
	fwd, err := BuildPlan(
		clientHelloRule(fragment(strategy.FragmentParams{Proto: strategy.FragTCP, Offset: 3, Order: strategy.FragForward}, send(), send())),
		outboundHello("0123456789"))
	if err != nil {
		t.Fatal(err)
	}
	if fwd.Ops[0].StreamOffset != 0 || fwd.Ops[1].StreamOffset != 3 {
		t.Fatalf("вперёд: смещения %d,%d, ожидались 0,3", fwd.Ops[0].StreamOffset, fwd.Ops[1].StreamOffset)
	}

	// Разрез назад: порядок отправки обратный, но смещения привязаны к позиции —
	// первой уходит часть с позиции cut, второй — с позиции 0.
	rev, err := BuildPlan(
		clientHelloRule(fragment(strategy.FragmentParams{Proto: strategy.FragTCP, Offset: 3, Order: strategy.FragReverse}, send(), send())),
		outboundHello("0123456789"))
	if err != nil {
		t.Fatal(err)
	}
	if rev.Ops[0].StreamOffset != 3 || rev.Ops[1].StreamOffset != 0 {
		t.Fatalf("назад: смещения %d,%d, ожидались 3,0", rev.Ops[0].StreamOffset, rev.Ops[1].StreamOffset)
	}

	// Дубль с фейком: обе копии на позиции 0.
	ttl := strategy.TamperParams{Field: strategy.FieldIPv4TTL, Mode: strategy.TamperReplace, Value: 3}
	d, err := BuildPlan(clientHelloRule(duplicate(tamper(ttl, send()), send())), outboundHello("ABCD"))
	if err != nil {
		t.Fatal(err)
	}
	if d.Ops[0].StreamOffset != 0 || d.Ops[1].StreamOffset != 0 {
		t.Fatalf("дубль: смещения %d,%d, ожидались 0,0", d.Ops[0].StreamOffset, d.Ops[1].StreamOffset)
	}
}

// TestBuildPlanDeterministic фиксирует детерминизм: один и тот же вход всегда
// даёт один и тот же план. На этом стоят золотые тесты и воспроизведение.
func TestBuildPlanDeterministic(t *testing.T) {
	s := clientHelloRule(duplicate(
		tamper(strategy.TamperParams{Field: strategy.FieldIPv4TTL, Mode: strategy.TamperReplace, Value: 5}, send()),
		fragment(strategy.FragmentParams{Proto: strategy.FragTCP, Offset: 2}, send(), send()),
	))
	in := outboundHello("ABCDEF")

	first, err := BuildPlan(s, in)
	if err != nil {
		t.Fatal(err)
	}
	for range 50 {
		got, err := BuildPlan(s, in)
		if err != nil {
			t.Fatal(err)
		}
		if dumpPlan(got) != dumpPlan(first) {
			t.Fatal("план недетерминирован")
		}
	}
}

// TestFragmentPreservesStream — свойство: для стратегии, которая только режет и
// шлёт (без drop, tamper и обратного порядка), склейка реальных отправок по
// порядку восстанавливает исходную нагрузку. Проверяется на всех смещениях.
func TestFragmentPreservesStream(t *testing.T) {
	payload := "the quick brown fox"
	for off := 1; off < len(payload); off++ {
		s := clientHelloRule(fragment(
			strategy.FragmentParams{Proto: strategy.FragTCP, Offset: off, Order: strategy.FragForward},
			send(), send(),
		))
		plan, err := BuildPlan(s, outboundHello(payload))
		if err != nil {
			t.Fatal(err)
		}
		var joined []byte
		for _, op := range plan.Ops {
			if op.Kind != OpSendReal {
				t.Fatalf("смещение %d: неожиданная операция %s", off, op.Kind)
			}
			joined = append(joined, op.Payload...)
		}
		if string(joined) != payload {
			t.Fatalf("смещение %d: склейка %q != %q", off, joined, payload)
		}
	}
}

// TestFragmentOffsetBeyondPayload — смещение больше длины нагрузки зажимается:
// первая часть забирает всё, вторая пуста и не порождает пустую отправку.
func TestFragmentOffsetBeyondPayload(t *testing.T) {
	s := clientHelloRule(fragment(
		strategy.FragmentParams{Proto: strategy.FragTCP, Offset: 1000, Order: strategy.FragForward},
		send(), send(),
	))
	plan, err := BuildPlan(s, outboundHello("short"))
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Ops) != 1 || string(plan.Ops[0].Payload) != "short" {
		t.Fatalf("ожидалась одна операция со всей нагрузкой, получено %s", dumpPlan(plan))
	}
}

// TestDuplicateIndependentEdits проверяет, что правки одной ветви дубликата не
// протекают в другую: иначе фейк «заразил» бы реальные данные правкой TTL.
func TestDuplicateIndependentEdits(t *testing.T) {
	s := clientHelloRule(duplicate(
		tamper(strategy.TamperParams{Field: strategy.FieldIPv4TTL, Mode: strategy.TamperReplace, Value: 2}, send()),
		send(),
	))
	plan, err := BuildPlan(s, outboundHello("DATA"))
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Ops) != 2 {
		t.Fatalf("ожидалось 2 операции, получено %d", len(plan.Ops))
	}
	if plan.Ops[1].Kind != OpSendReal || len(plan.Ops[1].Edits) != 0 {
		t.Fatalf("вторая ветвь не должна нести правок: %s", dumpPlan(plan))
	}
}

func TestBuildPlanNilStrategy(t *testing.T) {
	if _, err := BuildPlan(nil, outboundHello("x")); err == nil {
		t.Fatal("ожидалась ошибка на nil-стратегии")
	}
}

func TestBuildPlanDropAll(t *testing.T) {
	// Правило сработало и всё отбросило: план пуст (не сквозной пропуск).
	plan, err := BuildPlan(clientHelloRule(drop()), outboundHello("DATA"))
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Ops) != 0 {
		t.Fatalf("ожидался пустой план, получено %s", dumpPlan(plan))
	}
}

func md5sig(child *strategy.Action) *strategy.Action {
	return &strategy.Action{Kind: core.ActionMD5Sig, Left: child}
}

// TestBuildPlanMD5SigUnderDuplicate — md5sig под Duplicate: одна ветвь шлёт
// фейк с меткой вставки MD5-опции, другая — настоящие данные. План обязан
// нести ровно это: OpSendFake с InsertMD5Sig + OpSendReal, обе на одной позиции
// потока (decoy поверх настоящих данных).
func TestBuildPlanMD5SigUnderDuplicate(t *testing.T) {
	s := clientHelloRule(duplicate(md5sig(send()), send()))
	plan, err := BuildPlan(s, outboundHello("\x16\x03\x01hello"))
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if len(plan.Ops) != 2 {
		t.Fatalf("ожидалось 2 операции, получено %d", len(plan.Ops))
	}
	fake := plan.Ops[0]
	if fake.Kind != OpSendFake || !fake.InsertMD5Sig {
		t.Errorf("op0: вид %s InsertMD5Sig=%v, ожидался send_fake+true", fake.Kind, fake.InsertMD5Sig)
	}
	realOp := plan.Ops[1]
	if realOp.Kind != OpSendReal || realOp.InsertMD5Sig {
		t.Errorf("op1: вид %s InsertMD5Sig=%v, ожидался send_real+false", realOp.Kind, realOp.InsertMD5Sig)
	}
	if !bytes.Equal(fake.Payload, []byte("\x16\x03\x01hello")) {
		t.Errorf("нагрузка фейка %q, ожидалась исходная", fake.Payload)
	}
	if fake.StreamOffset != realOp.StreamOffset {
		t.Errorf("смещения различны: fake=%d real=%d", fake.StreamOffset, realOp.StreamOffset)
	}
}

// TestBuildPlanMD5SigStacksWithTamper — md5sig компонуется: md5sig → tamper(ttl)
// → send даёт один фейк и с меткой MD5, и с правкой TTL.
func TestBuildPlanMD5SigStacksWithTamper(t *testing.T) {
	tree := md5sig(tamper(strategy.TamperParams{Field: strategy.FieldIPv4TTL, Mode: strategy.TamperReplace, Value: 3}, send()))
	plan, err := BuildPlan(clientHelloRule(tree), outboundHello("\x16\x03\x01data"))
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if len(plan.Ops) != 1 {
		t.Fatalf("ожидалась 1 операция, получено %d", len(plan.Ops))
	}
	op := plan.Ops[0]
	if op.Kind != OpSendFake || !op.InsertMD5Sig || len(op.Edits) != 1 {
		t.Errorf("op: вид %s InsertMD5Sig=%v edits=%d, ожидался фейк с MD5 и правкой TTL",
			op.Kind, op.InsertMD5Sig, len(op.Edits))
	}
}

func ipv6ext(child *strategy.Action) *strategy.Action {
	return &strategy.Action{Kind: core.ActionIPv6Ext, Left: child}
}

// TestBuildPlanIPv6Ext — ipv6_ext помечает фейк флагом вставки Hop-by-Hop.
func TestBuildPlanIPv6Ext(t *testing.T) {
	plan, err := BuildPlan(clientHelloRule(ipv6ext(send())), outboundHello("\x16\x03\x01data"))
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if len(plan.Ops) != 1 {
		t.Fatalf("ожидалась 1 операция, получено %d", len(plan.Ops))
	}
	op := plan.Ops[0]
	if op.Kind != OpSendFake || !op.InsertIPv6HopByHop {
		t.Errorf("op: вид %s InsertIPv6HopByHop=%v, ожидался фейк с Hop-by-Hop", op.Kind, op.InsertIPv6HopByHop)
	}
}
