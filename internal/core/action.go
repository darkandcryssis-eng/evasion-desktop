package core

import "fmt"

// ActionKind — вид узла двоичного дерева действий стратегии.
//
// Дерево двоичное потому, что скрещивание стратегий (генетический поиск) — это
// обмен поддеревьями, и на двоичном дереве он выражается в несколько строк
// (обоснование в задании, 4.3). Виды делятся на терминальные листья (Send,
// Drop) и внутренние узлы-преобразователи (Tamper, Fragment, Duplicate).
//
// Арность (число дочерних ветвей) жёстко связана с видом и проверяется
// валидацией:
//
//	Send, Drop        — листья, ветвей нет;
//	Tamper            — одна ветвь (Left), Right всегда nil;
//	Duplicate, Fragment — две ветви.
type ActionKind uint8

const (
	// ActionSend — лист: отправить результат преобразований в сеть.
	// Это терминальная операция дерева, а не отдельный примитив обхода.
	ActionSend ActionKind = iota
	// ActionDrop — лист: уничтожить пакет, ничего не отправлять.
	ActionDrop
	// ActionDuplicate — внутренний узел: отдать копию пакета в обе ветви.
	ActionDuplicate
	// ActionTamper — внутренний узел: изменить поле заголовка или тело и
	// передать результат в единственную ветвь (Left).
	ActionTamper
	// ActionFragment — внутренний узел: разрезать пакет; первая часть идёт в
	// Left, вторая — в Right.
	ActionFragment
	// ActionTCPOverlap — лист: отправка настоящей нагрузки под прикрытием
	// предварительного cover-пакета, перекрытого по TCP sequence number.
	//
	// Механика:
	//
	//  1. Шлётся cover-пакет: заранее подготовленный безобидный ClientHello
	//     размером M, с TCP seq = baseSeq + L - M, где L — длина настоящей
	//     нагрузки события.
	//  2. Шлётся настоящая нагрузка размером L c TCP seq = baseSeq.
	//
	// Сервер TCP (RFC 1122) собирает перекрывающиеся сегменты по правилу
	// «последний пришедший перезаписывает»: байты [SN+L-M..SN+L] берутся из
	// пакета (2), байты [SN..SN+L-M] — тоже из (2) (там нет перекрытия).
	// Итого сервер получает ОРИГИНАЛЬНЫЙ ClientHello целиком, рукопожатие
	// проходит.
	//
	// DPI делает собственный reassembly без знания TCP state и опирается на
	// порядок прибытия: видит cover-пакет первым, парсит его как начало
	// соединения, классифицирует поток по безобидному SNI внутри cover'а —
	// пропускает. Второй пакет уже не разбирает (решение по соединению
	// принято). Настоящий SNI остаётся невидимым для DPI.
	//
	// Применяется там, где SNI блокируется ПО ИМЕНИ на TLS-уровне, и никакая
	// обфускация TCP-фрагментации или фейковых заголовков не помогает:
	// обычный `fragment` оставляет SNI читаемым в reassemble'нной склейке,
	// `fake-badseq` без overlap'а не маскирует настоящий ClientHello (DPI
	// видит его как второй пакет и парсит).
	//
	// Листом считается потому, что имеет только параметр `preset` (имя
	// cover-шаблона) и не несёт поддеревьев: вся механика — внутри двух
	// пакетов, без вложенных примитивов.
	ActionTCPOverlap

	// ActionMD5Sig — внутренний узел (одна ветвь Left): пометить сегмент
	// фейком, несущим опцию TCP MD5 Signature (RFC 2385, вид 19) с заведомо
	// неверной подписью, и передать результат в ветвь.
	//
	// Зачем. Многие DPI не валидируют MD5-подпись и пропускают сегмент как
	// обычные данные; хост же, если соединение не настроено на MD5 (а оно не
	// настроено), сегмент с неожиданной MD5-опцией обязан отбросить (RFC 2385).
	// Итог тот же, что у прочих фейков: DPI сегмент учитывает в своей модели
	// соединения, сервер — отбрасывает. В отличие от правок полей заголовка
	// (Tamper), приём РАСШИРЯЕТ заголовок TCP (вставляет опцию и двигает
	// смещение данных), поэтому вынесен отдельным видом, а не режимом Tamper.
	//
	// Арность 1 (как Tamper): пометка «вставить MD5-опцию» и спуск в
	// единственную ветвь. Обычно под Duplicate: одна ветвь шлёт настоящие
	// данные, другая — md5sig-фейк на той же позиции потока. Параметров нет:
	// содержимое опции (неверная подпись) детерминировано исполнителем.
	// Требует CapMD5Sig — только у пакетного исполнителя (вставка опции и
	// правка data offset требуют контроля над пакетом).
	ActionMD5Sig

	// ActionIPv6Ext — внутренний узел (одна ветвь Left): пометить сегмент
	// фейком, в который вставлен заголовок расширения IPv6 Hop-by-Hop, и
	// передать результат в ветвь.
	//
	// Зачем. Заголовки расширения IPv6 обрабатываются по-разному: хост их
	// проходит штатно, а упрощённый DPI, разбирающий только фиксированные 40
	// байт, за цепочкой расширений может не добраться до TCP/SNI или разобрать
	// её иначе — лишний способ рассогласовать разбор DPI и сервера. Приём
	// добавляет минимальный Hop-by-Hop (8 байт, PadN) перед протоколом верхнего
	// уровня. Применим только к пакетам IPv6; на IPv4 исполнитель вернёт ошибку
	// недоступности (как правка IPv6-поля на IPv4), и движок пропустит сырьём.
	//
	// Арность 1 (как Tamper/MD5Sig): пометка и спуск в ветвь. Параметров нет.
	// Требует CapIPv6ExtHeader — только у пакетного исполнителя.
	ActionIPv6Ext
)

// Строковые метки видов действий для текстовой сериализации.
const (
	actionSendText       = "send"
	actionDropText       = "drop"
	actionDuplicateText  = "duplicate"
	actionTamperText     = "tamper"
	actionFragmentText   = "fragment"
	actionTCPOverlapText = "tcp_overlap"
	actionMD5SigText     = "md5sig"
	actionIPv6ExtText    = "ipv6_ext"
)

// IsLeaf сообщает, является ли вид терминальным листом (Send, Drop, TCPOverlap).
// Листья не имеют дочерних ветвей; это используют и валидация, и обход дерева.
func (k ActionKind) IsLeaf() bool {
	return k == ActionSend || k == ActionDrop || k == ActionTCPOverlap
}

// Arity возвращает число обязательных дочерних ветвей для вида узла.
// Второе возвращаемое значение — признак того, что вид вообще известен.
func (k ActionKind) Arity() (n int, ok bool) {
	switch k {
	case ActionSend, ActionDrop, ActionTCPOverlap:
		return 0, true
	case ActionTamper, ActionMD5Sig, ActionIPv6Ext:
		return 1, true
	case ActionDuplicate, ActionFragment:
		return 2, true
	default:
		return 0, false
	}
}

// String возвращает человекочитаемую метку вида действия.
func (k ActionKind) String() string {
	switch k {
	case ActionSend:
		return actionSendText
	case ActionDrop:
		return actionDropText
	case ActionDuplicate:
		return actionDuplicateText
	case ActionTamper:
		return actionTamperText
	case ActionFragment:
		return actionFragmentText
	case ActionTCPOverlap:
		return actionTCPOverlapText
	case ActionMD5Sig:
		return actionMD5SigText
	case ActionIPv6Ext:
		return actionIPv6ExtText
	default:
		return fmt.Sprintf("ActionKind(%d)", uint8(k))
	}
}

// MarshalText сериализует вид действия как строковый токен.
func (k ActionKind) MarshalText() ([]byte, error) {
	if _, ok := k.Arity(); !ok {
		return nil, fmt.Errorf("core: недопустимый вид действия %d", uint8(k))
	}
	return []byte(k.String()), nil
}

// UnmarshalText разбирает строковый токен вида действия. Неизвестный токен —
// ошибка: внешнее описание стратегии недоверенно.
func (k *ActionKind) UnmarshalText(text []byte) error {
	switch string(text) {
	case actionSendText:
		*k = ActionSend
	case actionDropText:
		*k = ActionDrop
	case actionDuplicateText:
		*k = ActionDuplicate
	case actionTamperText:
		*k = ActionTamper
	case actionFragmentText:
		*k = ActionFragment
	case actionTCPOverlapText:
		*k = ActionTCPOverlap
	case actionMD5SigText:
		*k = ActionMD5Sig
	case actionIPv6ExtText:
		*k = ActionIPv6Ext
	default:
		return fmt.Errorf("core: неизвестный вид действия %q", string(text))
	}
	return nil
}
