package core

// Status — положение стратегии в жизненном цикле портфеля (4.5).
//
// Состояние принадлежит СТРАТЕГИИ, а не соединению: соединение живёт секунды и
// устареть не может, у него есть лишь ссылка на применённую стратегию, фаза и
// исход. И не оценке: оценка — свойство четвёрки «стратегия × цель × точка
// наблюдения × время» (6.1), а статус у стратегии ровно один.
//
// Из этого следует неочевидное: статус и вердикт — разные вещи. Стратегия
// может быть active, имея отрицательный вердикт по одной из целей; статус
// говорит, до какой ступени допуска она дошла вообще, вердикт — работает ли
// она у конкретной цели в конкретной сети. Плоское поле «работает» начало бы
// врать при появлении второй цели или второй сети, поэтому вердикт живёт в
// оценках (scoring), а здесь только ступень.
type Status uint8

const (
	// StatusUnset — статус не задан. Нулевое значение намеренно непригодно:
	// стратегия без статуса — это дефект портфеля, а не «новая стратегия».
	// Новая называется StatusCandidate явно.
	StatusUnset Status = iota
	// StatusCandidate — порождена генератором, не проверена. Допускается
	// только к соединениям, которые инициирует сам движок (5.1).
	StatusCandidate
	// StatusTesting — проверяется на доле реальных соединений (5.1).
	StatusTesting
	// StatusActive — применяется полностью.
	StatusActive
	// StatusBenched — в портфеле, но есть лучше. Не применяется, оценка
	// продолжает затухать (5.1).
	StatusBenched
	// StatusDegraded — работала и перестала.
	StatusDegraded
	// StatusRetired — выведена, не применять.
	StatusRetired
)

// statusTokens — машинно-читаемые имена статусов. Текст, а не числа: статусы
// попадают в архив и в вывод --json, а привязка к текущему порядку констант
// молча испортила бы историю при их перестановке (то же решение, что в store).
var statusTokens = []struct {
	status Status
	text   string
}{
	{StatusUnset, "unset"},
	{StatusCandidate, "candidate"},
	{StatusTesting, "testing"},
	{StatusActive, "active"},
	{StatusBenched, "benched"},
	{StatusDegraded, "degraded"},
	{StatusRetired, "retired"},
}

// Valid сообщает, что статус задан. StatusUnset годным не считается.
func (s Status) Valid() bool { return s >= StatusCandidate && s <= StatusRetired }

// String возвращает машинно-читаемое имя статуса.
func (s Status) String() string {
	for _, t := range statusTokens {
		if t.status == s {
			return t.text
		}
	}
	return "unset"
}

// MarshalText сериализует статус текстом.
func (s Status) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// UnmarshalText разбирает статус из текста. Неизвестное имя — ошибка, а не
// молчаливый StatusUnset: архив с незнакомым статусом надо читать осознанно, а
// не превращать в «статуса нет».
func (s *Status) UnmarshalText(text []byte) error {
	for _, t := range statusTokens {
		if t.text == string(text) {
			*s = t.status
			return nil
		}
	}
	return &UnknownTokenError{Kind: "status", Token: string(text)}
}

// Statuses возвращает все заданные статусы в порядке жизненного цикла.
// StatusUnset в список не входит: это не ступень, а отсутствие ступени.
func Statuses() []Status {
	out := make([]Status, 0, len(statusTokens)-1)
	for _, t := range statusTokens {
		if t.status != StatusUnset {
			out = append(out, t.status)
		}
	}
	return out
}

// ServesLiveTraffic сообщает, допускается ли стратегия к пользовательским
// соединениям хоть в какой-то доле (5.1).
//
// Истинно для StatusTesting (доля соединений) и StatusActive (полностью).
// StatusCandidate ложен: кандидат допускается только к соединениям, которые
// движок инициирует сам, и путать это с долей реального трафика нельзя —
// именно на этом различии держится запрет генетического поиска на живом
// трафике (1.4 п. 6).
func (s Status) ServesLiveTraffic() bool {
	return s == StatusTesting || s == StatusActive
}

// ServesAllTraffic сообщает, применяется ли стратегия ко всем соединениям
// своей цели. Истинно только для StatusActive.
func (s Status) ServesAllTraffic() bool { return s == StatusActive }
