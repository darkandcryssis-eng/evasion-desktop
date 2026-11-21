package policy

import (
	"bytes"
	"errors"
	"fmt"
	"sort"

	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/proxy"
	"github.com/fitting-1c/evasion/internal/strategy"
)

// errNoVantage и errZeroRev — ошибки построения снимка.
var (
	errNoVantage         = errors.New("policy: снимок без точки наблюдения")
	errZeroRev           = errors.New("policy: номер снимка должен быть больше нуля")
	errTrialInconsistent = errors.New("несогласованная ступень проверки")
	errTrialSameAsMain   = errors.New("проверяемая стратегия совпадает с действующей: делить трафик между ними нечем")
)

// Entry — одна запись горячей таблицы: какому домену что применять.
//
// Domain задаёт радиус по суффиксу: запись покрывает сам домен и все его
// поддомены. Strategy == nil — не пропуск записи, а осознанное исключение:
// «к этому имени не применять ничего». Исключение перекрывает более общую
// запись, потому что обход идёт от точного имени к общему. Так из
// "youtube.com" со стратегией и "api.youtube.com" без неё получается радиус с
// вырезанной серединой.
//
// Trial и TrialPermille выражают ступенчатое допущение к трафику (5.1):
// проверяемая стратегия получает заданную долю соединений, остальные идут по
// действующей. Пустой Trial означает, что на этой цели ничего не проверяется.
type Entry struct {
	// Domain — имя или суффикс имени, к которому относится запись.
	Domain string
	// Strategy — действующая стратегия (статус active); nil — исключение.
	Strategy *strategy.Strategy
	// Trial — проверяемая стратегия (статус testing); nil — проверки нет.
	//
	// Допустима и при пустой Strategy: это обычное состояние цели, на которой
	// рабочей стратегии ещё нет, а кандидат уже проверяется. Тогда доля
	// соединений идёт под кандидата, а остальные — прозрачным пропуском.
	Trial *strategy.Strategy
	// TrialPermille — доля соединений под Trial, в промилле (50 = 5%).
	//
	// Величина приходит из конфигурации (5.7) и здесь только переносится:
	// policy не решает, какой доле трафика рисковать, — это решение контура
	// управления и владельца.
	TrialPermille int
}

// Snapshot — неизменяемый снимок таблицы решений.
//
// Создаётся целиком и после создания не меняется: у снимка нет ни одного
// метода, который бы его правил. Поэтому его можно читать из любого числа
// горутин без блокировок — это и есть условие бюджета в 10 мкс (4.2,
// правило 1). Новое решение выражается новым снимком, а не правкой текущего
// (см. Table.Install).
type Snapshot struct {
	// vantage — точка наблюдения, для которой снимок построен. Снимок к ней
	// привязан: при переезде в другую сеть (vantage.NetworkChanged) прежние
	// оценки неприменимы, и control обязан построить снимок заново. Само
	// сопоставление точку наблюдения не читает — она здесь для учёта и
	// проверки, что живёт именно тот снимок, которого ждали.
	vantage core.VantageID
	// rev — номер снимка, сквозной у control. Нужен журналу и команде status,
	// чтобы отличать снимки друг от друга: в логах иначе не понять, по какому
	// снимку принято решение. Нумерация начинается с единицы, ноль означает
	// «снимка нет» (Table.Rev у пустой таблицы).
	rev uint64
	// byName — нормализованное имя -> запись. Карта, а не срез: сопоставление
	// идёт обходом суффиксов имени соединения, а не перебором записей, поэтому
	// стоимость решения не зависит от размера таблицы.
	byName map[string]record
}

// NewSnapshot строит снимок из записей.
//
// Вся дорогая работа сосредоточена здесь: нормализация имён, проверка записей,
// вычисление идентификаторов стратегий. Горячий путь после этого только читает.
//
// Идентификатор считается из самой стратегии (strategy.ComputeID), а не
// берётся у вызывающего: телеметрия связывает исход соединения с применённой
// стратегией по этому идентификатору, и разойтись он не имеет права. Для
// одного и того же указателя стратегии хеш считается один раз — записей с
// общей стратегией в радиусе обычно много.
//
// Повторный домен — ошибка, а не «победит последний»: два решения для одного
// имени означают ошибку в control, и тихий выбор одного из них спрятал бы её.
func NewSnapshot(vantage core.VantageID, rev uint64, entries []Entry) (*Snapshot, error) {
	if vantage == "" {
		return nil, errNoVantage
	}
	if rev == 0 {
		return nil, errZeroRev
	}

	byName := make(map[string]record, len(entries))
	ids := make(map[*strategy.Strategy]core.StrategyID, len(entries))

	// selectionFor вычисляет выбор для одной ступени. Идентификатор считается
	// один раз на указатель: записей с общей стратегией в радиусе обычно много.
	selectionFor := func(s *strategy.Strategy, trial bool) (proxy.Selection, error) {
		if s == nil {
			return proxy.Selection{}, nil
		}
		id, ok := ids[s]
		if !ok {
			var err error
			if id, err = strategy.ComputeID(s); err != nil {
				return proxy.Selection{}, err
			}
			ids[s] = id
		}
		return proxy.Selection{Strategy: s, ID: id, Trial: trial}, nil
	}

	for i, e := range entries {
		name, err := canonicalDomain(e.Domain)
		if err != nil {
			return nil, fmt.Errorf("policy: запись %d (%q): %w", i, e.Domain, err)
		}
		if _, dup := byName[name]; dup {
			return nil, fmt.Errorf("policy: запись %d: домен %q встречается дважды", i, name)
		}
		if err := validateTrial(e); err != nil {
			return nil, fmt.Errorf("policy: запись %d (%q): %w", i, name, err)
		}

		main, err := selectionFor(e.Strategy, false)
		if err != nil {
			return nil, fmt.Errorf("policy: запись %d (%q): идентификатор стратегии: %w", i, name, err)
		}
		trial, err := selectionFor(e.Trial, true)
		if err != nil {
			return nil, fmt.Errorf("policy: запись %d (%q): идентификатор проверяемой стратегии: %w", i, name, err)
		}
		if trial.Strategy != nil && trial.ID == main.ID {
			return nil, fmt.Errorf("policy: запись %d (%q): %w", i, name, errTrialSameAsMain)
		}

		byName[name] = record{target: name, main: main, trial: trial, permille: uint32(e.TrialPermille)}
	}

	return &Snapshot{vantage: vantage, rev: rev, byName: byName}, nil
}

// validateTrial проверяет согласованность ступени проверки.
//
// Оба несогласованных случая — молча бездействующая настройка, а такие в этом
// проекте запрещены: доля без стратегии ничего не проверяет, стратегия без
// доли не получает ни одного соединения. И то и другое выглядело бы как
// настроенная проверка.
func validateTrial(e Entry) error {
	switch {
	case e.Trial == nil && e.TrialPermille != 0:
		return fmt.Errorf("%w: доля %d промилле задана без проверяемой стратегии",
			errTrialInconsistent, e.TrialPermille)
	case e.Trial != nil && e.TrialPermille <= 0:
		return fmt.Errorf("%w: проверяемая стратегия задана с долей %d промилле — она не получит ни одного соединения",
			errTrialInconsistent, e.TrialPermille)
	case e.TrialPermille > permilleScale:
		return fmt.Errorf("%w: доля %d промилле больше 1000", errTrialInconsistent, e.TrialPermille)
	}
	return nil
}

// Lookup находит решение для соединения с данными именами.
//
// Второй результат — было ли попадание в таблицу, и он не выводится из
// первого: запись-исключение даёт пустой выбор при попадании. Различать их
// обязательно, иначе «записи нет» и «запись велит не вмешиваться» слились бы
// в одно значение, и журнал не смог бы объяснить, почему стратегия не
// применилась.
//
// Порядок проверки — сначала SNI, затем host: DPI судит по имени из
// ClientHello, поэтому и стратегия выбирается по нему. Для не-TLS соединений
// SNI пуст, и остаётся host.
func (s *Snapshot) Lookup(host, sni string) (proxy.Selection, bool) {
	// Нулевой снимок и пустой снимок ведут себя одинаково: не совпадают ни с
	// чем. Пустой радиус — это «не применять ничего», а не «применять ко
	// всему» (так же у config.DomainSet.Empty).
	if s == nil || len(s.byName) == 0 {
		return proxy.Selection{}, false
	}
	rec, ok := s.match(sni)
	if !ok {
		if rec, ok = s.match(host); !ok {
			return proxy.Selection{}, false
		}
	}
	// Жребий бросается после того, как запись найдена: ступень допуска — это
	// свойство записи, а не имени.
	return rec.pick(), true
}

// match сопоставляет одно имя с таблицей, обходя его суффиксы по границам
// меток — от полного имени к корню. Первое попадание и есть ответ, поэтому
// более точная запись выигрывает у более общей.
//
// Аллокаций не делает: имя приводится к канонической форме в массив на стеке,
// а поиск в карте идёт выражением m[string(folded)], которое компилятор
// выполняет без копии ключа.
//
// Проверки «а не адрес ли это» здесь нет намеренно, хотя по IP сопоставление
// и не делается. Она была бы невыполнимой работой на горячем пути: запись,
// похожая на адрес, в снимок не попадает (canonicalDomain её отвергает), а
// всякий суффикс IPv4 состоит из одних цифр и точек, а IPv6 содержит
// двоеточие — то есть совпасть с записью не может ни один из них. Запрет
// держится там, где он проверяется один раз при построении, а не миллион раз
// при чтении. Проверка здесь проходила бы при любой поломке, то есть была бы
// украшением (это и показала мутация: тест на адреса не падал без неё).
func (s *Snapshot) match(name string) (record, bool) {
	if name == "" {
		return record{}, false
	}
	var buf [maxNameLen]byte
	n, ok := foldName(buf[:], name)
	if !ok {
		return record{}, false
	}
	folded := buf[:n]
	for {
		if rec, hit := s.byName[string(folded)]; hit {
			return rec, true
		}
		i := bytes.IndexByte(folded, '.')
		if i < 0 {
			return record{}, false
		}
		folded = folded[i+1:]
	}
}

// VantageID возвращает точку наблюдения, для которой построен снимок.
func (s *Snapshot) VantageID() core.VantageID {
	if s == nil {
		return ""
	}
	return s.vantage
}

// Rev возвращает номер снимка; 0 — снимка нет.
func (s *Snapshot) Rev() uint64 {
	if s == nil {
		return 0
	}
	return s.rev
}

// Len возвращает число записей в снимке.
func (s *Snapshot) Len() int {
	if s == nil {
		return 0
	}
	return len(s.byName)
}

// RecordInfo — содержимое записи снимка в машинно-читаемом виде.
//
// Нужен команде status и доктору: это данные, а не представление (2.2) —
// идентификаторы и доля числом, без готовых подписей.
type RecordInfo struct {
	// Domain — имя или суффикс записи.
	Domain string `json:"domain"`
	// Active — действующая стратегия; пусто означает прозрачный пропуск.
	Active core.StrategyID `json:"active"`
	// Trial — проверяемая стратегия; пусто означает, что проверки нет.
	Trial core.StrategyID `json:"trial"`
	// TrialPermille — доля соединений под Trial, в промилле.
	TrialPermille int `json:"trial_permille"`
}

// Records возвращает содержимое снимка, отсортированное по имени. Порядок
// задан явно: обход карты в Go случаен, а вывод команды обязан быть
// воспроизводимым.
func (s *Snapshot) Records() []RecordInfo {
	if s == nil {
		return nil
	}
	out := make([]RecordInfo, 0, len(s.byName))
	for name, rec := range s.byName {
		out = append(out, RecordInfo{
			Domain:        name,
			Active:        rec.main.ID,
			Trial:         rec.trial.ID,
			TrialPermille: int(rec.permille),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return out
}

// Domains возвращает отсортированные имена записей — для status/doctor и
// тестов. Порядок задан явно: обход карты в Go случаен, а вывод команды
// обязан быть воспроизводимым.
func (s *Snapshot) Domains() []string {
	if s == nil {
		return nil
	}
	out := make([]string, 0, len(s.byName))
	for name := range s.byName {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
