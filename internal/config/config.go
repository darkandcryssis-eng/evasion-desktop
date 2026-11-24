package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/fitting-1c/evasion/internal/strategy"
	"github.com/fitting-1c/evasion/internal/vantage"
)

// Значения по умолчанию. Это единственное место, где они заданы (10.1): всё,
// что задание называет «по умолчанию», принадлежит конфигу, а не коду
// потребителей.
const (
	// DefaultListen — адрес прослушивания SOCKS5-прокси по умолчанию. Только
	// петля: прокси локальный и наружу не слушает.
	DefaultListen = "127.0.0.1:1080"

	// maxConfigBytes — верхний предел размера файла конфига. Конфиг —
	// недоверенный ввод (10.2); без предела битый или враждебный файл заставил
	// бы читать произвольный объём в память. Реальные конфиги — килобайты.
	maxConfigBytes = 1 << 20
)

// Config — разобранный и проверенный конфиг движка.
//
// Поля соответствуют разделам JSON-файла. Состав намеренно скромен: раздел
// появляется, когда у него есть потребитель (сейчас — режим прокси M3b).
type Config struct {
	YouTubeQUICMode *QUICMode
	// Listen — адрес прослушивания SOCKS5-прокси (host:port).
	Listen string
	// Observe — режим наблюдения: стратегии не применяются (1.6).
	Observe bool
	// BlockQUIC — блокировать QUIC к отслеживаемым группам в режиме перехвата,
	// чтобы приложение откатилось на TCP, где работает десинк (3.3). По
	// умолчанию включено: без этого цель вроде YouTube «не лечится» по
	// непонятной причине — она просто ушла в QUIC мимо TCP-десинка. Блокируется
	// ТОЛЬКО трафик отслеживаемых групп, не весь UDP/443; при выходе снимается
	// полностью (дескриптор закрывается). Выключается block_quic: false.
	//
	// Устаревающий псевдоним QUICMode: block_quic true ≡ quic_mode "block",
	// false ≡ "off". Канонично — QUICMode; поле оставлено для совместимости.
	BlockQUIC bool
	// QUICMode — как поступать с QUIC к отслеживаемым группам (3.3): block
	// (ронять, откат на TCP), desync (переписывать Initial, не роняя), off (не
	// трогать). По умолчанию block.
	QUICMode QUICMode
	// Groups — группы доменов: имя группы → домены в ней. Задают радиус
	// поражения (1.6, 2.3): стратегия применяется только к соединениям,
	// попадающим в выбранные группы.
	Groups map[string][]string
	// Radius задаёт режим применения резервной стратегии в intercept.
	Radius RadiusConfig
	// Strategy — стратегия по умолчанию режима прокси (этап 0, до появления
	// policy на M6). nil допустимо: тогда прокси работает прозрачно.
	//
	// Применяется ко всем группам радиуса, у которых нет собственной записи в
	// Strategies. Служит общим «запасным» для групп без явного переопределения.
	Strategy *strategy.Strategy

	// Strategies — стратегии по группам: имя группы → стратегия.
	//
	// Действует на пути закреплённого перехвата (evasion run --mode intercept
	// без --auto). Автопилот v2 (--auto) эту карту пока не читает: там
	// стратегии назначаются по целям контуром управления, а не статическим
	// переопределением; добавление поддержки — отдельная работа над
	// control.Portfolio/Pins.
	//
	// Нужны, когда одна и та же стратегия ломает один домен, но нужна другому.
	// У владельца это проявилось так: fake-badsum работает 5/5 для
	// `*.discord.media` (голос, Spectrum), но для discord.com на том же
	// hosts-fallback IP ломает TLS. Единственная глобальная стратегия
	// лечит одно — ломает другое; выбор по группам снимает конфликт.
	//
	// Семантика при выборе на горячем пути (см. proxy.MultiGroupProvider):
	//   1) сначала проверяется каждая группа из Strategies в стабильном
	//      порядке (имена отсортированы); первая, которой принадлежит host или
	//      SNI, выигрывает;
	//   2) если ни одна не совпала, применяется Strategy, но только внутри
	//      общего радиуса domainSet (groups ∩ --groups);
	//   3) иначе — прозрачный пропуск.
	//
	// Записи для групп вне --groups тихо игнорируются: радиус выбирается на
	// старте, а strategies — лишь способ разнести стратегии внутри него.
	// Запись для неизвестной группы (не из cfg.Groups) — ошибка валидации:
	// это опечатка, молчать нельзя (10.1).
	//
	// Пусто означает «без переопределений»: действует только Strategy, т.е.
	// старое поведение.
	Strategies map[string]*strategy.Strategy
	// StrategiesRotation — альтернативная форма Strategies: по имени группы
	// лежит СРЕЗ стратегий (ротация). Если группа есть и там и там, в
	// StrategiesRotation полный список, в Strategies — первый элемент
	// (для обратной совместимости со старыми потребителями).
	StrategiesRotation map[string][]*strategy.Strategy

	// Vantage — метка точки наблюдения: оператор, регион, тип доступа (6.2).
	//
	// Основной способ определения точки наблюдения — именно метка из конфига,
	// а не внешний запрос: определение точки наблюдения не должно само
	// становиться утечкой (6.2, 6.6). Отпечаток интерфейсов добавляется к ней
	// пакетом vantage и служит обнаружению смены сети.
	Vantage vantage.Label

	// Autopilot — числовые параметры автопилота (5.5, 5.7).
	Autopilot Autopilot
	// Parallelism — пределы параллельности прогонов (5.4).
	Parallelism Parallelism
	// Budgets — бюджеты горячего пути (8.1).
	Budgets Budgets
	// Retention — сроки хранения (6.4).
	Retention Retention

	// ProbeTargets — цели активных проб (10.1).
	ProbeTargets []string
	// ControlTargets — контрольные цели: то, что обязано работать всегда.
	//
	// По ним измеряется побочный вред (4.5): если контрольная цель начала
	// падать при применённой стратегии, причина в стратегии, и её надо
	// снимать, даже если основная цель при ней ожила. Признак обязан быть
	// измеренным, а не объявленным, — отсюда и список.
	ControlTargets []string

	// TransportFallback — hosts-подмена для доменов, которые провайдер режет
	// на IP-уровне (SYN до реального Cloudflare-диапазона Discord
	// `162.159.*` не доходит, но тот же Cloudflare на другом IP доступен).
	//
	// Переопределяет 1.3 в части маршрутизации (решение владельца): hosts-
	// подмена меняет destination IP пакета, но не меняет исходящий интерфейс
	// и не отправляет трафик на третий сервер — тот же путь, другой адресат
	// Cloudflare, SNI-routing у Cloudflare делает остальное. Это
	// промежуточный слой между DPI-десинком и настоящим VPN.
	//
	// По умолчанию выключен: правка системного hosts — операция, требующая
	// явного согласия. Включается enabled: true. При выключенном поле
	// остальные ничего не делают.
	TransportFallback TransportFallback
}

// TransportFallback — настройка hosts-подмены (транспортный слой-A, 1.3.1).
type TransportFallback struct {
	// Enabled — применять ли hosts-подмену. По умолчанию false, т.е. правки
	// системного hosts не происходит. Включается осознанно.
	Enabled bool
	// SafeIP — ОДИНОЧНЫЙ IP для всех Domains (устаревшая форма). Сохранён
	// ради обратной совместимости: конфиги вида {safe_ip, domains} по-прежнему
	// работают. Если задан, в парсере он сворачивается в единственную Entry
	// внутри Entries, остальной код работает только с Entries.
	//
	// Проблема одиночного IP: разные Cloudflare Spectrum endpoints не
	// обслуживают чужой SNI. 162.159.138.232 обслуживает gateway.discord.gg
	// и media.discordapp.net, но НЕ обслуживает cdn.discordapp.com — у
	// последнего IP пул с суффиксом .233 (а не .232). Поэтому новые
	// конфиги задают несколько Entries с разным safe_ip.
	SafeIP string
	// Domains — домены для SafeIP (устаревшая форма, см. SafeIP).
	Domains []string
	// Entries — несколько групп (IP, домены). Каждая Entry — свой IP для
	// своего набора доменов. Применяется, если задан; при пустом Entries
	// используется SafeIP+Domains (одна виртуальная Entry).
	//
	// Для Discord рабочее разделение: gateway.discord.gg +
	// media.discordapp.net идут на 162.159.138.232 (Spectrum с суффиксом
	// .232), cdn.discordapp.com идёт на 162.159.130.233 (Spectrum с
	// суффиксом .233 — именно этот пул отдаёт DNS для cdn.discordapp.com).
	Entries []TransportFallbackEntry
}

// TransportFallbackEntry — одна группа hosts-подмены: IP для набора доменов.
//
// Выделено отдельным типом, потому что разные домены требуют разных Cloudflare
// Spectrum endpoints (разные IP в блоке 162.159.128.0/22). Один IP не серверит
// чужой SNI — тот Cloudflare, что отвечает на 162.159.138.232 для gateway,
// отказывается обслуживать cdn.discordapp.com, которому нужен .233 суффикс.
type TransportFallbackEntry struct {
	// SafeIP — IP, не блокированный провайдером и обслуживающий SNI
	// доменов из Domains. Проверяется как IPv4/IPv6 текст; не резолвится.
	SafeIP string
	// SafeIPs — дополнительные кандидаты после SafeIP.
	SafeIPs []string
	// Domains — домены для этого IP. См. комментарий у устаревшего
	// TransportFallback.Domains.
	Domains []string
}

// Candidates возвращает уникальные IP в порядке предпочтения из конфига.
func (e TransportFallbackEntry) Candidates() []string {
	out := make([]string, 0, 1+len(e.SafeIPs))
	seen := make(map[string]struct{}, cap(out))
	candidates := make([]string, 0, 1+len(e.SafeIPs))
	if e.SafeIP != "" {
		candidates = append(candidates, e.SafeIP)
	}
	candidates = append(candidates, e.SafeIPs...)
	for _, candidate := range candidates {
		if _, exists := seen[candidate]; exists {
			continue
		}
		seen[candidate] = struct{}{}
		out = append(out, candidate)
	}
	return out
}

type RadiusMode string

const (
	RadiusGroups RadiusMode = "groups"
	RadiusAll    RadiusMode = "all"
)

type RadiusConfig struct {
	Mode    RadiusMode
	Exclude []string
}

// ParseRadiusMode разбирает режим радиуса.
func ParseRadiusMode(value string) (RadiusMode, error) {
	switch RadiusMode(strings.ToLower(strings.TrimSpace(value))) {
	case RadiusGroups:
		return RadiusGroups, nil
	case RadiusAll:
		return RadiusAll, nil
	default:
		return "", fmt.Errorf("config: неизвестный radius.mode %q: допустимы groups, all", value)
	}
}

func (r RadiusConfig) validate() error {
	if r.Mode != RadiusGroups && r.Mode != RadiusAll {
		return fmt.Errorf("config: неизвестный radius.mode %q: допустимы groups, all", r.Mode)
	}
	for i, domain := range r.Exclude {
		if normalizeDomain(domain) == "" {
			return fmt.Errorf("config: radius.exclude[%d] пуст", i)
		}
	}
	return nil
}

// NewDomainSet создаёт нормализованный суффиксный matcher.
func NewDomainSet(domains []string) *DomainSet {
	normalized := make([]string, 0, len(domains))
	for _, domain := range domains {
		if domain = normalizeDomain(domain); domain != "" {
			normalized = append(normalized, domain)
		}
	}
	return &DomainSet{domains: normalized}
}

// QUICMode — как движок поступает с QUIC к отслеживаемым группам (3.3).
type QUICMode string

const (
	// QUICBlock — ронять клиентский QUIC Initial к радиусу, чтобы приложение
	// откатилось на TCP. Поведение по умолчанию.
	QUICBlock QUICMode = "block"
	// QUICDesync — переписывать QUIC Initial к радиусу (переупорядочение CRYPTO),
	// чтобы DPI не разобрал SNI, не роняя сам QUIC.
	QUICDesync QUICMode = "desync"
	// QUICOff — не трогать QUIC вовсе.
	QUICOff QUICMode = "off"
)

// ParseQUICMode разбирает значение режима QUIC (quic_mode из конфига или флаг
// --quic), отвергая неизвестное внятной ошибкой (опечатка не должна молча
// превратиться в «ничего не делать»).
func ParseQUICMode(s string) (QUICMode, error) {
	switch QUICMode(s) {
	case QUICBlock, QUICDesync, QUICOff:
		return QUICMode(s), nil
	default:
		return "", fmt.Errorf("config: неизвестный quic_mode %q: допустимы block, desync, off", s)
	}
}

// Default возвращает конфиг по умолчанию — ровно тот же, что получился бы из
// пустого файла.
//
// Нужен запуску без файла конфигурации: такой запуск законен (прокси поднимется
// прозрачным), но разделы автопилота обязаны быть заполнены, иначе их проверка
// отвергнет нулевые значения. Это единственная точка, где собираются значения
// по умолчанию всех разделов (10.1).
func Default() *Config {
	return &Config{
		Listen:      DefaultListen,
		BlockQUIC:   true,
		QUICMode:    QUICBlock,
		Radius:      RadiusConfig{Mode: RadiusGroups},
		Autopilot:   DefaultAutopilot(),
		Parallelism: DefaultParallelism(),
		Budgets:     DefaultBudgets(),
		Retention:   DefaultRetention(),
	}
}

// wire — проводная форма конфига. Отделена от Config, потому что стратегия в
// файле — недоверенный JSON, который проходит через strategy.Unmarshal, а не
// через прямой разбор в доменный тип.
type wire struct {
	YouTubeQUICMode *string                    `json:"youtube_quic_mode"`
	Listen          string                     `json:"listen"`
	Observe         bool                       `json:"observe"`
	BlockQUIC       *bool                      `json:"block_quic"`
	QUICMode        *string                    `json:"quic_mode"`
	Groups          map[string][]string        `json:"groups"`
	Radius          *radiusWire                `json:"radius"`
	Strategy        json.RawMessage            `json:"strategy"`
	Strategies      map[string]json.RawMessage `json:"strategies"`

	Vantage vantage.Label `json:"vantage"`

	Autopilot   autopilotWire `json:"autopilot"`
	Parallelism struct {
		Workers   *int `json:"workers"`
		PerTarget *int `json:"per_target"`
	} `json:"parallelism"`
	Budgets struct {
		InterestingConn *duration `json:"interesting_conn"`
		Decision        *duration `json:"decision"`
	} `json:"budgets"`
	Retention struct {
		Rows       *duration `json:"rows"`
		Aggregates *duration `json:"aggregates"`
		Events     *duration `json:"events"`
	} `json:"retention"`

	ProbeTargets   []string `json:"probe_targets"`
	ControlTargets []string `json:"control_targets"`

	TransportFallback *transportFallbackWire `json:"transport_fallback"`
}

type radiusWire struct {
	Mode    *string  `json:"mode"`
	Exclude []string `json:"exclude"`
}

// transportFallbackWire — проводная форма TransportFallback.
//
// Enabled — указатель по тому же правилу, что и прочие нули: false это
// заданное значение (включение по умолчанию невыгодно, но false это тоже
// намерение), поэтому отличить его от «ключа нет» нужно явно. Хотя тут,
// пожалуй, разница смысловая невелика — поведение одинаковое; оставлено ради
// единообразия с остальными разделами.
//
// Поддержаны ОБЕ формы:
//
//	Старая (одна safe_ip на все domains):
//	  {"enabled": true, "safe_ip": "162.159.138.232", "domains": [...]}
//
//	Новая (несколько entries с разными safe_ip):
//	  {"enabled": true, "entries": [
//	    {"safe_ip": "162.159.138.232", "domains": ["gateway.discord.gg"]},
//	    {"safe_ip": "162.159.130.233", "domains": ["cdn.discordapp.com"]}
//	  ]}
//
// Если задан entries, он используется; иначе safe_ip+domains сворачивается в
// единственную Entry. Задать и то и то одновременно — ошибка (неоднозначно).
type transportFallbackWire struct {
	Enabled *bool                        `json:"enabled"`
	SafeIP  string                       `json:"safe_ip"`
	Domains []string                     `json:"domains"`
	Entries []transportFallbackEntryWire `json:"entries"`
}

// transportFallbackEntryWire — проводная форма одной Entry (пара IP+домены).
type transportFallbackEntryWire struct {
	SafeIP  string   `json:"safe_ip"`
	SafeIPs []string `json:"safe_ips"`
	Domains []string `json:"domains"`
}

// Load читает, разбирает и проверяет конфиг из файла.
//
// Разбор строгий: неизвестный ключ верхнего уровня — ошибка, а не тихий пропуск.
// Опечатка в имени параметра иначе выглядела бы как молча не сработавшая
// настройка. Стратегия внутри проходит полную валидацию пакета strategy с
// пределами по умолчанию.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: чтение %s: %w", path, err)
	}
	if len(data) > maxConfigBytes {
		return nil, fmt.Errorf("config: файл %s больше предела %d байт", path, maxConfigBytes)
	}
	return parse(data)
}

// parse разбирает конфиг из байтов. Вынесено из Load, чтобы тесты проверяли
// разбор без обращения к файловой системе.
func parse(data []byte) (*Config, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var w wire
	if err := dec.Decode(&w); err != nil {
		return nil, fmt.Errorf("config: разбор: %w", err)
	}

	// Разделы, не заданные в файле, остаются по умолчанию целиком. Заданные
	// накладываются поверх по полям: конфиг, в котором поправили одно число,
	// не должен обнулять остальные (10.1).
	cfg := Default()
	cfg.Observe = w.Observe
	// Режим QUIC: канонично quic_mode; block_quic оставлен совместимым
	// псевдонимом (true→block, false→off). Если задан quic_mode, он важнее.
	switch {
	case w.QUICMode != nil:
		m, err := ParseQUICMode(*w.QUICMode)
		if err != nil {
			return nil, err
		}
		cfg.QUICMode = m
	case w.BlockQUIC != nil:
		if *w.BlockQUIC {
			cfg.QUICMode = QUICBlock
		} else {
			cfg.QUICMode = QUICOff
		}
	}
	if w.YouTubeQUICMode != nil {
		mode, err := ParseQUICMode(*w.YouTubeQUICMode)
		if err != nil {
			return nil, err
		}
		cfg.YouTubeQUICMode = &mode
	}
	// BlockQUIC держим согласованным с режимом для оставшихся читателей.
	cfg.BlockQUIC = cfg.QUICMode == QUICBlock
	cfg.Groups = normalizeGroups(w.Groups)
	if w.Radius != nil {
		cfg.Radius.Exclude = make([]string, len(w.Radius.Exclude))
		for i, domain := range w.Radius.Exclude {
			cfg.Radius.Exclude[i] = normalizeDomain(domain)
		}
		if w.Radius.Mode != nil {
			mode, err := ParseRadiusMode(*w.Radius.Mode)
			if err != nil {
				return nil, err
			}
			cfg.Radius.Mode = mode
		}
	}
	cfg.Vantage = w.Vantage
	cfg.Autopilot = w.Autopilot.apply(cfg.Autopilot)
	cfg.ProbeTargets = w.ProbeTargets
	cfg.ControlTargets = w.ControlTargets
	if w.TransportFallback != nil {
		tf := TransportFallback{
			SafeIP:  w.TransportFallback.SafeIP,
			Domains: w.TransportFallback.Domains,
		}
		if w.TransportFallback.Enabled != nil {
			tf.Enabled = *w.TransportFallback.Enabled
		}
		hasLegacy := tf.SafeIP != "" || len(tf.Domains) > 0
		hasEntries := len(w.TransportFallback.Entries) > 0
		switch {
		case hasLegacy && hasEntries:
			return nil, fmt.Errorf(
				"config: transport_fallback: нельзя задать и safe_ip/domains, и entries одновременно")
		case hasEntries:
			tf.Entries = make([]TransportFallbackEntry, 0, len(w.TransportFallback.Entries))
			for i, e := range w.TransportFallback.Entries {
				if e.SafeIP == "" && len(e.SafeIPs) == 0 {
					return nil, fmt.Errorf(
						"config: transport_fallback.entries[%d]: пустые safe_ip и safe_ips", i)
				}
				if len(e.Domains) == 0 {
					return nil, fmt.Errorf(
						"config: transport_fallback.entries[%d]: пустой domains", i)
				}
				tf.Entries = append(tf.Entries, TransportFallbackEntry{
					SafeIP:  e.SafeIP,
					SafeIPs: e.SafeIPs,
					Domains: e.Domains,
				})
			}
		case hasLegacy:
			// Сворачиваем старую форму в единственную Entry — остальной
			// код (applyFallback) работает ТОЛЬКО с Entries.
			tf.Entries = []TransportFallbackEntry{{
				SafeIP:  tf.SafeIP,
				Domains: tf.Domains,
			}}
		}
		cfg.TransportFallback = tf
	}
	if w.Listen != "" {
		cfg.Listen = w.Listen
	}
	if w.Parallelism.Workers != nil {
		cfg.Parallelism.Workers = *w.Parallelism.Workers
	}
	if w.Parallelism.PerTarget != nil {
		cfg.Parallelism.PerTarget = *w.Parallelism.PerTarget
	}
	if w.Budgets.InterestingConn != nil {
		cfg.Budgets.InterestingConn = time.Duration(*w.Budgets.InterestingConn)
	}
	if w.Budgets.Decision != nil {
		cfg.Budgets.Decision = time.Duration(*w.Budgets.Decision)
	}
	if w.Retention.Rows != nil {
		cfg.Retention.Rows = time.Duration(*w.Retention.Rows)
	}
	if w.Retention.Aggregates != nil {
		cfg.Retention.Aggregates = time.Duration(*w.Retention.Aggregates)
	}
	if w.Retention.Events != nil {
		cfg.Retention.Events = time.Duration(*w.Retention.Events)
	}

	// Стратегия присутствует, только если ключ непустой и не null: прокси без
	// стратегии — законная конфигурация (прозрачный пропуск).
	if hasJSON(w.Strategy) {
		s, err := strategy.Unmarshal(w.Strategy, strategy.DefaultLimits())
		if err != nil {
			return nil, fmt.Errorf("config: стратегия: %w", err)
		}
		cfg.Strategy = s
	}

	// Переопределения стратегий по группам. Поддерживается два формата:
	//
	//   { "rules": [...] }                     — одна стратегия на группу
	//   { "rotation": [{...}, {...}, ...] }    — ротация N стратегий между
	//                                            соединениями подгруппы
	//
	// Второй формат размывает DPI-сигнатуру: разные соединения одной группы
	// получают разную форму фейка, провайдер не может классифицировать
	// клиента по одному статичному паттерну.
	//
	// Разбор идёт отдельно от общей стратегии, чтобы ошибка внутри одной
	// группы называла группу по имени. Null- и пустые значения тихо
	// пропускаются.
	if len(w.Strategies) > 0 {
		cfg.Strategies = make(map[string]*strategy.Strategy, len(w.Strategies))
		cfg.StrategiesRotation = make(map[string][]*strategy.Strategy, len(w.Strategies))
		for name, raw := range w.Strategies {
			if !hasJSON(raw) {
				continue
			}
			// Пробуем новый формат: {"rotation": [...]}.
			var rotator struct {
				Rotation []json.RawMessage `json:"rotation"`
			}
			if err := json.Unmarshal(raw, &rotator); err == nil && len(rotator.Rotation) > 0 {
				list := make([]*strategy.Strategy, 0, len(rotator.Rotation))
				for i, rr := range rotator.Rotation {
					s, err := strategy.Unmarshal(rr, strategy.DefaultLimits())
					if err != nil {
						return nil, fmt.Errorf("config: strategies[%q].rotation[%d]: %w", name, i, err)
					}
					list = append(list, s)
				}
				cfg.StrategiesRotation[name] = list
				// Для обратной совместимости: Strategies содержит ПЕРВУЮ
				// стратегию ротации как "главную". Старые потребители,
				// которые читают только cfg.Strategies, получат одну из
				// ротируемых — не ошибку.
				cfg.Strategies[name] = list[0]
				continue
			}
			// Старый формат: {"rules": [...]} — одна стратегия.
			s, err := strategy.Unmarshal(raw, strategy.DefaultLimits())
			if err != nil {
				return nil, fmt.Errorf("config: strategies[%q]: %w", name, err)
			}
			cfg.Strategies[name] = s
		}
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// validate проверяет согласованность уже разобранного конфига.
func (c *Config) validate() error {
	for name, domains := range c.Groups {
		if name == "" {
			return fmt.Errorf("config: пустое имя группы")
		}
		if len(domains) == 0 {
			return fmt.Errorf("config: группа %q не содержит доменов", name)
		}
		for _, d := range domains {
			if d == "" {
				return fmt.Errorf("config: группа %q содержит пустой домен", name)
			}
		}
	}
	// Переопределение стратегии возможно только для существующих групп:
	// опечатка в имени иначе выглядела бы как молча не сработавшая настройка.
	for name := range c.Strategies {
		if name == "" {
			return fmt.Errorf("config: strategies: пустое имя группы")
		}
		if _, ok := c.Groups[name]; !ok {
			return fmt.Errorf("config: strategies[%q]: группа не задана в groups", name)
		}
	}
	if err := c.Autopilot.validate(); err != nil {
		return err
	}
	if err := c.Radius.validate(); err != nil {
		return err
	}
	if err := c.Parallelism.validate(); err != nil {
		return err
	}
	if err := c.Budgets.validate(); err != nil {
		return err
	}
	if err := c.Retention.validate(); err != nil {
		return err
	}
	for _, t := range c.ProbeTargets {
		if t == "" {
			return fmt.Errorf("config: пустая цель проб")
		}
	}
	for _, t := range c.ControlTargets {
		if t == "" {
			return fmt.Errorf("config: пустая контрольная цель")
		}
	}
	if err := c.TransportFallback.validate(); err != nil {
		return err
	}
	return nil
}

// validate проверяет TransportFallback. При Enabled=false ничего не проверяет
// — поля просто не используются. При Enabled=true требует непустой Entries
// (парсер уже свернул старую форму safe_ip+domains в единственную Entry, если
// задана), в каждой Entry — хотя бы один валидный candidate IP и непустой Domains.
func (t TransportFallback) validate() error {
	if !t.Enabled {
		return nil
	}
	if len(t.Entries) == 0 {
		return fmt.Errorf("config: transport_fallback.enabled=true, но нет ни safe_ip+domains, ни entries")
	}
	for i, e := range t.Entries {
		candidates := e.Candidates()
		if len(candidates) == 0 {
			return fmt.Errorf(
				"config: transport_fallback.entries[%d]: safe_ip и safe_ips пусты", i)
		}
		for _, candidate := range candidates {
			if net.ParseIP(candidate) == nil {
				return fmt.Errorf(
					"config: transport_fallback.entries[%d] candidate %q — не IP",
					i, candidate)
			}
		}
		if len(e.Domains) == 0 {
			return fmt.Errorf(
				"config: transport_fallback.entries[%d]: domains пуст", i)
		}
		for j, d := range e.Domains {
			if d == "" {
				return fmt.Errorf(
					"config: transport_fallback.entries[%d].domains[%d] пуст",
					i, j)
			}
		}
	}
	return nil
}

// hasJSON сообщает, несёт ли сырое сообщение содержимое (не пусто и не null).
func hasJSON(raw json.RawMessage) bool {
	return len(raw) > 0 && !bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}
