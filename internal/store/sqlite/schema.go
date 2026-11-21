package sqlite

// schemaVersion — текущая версия схемы.
//
// Хранится в самой базе, чтобы при развитии схемы было видно, с чем имеем дело.
// Без версии пришлось бы угадывать состав столбцов по наличию таблиц, а это
// ровно тот способ, которым теряют данные.
const schemaVersion = 1

// schemaStatements — создание схемы. Выполняются по порядку и повторно
// безопасны: все с проверкой существования.
//
// Решения, заложенные в схему:
//
//   - Первичного ключа у наблюдений НЕТ намеренно. Две одинаковые записи — это
//     два разных наблюдения, а не ошибка: стратегия могла дважды дать один исход
//     в одну миллисекунду. Первичный ключ здесь молча терял бы измерения.
//
//   - Время хранится целым числом миллисекунд от эпохи, а не типом даты
//     SQLite: типы даты у разных СУБД различаются, а целое переносится как есть.
//
//   - Перечисления хранятся текстовыми обозначениями. Числа привязали бы архив
//     к текущему порядку констант в коде: перестановка значения испортила бы
//     всю прошлую историю, причём молча.
//
//   - Столбец day — явный временной раздел. По нему идёт удаление по сроку, и
//     он же станет ключом раздела при переходе на колоночную СУБД (6.5).
//
//   - Логические значения хранятся целыми 0 и 1: отдельного типа для них в
//     SQLite нет, а числовое представление переносится куда угодно.
var schemaStatements = []string{
	`CREATE TABLE IF NOT EXISTS schema_version (
		version INTEGER NOT NULL
	)`,

	`CREATE TABLE IF NOT EXISTS observations (
		at_ms               INTEGER NOT NULL,
		day                 INTEGER NOT NULL,
		strategy_id         TEXT    NOT NULL,
		target              TEXT    NOT NULL,
		vantage_id          TEXT    NOT NULL,
		phase               TEXT    NOT NULL,
		outcome             TEXT    NOT NULL,
		reason              TEXT    NOT NULL,
		source              TEXT    NOT NULL,
		strategy_applied    INTEGER NOT NULL,
		rtt_ns              INTEGER NOT NULL,
		rtt_measured        INTEGER NOT NULL,
		throughput          INTEGER NOT NULL,
		throughput_measured INTEGER NOT NULL
	)`,

	// Порядок столбцов в указателе повторяет порядок отбора в запросе срезов:
	// точка наблюдения отбирается всегда, цель и стратегия — по желанию, время
	// ограничивает окно. При другом порядке указатель не использовался бы для
	// запроса без цели.
	`CREATE INDEX IF NOT EXISTS observations_by_key
		ON observations (vantage_id, target, strategy_id, at_ms)`,

	// Отдельный указатель по дню — для удаления по сроку. Без него удаление
	// перебирало бы всю таблицу, и чем дольше работает движок, тем дороже
	// становилась бы уборка.
	`CREATE INDEX IF NOT EXISTS observations_by_day
		ON observations (day)`,

	`CREATE TABLE IF NOT EXISTS strategy_events (
		at_ms       INTEGER NOT NULL,
		day         INTEGER NOT NULL,
		strategy_id TEXT    NOT NULL,
		kind        TEXT    NOT NULL,
		vantage_id  TEXT    NOT NULL,
		target      TEXT    NOT NULL,
		from_state  TEXT    NOT NULL,
		to_state    TEXT    NOT NULL,
		note        TEXT    NOT NULL
	)`,

	`CREATE INDEX IF NOT EXISTS strategy_events_by_strategy
		ON strategy_events (strategy_id, at_ms)`,

	`CREATE INDEX IF NOT EXISTS strategy_events_by_day
		ON strategy_events (day)`,
}

// pragmas — настройки соединения.
//
// Это единственное место, где используются особенности SQLite, и так и должно
// быть: настройки соединения не переносятся вместе со схемой, а их отсутствие
// заметно сразу, тогда как привязка схемы проявилась бы лишь при переходе.
var pragmas = []string{
	// Журнал опережающей записи: читатели не блокируют писателя и наоборот.
	// Прямо предписан заданием (6.5).
	`PRAGMA journal_mode = WAL`,

	// Сброс на диск не при каждой записи, а при контрольной точке.
	//
	// Обмен осознанный: при внезапном отключении питания можно потерять
	// последние принятые наблюдения, но повреждения базы не происходит. Для
	// телеметрии это верный обмен — потеря нескольких наблюдений не стоит
	// того, чтобы каждая пачка ждала физической записи. Для данных, терять
	// которые нельзя, такой выбор был бы неверен.
	`PRAGMA synchronous = NORMAL`,

	// Ожидание освобождения базы вместо немедленного отказа. Без этого
	// одновременная уборка и запись давали бы ошибку занятости там, где
	// достаточно подождать.
	`PRAGMA busy_timeout = 5000`,

	// Проверка внешних ключей. Их в схеме нет, но включение ничего не стоит и
	// защищает от ошибки при будущем развитии схемы.
	`PRAGMA foreign_keys = ON`,
}
