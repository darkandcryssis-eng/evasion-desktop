# Evasion

Движок автоматического обхода DPI для Windows на Go. Применяет стратегию обхода
к первым пакетам каждого TCP-соединения (TLS ClientHello) и к инициации
голосовых UDP-сессий Discord.

Headless: графического интерфейса в репозитории нет. Вся работа — через CLI с
машинно-читаемым `--json`.

## Для чего прямо сейчас

Один клик — Discord работает в сети с TSPU, без VPN и без сторонних обходчиков:

```
scripts\start-discord.bat
```

Что получит пользователь: вход в аккаунт, канал без переподключений, GUI,
картинки, эмодзи, аватарки, **голос** и **демонстрация экрана** на всех
RTC-портах (443 / 2053 / 2083 / 2087 / 2096 / 8443). Теория и ручной рецепт —
в `docs/discord-ru.md`; журнал закрытых работ — в `docs/DONE.md`.

## Как это работает

Движок цепляется к сетевому стеку через **WinDivert** и трогает только начало
каждого TCP-соединения (пакет с TLS ClientHello) и первый UDP-пакет голосовой
сессии Discord. К пакету применяется стратегия обхода. Основные примитивы:

- **`fragment`** — разрез TCP-сегмента по имени сервера (`disorder-sni`,
  `split-sni`) либо по границам TLS-записей;
- **`tamper` + `duplicate`** — фейковый пакет перед настоящим с короким TTL,
  битой суммой или сдвигом TCP seq (`badseq`);
- **`tcp_overlap`** — отправка настоящего ClientHello под прикрытием
  предварительного cover-пакета, перекрытого по TCP seq. Сервер по правилу
  overlap собирает оригинал, DPI парсит cover и пропускает соединение по
  безобидному SNI. Применяется там, где SNI блокируется по имени на
  TLS-уровне независимо от IP. Cover-пресет выбирается по имени: базовый
  `tls_cover_681` (SNI google) и варианты того же размера `tls_cover_681_apple`,
  `tls_cover_681_microsoft`, `tls_cover_681_yandex` — чтобы один cover не стал
  сам сигнатурой обхода.

Автопилот (`internal/control` + `internal/scoring`) ведёт портфель стратегий,
измеряет их на реальном трафике и живых пробах, повышает рабочие в `active`
по статистическому порогу и опускает деградировавшие. Стратегию на цели можно
закрепить руками через конфиг — закрепление обходит пороги. Все числа — из
конфига, не из кода.

Поверх TCP:

- `internal/discordvoice` — опознаёт голосовой UDP Discord по форме IP
  discovery (74 байта, тип `0x0001`) и прячет его начало от DPI через decoy
  с коротким TTL или битой UDP-суммой;
- `internal/hosts` + `transport_fallback` в конфиге — hosts-подмена для
  доменов, у которых реальный IP блокирован, но Cloudflare обслуживает
  любой SNI на том же IP (например, `gateway.discord.gg`);
- `internal/quicwatch` + `cmd/evasion quicblock` — блокировка QUIC к радиусу
  целей, чтобы Chromium откатился на TCP;
- `internal/rtcredirect` + файрвольный блок — переклейка душимых RTC-портов
  Discord на живые (экспериментально, в текущем конфиге выключено).

## Быстрый старт для Discord

```
scripts\start-discord.bat
```

Скрипт запрашивает права администратора, собирает свежий `evasion.exe`,
перезапускает Discord с выключенным DoH и поднимает движок в отдельном окне.
Окно `movok-engine` не закрывать, пока пользуешься Discord.

## Общий запуск

Собрать и запустить вручную:

```
go build -o evasion.exe .\cmd\evasion
evasion.exe run --mode intercept --config examples\config.json --quic off --voice ttl
```

CLI:

```
evasion run         поднять движок (прокси или перехват)
evasion status      состояние работающего движка (state\status.json)
evasion portfolio   стратегии портфеля с их ступенями
evasion doctor      проверка окружения — почему не работает
evasion blockcheck  перебор портфеля стратегий по одной цели
evasion search      генетический поиск стратегий в песочнице
evasion events      чтение events.jsonl: --tail, --since, --filter
evasion hosts       управление hosts: apply | clean | status
evasion cleanup     откат всех системных изменений (hosts, firewall)
evasion warp        регистрация в Cloudflare WARP
evasion tunnel      WireGuard-туннель к WARP: ping
```

У каждой команды есть `--json` — стабильный контракт для внешнего интерфейса
(`evasion <команда> -h`).

## Конфиг

Эталон — `examples/config.json`. Там заданы:

- **группы доменов** (`discord`, `discord_cdn`, `discord_updates`,
  `discord_gateway`, `discord_voice`, `video`) — радиус поражения;
- **стратегии по группам** (`strategies`):
  - `discord_voice` — `badseq` + apple-ClientHello + TCP split: голос;
  - `discord_cdn` — `tcp_overlap` с cover-пресетом: картинки на
    `cdn.discordapp.com`, `media.discordapp.net`;
  - `discord_updates` — reverse-fragment по SNI: клиентские апдейты;
- **транспортный обход** (`transport_fallback`) — hosts-подмена для доменов,
  у которых блокирован IP (один entry = один `safe_ip` + список доменов,
  entries может быть несколько);
- **автопилот** (`autopilot`) — полужизнь оценок, выдержка, доля
  экспериментов, маржа над базовой линией.

Готовые кандидатские стратегии для ручной проверки — в `examples/strategies/`
с собственным `README.md`.

Правила про конфиг, которые нельзя забыть:

- файл **без BOM**: строгий разбор JSON на нём падает (в PowerShell 5.1
  писать через `[IO.File]::WriteAllText`, не `Set-Content`);
- `--observe` включает режим наблюдения: стратегии не применяются;
- запуск без `--config` законен: прокси поднимется прозрачным.

## Структура

```
cmd/evasion/            CLI (run, status, portfolio, doctor, blockcheck,
                        search, events, hosts, warp, tunnel, cleanup)
internal/
  core/                 доменные типы, ни от чего не зависят
  packet/               разбор IP/TCP/UDP, контрольные суммы
  tlsparse/             ClientHello, SNI, точки разреза
  tlsfake/              пресеты фейковых ClientHello
  capture/              источник/приёмник пакетов: windivert, pcap, synthetic
  flow/                 таблица соединений
  strategy/             дерево примитивов, валидация, сериализация
  desync/               семантика примитивов (fragment, duplicate, tcp_overlap, ...)
  executor/             интерфейс исполнителя + возможности
  socketexec/           исполнитель пользовательского пространства
  packetexec/           исполнитель через перехват пакетов
  intercept/            контур перехвата WinDivert
  interception/         обнаружение чужих перехватчиков
  proxy/                SOCKS-сервер режима прокси
  policy/               снимок «цель → стратегия», горячий путь
  sandbox/              выделенные соединения для кандидатов
  generator/            генетический поиск стратегий
  scoring/              бандит с затуханием, пороги уверенности
  control/              контур управления автопилотом
  probe/                активные пробы
  vantage/              определение точки наблюдения
  store/                SQLite-журнал наблюдений (без CGO)
  telemetry/            счётчики, кольцевой буфер, slog-handler
  events/               journal.jsonl жизненного цикла соединений
  rtctrack/             статистика живучести Discord-соединений
  safego/               горутины с panic recovery
  sysmanifest/          журнал системных изменений для rollback
  enginelock/           защита от второго экземпляра движка
  hosts/                правка системного hosts
  windivert/            загрузчик .dll/.sys
  discordvoice/         опознание голосового UDP Discord
  rtcredirect/          переклейка RTC-портов (эксперимент)
  quic/, quicwatch/     блокировка/десинк QUIC
  quicfake/             benign QUIC v1 Initial для UDP decoy
  warp/, tunnel/        Cloudflare WARP + WireGuard как резерв
  repohygiene/          тесты свойств самого репозитория

docs/
  discord-ru.md         рабочий рецепт обхода блокировок Discord
  DONE.md               журнал закрытых работ
  ARCHITECTURE.md       инварианты и roadmap

examples/
  config.json           эталонный конфиг
  strategies/           кандидатские стратегии для ручной проверки
  *.bat                 примеры запуска

scripts/
  start-discord.bat     лаунчер в один клик

tests/                  живые прогоны: настоящий бинарник, настоящий трафик
```

## Требования

- Go 1.27 (`toolchain go1.27.2` в `go.mod` подтянет сам)
- Windows 10/11 x64 для перехвата; базовые пакеты собираются везде
- Без CGO
- `WinDivert.dll` + `WinDivert64.sys` рядом с бинарником (LGPLv3,
  динамическое связывание)
- Права администратора для режима `intercept`

## Сборка и проверки

```
go build ./...
go test -race ./...
go vet ./...
go run honnef.co/go/tools/cmd/staticcheck@latest ./...
```

Правила тестов и как добавлять новые — в `tests/README.md`.

## Лицензии

- Движок — исходный код этого репозитория.
- WinDivert поставляется отдельно под LGPLv3, связывается только динамически.
- Принципы устройства взяты из академических источников (Geneva, CCS 2019):
  примитивы `drop`/`tamper`/`duplicate`/`fragment` и представление стратегии
  деревом. Параметры стратегий существующих инструментов не используются.
