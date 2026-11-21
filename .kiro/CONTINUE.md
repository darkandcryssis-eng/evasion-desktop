# Prompt для продолжения работы над evasion

Этот файл — точка возврата для следующей сессии: что сейчас работает,
что ещё нет, с чего начинать. Короче `docs/DONE.md` (журнал всех
изменений) и `docs/ARCHITECTURE.md` (инварианты и полный roadmap).

---

## Текущее состояние (ноябрь 2026)

**Discord в сети пользователя (TSPU, Россия) работает**:

- ✅ Вход в аккаунт, GUI отрисовывается
- ✅ Текст, каналы, список друзей
- ✅ Аватарки, эмодзи, иконки
- ✅ Гифки на `media.discordapp.net`
- ✅ **Крупные картинки на `cdn.discordapp.com`** — через собственный
  примитив `tcp_overlap` с cover-пресетом (681 байт)
- ✅ **Голос** — стабильный, канал заходит моментально, нет
  переподключений. Через `--voice ttl` (6 UDP-decoy перед настоящим
  IP discovery) + hosts-подмена для `gateway.discord.gg` →
  `162.159.138.232`
- ✅ Демонстрация экрана на всех RTC-портах

**Запуск**: `scripts\start-discord.bat` — один клик, собирает,
поднимает движок, перезапускает Discord.

**Основной конфиг**: `examples/config.json`. Там живут:
- группы доменов (`discord`, `discord_cdn`, `discord_updates`,
  `discord_gateway`, `discord_voice`, `video`);
- `strategies` — стратегии по группам (голос `badseq+apple+split`,
  CDN `tcp_overlap`, апдейты `disorder-sni`);
- `transport_fallback` — hosts-подмена для доменов с заблокированным
  IP (список `entries` с per-domain `safe_ip`).

**Все 41 пакета** `go test -race -count=1 ./...` зелёные, `go vet`
чист.

---

## КРИТИЧНО: не удаляй `state\rtctrack.json`

Это память движка о «плохих» (SNI, порт) RTC-серверах; из неё строится
blocklist, который их обходит. Файл копится по мере использования и сам
переживает перезапуски (`AutoSaver` + восстановление на старте). Пока
память «прогрета» — залипающие голосовые сервера обходятся, канал заходит
мгновенно. Удаление файла (или всей папки `state\`) стирает выученное и
возвращает затупы на `AUTHENTICATING`, пока память не нарастёт заново
(10–15 минут обычного использования). Если затупы вернулись после чистки
`state\` — это ожидаемо, просто дай движку поработать.

Рычаг на стороне пользователя, когда флачит конкретный регион: Override
Region в настройках голосового канала Discord (напр. Finland вместо
Stockholm; сервера `c-arn*` — это Стокгольм).

Подробный разбор затупа и отвергнутые попытки (`--rtc-redirect` → `4006`,
firewall-блок порта, split без badseq) — в `docs/DONE.md`, волна PR #32.

### Главная цель следующей сессии C (голос + CDN, с полевой обкаткой)

Полевой журнал (ноябрь 2026, после `start-discord.bat`) дал два конкретных
симптома:

1. **`многосегментных_пропущено=3`** в логе движка — держится на 3 всю
   сессию и не падает. Три многосегментных ClientHello (крупные CDN-ресурсы
   Chrome) движок НЕ собирает и пропускает сырьём → TSPU рубит → `net_error
   -101` на `cdn.discordapp.com` (в т.ч. `.riv`-анимации), Chrome
   ретранслирует (`повторов_clienthello` 17→52). Чинить в `applyAssembled`
   (`internal/intercept/engine.go`): почему именно эти 3 не собираются —
   вероятно SNI расколот более чем на 2 сегмента или сегменты приходят не по
   порядку, и сборщик сдаётся. Это ГОРЯЧИЙ путь → только с полевой проверкой.
2. **Голос churn ~40 сек** на холодном старте: Discord перебирает 8 серверов
   `c-arn*` (Стокгольм), каждый CONNECTED→AUTHENTICATING→Force Close, пока не
   сядет на живой (в журнале — `c-arn08-e29bbb59`, дальше heartbeat-и идут
   стабильно). `rtctrack` восстановился «23 пары», но voice-SNI почти
   уникальны per-endpoint (`c-arnNN-<hex>.discord.media`), поэтому
   SNI-ключёванный blocklist для голоса почти не срабатывает — это и есть
   задача детектора churn (опция C из прошлой сессии): per-SNI частота
   переподключений в скользящем окне → blocklist → passthrough. Рычаг
   пользователю прямо сейчас: Override Region (Finland/Netherlands вместо
   Stockholm).

Диверсификация cover'а (волна `feat/wave2-cover-presets`) НЕ закрывает п.1 —
она про риск распознавания паттерна, а не про три несобранных hello.

---

## Что ещё не сделано (из `docs/ARCHITECTURE.md`, Волна 1)

### Расширение арсенала примитивов

Пригодится если TSPU начнёт распознавать текущий `tcp_overlap`-cover-
pattern (`PresetTLSCover681`): свежие стратегии увеличивают площадь
поиска.

1. **TCP options tampering**: расширить `strategy.FieldID` на
   `tcp_mss`, `tcp_wscale`, `tcp_timestamp`, `tcp_window`. Реализация в
   `internal/packet/tcp.go` (уже умеет MSS/WindowScale) + соответствие
   в `packetexec`. Тест на правильность `data offset` после правки.
2. **`md5sig`**: TCP MD5 Signature Option (RFC 2385, option 19) с
   заведомо неверной подписью на фейке. Многие DPI MD5 не валидируют,
   сервер отбрасывает по подписи. Нужна новая capability `CapMD5Sig`.
3. **IPv6 extension headers**: вставка Hop-by-Hop header на фейке.
   Опция в `strategy.FragmentParams` или новый tamper mode. Юнит +
   интеграционный через `capture/synthetic`.

### Пресеты (Волна 2) — ✅ СДЕЛАНО (ветка `feat/wave2-cover-presets`)

Базовый `tls_cover_681` дополнен вариантами того же размера 681 байт с
другими SNI: `tls_cover_681_apple`, `tls_cover_681_microsoft`,
`tls_cover_681_yandex`. Собираются в коде (`tlsfake/cover681_variants.go`,
padding-расширение RFC 7685 добивает до 681), не отдельными `.bin`. В
реестре `strategy.FakePresetNames()`; добавлен `strategy.CoverPresetNames()`.
Взаимозаменяемы в `discord_cdn`-стратегии — поменять `preset` в
`examples/config.json`, если google-cover начнёт распознаваться. Подробно —
`docs/DONE.md`, волна «варианты cover-пресета».

### Прочее

- **Генератор мутирует `ActionTCPOverlap`** — ✅ СДЕЛАНО (та же ветка): при
  `CapTCPOverlap` генератор порождает и мутирует tcp_overlap, пресет из
  `CoverPresetNames()`. `cloneParams` копирует `*TCPOverlapParams`.
- **Фаз-тест и крайние значения для `tcp_overlap`** — ✅ СДЕЛАНО (та же
  ветка): `growTree` в `internal/desync/fuzz_test.go` порождает и tcp_overlap
  (обход не паникует ни на коротком входе → `ErrCutUnavailable`, ни на длинном
  → реальный план); детерминированные крайние случаи — в
  `internal/desync/tcpoverlap_test.go` (M==L / M>L / L=0 → `ErrCutUnavailable`;
  L=M+1 — рабочая граница; геометрия смещений L-M; взаимозаменяемость
  вариантов cover по размеру).
- **UI/CLI**: `evasion doctor` видит capability `tcp_overlap` через общий
  механизм, отдельного описания в тексте команды нет. Не трогалось намеренно:
  вывод doctor — согласованный с владельцем контракт (`cmd/evasion/doctor.go`),
  менять его форму автономно рискованно.

---

## Если что-то сломается в сети пользователя

**Симптом: картинки на `cdn.discordapp.com` перестали грузиться**.
Возможно TSPU научился распознавать cover-pattern.
1. `scripts\test-cdn-ips.*` удалён (сделал своё дело). Для диагностики
   можно сделать аналогичный разовый скрипт с `curl --connect-to`.
2. Поменять preset в `examples/config.json`: сейчас
   `"preset": "tls_cover_681"`. Доступные альтернативы:
   `tls_clienthello_google`, `_apple`, `_cloudflare`, `_microsoft`,
   `_yandex`, `_vk` — но у них переменный размер. Для `tcp_overlap`
   нужен **фиксированный** размер, поэтому альтернативу придётся
   собрать (новый `.bin` + `go:embed` + имя в реестре).

**Симптом: голос снова виснет на `AUTHENTICATING`**.
1. Проверить что `--voice` не `off`: по умолчанию `ttl`, лаунчер
   передаёт явно.
2. Попробовать `--voice badsum` (другой fooling режим), `ttl-quic`
   (QUIC-подобная нагрузка decoy).
3. Проверить что нет сторонних перехватчиков через
   `evasion.exe doctor` — WinDivert-конфликт даёт зависания.

**Симптом: канал перезаходит**.
1. Проверить что `--quic off`: `block` может рубить gateway WSS
   keep-alive QUIC-пинги.

---

## Как войти в контекст быстро

1. Прочитать `README.md` — обзор, что умеет движок.
2. Прочитать `docs/discord-ru.md` — рабочий рецепт обхода Discord
   с полной картой блокировки.
3. При работе с историей решений — `docs/DONE.md` (журнал PR) и
   `.kiro/steering/progress.md` (архитектурный дневник).
4. При работе над новыми примитивами — `docs/ARCHITECTURE.md`,
   раздел «Волна 1».

**Исходное задание**: `.kiro/steering/task.md` — полное ТЗ от
владельца проекта, не меняется.

---

## Git / PR workflow

- Основная ветка: `main`
- PR создаются через `gh api repos/deco1q/afrga/pulls` (GraphQL
  `gh pr create` не работает в этом окружении)
- Все 26 PR слиты, последний — `#26` (`refactor: rename seqovl ->
  tcp_overlap`).
- Запуск сборки + тестов: `GOTOOLCHAIN=auto go build ./... &&
  GOTOOLCHAIN=auto go test -race -count=1 ./...`


---

## Десктопная оболочка (ветка `feat/ui`, PR #40)

`ui/` — отдельный модуль (Wails v2 + React), доведён до рабочего единого
`Evasion.exe`: оболочка управляет движком подпроцессом и несёт `evasion.exe` +
WinDivert + конфиг внутри себя (`go:embed`, `ui/payload/`). Сборка одним кликом
— `ui\build-and-run.bat`; манифест `requireAdministrator`. Единственная правка
движка — флаг `--stop-on-stdin-eof` в `cmd/evasion/run.go` (штатная остановка
подпроцесса на Windows без Ctrl+C). Движок не тронут функционально: 41 пакет
`go test -race ./...` зелёный. Подробности — `docs/DONE.md`, волна «Evasion UI».

Следующее по UI (не начато): перенести свои стратегии/профили в редактор целей,
живой хвост журнала движка на отдельном экране, отображение `status.json` при
автопилоте уже есть. CDN cover трогать нельзя (см. выше).
