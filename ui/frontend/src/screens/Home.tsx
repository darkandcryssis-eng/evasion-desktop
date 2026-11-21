import { useState } from "react";
import { api, type EnginePhase, type GameFilterView, type NetworkTuningView, type StartOptions } from "../api";
import type { EngineController } from "../useEngine";
import { useConnectionOptions, readPreference, savePreference } from "../preferences";
import { gameStatus } from "../gameStatus";
import { telegramBadge } from "../telegramBadge";
import { useElapsed, usePoll } from "../hooks";
import { Orb } from "../fx/Orb";
import { Badge, Button, Disclosure, Feed, Glass, Icon, Note, Row, Segmented, Ticker, Toggle, type IconName, type Tone } from "../ui";
import type { Page } from "../types";

const voiceOptions = [
  { id: "ttl", label: "TTL — по умолчанию" },
  { id: "badsum", label: "Bad checksum" },
  { id: "ttl-quic", label: "TTL + QUIC-ловушки" },
  { id: "badsum-quic", label: "Bad checksum + QUIC" },
  { id: "off", label: "Не трогать голос" },
];
const quicOptions: { id: string; label: string; hint: string }[] = [
  { id: "off", label: "Не трогать", hint: "Приложение само договорится — обычный выбор" },
  { id: "block", label: "Блокировать", hint: "Заставляет браузер уйти на TCP, где работает обход" },
  { id: "desync", label: "Десинк", hint: "Экспериментально" },
];
const telegramModes: { id: TelegramMode; label: string; hint: string }[] = [
  { id: "ask", label: "Спрашивать", hint: "Уточнять при каждом включении" },
  { id: "yes", label: "Всегда", hint: "Запускать прокси вместе с обходом" },
  { id: "no", label: "Никогда", hint: "Только обход" },
];
export type TelegramMode = "ask" | "yes" | "no";
export function telegramMode(): TelegramMode {
  const v = readPreference("evasion-connect-telegram");
  return v === "yes" || v === "no" ? v : "ask";
}

const statusLabel: Record<EnginePhase, string> = { stopped: "Готов к запуску", starting: "Включаем", running: "Обход включён", stopping: "Завершаем", failed: "Не удалось включить" };
const statusTone: Record<EnginePhase, Tone> = { stopped: "neutral", starting: "accent", running: "success", stopping: "accent", failed: "warning" };
const headline: Record<EnginePhase, [string, string]> = {
  stopped: ["Ваш интернет.", "Свободнее."],
  starting: ["Настраиваем", "соединение…"],
  running: ["Всё работает.", "Спокойно."],
  stopping: ["Сворачиваем", "обход…"],
  failed: ["Что-то пошло", "не так."],
};
const hint: Record<EnginePhase, string> = {
  stopped: "Нажмите на кольцо или Ctrl + Enter",
  starting: "Поднимаем движок и перехват",
  running: "Окно можно свернуть — Evasion продолжит работу в трее",
  stopping: "Возвращаем сеть в исходное состояние",
  failed: "Посмотрите сообщение ниже или откройте диагностику",
};

const ytPhase: Record<string, [string, Tone]> = {
  waiting: ["Проверка запускается", "neutral"], awaiting_media: ["Сайт доступен, ждём видео", "accent"], stopped: ["Ждёт включения обхода", "neutral"],
  disabled: ["Исключён из обхода", "neutral"], checking: ["Проверяем", "accent"], healthy: ["Доступен", "success"], degraded: ["Перепроверяем сбой", "warning"],
  recovering: ["Подбираем способ", "accent"], recovered: ["Способ заменён", "success"], network_down: ["Нет интернета", "warning"], unavailable: ["Пока недоступен", "warning"],
};

type Props = { engine: EngineController; onConnect: (o: StartOptions) => void; onNavigate: (p: Page) => void };

export function HomeScreen({ engine, onConnect, onNavigate }: Props) {
  const { state, busy, error, stop, reconnect, restartDiscord } = engine;
  const [options, update] = useConnectionOptions();
  const [tgMode, setTgMode] = useState<TelegramMode>(telegramMode);
  const phase: EnginePhase = state?.engine.phase ?? "stopped";
  const running = phase === "running";
  const active = running || phase === "starting" || phase === "stopping";
  const transit = phase === "starting" || phase === "stopping";
  const ready = !!state && state.payload.engine;
  const elapsed = useElapsed(state?.engine.startedAt, running);
  const tuning = usePoll<NetworkTuningView>(() => api.getNetworkTuning(options), 3000).value;
  const games = usePoll<GameFilterView>(() => api.getGameFilter(), 3000).value;

  const logs = [...(state?.engine.logs ?? []), ...(state?.telegram?.logs ?? [])].sort((a, b) => (Date.parse(a.at) || 0) - (Date.parse(b.at) || 0)).slice(-400);
  const hello = state?.engine.hello;
  const tg = state?.telegram;
  const tgBadge: { label: string; tone: Tone } = tg ? telegramBadge(tg) : { label: "Выключен", tone: "neutral" };
  const yt = tuning?.health;
  const ytState: [string, Tone] = !active ? ["Ждёт включения обхода", "neutral"] : ytPhase[yt?.fresh ? yt.phase : "waiting"] ?? ["Проверяется", "neutral"];
  const [ytLabel, ytTone] = ytState;
  const groups = state?.engine.strategies.length ?? 0;
  const gameOn = !!games?.engineRunning && games.activeMode !== "off";

  const press = () => {
    if (active) { void stop(); return; }
    onConnect(options);
  };

  return (
    <div className="home">
      <section className="hero" aria-label="Управление подключением">
        <Badge tone={state ? statusTone[phase] : "neutral"} pulse={transit || running}>{state ? statusLabel[phase] : "Получаем состояние…"}</Badge>
        <h1 className="hero__title" key={phase}>{headline[phase][0]}<br /><em>{headline[phase][1]}</em></h1>
        <div className="hero__orb">
          <Orb phase={phase} busy={busy} disabled={busy || transit || (!active && !ready)} label={active ? "Выключить Evasion" : "Включить Evasion"} onPress={press} />
        </div>
        <div className={`goo${running ? " goo--open" : ""}`} data-busy={busy || transit || undefined}>
          <div className="goo__paint" aria-hidden="true"><i /><i /><i /></div>
          <div className="goo__content">
            {!running && <button type="button" className="goo__main" disabled={busy || transit || (!active && !ready)} onClick={press}>{transit ? (phase === "starting" ? "Включаем…" : "Выключаем…") : phase === "failed" ? "Повторить" : "Включить"}</button>}
            {running && <>
              <span className="goo__time" title="Время работы"><i />{elapsed}</span>
              <button type="button" className="goo__icon" aria-label="Переподключить" title="Переподключить" disabled={busy} onClick={() => void reconnect()}><Icon name="refresh" size={16} /></button>
              <button type="button" className="goo__stop" disabled={busy} onClick={press}>Выключить</button>
            </>}
          </div>
        </div>
        <p className="hero__hint">{state ? hint[phase] : "Получаем состояние приложения"}</p>
        <div className="hero__notices">
          {state && !state.elevated && <Note tone="warn" icon="alert">Нужны права администратора. Запустите Evasion от имени администратора.</Note>}
          {state && !state.payload.engine && <Note tone="warn" icon="alert">Движок не встроен в эту сборку. Пересоберите через ui\build-and-run.bat.</Note>}
          {error && <Note tone="warn" icon="alert">{error}{error.toLowerCase().includes("windivert") && <> <button type="button" className="link" onClick={() => onNavigate("diagnostics")}>Диагностика драйвера</button></>}</Note>}
          {state?.engine.guard && !error && <Note icon="shield">{state.engine.guard}</Note>}
        </div>
      </section>

      <section className="bento" aria-label="Состояние">
        <Glass className="services">
          <header className="card-head"><span className="kicker">Сервисы</span><button type="button" className="link" onClick={() => onNavigate("services")}>Все цели</button></header>
          <ServiceRow icon="bolt" name="Discord" note={running ? (groups ? `Стратегий по группам: ${groups}` : "Общая стратегия") : "Голос, чат и картинки"} tone={running ? "success" : "neutral"} label={running ? "Под защитой" : "Ожидает"} live={running} onClick={() => onNavigate("services")} />
          <ServiceRow icon="play" name="YouTube" note={yt?.fresh && yt.switches > 0 ? `Автозамен способа: ${yt.switches}` : "Автовосстановление в фоне"} tone={ytTone} label={ytLabel} live={active && (ytTone === "success" || ytTone === "accent")} onClick={() => onNavigate("settings")} />
          <ServiceRow icon="send" name="Telegram" note={tg?.running ? (tg.route || "Локальный прокси готов") : "Встроенный прокси"} tone={tgBadge.tone} label={tgBadge.label} live={!!tg?.running} onClick={() => onNavigate("telegram")} />
          <ServiceRow icon="game" name="Игры" note={games?.armed ? "Включится вместе с игрой" : "Только выбранные игры"} tone={gameOn ? "success" : games?.armed ? "accent" : "neutral"} label={games?.armed && !gameOn ? "Ждёт игру" : gameStatus(games, false)} live={gameOn} onClick={() => onNavigate("games")} />
        </Glass>

        <div className="stats">
          <Glass className="stat"><span className="kicker">Сессия</span><strong className="stat__num stat__num--mono">{elapsed}</strong><small>{state?.engine.pid ? `PID ${state.engine.pid}` : "движок остановлен"}</small></Glass>
          <Glass className="stat"><span className="kicker">ClientHello</span><strong className="stat__num"><Ticker value={(hello?.complete ?? 0) + (hello?.assembled ?? 0)} /></strong><small>{hello && hello.skipped > 0 ? `пропущено ${hello.skipped}` : "обработано соединений"}</small></Glass>
          <Glass className="stat"><span className="kicker">Сторож</span><strong className="stat__num"><Ticker value={state?.engine.restarts ?? 0} /></strong><small>автоподъёмов движка</small></Glass>
        </div>

        {!active && (
          <Disclosure icon="settings" title="Параметры подключения" note={`Голос: ${voiceOptions.find((o) => o.id === options.voice)?.label ?? options.voice} · QUIC: ${quicOptions.find((o) => o.id === options.quic)?.label ?? options.quic}${options.boost ? " · Сильный обход" : ""}`}>
            <Row title="Голос Discord" note="Как прятать голосовой трафик. TTL подходит большинству сетей.">
              <select className="field" aria-label="Голос Discord" value={options.voice} onChange={(e) => update({ voice: e.target.value })}>{voiceOptions.map((o) => <option key={o.id} value={o.id}>{o.label}</option>)}</select>
            </Row>
            <Row title="QUIC" note="Обычно менять не нужно.">
              <Segmented label="QUIC" value={options.quic} options={quicOptions} onChange={(quic) => update({ quic })} />
            </Row>
            <Row title="Telegram-прокси вместе с обходом" note="Чтобы не отвечать на вопрос при каждом включении.">
              <Segmented label="Telegram-прокси" value={tgMode} options={telegramModes} onChange={(v) => { setTgMode(v); savePreference("evasion-connect-telegram", v); }} />
            </Row>
            <Row title="Сильный обход сразу" note="Без прогрева от базового: YouTube стартует с сильного профиля, QUIC блокируется — видео грузится сразу. Автовосстановление продолжает работать.">
              <Toggle label="Сильный обход сразу" checked={options.boost} onChange={(v) => update({ boost: v })} />
            </Row>
            <Row title="Перезапускать Discord при включении" note="Клиент стартует с выключенным DoH — так обход цепляется надёжнее."><Toggle label="Перезапускать Discord" checked={options.restartDiscord} onChange={(v) => update({ restartDiscord: v })} /></Row>
            <Row title="Только наблюдать" note="Движок смотрит на трафик, но ничего не меняет."><Toggle label="Только наблюдать" checked={options.observe} onChange={(v) => update({ observe: v })} /></Row>
          </Disclosure>
        )}

        <Disclosure icon="pulse" title="Активность" note={logs.length ? `Событий в журнале: ${logs.length}` : "Здесь появятся события подключения"} defaultOpen={active}>
          {running && hello && (
            <div className="hello">
              <div><strong><Ticker value={hello.complete} /></strong><span>целых</span></div>
              <div><strong><Ticker value={hello.assembled} /></strong><span>собрано</span></div>
              <div className={hello.skipped > 0 ? "hello--warn" : ""}><strong><Ticker value={hello.skipped} /></strong><span>пропущено</span></div>
              <div><strong><Ticker value={hello.retransmits} /></strong><span>повторов</span></div>
            </div>
          )}
          {running && hello?.reasons && <Note>Причины пропусков: {hello.reasons}</Note>}
          <Feed logs={logs} />
        </Disclosure>

        <footer className="home__foot">
          <Button kind="ghost" icon="refresh" disabled={busy} onClick={() => void restartDiscord()}>Перезапустить Discord</Button>
          <span>{state?.engine.discord || "Evasion работает локально на вашем устройстве"}</span>
        </footer>
      </section>
    </div>
  );
}

function ServiceRow({ icon, name, note, tone, label, live, onClick }: { icon: IconName; name: string; note: string; tone: Tone; label: string; live: boolean; onClick: () => void }) {
  return (
    <button type="button" className={`service service--${tone}${live ? " service--live" : ""}`} onClick={onClick}>
      <span className="service__icon"><i /><i /><Icon name={icon} size={17} /></span>
      <span className="service__text"><strong>{name}</strong><small>{note}</small></span>
      <Badge tone={tone}>{label}</Badge>
    </button>
  );
}
