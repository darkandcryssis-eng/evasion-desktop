import { useState } from "react";
import { api, type EnginePhase, type NetworkTuningView, type StartOptions } from "../api";
import type { EngineController } from "../useEngine";
import { useConnectionOptions, readPreference, savePreference } from "../preferences";
import { telegramBadge } from "../telegramBadge";
import { useElapsed, usePoll } from "../hooks";
import { AsciiBloom } from "../fx/AsciiBloom";
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
  stopped: ["Интернет.", "Без границ."],
  starting: ["Настраиваем", "соединение…"],
  running: ["Вы на связи.", "Без границ."],
  stopping: ["Сворачиваем", "обход…"],
  failed: ["Что-то пошло", "не так."],
};
const hint: Record<EnginePhase, string> = {
  stopped: "Прямое соединение. Без лишних посредников.",
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

type Props = { motion: boolean; engine: EngineController; onConnect: (o: StartOptions) => void; onNavigate: (p: Page) => void };

export function HomeScreen({ engine, motion, onConnect, onNavigate }: Props) {
  const { state, busy, error, stop, reconnect, restartDiscord } = engine;
  const [options, update] = useConnectionOptions();
  const [tgMode, setTgMode] = useState<TelegramMode>(telegramMode);
  const phase: EnginePhase = state?.engine.phase ?? "stopped";
  const running = phase === "running";
  const active = running || phase === "starting" || phase === "stopping";
  const transit = phase === "starting" || phase === "stopping";
  // WinDivert may be installed in runtime even when it isn't embedded.
  // The backend validates installed driver files when starting the engine.
  const ready = !!state && state.elevated && state.payload.engine && (state.payload.config || state.userConfig);
  const elapsed = useElapsed(state?.engine.startedAt, running);
  const tuning = usePoll<NetworkTuningView>(() => api.getNetworkTuning(options), 3000).value;

  const logs = [...(state?.engine.logs ?? []), ...(state?.telegram?.logs ?? [])].sort((a, b) => (Date.parse(a.at) || 0) - (Date.parse(b.at) || 0)).slice(-400);
  const hello = state?.engine.hello;
  const tg = state?.telegram;
  const tgBadge: { label: string; tone: Tone } = tg ? telegramBadge(tg) : { label: "Выключен", tone: "neutral" };
  const yt = tuning?.health;
  const ytState: [string, Tone] = !active ? ["Ждёт включения обхода", "neutral"] : ytPhase[yt?.fresh ? yt.phase : "waiting"] ?? ["Проверяется", "neutral"];
  const [ytLabel, ytTone] = ytState;

  const press = () => {
    if (active) { void stop(); return; }
    onConnect(options);
  };

  return (
    <div className="dashboard">
      <header className="dashboard-heading"><div><span className="kicker">ВАШЕ ЛИЧНОЕ ПРОСТРАНСТВО</span><h2>Хороший день быть на связи<span>.</span></h2></div><span className="edition">[ DIRECT CONNECTION ]</span></header>
      <section className="connection-panel" aria-label="Управление подключением" data-phase={phase}>
        <div className="connection-panel__copy">
          <div className="eyebrow"><span className="signal-bars" aria-hidden="true"><i /><i /><i /><i /></span> СВОБОДА НАЧИНАЕТСЯ ЗДЕСЬ</div>
          <h1 key={phase}>{headline[phase][0]}<br /><span>{headline[phase][1]}</span></h1>
          <p>Ближе к людям. Ближе к тому, что любите.<br />Один клик — и вы снова на связи.</p>
          <div className="connection-panel__controls">
            <button type="button" className="connect-button" disabled={busy || transit || (!active && !ready)} onClick={press}><Icon name={active ? "power" : "up"} size={18} /><span>{transit ? phase === "starting" ? "Подключаем…" : "Отключаем…" : running ? "Отключиться" : phase === "failed" ? "Повторить" : "Подключиться"}</span><span className="connect-button__arrow" aria-hidden="true">↗</span></button>
            {running ? <button type="button" className="reconnect-button" disabled={busy} aria-label="Переподключить" onClick={() => void reconnect()}><Icon name="refresh" size={17} /></button> : <kbd>CTRL + ↵</kbd>}
          </div>
          <div className="connection-panel__state"><Badge tone={state ? statusTone[phase] : "neutral"} pulse={transit || running}>{state ? statusLabel[phase] : "Получаем состояние…"}</Badge><span>{running ? elapsed : "ВАШ МАРШРУТ — ВАШИ ПРАВИЛА"}</span></div>
        </div>
        <AsciiBloom motion={motion} active={running} />
        <div className="connection-panel__foot"><span>Никаких туннелей. Только ваш интернет.</span><span>ASCII / ЖИВАЯ ПРИРОДА <span aria-hidden="true">✳</span></span></div>
      </section>
      <div className="connection-notices">
        {state && !state.elevated && <Note tone="warn" icon="alert">Для подключения запустите Evasion от имени администратора.</Note>}
        {state && !state.payload.engine && <Note tone="warn" icon="alert">Движок не встроен в эту сборку. Пересоберите приложение.</Note>}
        {state && !state.payload.config && !state.userConfig && <Note tone="warn" icon="alert">Не найден конфиг подключения. Откройте диагностику.</Note>}
        {error && <Note tone="warn" icon="alert">{error}</Note>}
      </div>
      <section className="service-section" aria-label="Состояние сервисов">
        <header className="section-heading"><span className="kicker">ПРИВЫЧНЫЕ СЕРВИСЫ. БЕЗ ПРЕГРАД.</span><button type="button" className="link" onClick={() => onNavigate("services")}>Все сервисы <span aria-hidden="true">↗</span></button></header>
        <div className="service-grid">
          <ServiceRow icon="bolt" name="Discord" note="Разговоры, которые не обрываются" tone={running ? "accent" : "neutral"} label={running ? "Обход включён" : "Ждёт подключения"} live={running} onClick={() => onNavigate("services")} />
          <ServiceRow icon="play" name="YouTube" note="Больше того, что вдохновляет" tone={ytTone} label={ytLabel} live={active && (ytTone === "success" || ytTone === "accent")} onClick={() => onNavigate("settings")} />
          <ServiceRow icon="send" name="Telegram" note="Всё важное — на расстоянии сообщения" tone={tgBadge.tone} label={tgBadge.label} live={!!tg?.running} onClick={() => onNavigate("telegram")} />
        </div>
      </section>
      <section className="session-strip" aria-label="Текущая сессия">
        <div><span className="kicker">ВРЕМЯ НА СВЯЗИ</span><strong>{elapsed}</strong></div>
        <div><span className="kicker">ОБРАБОТАНО СОЕДИНЕНИЙ</span><strong><Ticker value={(hello?.complete ?? 0) + (hello?.assembled ?? 0)} /><small> / TCP</small></strong></div>
        <div><span className="kicker">АВТОВОССТАНОВЛЕНИЕ</span><strong><Ticker value={state?.engine.restarts ?? 0} /><small> перезапусков</small></strong></div>
        <button type="button" className="session-strip__action" onClick={() => onNavigate("diagnostics")}><Icon name="pulse" size={18} /><span>Проверить связь</span><span aria-hidden="true">↗</span></button>
      </section>
      <section className="dashboard-details" aria-label="Параметры и журнал">
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
      <span className="service__icon"><Icon name={icon} size={22} /></span><span className="service__arrow" aria-hidden="true">↗</span>
      <span className="service__text"><strong>{name}</strong><small>{note}</small></span>
      <Badge tone={tone}>{label}</Badge>
    </button>
  );
}
