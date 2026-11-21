import { useEffect, useState } from "react";
import { api, type EnginePhase, type NetworkTuningView, type StartOptions } from "../api";
import type { EngineController } from "../useEngine";
import { useConnectionOptions, readPreference, savePreference } from "../preferences";
import { telegramBadge } from "../telegramBadge";
import { useElapsed, usePoll } from "../hooks";
import { PowerOrb, type OrbMode } from "../fx/PowerOrb";
import { Badge, BrandIcon, Button, Disclosure, Feed, Icon, Note, Row, Segmented, Ticker, Toggle, type BrandName, type Tone } from "../ui";
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

// Two-tone headline: a quiet lead-in and the word that matters.
const headline: Record<EnginePhase, [string, string]> = { stopped: ["Всё готово", "к запуску"], starting: ["Секунду,", "соединяем"], running: ["Вы", "подключены"], stopping: ["Возвращаем", "сеть"], failed: ["Не удалось", "подключить"] };
const hint: Record<EnginePhase, string> = {
  stopped: "Включите обход для Discord и YouTube. Остальное настроим за вас.",
  starting: "Это займёт несколько секунд.",
  running: "Можно свернуть окно — обход продолжит работать.",
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

  // The ring answers the press at once; the engine phase takes over when it arrives.
  const [intent, setIntent] = useState<"on" | "off" | null>(null);
  useEffect(() => { if (!busy) setIntent(null); }, [busy, phase]);
  // aria-disabled instead of disabled: the ring keeps keyboard focus while the engine changes state.
  const locked = busy || transit || (!active && !ready);
  const press = () => {
    if (locked) return;
    if (active) { setIntent("off"); void stop(); return; }
    setIntent("on"); onConnect(options);
  };
  const lit = intent === "off" && busy ? false : phase === "starting" || running || (busy && intent === "on");
  const orb: OrbMode = lit ? (running ? "on" : "busy") : phase === "failed" ? "failed" : "off";
  const action = transit ? (phase === "starting" ? "Подключаем…" : "Отключаем…") : running ? "Выключить обход" : phase === "failed" ? "Попробовать снова" : "Включить обход";
  const [lead, strong] = headline[phase];
  const [hours, minutes, seconds] = elapsed.split(":");

  return (
    <div className="home">
      <div className="bento">
        <section className="tile hero" aria-label="Управление подключением" data-phase={phase} data-lit={lit || undefined}>
          <div className="hero__copy">
            <span className="eyebrow"><i />{running ? "Обход работает" : transit ? "Меняем состояние" : "Обход выключен"}</span>
            <h1 aria-live="polite" key={phase}>{state ? <><span>{lead}</span> <strong>{strong}</strong></> : <span>Получаем состояние…</span>}</h1>
            <p key={`hint-${phase}`}>{hint[phase]}</p>
          </div>
          <button type="button" className="power" aria-label={action} aria-pressed={active} title={action} aria-disabled={locked} onClick={press}>
            <PowerOrb mode={orb} motion={motion} />
          </button>
          <div className="hero__foot">
            <span className="hero__action" key={action}>{action}</span>
            <span className="hero__keys">{running ? <>В сети <b>{elapsed}</b></> : <><kbd>Ctrl</kbd><kbd>Enter</kbd> быстрое подключение</>}</span>
            {running && <button type="button" className="ghost-chip" title="Переподключить" disabled={busy} aria-label="Переподключить" onClick={() => void reconnect()}><Icon name="refresh" size={14} />Переподключить</button>}
          </div>
        </section>

        <section className="tile session" aria-label="Сессия" data-live={running || undefined}>
          <div className="aurora" aria-hidden="true"><i /><i /><i /><i /></div>
          <div className="folder">
            <div className="folder__tab"><span>Сессия</span></div>
            <div className="folder__body">
              <div className="timer" aria-label={running ? `В сети ${elapsed}` : "Сессия не начата"}><b>{hours}</b><i>:</i><b>{minutes}</b><i>:</i><b>{seconds}</b></div>
              <div className="folder__meta">
                <div><strong>{running && hello ? <Ticker value={hello.complete + hello.assembled} /> : "—"}</strong><span>соединений</span></div>
                <div><strong>{yt?.fresh && active ? yt.switches : "—"}</strong><span>замен способа</span></div>
              </div>
            </div>
          </div>
        </section>

        <ServiceTile brand="discord" name="Discord" note="Голос · чат · медиа" tone={running ? "success" : "neutral"} label={running ? "Обход включён" : "Ждёт подключения"} live={running} onClick={() => onNavigate("services")} />
        <ServiceTile brand="youtube" name="YouTube" note="Видео · прямые эфиры" tone={ytTone} label={ytLabel} live={active && (ytTone === "success" || ytTone === "accent")} onClick={() => onNavigate("settings")} />
        <ServiceTile brand="telegram" name="Telegram" note="Сообщения · MTProto" tone={tgBadge.tone} label={tgBadge.label} live={!!tg?.running} onClick={() => onNavigate("telegram")} />
        <button type="button" className="tile cta" onClick={() => onNavigate("diagnostics")}>
          <span className="cta__arrow" aria-hidden="true"><Icon name="up" size={18} /></span>
          <span className="cta__text"><small>Что-то не работает?</small><strong>Проверить связь</strong></span>
        </button>
      </div>

      <div className="connection-notices">
        {state && !state.elevated && <Note tone="warn" icon="alert">Для подключения запустите Evasion от имени администратора.</Note>}
        {state && !state.payload.engine && <Note tone="warn" icon="alert">Движок не встроен в эту сборку. Пересоберите приложение.</Note>}
        {state && !state.payload.config && !state.userConfig && <Note tone="warn" icon="alert">Не найден конфиг подключения. Откройте диагностику.</Note>}
        {error && <Note tone="warn" icon="alert">{error}</Note>}
      </div>
      <section className="dashboard-details" aria-label="Параметры и журнал">
        {!active && (
          <Disclosure icon="settings" title="Дополнительные параметры" note="Для большинства сетей менять ничего не нужно">
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

        <Disclosure icon="pulse" title="Журнал подключения" note={logs.length ? `Событий: ${logs.length}` : "События и техническая информация"}>
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

function ServiceTile({ brand, name, note, tone, label, live, onClick }: { brand: BrandName; name: string; note: string; tone: Tone; label: string; live: boolean; onClick: () => void }) {
  return (
    <button type="button" className={`tile service service--${tone}${live ? " service--live" : ""}`} onClick={onClick}>
      <span className="service__top"><span className="service__icon" aria-hidden="true"><BrandIcon name={brand} size={brand === "telegram" ? 17 : 19} /></span><span className="service__arrow" aria-hidden="true"><Icon name="up" size={15} /></span></span>
      <span className="service__text"><strong>{name}</strong><small>{note}</small></span>
      <Badge tone={tone} pulse={live}>{label}</Badge>
    </button>
  );
}
