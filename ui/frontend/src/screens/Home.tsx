import { useEffect, useMemo, useState } from "react";
import { api, type EnginePhase, type NetworkTuningView, type StartOptions } from "../api";
import type { EngineController } from "../useEngine";
import { useConnectionOptions, readPreference, savePreference } from "../preferences";
import { connectionLogs } from "../logFlow";
import { useElapsed, usePoll } from "../hooks";
import { PowerOrb, type OrbMode } from "../fx/PowerOrb";
import { LogShowcase, LogStream } from "../components/LogShowcase";
import { BrandLogo, Disclosure, Icon, Note, Row, Segmented, Ticker, Toggle, type BrandName } from "../ui";

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

type Props = { motion: boolean; engine: EngineController; onConnect: (o: StartOptions) => void };

export function HomeScreen({ engine, motion, onConnect }: Props) {
  const { state, busy, error, stop, reconnect } = engine;
  const [options, update] = useConnectionOptions();
  const [tgMode, setTgMode] = useState<TelegramMode>(telegramMode);
  const phase: EnginePhase = state?.engine.phase ?? "stopped";
  const running = phase === "running";
  const active = running || phase === "starting" || phase === "stopping";
  const transit = phase === "starting" || phase === "stopping";
  // WinDivert may be installed in runtime even when it isn't embedded.
  // The backend validates installed driver files when starting the engine.
  const ready = !!state && state.elevated && state.payload.engine && (state.payload.config || state.userConfig);
  const tuning = usePoll<NetworkTuningView>(() => api.getNetworkTuning(options), 3000).value;

  const logs = useMemo(() => connectionLogs(state), [state]);
  const hello = state?.engine.hello;
  const yt = tuning?.health;

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
  // The ring names itself until it is pressed: the hint goes the moment the bypass starts.
  const invite = !!state && !locked && !active && !lit;
  const [lead, strong] = headline[phase];

  return (
    <div className="home">
      <div className="bento">
        <section className="tile hero" aria-label="Управление подключением" data-phase={phase} data-lit={lit || undefined}>
          <div className="hero__copy">
            <h1 aria-live="polite" key={phase}>{state ? <><span>{lead}</span> <strong>{strong}</strong></> : <span>Получаем состояние…</span>}</h1>
            <p key={`hint-${phase}`}>{hint[phase]}</p>
          </div>
          <div className="orbit" aria-hidden="true" data-on={(running && lit) || undefined}>
            {orbit.map((name) => <span className="orbit__lane" key={name}><span className="orbit__mark" data-brand={name}><BrandLogo name={name} size={name === "discord" ? 30 : 28} /></span></span>)}
          </div>
          <button type="button" className="power" aria-label={action} aria-pressed={active} aria-disabled={locked} onClick={press}>
            <PowerOrb mode={orb} motion={motion} />
            <span className="power__hint" aria-hidden="true" data-show={invite || undefined}><Icon name="power" size={22} /><span>{phase === "failed" ? <>Нажмите, чтобы<br />повторить</> : <>Нажмите, чтобы<br />включить</>}</span></span>
          </button>
          <div className="hero__foot">
            {!invite && !running && <span className="hero__action" key={action}>{action}</span>}
            {!active && <span className="hero__keys"><kbd>Ctrl</kbd><kbd>Enter</kbd> быстрое подключение</span>}
            {running && <button type="button" className="ghost-chip" disabled={busy} aria-label="Переподключить" onClick={() => void reconnect()}><Icon name="refresh" size={14} />Переподключить</button>}
          </div>
        </section>

        <section className="tile session" aria-label="Сессия" data-live={running || undefined}>
          <div className="aurora" aria-hidden="true"><i /><i /><i /><i /><i /><i /></div>
          <LogStream logs={logs} live={running} motion={motion} session={state?.engine.startedAt} />
          <LogShowcase>
            <SessionTimer startedAt={state?.engine.startedAt} running={running} />
            <div className="pane__meta">
              <div><strong>{running && hello ? <Ticker value={hello.complete + hello.assembled} /> : "—"}</strong><span>соединений</span></div>
              <div><strong>{yt?.fresh && active ? yt.switches : "—"}</strong><span>замен способа</span></div>
            </div>
          </LogShowcase>
        </section>
      </div>

      <div className="connection-notices">
        {state && !state.elevated && <Note tone="warn" icon="alert">Для подключения запустите Evasion от имени администратора.</Note>}
        {state && !state.payload.engine && <Note tone="warn" icon="alert">Движок не встроен в эту сборку. Пересоберите приложение.</Note>}
        {state && !state.payload.config && !state.userConfig && <Note tone="warn" icon="alert">Не найден конфиг подключения. Откройте диагностику.</Note>}
        {error && <Note tone="warn" icon="alert">{error}</Note>}
      </div>
      <section className="dashboard-details" aria-label="Параметры подключения">
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

        {state?.engine.discord && <footer className="home__foot">{state.engine.discord}</footer>}
      </section>
    </div>
  );
}

const orbit: BrandName[] = ["discord", "youtube", "telegram"];

function SessionTimer({ startedAt, running }: { startedAt?: string; running: boolean }) {
  const elapsed = useElapsed(startedAt, running);
  const [hours, minutes, seconds] = elapsed.split(":");
  return <div className="timer" aria-label={running ? `В сети ${elapsed}` : "Сессия не начата"}>
    <b>{hours}</b><i>:</i><b>{minutes}</b><i>:</i><b>{seconds}</b>
  </div>;
}
