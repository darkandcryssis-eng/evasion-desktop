import {
  Activity,
  AlertTriangle,
  Eye,
  Power,
  RefreshCw,
  ChevronDown,
  SlidersHorizontal,
  type LucideIcon,
} from "lucide-react";
import { useConnectionOptions } from "../preferences";
import { InfoLabel } from "../components/InfoLabel";
import { Select } from "../components/Select";
import { LogFeed } from "../components/LogFeed";
import { Disclosure } from "../components/Disclosure";
import { type EnginePhase, type StartOptions } from "../api";
import type { EngineController } from "../useEngine";
import { TelegramStatus } from "../components/TelegramStatus";
import { OrbitLoader } from "../components/OrbitLoader";

type OverviewScreenProps = {
  engine: EngineController;
  motion: boolean;
  onConnectRequested: (options: StartOptions) => void;
 onDiagnosticsRequested:()=>void;
};

const voiceOptions = [
  { id: "ttl", label: "TTL (по умолчанию)", desc: "Ложные пакеты с коротким TTL перед настоящим. Подходит большинству — ставь это." },
  { id: "badsum", label: "Bad checksum", desc: "Ложные пакеты с неверной контрольной суммой. Если TTL не помог." },
  { id: "ttl-quic", label: "TTL + QUIC-ловушки", desc: "TTL плюс QUIC-приманки. Для сетей, где режут и то, и другое." },
  { id: "badsum-quic", label: "Bad checksum + QUIC", desc: "Bad checksum плюс QUIC-приманки. Запасной вариант." },
  { id: "off", label: "Выключить", desc: "Не трогать голос. Если и так работает или мешает." },
];

const quicOptions = [
  { id: "off", label: "Не трогать", desc: "Не вмешиваться в QUIC. Обычный выбор — приложение само договорится." },
  { id: "block", label: "Блокировать", desc: "Резать QUIC. Иногда помогает, но может порвать связь — осторожно." },
  { id: "desync", label: "Десинхронизация", desc: "Рассинхронизировать QUIC. Экспериментально." },
];

const phaseHint: Record<EnginePhase, string> = {
  stopped: "Параметры готовы. Можно включать.",
  starting: "Настраиваем соединение…",
  running: "Можно свернуть окно — Evasion продолжит работу",
  stopping: "Завершаем работу…",
  failed: "Проверьте сообщение об ошибке",
};

const connectionLabel: Record<EnginePhase, string> = {
  stopped: "Готов к запуску",
  starting: "Включаем Evasion",
  running: "Evasion включён",
  stopping: "Завершаем работу",
  failed: "Не удалось включить",
};

type ChipProps = { active: boolean; onClick: () => void; icon: LucideIcon; label: string };

function ToggleChip({ active, onClick, icon: Icon, label }: ChipProps) {
  return (
    <button type="button" className={`chip${active ? " chip--on" : ""}`} aria-pressed={active} onClick={onClick}>
      <Icon size={15} strokeWidth={1.8} />
      <span>{label}</span>
    </button>
  );
}

export function OverviewScreen({ engine, motion, onConnectRequested, onDiagnosticsRequested }: OverviewScreenProps) {
  const { state, busy, error, stop, restartDiscord } = engine;
  const logs = [...(state?.engine.logs ?? []), ...(state?.telegram?.logs ?? [])].sort((a, b) => (Date.parse(a.at) || 0) - (Date.parse(b.at) || 0)).slice(-400);
  const [options, update] = useConnectionOptions();
  const { voice, quic, observe, restartDiscord: restart } = options;
  const setVoice = (voice: string) => update({ voice });
  const setQuic = (quic: string) => update({ quic });

  const phase: EnginePhase = state?.engine.phase ?? "stopped";
  const running = phase === "running" || phase === "starting" || phase === "stopping";
  const transitional = phase === "starting" || phase === "stopping";

  const onStart = () => {
    const opts: StartOptions = { ...options, voice, quic, observe, restartDiscord: restart };
    onConnectRequested(opts);
  };

  return (
    <div className="screen screen--overview">
      <section className="connection-stage" aria-label="Управление подключением">
        <span className={`connection-status connection-status--${phase}`} aria-live="polite">
          <i />{state ? connectionLabel[phase] : "Получаем состояние…"}
        </span>
        <h1>Ваш интернет.<br /><em>Свободнее.</em></h1>
        <p className="connection-description">Привычные сайты и общение.<br className="small-break" /> Без лишних преград.</p>
        <button
          className={`connection-button connection-button--${phase}`}
          type="button"
          aria-keyshortcuts="Control+Enter"
          aria-label={running ? "Остановить Evasion" : "Включить Evasion"}
          disabled={busy || transitional || (!running && !state?.payload.engine)}
          aria-busy={busy || transitional}
          onClick={running ? () => void stop() : onStart}
        >
          <span className="connection-button__orb" aria-hidden="true"><span className="connection-button__lens" /><span className="connection-button__caustic" />{busy || transitional ? <OrbitLoader className="connection-button__loader" /> : <Power size={32} strokeWidth={1.25} />}</span>
        </button>
        <p className="connection-hint">{state ? phaseHint[phase] : "Получаем состояние приложения"}</p>
        <div className="connection-notices">
          {state && !state.elevated && <div className="info-banner info-banner--warn"><AlertTriangle size={15} /><span>Для работы нужны права администратора. Запустите Evasion от имени администратора.</span></div>}
          {state && !state.payload.engine && <div className="info-banner info-banner--warn"><AlertTriangle size={15} /><span>Движок не встроен в сборку. Пересоберите через ui\build-and-run.bat.</span></div>}
          {error && <div className="info-banner info-banner--warn"><AlertTriangle size={15} /><span>{error}</span>{error.toLowerCase().includes("windivert") && <button className="quiet-button" type="button" onClick={onDiagnosticsRequested}>Диагностика драйвера</button>}</div>}
        </div>
      </section>
      <TelegramStatus compact state={state?.telegram} motion={motion} onRefresh={engine.refresh} />
      <div className={`connection-panels${running ? " connection-panels--running" : ""}`}>
        {!running && (
          <Disclosure summary={<>
              <SlidersHorizontal size={18} strokeWidth={1.5} />
              <span><strong>Параметры подключения</strong><small>Голос: {voice === "ttl" ? "TTL" : voiceOptions.find((o) => o.id === voice)?.label} · QUIC: {quic === "off" ? "без изменений" : quicOptions.find((o) => o.id === quic)?.label}</small></span>
              <ChevronDown size={15} className="disclosure__chevron" />
          </>}>
            <div className="disclosure__body">
              <div className="control-row">
                <span className="control-row__label"><InfoLabel tip="Как прятать голосовой трафик Discord от DPI. TTL — проверенный вариант по умолчанию, работает в большинстве сетей.">Голос Discord</InfoLabel></span>
                <Select value={voice} options={voiceOptions} onChange={setVoice} />
              </div>
              <div className="control-row">
                <span className="control-row__label"><InfoLabel tip="Обычно можно оставить «Не трогать». Блокировка и десинхронизация QUIC нужны только для отдельных сетей.">QUIC</InfoLabel></span>
                <Select value={quic} options={quicOptions} onChange={setQuic} />
              </div>
              <div className="connection-options">
                <ToggleChip active={observe} onClick={() => update({ observe: !observe })} icon={Eye} label="Только наблюдать" />
                <ToggleChip active={restart} onClick={() => update({ restartDiscord: !restart })} icon={RefreshCw} label="Перезапустить Discord при включении" />
              </div>
            </div>
          </Disclosure>
        )}
        <Disclosure className="disclosure--activity" summary={<>
            <Activity size={18} strokeWidth={1.5} />
            <span><strong>Активность</strong><small>{logs.length ? `Событий в журнале: ${logs.length}` : "Здесь появятся события подключения"}</small></span>
            <ChevronDown size={15} className="disclosure__chevron" />
        </>}>
          <div className="disclosure__body">
            {state?.engine.pid ? <p className="connection-pid">Процесс {state.engine.pid}</p> : null}
            {running && state?.engine.hello && (
              <section className="hello-card">
                <span className="card-label">Разбор ClientHello</span>
                <div className="hello-grid">
                  <div><strong>{state.engine.hello.complete}</strong><span>целых</span></div>
                  <div><strong>{state.engine.hello.assembled}</strong><span>собрано</span></div>
                  <div className={state.engine.hello.skipped > 0 ? "hello-grid__warn" : ""}><strong>{state.engine.hello.skipped}</strong><span>пропущено</span></div>
                  <div><strong>{state.engine.hello.retransmits}</strong><span>повторов</span></div>
                </div>
                {state.engine.hello.reasons && <small>Причины пропусков: {state.engine.hello.reasons}</small>}
              </section>
            )}
            <LogFeed logs={logs} motion={motion} />
          </div>
        </Disclosure>
      </div>
      <div className="connection-footer">
        <button className="ghost-button" type="button" onClick={() => void restartDiscord()} disabled={busy}><RefreshCw size={12} />Перезапустить Discord</button>
        <span>{state?.engine.discord || "Evasion работает локально на вашем устройстве"}</span>
      </div>
    </div>
  );
}
