import { Activity, Copy, ExternalLink, RefreshCw, Send } from "lucide-react";
import { useState } from "react";
import { ClipboardSetText } from "../../wailsjs/runtime/runtime";
import { api, type TelegramState } from "../api";
import { LogFeed } from "./LogFeed";
import { Disclosure } from "./Disclosure";
import { telegramBadge } from "../telegramBadge";

export { telegramPhase } from "../telegramBadge";

export function traffic(bytes: number) {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 Б";
  const units = ["Б", "КБ", "МБ", "ГБ"];
  const index = Math.min(3, Math.floor(Math.log(bytes) / Math.log(1024)));
  return `${(bytes / 1024 ** index).toLocaleString("ru", { maximumFractionDigits: index ? 1 : 0 })} ${units[index]}`;
}

export function TelegramStatus({ state, motion, compact = false, onRefresh }: { state?: TelegramState; motion: boolean; compact?: boolean; onRefresh: () => unknown }) {
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");
  const action = async (kind: "open" | "copy" | "stop") => {
    if (busy) return;
    setBusy(true); setNotice("");
    try {
      if (kind === "open") await api.openTelegramProxy();
      if (kind === "stop") await api.stopTelegramProxy();
      if (kind === "copy") {
        const copied = await ClipboardSetText(state?.link || "");
        setNotice(copied ? "Ссылка скопирована" : "Не удалось скопировать ссылку");
      }
      onRefresh();
    } catch (e) { setNotice(String(e)); }
    finally { setBusy(false); }
  };
  if (!state || (compact && !state.running && !state.error)) return null;
  const badge = telegramBadge(state);
  return (
    <section className={`telegram-status-card${compact ? " telegram-status-card--compact" : ""}`} aria-label="Состояние Telegram">
      <div className="telegram-status-heading"><div><Send size={17} /><strong>Telegram</strong><span className={`status-badge status-badge--${badge.tone}`} role="status">{badge.label}</span></div><span className="telegram-route">{state.route || (state.running ? "Локальный прокси готов" : "Подключение выключено")}</span></div>
      <div className="telegram-metrics">
        <div><strong>{state.active || 0}</strong><span>активных соединений</span></div>
        <div><strong>{traffic(state.bytesDown)}</strong><span>получено</span></div>
        <div><strong>{traffic(state.bytesUp)}</strong><span>отправлено</span></div>
        <div><strong>{state.failures || 0}</strong><span>ошибок за сеанс</span></div>
      </div>
      {!compact && <div className="telegram-session-details"><span>Всего соединений: {state.connections || 0}</span><span>Установка канала: {state.route ? state.dialMs ? `${state.dialMs} мс` : "<1 мс" : "—"}</span><span>Последние данные: {state.lastDataAt ? new Date(state.lastDataAt).toLocaleTimeString("ru") : "—"}</span></div>}
      {!state.running && state.error && <p className="local-note" role="status">{state.error}</p>}
      {state.running && <div className="telegram-inline-actions"><button className="secondary-button" disabled={busy} type="button" onClick={() => void action("open")}><ExternalLink size={13} />Подключить в Telegram</button><button className="quiet-button" disabled={busy || !state.link} type="button" onClick={() => void action("copy")}><Copy size={13} />Скопировать ссылку</button>{compact && <button className="ghost-button" disabled={busy} type="button" onClick={() => void action("stop")}>Выключить прокси</button>}</div>}
      {notice && <p className="local-note" role="status">{notice}</p>}
      {!compact && <Disclosure summary={<><Activity size={17} /><span><strong>Активность Telegram</strong><small>Подключения, маршруты и ошибки</small></span><RefreshCw size={14} /></>}><div className="disclosure__body"><LogFeed logs={state.logs || []} motion={motion} /></div></Disclosure>}
      {state.running && state.phase === "waiting" && <p className="local-note">Нажмите «Подключить в Telegram» и подтвердите прокси в клиенте. Статус изменится после реального обмена данными.</p>}
    </section>
  );
}
