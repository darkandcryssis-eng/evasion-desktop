import { Activity, ArrowDownLeft, ArrowUpRight, History, Network, RefreshCw } from "lucide-react";
import { useEffect, useId, useState } from "react";
import { api, type SpeedSample, type TelegramDisconnect, type TelegramRoute } from "../api";
import { speedChart } from "../speedChart";
import { StatusBadge } from "./StatusBadge";
import { traffic } from "./TelegramStatus";

const routeLabels: Record<string, string> = { untested: "Не проверен", checking: "Проверка", verified: "Telegram ответил", opened: "Канал открыт", cooldown: "Пауза после сбоя", failed: "Нет ответа" };
const causeLabels: Record<string, string> = { reset: "Сброс TCP", timeout: "Таймаут", eof: "Закрыт каналом", ws_close: "Закрыт WS", tls: "Ошибка TLS", dns: "Ошибка DNS", mtproto: "Сбой MTProto", cancelled: "Отменено", error: "Ошибка" };

export function SpeedGraph({ samples = [], running }: { samples?: SpeedSample[]; running: boolean }) {
  const chart = speedChart(samples);
  const gradient = `traffic-${useId().replace(/:/g, "")}`;
  return <section className="insight-panel speed-panel" aria-label="Скорость Telegram">
    <div className="insight-heading"><div><Activity size={16} /><strong>Поток данных</strong></div><span>Telegram · последние 2 минуты</span></div>
    <div className="speed-readings"><div><ArrowDownLeft size={15} /><strong>{traffic(running ? chart.current?.down || 0 : 0)}<small>/с</small></strong><span>получение</span></div><div><ArrowUpRight size={15} /><strong>{traffic(running ? chart.current?.up || 0 : 0)}<small>/с</small></strong><span>отправка</span></div></div>
    <div className="speed-plot"><span className="speed-scale">{traffic(chart.scale)}/с</span><svg viewBox="0 0 600 112" preserveAspectRatio="none" role="img" aria-label={chart.count ? "График получения и отправки данных Telegram" : "Нет измерений скорости"}>
      <defs><linearGradient id={gradient} x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="var(--traffic-down)" stopOpacity=".2" /><stop offset="100%" stopColor="var(--traffic-down)" stopOpacity="0" /></linearGradient></defs>
      {[8, 56, 104].map((y) => <line key={y} x1="0" x2="600" y1={y} y2={y} className="speed-grid" />)}
      {chart.count > 1 && <><polygon points={`${chart.down.split(" ")[0].split(",")[0]},104 ${chart.down} 600,104`} fill={`url(#${gradient})`} /><polyline points={chart.down} className="speed-line speed-line--down" /><polyline points={chart.up} className="speed-line speed-line--up" /></>}
    </svg>{chart.count < 2 && <span className="speed-empty">{running ? "Собираем первые измерения…" : "Включите Telegram, чтобы видеть скорость"}</span>}</div>
    <div className="speed-axis"><span>−2 мин</span><span>−1 мин</span><span>сейчас</span></div>
    <p className="local-note">Трафик встроенного прокси, а не скорость всего интернета. Без тестовых загрузок.</p>
  </section>;
}

export function RoutePanel() {
  const [routes, setRoutes] = useState<TelegramRoute[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => {
    let disposed = false, pending = false;
    const load = async () => { if (pending) return; pending = true; try { const value = await api.getTelegramRoutes(); if (!disposed) setRoutes(value || []); } catch { if (!disposed) setError("Не удалось получить состояние маршрутов"); } finally { pending = false; } };
    void load(); const timer = window.setInterval(() => void load(), 2000);
    return () => { disposed = true; window.clearInterval(timer); };
  }, []);
  const check = async () => { setBusy(true); setError(""); try { setRoutes(await api.checkTelegramRoutes()); } catch (e) { setError(String(e)); } finally { setBusy(false); } };
  return <section className="insight-panel route-panel" aria-label="Состояние резервных маршрутов">
    <div className="insight-heading"><div><Network size={16} /><strong>Маршруты Telegram</strong></div><button className="quiet-button" type="button" disabled={busy} onClick={() => void check()}><RefreshCw size={13} className={busy ? "spin-icon" : ""} />{busy ? "Проверяем…" : "Проверить резерв"}</button></div>
    <p className="local-note">Проверка DC2 без входа в аккаунт. Открытый WSS ещё не подтверждает ответ Telegram.</p>
    {routes.length === 0 && <p className="route-empty">Запустите проверку — здесь появится состояние прямых и резервных каналов.</p>}
    <div className="route-list">{routes.map((r) => <div className="route-row" key={r.id}><div><strong>{r.host}</strong><span>{r.kind}{typeof r.stability === "number" ? ` · стабильность ${r.stability}%` : ""}{r.drops ? ` · обрывов ${r.drops}` : ""}{r.checkedAt ? ` · ${new Date(r.checkedAt).toLocaleTimeString("ru", { hour: "2-digit", minute: "2-digit" })}` : ""}</span>{r.reason && (r.status === "failed" || r.status === "cooldown") && <span className="route-reason">{r.reason}</span>}</div><span className="route-latency">{r.latencyMs > 0 ? `${r.latencyMs} мс` : "—"}</span><StatusBadge tone={r.status === "verified" ? "success" : r.status === "failed" || r.status === "cooldown" ? "warning" : "neutral"}>{routeLabels[r.status] || "Не проверен"}</StatusBadge></div>)}</div>
    {error && <p className="local-note" role="alert">{error}</p>}
  </section>;
}

export function DisconnectJournalPanel({ disconnects = [], switches = 0 }: { disconnects?: TelegramDisconnect[]; switches?: number }) {
  const recent = disconnects.slice(0, 12);
  return <section className="insight-panel route-panel" aria-label="Журнал обрывов Telegram">
    <div className="insight-heading"><div><History size={16} /><strong>Журнал обрывов</strong></div><span>Бесшовных переключений: {switches}</span></div>
    {recent.length === 0 ? <p className="route-empty">Обрывов пока не зафиксировано. При сбое здесь появится причина (сброс, таймаут), маршрут и результат переключения.</p> :
      <div className="route-list">{recent.map((d, i) => <div className="route-row" key={`${d.at}-${i}`}><div><strong>{causeLabels[d.cause] || d.cause} · {d.routeLabel || d.route}</strong><span>{d.transport.toUpperCase()} · DC{d.dc}{d.media ? " media" : ""} · {d.durationMs > 0 ? `${Math.round(d.durationMs / 1000)} с` : "старт"}{d.at ? ` · ${new Date(d.at).toLocaleTimeString("ru", { hour: "2-digit", minute: "2-digit", second: "2-digit" })}` : ""}</span>{d.replacementRoute && <span className="route-reason">Переключён на {d.replacementRoute}</span>}</div><StatusBadge tone={d.recovered ? "success" : "warning"}>{d.recovered ? "Переключён" : "Обрыв"}</StatusBadge></div>)}</div>}
  </section>;
}
