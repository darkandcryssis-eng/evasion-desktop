import { ChevronDown, Download, RefreshCw, ShieldCheck, Stethoscope } from "lucide-react";
import { useEffect, useState } from "react";
import { PageHeader } from "../components/PageHeader";
import { AnimatedCollapse } from "../components/AnimatedCollapse";
import { StatusBadge } from "../components/StatusBadge";
import { api, type DiagnosticItem, type DiagnosticTone, type DoctorCheck, type ServiceDiagnostic } from "../api";

const serviceNames = [ ["telegram", "Telegram · протокол"], ["telegram-web", "Telegram · веб-доступ"], ["discord-api", "Discord · API"], ["discord-gateway", "Discord · события"] ];
const stageNames: Record<string, string> = { dns: "DNS", tcp: "TCP", tls: "TLS", https: "HTTPS", gateway: "WebSocket", mtproto: "MTProto" };

const doctorTone = (status: string): DiagnosticTone => {
  switch (status) {
    case "ok":
      return "success";
    case "warn":
      return "warning";
    case "fail":
      return "warning";
    default:
      return "neutral";
  }
};

export function DiagnosticsScreen() {
  const [items, setItems] = useState<DiagnosticItem[]>([]);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [checks, setChecks] = useState<DoctorCheck[] | null>(null);
  const [doctorError, setDoctorError] = useState("");
  const [doctorBusy, setDoctorBusy] = useState(false);
  const [services, setServices] = useState<ServiceDiagnostic[]>([]);
  const [serviceBusy, setServiceBusy] = useState(false);
  const [exportBusy, setExportBusy] = useState(false);
  const [notice, setNotice] = useState("");

  const load = async () => {
    try {
      setItems(await api.getDiagnostics());
      setServices(await api.getServiceDiagnostics() || []);
    } catch (e) {
      setDoctorError(String(e));
    }
  };

  const checkServices = async () => {
    setServiceBusy(true); setNotice("");
    try { setServices(await api.runServiceDiagnostics()); await load(); }
    catch (e) { setNotice(String(e)); }
    finally { setServiceBusy(false); }
  };
  const exportReport = async () => {
    setExportBusy(true); setNotice("");
    try { const path = await api.exportDiagnosticReport(); if (path) { setNotice(`Отчёт сохранён: ${path.split(/[\\/]/).pop()}`); await load(); } }
    catch (e) { setNotice(String(e)); }
    finally { setExportBusy(false); }
  };

  useEffect(() => {
    void load();
  }, []);

  const runDoctor = async () => {
    setDoctorBusy(true);
    setDoctorError("");
    try {
      setChecks(await api.runDoctor());
    } catch (e) {
      setDoctorError(String(e));
    } finally {
      setDoctorBusy(false);
    }
  };

  return (
    <div className="screen">
      <PageHeader
        title="Диагностика"
        description="Где прервалась связь и что поможет её вернуть"
        action={
          <button className="secondary-button" type="button" onClick={() => void checkServices()} disabled={serviceBusy}>
            <Stethoscope size={14} />{serviceBusy ? "Проверяем…" : "Проверить связь"}
          </button>
        }
      />

      <div className="service-grid" aria-busy={serviceBusy}>
        {serviceNames.map(([id, name]) => {
          const result = services.find((s) => s.id === id);
          return <article className={`service-card${result?.status === "fail" ? " service-card--attention" : ""}`} key={id}>
            <div className="insight-heading"><strong>{name}</strong><StatusBadge tone={serviceBusy ? "accent" : result?.status === "ok" ? "success" : result?.status === "fail" ? "warning" : "neutral"}>{serviceBusy ? "Проверяем" : result?.status === "ok" ? "Доступен" : result ? "Нужна проверка" : "Не проверен"}</StatusBadge></div>
            <p className="service-summary">{result?.summary || "Нажмите «Проверить связь»"}</p>
            <div className="service-stages">{(result?.steps || []).map((step) => <span className={`service-stage service-stage--${step.status}`} key={step.id}><i />{stageNames[step.id] || step.id}<small>{step.status === "ok" ? `${step.ms} мс` : "сбой"}</small></span>)}</div>
            {result?.advice && <p className="local-note">{result.advice}</p>}
            {result?.checkedAt && <time className="service-checked" dateTime={result.checkedAt}>Проверено в {new Date(result.checkedAt).toLocaleTimeString("ru")}</time>}
          </article>;
        })}
      </div>
      {serviceBusy && <p className="local-note" role="status">Проверяем публичные адреса и ответы протоколов. Обычно до 16 секунд.</p>}
      <div className="report-panel"><ShieldCheck size={19} /><div><strong>Отчёт без секретов</strong><p>Результаты, состояния маршрутов и счётчики. Без ключей, ссылок прокси, конфигов, журналов и личных путей.</p></div><button className="quiet-button" type="button" onClick={() => void exportReport()} disabled={exportBusy || serviceBusy}><Download size={14} />{exportBusy ? "Сохранение…" : "Экспорт JSON"}</button></div>
      {notice && <p className="local-note" role="status">{notice}</p>}

      <div className="insight-heading system-check-heading"><strong>Готовность приложения</strong><button className="quiet-button" type="button" onClick={() => void runDoctor()} disabled={doctorBusy}><Stethoscope size={13} />{doctorBusy ? "Проверка…" : "Проверить движок"}</button></div>

      <div className="diagnostic-list">
        {items.map((item) => {
          const isExpanded = expanded === item.name;
          return (
            <article className={`diagnostic-row${isExpanded ? " diagnostic-row--expanded" : ""}`} key={item.name}>
              <button type="button" aria-expanded={isExpanded} onClick={() => setExpanded(isExpanded ? null : item.name)}>
                <span>{item.name}</span>
                <span className="diagnostic-row__status">
                  <StatusBadge tone={item.tone}>{item.status}</StatusBadge>
                  <ChevronDown className="diagnostic-row__chevron" size={14} />
                </span>
              </button>
              <AnimatedCollapse open={isExpanded}><p>{item.detail}</p></AnimatedCollapse>
            </article>
          );
        })}
      </div>

      {doctorError && <div className="info-banner info-banner--warn"><span>{doctorError}</span></div>}

      {checks && (
        <section className="settings-section settings-section--compact">
          <div className="section-caption"><RefreshCw size={13} />Результаты проверки</div>
          {checks.length === 0 && <p className="local-note">Проверок нет.</p>}
          {checks.map((c) => (
            <div className="setting-row" key={c.id}>
              <div><strong>{c.id}</strong>{c.reason && <small>{c.reason}</small>}</div>
              <StatusBadge tone={doctorTone(c.status)}>{c.status}</StatusBadge>
            </div>
          ))}
        </section>
      )}
    </div>
  );
}
