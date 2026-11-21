import { Boxes, RefreshCw } from "lucide-react";
import { useEffect, useState } from "react";
import { PageHeader } from "../components/PageHeader";
import { StatusBadge } from "../components/StatusBadge";
import { api, type DiagnosticTone, type PortfolioView } from "../api";

const statusTone = (s: string): DiagnosticTone => {
  if (s === "active") return "success";
  if (s === "testing" || s === "candidate") return "accent";
  return "neutral";
};

export function PortfolioScreen() {
  const [view, setView] = useState<PortfolioView | null>(null);
  const [error, setError] = useState("");

  const load = async () => {
    try {
      setView(await api.getPortfolio());
      setError("");
    } catch (e) {
      setError(String(e));
    }
  };

  useEffect(() => {
    void load();
  }, []);

  const holdings = view?.holdings ?? [];
  const active = holdings.filter((h) => h.status === "active").length;

  return (
    <div className="screen">
      <PageHeader
        title="Стратегии"
        description="Стратегии и результаты автоматического подбора"
        badge={view?.found ? "Автопилот" : "Нет данных"}
        action={<button className="icon-action" type="button" aria-label="Обновить" onClick={() => void load()}><RefreshCw size={15} /></button>}
      />

      {error && <div className="info-banner info-banner--warn"><span>{error}</span></div>}

      <div className="stat-strip">
        <div className="stat-item"><strong>{holdings.length}</strong><span>Всего</span></div>
        <div className="stat-item"><strong>{active}</strong><span>Активны</span></div>
        <div className="stat-item"><strong>{holdings.length - active}</strong><span>В проверке</span></div>
      </div>

      {holdings.length === 0 ? (
        <div className="empty-state">
          <div className="empty-state__icon"><Boxes size={22} strokeWidth={1.5} /></div>
          <strong>Портфель пуст</strong>
          <p>Здесь появятся стратегии при работе в режиме автопилота. В обычном режиме Evasion использует стратегии из конфигурации.</p>
        </div>
      ) : (
        <div className="target-list">
          {holdings.map((h) => (
            <article className="target-row" key={h.strategy_id}>
              <div className="target-row__copy">
                <strong className="mono">{h.strategy_id}</strong>
                <small>{h.observations} наблюдений · {h.targets} целей</small>
              </div>
              <StatusBadge tone={statusTone(h.status)}>{h.status}</StatusBadge>
            </article>
          ))}
        </div>
      )}
    </div>
  );
}
