import { RefreshCw, Search } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { PageHeader } from "../components/PageHeader";
import { StatusBadge } from "../components/StatusBadge";
import { api, type TargetGroup } from "../api";

export function TargetsScreen() {
  const [query, setQuery] = useState("");
  const [groups, setGroups] = useState<TargetGroup[]>([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  const load = async () => {
    setLoading(true);
    try {
      setGroups(await api.getTargets());
      setError("");
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void load();
  }, []);

  const filtered = useMemo(() => {
    const q = query.trim().toLocaleLowerCase("ru");
    return groups.filter(
      (g) => g.name.toLocaleLowerCase("ru").includes(q) || g.domains.some((d) => d.includes(q)),
    );
  }, [groups, query]);

  return (
    <div className="screen">
      <PageHeader
        title="Сервисы"
        description="Сервисы, для которых настроен обход"
        badge={`${groups.length} групп`}
        action={<button className="icon-action" type="button" aria-label="Обновить" onClick={() => void load()}><RefreshCw size={15} /></button>}
      />

      {error && <div className="info-banner info-banner--warn"><span>{error}</span></div>}

      <div className="toolbar">
        <label className="search-field">
          <Search size={14} />
          <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Найти группу или домен" />
        </label>
      </div>

      <div className="target-list">
        {filtered.map((g) => (
          <article className="target-row" key={g.name}>
            <span className={`target-row__dot${g.active ? " target-row__dot--active" : ""}`} />
            <div className="target-row__copy">
              <strong>{g.name}</strong>
              <small>{g.domains.join(", ")}</small>
              {g.active && <small className="target-row__strategy">Стратегия: {g.active}</small>}
            </div>
            <StatusBadge tone={g.active ? "success" : g.ownStrategy ? "accent" : "neutral"}>
              {g.active ? "Применяется" : g.ownStrategy ? "Своя стратегия" : "Общая"}
            </StatusBadge>
          </article>
        ))}

        {!loading && filtered.length === 0 && <div className="compact-empty">Ничего не найдено</div>}
        {loading && groups.length === 0 && <div className="compact-empty">Загрузка…</div>}
      </div>
    </div>
  );
}
