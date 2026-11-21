// Остальные разделы: сервисы, игры, Telegram, диагностика, настройки.
import { useEffect, useId, useMemo, useState } from "react";
import { ClipboardSetText } from "../../wailsjs/runtime/runtime";
import {
  api, type AppState, type DiagnosticItem, type DiagnosticTone, type DoctorCheck, type GameFilterSettings, type GameFilterView,
  type NetworkTuningView, type PortfolioView, type ServiceDiagnostic, type SpeedSample, type TargetGroup, type TelegramRoute, type TelegramState,
} from "../api";
import { loadOptions } from "../preferences";
import { gameConnectionNote, gameStatus } from "../gameStatus";
import { speedChart } from "../speedChart";
import { telegramBadge } from "../telegramBadge";
import { usePoll } from "../hooks";
import { Badge, Button, Collapse, Disclosure, Feed, Glass, Icon, Note, PageHead, Row, Segmented, Ticker, Toggle, fileName, traffic, type Tone } from "../ui";
import type { Page, Skin } from "../types";

/* ═════════════ Сервисы ═════════════ */
const RU_ZONES = [".ru", ".рф", ".su", ".москва", "yandex", "vk", "mail.ru", "sber", "gosuslugi", "tbank", "ozon", "wildberries", "avito", "rutube", "kinopoisk"];

export function ServicesScreen({ state }: { state: AppState | null }) {
  const [query, setQuery] = useState("");
  const [tab, setTab] = useState<"targets" | "portfolio">("targets");
  const targets = usePoll<TargetGroup[]>(() => api.getTargets(), 4000);
  const portfolio = usePoll<PortfolioView>(() => api.getPortfolio(), 6000, tab === "portfolio");
  const groups = targets.value ?? [];
  const filtered = useMemo(() => {
    const q = query.trim().toLocaleLowerCase("ru");
    return groups.filter((g) => g.name.toLocaleLowerCase("ru").includes(q) || g.domains.some((d) => d.includes(q)));
  }, [groups, query]);
  const holdings = portfolio.value?.holdings ?? [];
  const removed = state?.ruGuard ?? [];
  return (
    <div className="page-body">
      <PageHead kicker="Радиус обхода" title="Сервисы" note="Обход применяется только к перечисленным доменам. Всё остальное идёт напрямую, как без Evasion."
        action={<Segmented label="Раздел" value={tab} options={[{ id: "targets", label: "Цели" }, { id: "portfolio", label: "Стратегии" }]} onChange={setTab} />} />
      <Glass className="guard">
        <span className="guard__mark"><Icon name="shield" size={20} /></span>
        <div><strong>Российские сервисы не затрагиваются</strong>
          <p>Домены зон {RU_ZONES.slice(0, 3).join(", ")} и крупные российские площадки (банки, Госуслуги, Яндекс, VK, маркетплейсы) исключаются из обхода ещё до запуска движка — даже если попали в пользовательский конфиг.</p>
          {removed.length > 0 && <Note icon="info">Из вашего config.json убрано: {removed.join(", ")}</Note>}
        </div>
      </Glass>
      {tab === "targets" ? <>
        {targets.error && <Note tone="warn" icon="alert">{targets.error}</Note>}
        <label className="search"><Icon name="search" size={15} /><input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Найти группу или домен" /></label>
        <div className="list">
          {filtered.map((g) => (
            <Glass as="article" className="item" key={g.name}>
              <span className={`dot${g.active ? " dot--on" : ""}`} />
              <div className="item__text"><strong>{g.name}</strong><small>{g.domains.join(" · ")}</small>{g.active && <small className="mono">Стратегия {g.active}</small>}</div>
              <Badge tone={g.active ? "success" : g.ownStrategy ? "accent" : "neutral"}>{g.active ? "Применяется" : g.ownStrategy ? "Своя стратегия" : "Общая"}</Badge>
            </Glass>
          ))}
          {!filtered.length && <p className="empty">{targets.value ? "Ничего не найдено" : "Загрузка…"}</p>}
        </div>
      </> : <>
        {portfolio.error && <Note tone="warn" icon="alert">{portfolio.error}</Note>}
        <div className="stats">
          <Glass className="stat"><span className="kicker">Всего</span><strong className="stat__num"><Ticker value={holdings.length} /></strong><small>стратегий</small></Glass>
          <Glass className="stat"><span className="kicker">Активны</span><strong className="stat__num"><Ticker value={holdings.filter((h) => h.status === "active").length} /></strong><small>в работе</small></Glass>
          <Glass className="stat"><span className="kicker">В проверке</span><strong className="stat__num"><Ticker value={holdings.filter((h) => h.status !== "active").length} /></strong><small>кандидаты</small></Glass>
        </div>
        {holdings.length === 0 ? <Glass className="blank"><Icon name="layers" size={24} /><strong>Портфель пуст</strong><p>Стратегии появятся здесь в режиме автопилота. В обычном режиме Evasion берёт их из конфигурации.</p></Glass> : (
          <div className="list">{holdings.map((h) => (
            <Glass as="article" className="item" key={h.strategy_id}><div className="item__text"><strong className="mono">{h.strategy_id}</strong><small>{h.observations} наблюдений · {h.targets} целей</small></div>
              <Badge tone={h.status === "active" ? "success" : h.status === "testing" || h.status === "candidate" ? "accent" : "neutral"}>{h.status}</Badge></Glass>
          ))}</div>
        )}
      </>}
    </div>
  );
}

/* ═════════════ Игры ═════════════ */
const gameDefaults: GameFilterSettings = { adaptive: true, mode: "auto", protocol: "both", albion: true, ubisoft: true, executables: [], onDemand: true };
const gameModes = [
  { id: "auto", label: "Авто", hint: "Evasion сам усиливает обработку, если игра не отвечает" },
  { id: "gentle", label: "Мягко", hint: "Минимальное вмешательство" },
  { id: "balanced", label: "Средне", hint: "Перекрытие первого пакета" },
  { id: "strong", label: "Сильно", hint: "Ложный пакет + перекрытие" },
];
const protocols = [{ id: "both", label: "TCP + UDP" }, { id: "tcp", label: "TCP" }, { id: "udp", label: "UDP" }];

export function GamesScreen({ onNavigate }: { onNavigate: (p: Page) => void }) {
  const poll = usePoll<GameFilterView>(() => api.getGameFilter(), 1500);
  const view = poll.value;
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [route, setRoute] = useState("");
  const settings: GameFilterSettings = { ...gameDefaults, ...(view?.settings ?? {}) };
  if (settings.mode === "off") settings.mode = "auto";
  const active = Boolean(view?.engineRunning && view.activeMode !== "off");
  const armed = Boolean(view?.armed);
  const on = active || armed;
  const status = armed && !active ? "Ждёт запуска игры" : gameStatus(view, busy);
  const note = gameConnectionNote(view);
  const albion = (view?.processes ?? []).find((p) => p.family === "albion");
  const anyGame = settings.albion || settings.ubisoft || settings.executables.length > 0;

  const act = async (fn: () => Promise<unknown>) => {
    setBusy(true); setError("");
    try { await fn(); const next = await api.getGameFilter(); poll.set(next); if (next.error) throw new Error(next.error); }
    catch (e) { setError(String(e)); void poll.refresh(); }
    finally { setBusy(false); }
  };
  const persist = (patch: Partial<GameFilterSettings>, apply: boolean) => act(async () => {
    await api.setGameFilter({ ...settings, ...patch, adaptive: true });
    if (apply) await api.applyGameFilter(loadOptions());
  });
  const toggle = () => on ? act(() => api.stopGameFilter()) : persist({}, true);
  const add = async () => {
    try { const path = await api.selectGameExecutable(); if (path && !settings.executables.some((p) => p.toLowerCase() === path.toLowerCase())) await persist({ executables: [...settings.executables, path] }, on); }
    catch (e) { setError(String(e)); }
  };
  const shown = error || view?.error || "";

  return (
    <div className="page-body">
      <PageHead kicker="Game filter" title="Игровой обход" note="Работает только для выбранных игр и только пока они запущены. Остальные игры и программы не затрагиваются."
        action={<Badge tone={active ? "success" : armed ? "accent" : "neutral"} pulse={on}>{status}</Badge>} />
      <Glass className="launch" aria-busy={busy}>
        <div className={`launch__pulse${on ? " launch__pulse--on" : ""}`} aria-hidden="true"><i /><i /><i /><Icon name="game" size={22} /></div>
        <div className="launch__text"><strong>{on ? (active ? "Игровой обход работает" : "Готов — включится вместе с игрой") : "Игровой обход выключен"}</strong>
          <small>{settings.onDemand ? "Фильтр поднимается при запуске выбранной игры и снимается после выхода" : "Фильтр работает постоянно, пока включён"}</small></div>
        <Button kind={on ? "soft" : "solid"} icon="power" disabled={!view || busy || (!on && !anyGame)} onClick={() => void toggle()}>{busy ? "Подождите…" : on ? "Выключить" : "Включить"}</Button>
      </Glass>
      {shown && <Note tone="warn" icon="alert">{shown}{shown.toLowerCase().includes("windivert") && <> <button type="button" className="link" onClick={() => onNavigate("diagnostics")}>Диагностика драйвера</button></>}</Note>}

      <Glass className="card">
        <header className="card-head"><span className="kicker">Какие игры обрабатывать</span></header>
        <Row title="Albion Online" note="Клиент и лаунчер"><Toggle label="Albion Online" checked={settings.albion} disabled={!view || busy} onChange={(v) => void persist({ albion: v }, on)} /></Row>
        <Row title="Ubisoft Connect" note="Лаунчер и запущенные из него игры"><Toggle label="Ubisoft Connect" checked={settings.ubisoft} disabled={!view || busy} onChange={(v) => void persist({ ubisoft: v }, on)} /></Row>
        {settings.executables.map((path) => (
          <Row key={path} title={fileName(path)} note={<span className="path">{path}</span>}><Button kind="ghost" icon="trash" aria-label={`Убрать ${fileName(path)}`} disabled={busy} onClick={() => void persist({ executables: settings.executables.filter((p) => p !== path) }, on)} /></Row>
        ))}
        <div className="card__foot"><Button icon="plus" disabled={!view || busy || settings.executables.length >= 16} onClick={() => void add()}>Добавить игру (.exe)</Button><small>Браузеры, лаунчеры магазинов и системные программы добавить нельзя.</small></div>
      </Glass>

      <Glass className="card">
        <header className="card-head"><span className="kicker">Как обрабатывать</span></header>
        <Row title="Включать только вместе с игрой" note="Пока выбранная игра не запущена, перехват не стоит вовсе — нулевое влияние на другие игры и пинг."><Toggle label="Включать только вместе с игрой" checked={!!settings.onDemand} disabled={!view || busy} onChange={(v) => void persist({ onDemand: v }, on)} /></Row>
        <Row title="Сила обработки" note={gameModes.find((m) => m.id === settings.mode)?.hint}><Segmented label="Сила обработки" value={settings.mode} options={gameModes} disabled={!view || busy} onChange={(mode) => void persist({ mode }, on)} /></Row>
        <Row title="Тип соединения"><Segmented label="Игровые протоколы" value={settings.protocol} options={protocols} disabled={!view || busy} onChange={(protocol) => void persist({ protocol }, on)} /></Row>
      </Glass>

      <Glass className="card">
        <header className="card-head"><span className="kicker">Что происходит</span></header>
        {active && note && <Note icon="info">{note}</Note>}
        {active && albion && !note && <Note icon="info">{albion.clients > 0 ? "Процесс клиента Albion обнаружен. Вход в игру ещё не подтверждён." : "Обнаружен лаунчер Albion; клиент игры пока не запущен."}</Note>}
        <div className="hello">
          <div><strong><Ticker value={view?.stats.connections ?? 0} /></strong><span>{view?.stats.tunnel ? "через маршрут" : "соединений"}</span></div>
          <div><strong><Ticker value={view?.stats.udp ?? 0} /></strong><span>UDP-обработок</span></div>
          <div><strong><Ticker value={view?.stats.tlsApplied ?? 0} /></strong><span>TLS-обработок</span></div>
          <div className={(view?.stats.errors ?? 0) > 0 ? "hello--warn" : ""}><strong><Ticker value={view?.stats.errors ?? 0} /></strong><span>ошибок</span></div>
        </div>
        {view?.stats.tunnel && <Note>Получено {traffic(view.stats.tunnelReceived ?? 0)} · отправлено {traffic(view.stats.tunnelSent ?? 0)}</Note>}
        <Note>{view?.stats.tunnel ? "Через сервер идут только выбранные игры и лаунчеры." : "Обработка идёт напрямую, без VPN: внешний IP не меняется. Вход в игру проверяется в самой игре."}</Note>
      </Glass>

      <Disclosure icon="route" title="Запасной маршрут (необязателен)" note={view?.route?.configured ? `Подключён · серверов: ${view.route.nodes}` : "Только если прямой обход игре не помогает"}>
        <Note>Игровой обход работает без VPN. Маршрут нужен лишь для сетей, где адрес игры закрыт целиком и прямая обработка бессильна: добавьте свою подписку VLESS/Reality — через неё пойдут только выбранные игры. Профиль хранится на этом компьютере.</Note>
        {view?.route?.configured && <Row title="Сервер выбирается автоматически" note={`Серверов в профиле: ${view.route.nodes}`}><Button kind="ghost" disabled={busy} onClick={() => void act(async () => { await api.removeGameRoute(); if (on) await api.applyGameFilter(loadOptions()); })}>Убрать маршрут</Button></Row>}
        <div className="inline">
          <input className="field field--wide" type="password" autoComplete="off" spellCheck={false} aria-label="Подписка, VLESS или JSON" placeholder="Подписка, VLESS или JSON из Happ" value={route} disabled={busy} onChange={(e) => setRoute(e.target.value)} />
          <Button disabled={busy || !route.trim()} onClick={() => void act(async () => { await api.importGameRoute(route); setRoute(""); if (on) await api.applyGameFilter(loadOptions()); })}>{view?.route?.configured ? "Заменить" : "Добавить"}</Button>
        </div>
      </Disclosure>
    </div>
  );
}

/* ═════════════ Telegram ═════════════ */
const routeLabels: Record<string, string> = { untested: "Не проверен", checking: "Проверка", verified: "Telegram ответил", opened: "Канал открыт", cooldown: "Пауза после сбоя", failed: "Нет ответа" };

function SpeedGraph({ samples = [], running }: { samples?: SpeedSample[]; running: boolean }) {
  const chart = speedChart(samples ?? []);
  const gradient = `g-${useId().replace(/:/g, "")}`;
  return (
    <Glass className="card speed">
      <header className="card-head"><span className="kicker">Поток данных · 2 минуты</span></header>
      <div className="speed__read">
        <div><Icon name="down" size={15} /><strong>{traffic(running ? chart.current?.down || 0 : 0)}<small>/с</small></strong><span>получение</span></div>
        <div><Icon name="up" size={15} /><strong>{traffic(running ? chart.current?.up || 0 : 0)}<small>/с</small></strong><span>отправка</span></div>
      </div>
      <div className="speed__plot"><span className="speed__scale">{traffic(chart.scale)}/с</span>
        <svg viewBox="0 0 600 112" preserveAspectRatio="none" role="img" aria-label={chart.count ? "График получения и отправки данных Telegram" : "Нет измерений скорости"}>
          <defs><linearGradient id={gradient} x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="var(--accent)" stopOpacity=".32" /><stop offset="100%" stopColor="var(--accent)" stopOpacity="0" /></linearGradient></defs>
          {[8, 56, 104].map((y) => <line key={y} x1="0" x2="600" y1={y} y2={y} className="speed__grid" />)}
          {chart.count > 1 && <><polygon points={`${chart.down.split(" ")[0].split(",")[0]},104 ${chart.down} 600,104`} fill={`url(#${gradient})`} /><polyline points={chart.down} className="speed__line speed__line--down" /><polyline points={chart.up} className="speed__line speed__line--up" /></>}
        </svg>
        {chart.count < 2 && <span className="speed__empty">{running ? "Собираем первые измерения…" : "Включите Telegram, чтобы видеть скорость"}</span>}
      </div>
      <Note>Трафик встроенного прокси, а не скорость всего интернета.</Note>
    </Glass>
  );
}

export function TelegramScreen({ state, onRefresh }: { state?: TelegramState; onRefresh: () => unknown }) {
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");
  const [port, setPort] = useState<string | null>(null);
  const [community, setCommunity] = useState<boolean | null>(null);
  const [checking, setChecking] = useState(false);
  const routes = usePoll<TelegramRoute[]>(() => api.getTelegramRoutes(), 2000);
  const badge = state ? telegramBadge(state) : { label: "Получаем состояние…", tone: "neutral" as const };
  const run = async (fn: () => Promise<unknown>) => {
    if (busy) return;
    setBusy(true); setNotice("");
    try { await fn(); } catch (e) { setNotice(String(e)); } finally { setBusy(false); onRefresh(); }
  };
  const toggle = () => run(async () => {
    if (state?.running) { await api.stopTelegramProxy(); return; }
    const value = Number(port ?? state?.port ?? 17655);
    if (!Number.isInteger(value) || value < 1024 || value > 65535) throw new Error("Укажите порт от 1024 до 65535");
    await api.setTelegramOptions(value, community ?? state?.community ?? true);
    await api.startTelegramProxy(value);
    await api.openTelegramProxy();
  });
  const copy = () => run(async () => { const ok = await ClipboardSetText(state?.link || ""); setNotice(ok ? "Ссылка скопирована" : "Не удалось скопировать ссылку"); });
  const check = async () => { setChecking(true); try { routes.set(await api.checkTelegramRoutes()); } catch (e) { setNotice(String(e)); } finally { setChecking(false); } };
  const list = routes.value ?? [];
  return (
    <div className="page-body">
      <PageHead kicker="Встроенный прокси" title="Telegram" note="Локальный MTProto-прокси с автоматическим выбором маршрута. Сообщения остаются зашифрованы Telegram."
        action={<Button kind={state?.running ? "soft" : "solid"} icon="power" disabled={busy || !state} onClick={() => void toggle()}>{busy ? "Подождите…" : state?.running ? "Выключить" : "Включить Telegram"}</Button>} />
      {notice && <Note icon="info">{notice}</Note>}
      {!state?.running && state?.error && <Note tone="warn" icon="alert">{state.error}</Note>}
      <Glass className="card">
        <header className="card-head"><span className="kicker">Состояние</span><Badge tone={badge.tone} pulse={!!state?.running}>{badge.label}</Badge></header>
        <p className="lead">{state?.route || (state?.running ? "Локальный прокси готов" : "Подключение выключено")}</p>
        <div className="hello">
          <div><strong><Ticker value={state?.active ?? 0} /></strong><span>активных</span></div>
          <div><strong>{traffic(state?.bytesDown ?? 0)}</strong><span>получено</span></div>
          <div><strong>{traffic(state?.bytesUp ?? 0)}</strong><span>отправлено</span></div>
          <div className={(state?.failures ?? 0) > 0 ? "hello--warn" : ""}><strong><Ticker value={state?.failures ?? 0} /></strong><span>ошибок</span></div>
        </div>
        <div className="meta"><span>Всего соединений: {state?.connections ?? 0}</span><span>Установка канала: {state?.route ? (state.dialMs ? `${state.dialMs} мс` : "<1 мс") : "—"}</span><span>Последние данные: {state?.lastDataAt ? new Date(state.lastDataAt).toLocaleTimeString("ru") : "—"}</span></div>
        {state?.running && <div className="inline">
          <Button kind="solid" icon="external" disabled={busy} onClick={() => void run(() => api.openTelegramProxy())}>Подключить в Telegram</Button>
          <Button icon="copy" disabled={busy || !state.link} onClick={() => void copy()}>Скопировать ссылку</Button>
        </div>}
        {state?.running && state.phase === "waiting" && <Note>Нажмите «Подключить в Telegram» и подтвердите прокси в клиенте. Статус изменится после реального обмена данными.</Note>}
      </Glass>
      <SpeedGraph samples={state?.speeds} running={!!state?.running} />
      <Glass className="card">
        <header className="card-head"><span className="kicker">Маршруты</span><Button kind="ghost" icon="refresh" disabled={checking} onClick={() => void check()}>{checking ? "Проверяем…" : "Проверить резерв"}</Button></header>
        {list.length === 0 && <p className="empty">Запустите проверку — здесь появится состояние прямых и резервных каналов.</p>}
        <div className="routes">{list.map((r) => (
          <div className="route" key={r.id}>
            <div><strong>{r.host}</strong><small>{r.kind}{r.checkedAt ? ` · ${new Date(r.checkedAt).toLocaleTimeString("ru", { hour: "2-digit", minute: "2-digit" })}` : ""}{r.reason && (r.status === "failed" || r.status === "cooldown") ? ` · ${r.reason}` : ""}</small></div>
            <span className="mono">{r.latencyMs > 0 ? `${r.latencyMs} мс` : "—"}</span>
            <Badge tone={r.status === "verified" ? "success" : r.status === "failed" || r.status === "cooldown" ? "warning" : "neutral"}>{routeLabels[r.status] || "Не проверен"}</Badge>
          </div>
        ))}</div>
      </Glass>
      <Disclosure icon="settings" title="Параметры подключения" note="Обычно менять не требуется">
        <Row title="Локальный порт" note="Меняется только при выключенном прокси"><input className="field field--num" type="number" min={1024} max={65535} aria-label="Локальный порт" value={port ?? state?.port ?? 17655} disabled={state?.running || busy} onChange={(e) => setPort(e.target.value)} /></Row>
        <Row title="Резервные узлы сообщества" note="Используются, если прямой маршрут заблокирован"><Toggle label="Резервные узлы сообщества" checked={community ?? state?.community ?? true} disabled={state?.running || busy} onChange={setCommunity} /></Row>
      </Disclosure>
      <Disclosure icon="pulse" title="Активность Telegram" note="Подключения, маршруты и ошибки"><Feed logs={state?.logs ?? []} /></Disclosure>
    </div>
  );
}

/* ═════════════ Диагностика ═════════════ */
const serviceNames = [["telegram", "Telegram · протокол"], ["telegram-web", "Telegram · веб"], ["discord-api", "Discord · API"], ["discord-gateway", "Discord · события"]];
const stageNames: Record<string, string> = { dns: "DNS", tcp: "TCP", tls: "TLS", https: "HTTPS", gateway: "WebSocket", mtproto: "MTProto" };
const doctorTone = (s: string): DiagnosticTone => (s === "ok" ? "success" : s === "warn" || s === "fail" ? "warning" : "neutral");

export function DiagnosticsScreen() {
  const [items, setItems] = useState<DiagnosticItem[]>([]);
  const [open, setOpen] = useState<string | null>(null);
  const [checks, setChecks] = useState<DoctorCheck[] | null>(null);
  const [services, setServices] = useState<ServiceDiagnostic[]>([]);
  const [busy, setBusy] = useState<"" | "services" | "doctor" | "export">("");
  const [notice, setNotice] = useState("");
  const load = async () => { try { setItems(await api.getDiagnostics()); setServices((await api.getServiceDiagnostics()) || []); } catch (e) { setNotice(String(e)); } };
  useEffect(() => { void load(); }, []);
  const run = async (kind: "services" | "doctor" | "export", fn: () => Promise<void>) => { setBusy(kind); setNotice(""); try { await fn(); } catch (e) { setNotice(String(e)); } finally { setBusy(""); } };
  return (
    <div className="page-body">
      <PageHead kicker="Проверки" title="Диагностика" note="Где прервалась связь и что поможет её вернуть"
        action={<Button kind="solid" icon="pulse" disabled={busy !== ""} onClick={() => void run("services", async () => { setServices(await api.runServiceDiagnostics()); await load(); })}>{busy === "services" ? "Проверяем…" : "Проверить связь"}</Button>} />
      <div className="grid2" aria-busy={busy === "services"}>
        {serviceNames.map(([id, name]) => {
          const r = services.find((s) => s.id === id);
          const tone: Tone = busy === "services" ? "accent" : r?.status === "ok" ? "success" : r?.status === "fail" ? "warning" : "neutral";
          return (
            <Glass as="article" className={`card probe probe--${tone}`} key={id}>
              <header className="card-head"><strong>{name}</strong><Badge tone={tone} pulse={busy === "services"}>{busy === "services" ? "Проверяем" : r?.status === "ok" ? "Доступен" : r ? "Нужна проверка" : "Не проверен"}</Badge></header>
              <p className="probe__sum">{r?.summary || "Нажмите «Проверить связь»"}</p>
              <div className="stages">{(r?.steps || []).map((s) => <span className={`chip chip--${s.status}`} key={s.id}><i />{stageNames[s.id] || s.id}<small>{s.status === "ok" ? `${s.ms} мс` : "сбой"}</small></span>)}</div>
              {r?.advice && <Note>{r.advice}</Note>}
              {r?.checkedAt && <time dateTime={r.checkedAt}>Проверено в {new Date(r.checkedAt).toLocaleTimeString("ru")}</time>}
            </Glass>
          );
        })}
      </div>
      {busy === "services" && <Note icon="info">Проверяем публичные адреса и ответы протоколов. Обычно до 16 секунд.</Note>}
      {notice && <Note icon="info">{notice}</Note>}
      <Glass className="guard">
        <span className="guard__mark"><Icon name="shield" size={20} /></span>
        <div><strong>Отчёт без секретов</strong><p>Результаты, состояния маршрутов и счётчики. Без ключей, ссылок прокси, конфигов, журналов и личных путей.</p></div>
        <Button icon="download" disabled={busy !== ""} onClick={() => void run("export", async () => { const path = await api.exportDiagnosticReport(); if (path) setNotice(`Отчёт сохранён: ${fileName(path)}`); })}>{busy === "export" ? "Сохранение…" : "Экспорт JSON"}</Button>
      </Glass>
      <Glass className="card">
        <header className="card-head"><span className="kicker">Готовность приложения</span><Button kind="ghost" icon="pulse" disabled={busy !== ""} onClick={() => void run("doctor", async () => setChecks(await api.runDoctor()))}>{busy === "doctor" ? "Проверка…" : "Проверить движок"}</Button></header>
        {items.map((item) => (
          <div className={`diag${open === item.name ? " diag--open" : ""}`} key={item.name}>
            <button type="button" aria-expanded={open === item.name} onClick={() => setOpen(open === item.name ? null : item.name)}><span>{item.name}</span><Badge tone={item.tone}>{item.status}</Badge><Icon name="chevron" size={14} className="diag__chev" /></button>
            <Collapse open={open === item.name}><p>{item.detail}</p></Collapse>
          </div>
        ))}
        {!items.length && <p className="empty">Загрузка…</p>}
      </Glass>
      {checks && <Glass className="card">
        <header className="card-head"><span className="kicker">Результаты проверки движка</span></header>
        {checks.length === 0 && <p className="empty">Проверок нет.</p>}
        {checks.map((c) => <Row key={c.id} title={<span className="mono">{c.id}</span>} note={c.reason}><Badge tone={doctorTone(c.status)}>{c.status}</Badge></Row>)}
      </Glass>}
    </div>
  );
}

/* ═════════════ Настройки ═════════════ */
const ytProfiles: Record<string, string> = { current: "Базовый способ", "media-sld": "Защита видеоподключений", "split-sld": "Разделение домена", "fake-sld": "Защита домена", split: "Разделение соединения", "split-forward": "Совместимый способ", overlap: "Альтернативный способ", "fake-forward": "Совместимая защита", "fake-split": "Дополнительная защита", "fake-overlap": "Альтернативная защита" };
const ytPhases: Record<string, string> = { waiting: "Проверка запускается", awaiting_media: "Сайт доступен — откройте видео для проверки видеосервера", stopped: "Начнёт работу после включения обхода", disabled: "YouTube исключён из текущего обхода", checking: "Проверяем соединение", healthy: "Проверенные подключения доступны", degraded: "Перепроверяем сбой", recovering: "Подбираем рабочий способ в фоне", recovered: "Рабочий способ заменён и проверен", network_down: "Контрольные сайты тоже недоступны", unavailable: "Проверенные способы пока не помогли — повторим автоматически" };
const ytTargets: Record<string, string> = { site: "YouTube", image: "Изображения", media_transport: "Видеосеть" };
const ytStages: Record<string, string> = { dns: "не найден адрес", tcp: "нет соединения", tls: "не отвечает HTTPS", http: "нет ответа" };

export function SettingsScreen({ motion, startup, skin, onMotion, onStartup, onSkin, baseDir }: { motion: boolean; startup: boolean; skin: Skin; onMotion: (v: boolean) => void; onStartup: (v: boolean) => void; onSkin: (v: Skin) => void; baseDir?: string }) {
  const tuning = usePoll<NetworkTuningView>(() => api.getNetworkTuning(loadOptions()), 1500);
  const [auto, setAuto] = useState(false);
  const [busy, setBusy] = useState(true);
  const [error, setError] = useState("");
  useEffect(() => { let alive = true; void api.getAutoStart().then((v) => { if (alive) setAuto(v); }).catch((e) => { if (alive) setError(String(e)); }).finally(() => { if (alive) setBusy(false); }); return () => { alive = false; }; }, []);
  const change = async (fn: () => Promise<void>) => { setBusy(true); setError(""); try { await fn(); } catch (e) { setError(String(e)); } finally { setBusy(false); } };
  const health = tuning.value?.health;
  const phase = health?.phase ?? "waiting";
  const tone: Tone = phase === "healthy" || phase === "recovered" ? "success" : phase === "unavailable" || phase === "network_down" || phase === "degraded" ? "warning" : "neutral";
  return (
    <div className="page-body">
      <PageHead kicker="Под себя" title="Настройки" note="Сделайте Evasion удобным" />
      <Glass className="card">
        <header className="card-head"><span className="kicker">Оформление</span></header>
        <Row title="Пейзаж" note="Сакура — нежные лепестки; Природа — лесной ручей ночью и кроны деревьев днём. У обоих живой параллакс и своя палитра."><Segmented label="Пейзаж" value={skin} options={[{ id: "sakura", label: "Сакура" }, { id: "natural", label: "Природа" }]} onChange={onSkin} /></Row>
        <Row title="Живой фон и мягкие анимации" note="Туман, параллакс, переливы стекла. Выключите на слабой видеокарте или во время игры."><Toggle label="Мягкие анимации" checked={motion} onChange={onMotion} /></Row>
        <Row title="Стартовый экран" note="Действует со следующего запуска"><Toggle label="Стартовый экран" checked={startup} onChange={onStartup} /></Row>
      </Glass>
      <Glass className="card">
        <header className="card-head"><span className="kicker">YouTube · автовосстановление</span><Badge tone={tone} pulse={phase === "checking" || phase === "recovering"}>Автоматически</Badge></header>
        <p className="lead">{ytPhases[phase] ?? "Проверка недоступна"}</p>
        {health?.fresh && <div className="meta"><span>{ytProfiles[health.profile] ?? "Способ проверяется"}</span><span>{health.checkedAt ? `проверено в ${new Date(health.checkedAt).toLocaleTimeString("ru", { hour: "2-digit", minute: "2-digit" })}` : "проверяется"}</span>{health.switches > 0 && <span>замен: {health.switches}</span>}{health.rollbacks > 0 && <span>откатов: {health.rollbacks}</span>}</div>}
        {health?.fresh && health.checks.length > 0 && <div className="stages">{health.checks.map((c) => {
          const waitingMedia = c.target === "media_transport" && !health.mediaObserved;
          return <span key={c.target} className={`chip chip--${waitingMedia ? "idle" : c.ok ? "ok" : "fail"}`}><i />{ytTargets[c.target] ?? "Проверка"}<small>{waitingMedia ? "ждём видео" : c.ok ? `${c.ms} мс` : ytStages[c.stage] ?? "сбой"}</small></span>;
        })}</div>}
        <Note>При повторном сбое Evasion проверяет другие способы на тестовых соединениях; подходящий применяется сразу, неудачная замена откатывается. Без интернета стратегии вслепую не переключаются.</Note>
        <Row title="Память проверенных маршрутов Telegram" note="Ускоряет следующий запуск; доступность каналов всё равно проверяется заново."><Toggle label="Память маршрутов Telegram" checked={tuning.value?.telegram ?? true} disabled={!tuning.value || busy} onChange={(v) => void change(async () => { await api.setNetworkTuningSettings(true, v); await tuning.refresh(); })} /></Row>
      </Glass>
      <Glass className="card" aria-busy={busy}>
        <header className="card-head"><span className="kicker">Система</span></header>
        <Row title="Автозапуск с Windows" note="Запускать Evasion после входа и сразу подключаться"><Toggle label="Автозапуск с Windows" checked={auto} disabled={busy} onChange={(v) => void change(async () => { await api.setAutoStart(v, loadOptions()); setAuto(await api.getAutoStart()); })} /></Row>
        <Row title="Папка данных" note={<span className="path">{baseDir || "%LOCALAPPDATA%\\Evasion"}</span>}><Button icon="folder" onClick={() => void api.openDataFolder()}>Открыть</Button></Row>
        {(error || tuning.error) && <Note tone="warn" icon="alert">{error || tuning.error}</Note>}
      </Glass>
      <p className="colophon">Evasion · движок работает локально на вашем устройстве</p>
    </div>
  );
}
