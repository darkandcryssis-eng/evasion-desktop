import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import { EventsOn, WindowCenter, WindowMinimise, WindowSetMinSize, WindowSetSize, WindowToggleMaximise } from "../wailsjs/runtime/runtime";
import { api, phaseLabel, type StartOptions } from "./api";
import { useEngine } from "./useEngine";
import { UpdateBanner } from "./Update";
import { loadOptions, readPreference, savePreference } from "./preferences";
import { Boundary, Button, Dialog, Icon, type IconName } from "./ui";
import { HomeScreen, telegramMode } from "./screens/Home";
import { DiagnosticsScreen, GamesScreen, ServicesScreen, SettingsScreen, TelegramScreen } from "./screens/Pages";
import type { Page, Theme } from "./types";

const pages: { id: Page; title: string; icon: IconName }[] = [
  { id: "home", title: "Главная", icon: "home" }, { id: "services", title: "Сервисы", icon: "layers" },
  { id: "telegram", title: "Telegram", icon: "send" }, { id: "games", title: "Игры", icon: "game" },
  { id: "diagnostics", title: "Диагностика", icon: "pulse" }, { id: "settings", title: "Настройки", icon: "settings" },
];
const storedFlag = (key: string, fallback: boolean) => { const value = readPreference(key); return value === null ? fallback : value === "true"; };

export default function App() {
  const [startup, setStartup] = useState(() => storedFlag("evasion-ui-startup", true));
  const [motion, setMotion] = useState(() => storedFlag("evasion-ui-motion", true));
  const [booting, setBooting] = useState(startup);
  const [page, setPage] = useState<Page>("home");
  const [theme, setTheme] = useState<Theme>(() => readPreference("evasion-ui-theme") === "light" ? "light" : "black");
  const [closing, setClosing] = useState(false);
  const [pending, setPending] = useState<StartOptions | null>(null);
  const engine = useEngine();
  const viewport = useRef<HTMLElement>(null);
  useLayoutEffect(() => {
    document.documentElement.dataset.theme = theme;
    document.documentElement.dataset.motion = motion ? "full" : "reduced";
    delete document.documentElement.dataset.skin;
  }, [theme, motion]);
  useEffect(() => {
    // Keep the native tray in sync; landscape selection is intentionally retired.
    const sync = () => { void api.setTrayPreferences(theme, loadOptions(), "minimal").catch(() => {}); };
    sync(); window.addEventListener("evasion:options-changed", sync);
    return () => window.removeEventListener("evasion:options-changed", sync);
  }, [theme]);
  useEffect(() => EventsOn("evasion:navigate", (tab: unknown) => {
    if (tab === "Диагностика") { setClosing(false); setPending(null); setPage("diagnostics"); }
  }), []);
  useEffect(() => {
    savePreference("evasion-ui-theme", theme);
    savePreference("evasion-ui-motion", String(motion));
    savePreference("evasion-ui-startup", String(startup));
  }, [motion, startup, theme]);
  useEffect(() => {
    WindowSetSize(900, 700); WindowSetMinSize(700, 540); WindowCenter();
    const timer = window.setTimeout(() => setBooting(false), 1500);
    return () => window.clearTimeout(timer);
  }, []);
  useLayoutEffect(() => { if (viewport.current) viewport.current.scrollTop = 0; }, [page]);
  const requestConnect = useCallback((options: StartOptions) => {
    const mode = telegramMode();
    if (mode === "ask") { setPending(options); return; }
    void engine.connect(options, mode === "yes");
  }, [engine]);
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement | null;
      if (!event.ctrlKey || event.key !== "Enter" || event.repeat || event.altKey || event.shiftKey || closing || pending || booting || target?.closest("input, textarea, select, [contenteditable=true]")) return;
      event.preventDefault();
      const state = engine.state, phase = state?.engine.phase;
      if (engine.busy || !phase || phase === "starting" || phase === "stopping") return;
      if (phase === "running") void engine.stop();
      else if (state?.elevated && state.payload.engine && (state.payload.config || state.userConfig)) requestConnect(loadOptions());
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [engine, closing, pending, booting, requestConnect]);
  const phase = engine.state?.engine.phase ?? "stopped";
  const renderPage = () => {
    switch (page) {
      case "services": return <ServicesScreen state={engine.state} />;
      case "games": return <GamesScreen onNavigate={setPage} />;
      case "telegram": return <TelegramScreen state={engine.state?.telegram} onRefresh={engine.refresh} />;
      case "diagnostics": return <DiagnosticsScreen />;
      case "settings": return <SettingsScreen motion={motion} startup={startup} onMotion={setMotion} onStartup={setStartup} baseDir={engine.state?.baseDir} />;
      default: return <HomeScreen engine={engine} motion={motion} onConnect={requestConnect} onNavigate={setPage} />;
    }
  };
  return (
    <main className="shell" data-phase={phase} data-page={page}>
      <header className="bar">
        <div className="brand" aria-label="Evasion"><span className="brand__mark" aria-hidden="true"><i /></span><span className="brand__name">evasion</span></div>
        <Navigation page={page} onChange={setPage} />
        <div className="bar__tools">
          <span className="engine-pill" data-phase={phase}><i />{engine.state ? phaseLabel[phase] : "Получаем состояние"}</span>
          <button type="button" className="tool" title={theme === "black" ? "Светлая тема" : "Тёмная тема"} aria-label={theme === "black" ? "Включить светлую тему" : "Включить тёмную тему"} onClick={() => setTheme(theme === "black" ? "light" : "black")}><Icon name={theme === "black" ? "sun" : "moon"} size={15} /></button>
          <div className="window-actions">
            <button type="button" className="tool" aria-label="Свернуть" onClick={WindowMinimise}><Icon name="minus" size={15} /></button>
            <button type="button" className="tool" aria-label="Развернуть или восстановить" onClick={WindowToggleMaximise}><Icon name="square" size={12} /></button>
            <button type="button" className="tool tool--close" aria-label="Закрыть" onClick={() => setClosing(true)}><Icon name="x" size={15} /></button>
          </div>
        </div>
      </header>
      <UpdateBanner />
      <section className="stage" ref={viewport}>
        <div className="stage__page" key={page}><Boundary resetKey={page}>{renderPage()}</Boundary></div>
      </section>
      {booting && <div className="boot" aria-live="polite"><svg viewBox="0 0 120 120" aria-hidden="true"><circle className="boot__ring" cx="60" cy="60" r="44" pathLength="1" /><circle className="boot__dot" cx="60" cy="60" r="5" /></svg><span>evasion</span></div>}
      <Dialog open={closing} onClose={() => setClosing(false)} icon="power" title="Остаться на связи?" text="Сверните Evasion в трей, чтобы соединение продолжало работать."><button type="button" className="choice" onClick={() => { setClosing(false); void api.minimiseToTray(); }}><Icon name="tray" size={17} /><span><strong>Свернуть в трей</strong><small>Оставить обход работать в фоне</small></span></button><button type="button" className="choice choice--quit" onClick={() => void api.exitApplication()}><Icon name="power" size={17} /><span><strong>Завершить работу</strong><small>Остановить движок и выйти</small></span></button></Dialog>
      <Dialog open={pending !== null} onClose={() => setPending(null)} icon="send" title="Telegram — тоже?" text="Включить встроенный прокси вместе с обходом? При первом запуске подтвердите подключение в Telegram."><Button kind="ghost" onClick={() => { const options = pending; setPending(null); if (options) void engine.connect(options, false); }}>Только обход</Button><Button kind="solid" data-autofocus onClick={() => { const options = pending; setPending(null); if (options) void engine.connect(options, true); }}>Включить Telegram</Button></Dialog>
    </main>
  );
}

// Pill navigation: the active marker glides between sections and the active label unfolds.
function Navigation({ page, onChange }: { page: Page; onChange: (p: Page) => void }) {
  const root = useRef<HTMLElement>(null);
  const [box, setBox] = useState<{ left: number; width: number } | null>(null);
  useLayoutEffect(() => {
    const el = root.current;
    if (!el) return;
    const measure = () => {
      const active = el.querySelector<HTMLElement>("[aria-current=page]");
      if (active) setBox({ left: active.offsetLeft, width: active.offsetWidth });
    };
    measure();
    const ro = typeof ResizeObserver === "undefined" ? null : new ResizeObserver(measure);
    el.querySelectorAll("button").forEach((b) => ro?.observe(b));
    return () => ro?.disconnect();
  }, [page]);
  return (
    <nav className="nav" aria-label="Разделы приложения" ref={root}>
      {box && <span className="nav__marker" style={{ transform: `translateX(${box.left}px)`, width: box.width }} aria-hidden="true" />}
      {pages.map((p) => (
        <button key={p.id} type="button" className="nav__item" aria-label={p.title} title={p.title} aria-current={page === p.id ? "page" : undefined} onClick={() => onChange(p.id)}>
          <Icon name={p.icon} size={15} /><span className="nav__label">{p.title}</span>
        </button>
      ))}
    </nav>
  );
}
