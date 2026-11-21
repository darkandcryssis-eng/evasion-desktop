import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import { EventsOn, WindowCenter, WindowMinimise, WindowSetMinSize, WindowSetSize, WindowToggleMaximise } from "../wailsjs/runtime/runtime";
import { api, phaseLabel, type StartOptions } from "./api";
import { useEngine } from "./useEngine";
import { loadOptions, readPreference, savePreference } from "./preferences";
import { Boundary, Button, Dialog, Icon, type IconName } from "./ui";
import { HomeScreen, telegramMode } from "./screens/Home";
import { DiagnosticsScreen, GamesScreen, ServicesScreen, SettingsScreen, TelegramScreen } from "./screens/Pages";
import type { Page, Theme } from "./types";
import { AsciiCat } from "./fx/AsciiCat";

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
    const timer = window.setTimeout(() => setBooting(false), 500);
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
    <main className="workspace" data-phase={phase}>
      <header className="workspace__header">
        <div className="identity" aria-label="Evasion"><span aria-hidden="true">/\_/\</span> evasion</div>
        <div className="header-tools"><span className="engine-indicator" data-phase={phase}><i />{engine.state ? phaseLabel[phase] : "Получаем состояние"}</span>
          <button type="button" className="theme-switch" title={theme === "black" ? "Светлая тема" : "Тёмная тема"} aria-label={theme === "black" ? "Включить светлую тему" : "Включить тёмную тему"} onClick={() => setTheme(theme === "black" ? "light" : "black")}><span aria-hidden="true">{theme === "black" ? "☼" : "◐"}</span></button>
          <div className="window-actions"><button type="button" aria-label="Свернуть" onClick={WindowMinimise}>_</button><button type="button" aria-label="Развернуть или восстановить" onClick={WindowToggleMaximise}>□</button><button type="button" aria-label="Закрыть" onClick={() => setClosing(true)}>×</button></div>
        </div>
      </header>
      <nav className="navigation" aria-label="Разделы приложения">{pages.map((p) => <button key={p.id} type="button" className={`nav-item${page === p.id ? " nav-item--active" : ""}`} aria-label={p.title} title={p.title} aria-current={page === p.id ? "page" : undefined} onClick={() => setPage(p.id)}>{p.title}</button>)}</nav>
      <section className="workspace__viewport" ref={viewport}>
        <div className="workspace__page" key={page}><Boundary resetKey={page}>{renderPage()}</Boundary></div>
        <footer className="workspace__footer">Evasion · работает на вашем устройстве</footer>
      </section>
      {booting && <div className="boot" aria-live="polite"><AsciiCat /><span>Запускаем Evasion…</span></div>}
      <Dialog open={closing} onClose={() => setClosing(false)} icon="power" title="Остаться на связи?" text="Сверните Evasion в трей, чтобы соединение продолжало работать."><button type="button" className="choice" onClick={() => { setClosing(false); void api.minimiseToTray(); }}><Icon name="tray" size={17} /><span><strong>Свернуть в трей</strong><small>Оставить обход работать в фоне</small></span></button><button type="button" className="choice choice--quit" onClick={() => void api.exitApplication()}><Icon name="power" size={17} /><span><strong>Завершить работу</strong><small>Остановить движок и выйти</small></span></button></Dialog>
      <Dialog open={pending !== null} onClose={() => setPending(null)} icon="send" title="Telegram — тоже?" text="Включить встроенный прокси вместе с обходом? При первом запуске подтвердите подключение в Telegram."><Button kind="ghost" onClick={() => { const options = pending; setPending(null); if (options) void engine.connect(options, false); }}>Только обход</Button><Button kind="solid" data-autofocus onClick={() => { const options = pending; setPending(null); if (options) void engine.connect(options, true); }}>Включить Telegram</Button></Dialog>
    </main>
  );
}
