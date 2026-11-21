import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import { flushSync } from "react-dom";
import { EventsOn, WindowCenter, WindowMinimise, WindowSetMinSize, WindowSetSize, WindowToggleMaximise } from "../wailsjs/runtime/runtime";
import { api, phaseLabel, type StartOptions } from "./api";
import { useEngine } from "./useEngine";
import { loadOptions, readPreference, savePreference } from "./preferences";
import { greetingAt } from "./greeting";
import { telegramPhase } from "./telegramBadge";
import { Backdrop, type BackdropHandle } from "./fx/Backdrop";
import { StartupParticles } from "./fx/StartupParticles";
import { Boundary, Button, Dialog, FilterDefs, Icon, type IconName } from "./ui";
import { HomeScreen, telegramMode } from "./screens/Home";
import { DiagnosticsScreen, GamesScreen, ServicesScreen, SettingsScreen, TelegramScreen } from "./screens/Pages";
import type { Page, Skin, Theme } from "./types";

type Screen = "startup" | "leaving" | "main";

const pages: { id: Page; title: string; icon: IconName }[] = [
  { id: "home", title: "Главная", icon: "home" },
  { id: "services", title: "Сервисы", icon: "layers" },
  { id: "games", title: "Игры", icon: "game" },
  { id: "telegram", title: "Telegram", icon: "send" },
  { id: "diagnostics", title: "Диагностика", icon: "pulse" },
  { id: "settings", title: "Настройки", icon: "settings" },
];

const startupSteps = ["Собираем туман", "Проверяем движок", "Настраиваем стекло", "Готово"];
const introSize = { width: 420, height: 300 };
const mainSize = { width: 1120, height: 760 };
const minSize = { width: 700, height: 500 };
const RIPPLE_MS = 1150;

const storedTheme = (): Theme => (readPreference("evasion-ui-theme") === "light" ? "light" : "black");
const storedSkin = (): Skin => (readPreference("evasion-ui-skin") === "natural" ? "natural" : "sakura");
const storedFlag = (key: string, fallback: boolean) => { const v = readPreference(key); return v === null ? fallback : v === "true"; };

type ViewTransitionDoc = Document & { startViewTransition?: (cb: () => void) => { ready: Promise<void>; finished: Promise<void> } };

function filamentPath(radius: number, phase: number) {
  let path = "";
  for (let i = 0; i <= 96; i++) {
    const angle = (i / 96) * Math.PI * 2;
    const r = radius + Math.sin(angle * 3 + phase) * 3.8 + Math.sin(angle * 5 - phase) * 1.6;
    path += `${i ? "L" : "M"}${(Math.cos(angle) * r).toFixed(2)},${(Math.sin(angle) * r * 0.97).toFixed(2)}`;
  }
  return `${path}Z`;
}

function Mark({ size = 26 }: { size?: number }) {
  // Знак «Поток»: нити медленно перетекают друг через друга, цвет — от темы.
  return (
    <svg className="mark" width={size} height={size} viewBox="-128 -128 256 256" aria-hidden="true">
      <g className="mark__flow">
        {[0, 1, 2, 3, 4].map((i) => (
          <g className="mark__filament" key={i} style={{ animationDuration: `${15 + i * 3}s` }}>
            <path d={filamentPath(72 + i * 6, i * 0.55)} fill="none" stroke="currentColor" strokeWidth="4.2" strokeLinejoin="round" opacity={0.62 + i * 0.09} />
          </g>
        ))}
      </g>
    </svg>
  );
}

export default function App() {
  const [startupEnabled, setStartupEnabled] = useState(() => storedFlag("evasion-ui-startup", true));
  const [motion, setMotion] = useState(() => storedFlag("evasion-ui-motion", true));
  const [screen, setScreen] = useState<Screen>(startupEnabled ? "startup" : "main");
  const [step, setStep] = useState(0);
  const [page, setPage] = useState<Page>("home");
  const [theme, setTheme] = useState<Theme>(storedTheme);
  const [skin, setSkin] = useState<Skin>(storedSkin);
  const [closing, setClosing] = useState(false);
  const [pending, setPending] = useState<StartOptions | null>(null);
  const [greeting] = useState(greetingAt);
  const engine = useEngine();
  const backdrop = useRef<BackdropHandle>(null);
  const viewport = useRef<HTMLDivElement>(null);
  const dock = useRef<HTMLElement>(null);
  const [drop, setDrop] = useState<{ y: number; h: number } | null>(null);
  const switching = useRef(false);

  useLayoutEffect(() => {
    document.documentElement.dataset.theme = theme;
    document.documentElement.dataset.skin = skin;
    document.documentElement.dataset.motion = motion ? "full" : "reduced";
  }, [theme, skin, motion]);

  useEffect(() => {
    const sync = () => { void api.setTrayPreferences(theme, loadOptions(), skin).catch(() => {}); };
    sync();
    window.addEventListener("evasion:options-changed", sync);
    return () => window.removeEventListener("evasion:options-changed", sync);
  }, [theme, skin, screen]);

  useEffect(() => EventsOn("evasion:navigate", (tab: unknown) => {
    if (tab === "Диагностика") { setClosing(false); setPending(null); setPage("diagnostics"); }
  }), []);

  useEffect(() => {
    savePreference("evasion-ui-theme", theme);
    savePreference("evasion-ui-skin", skin);
    savePreference("evasion-ui-motion", String(motion));
    savePreference("evasion-ui-startup", String(startupEnabled));
  }, [motion, startupEnabled, skin, theme]);

  useLayoutEffect(() => { if (viewport.current) viewport.current.scrollTop = 0; }, [page]);

  // Капля-индикатор в доке переезжает к активному разделу.
  useLayoutEffect(() => {
    if (screen !== "main") return;
    const el = dock.current?.querySelector<HTMLElement>(`[data-page="${page}"]`);
    if (el) setDrop({ y: el.offsetTop, h: el.offsetHeight });
  }, [page, screen]);

  const requestConnect = useCallback((options: StartOptions) => {
    const mode = telegramMode();
    if (mode === "ask") { setPending(options); return; }
    void engine.connect(options, mode === "yes");
  }, [engine]);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement | null;
      if (!event.ctrlKey || event.key !== "Enter" || event.repeat || event.altKey || event.shiftKey || closing || pending || screen !== "main" || target?.closest("input, textarea, select, [contenteditable=true]")) return;
      event.preventDefault();
      const phase = engine.state?.engine.phase;
      if (engine.busy || !phase || phase === "starting" || phase === "stopping") return;
      if (phase === "running") void engine.stop();
      else if (engine.state?.elevated && engine.state.payload.engine && engine.state.payload.windivert && (engine.state.payload.config || engine.state.userConfig)) requestConnect(loadOptions());
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [engine, closing, pending, screen, requestConnect]);

  // Стартовый экран: шаги → окно плавно раскрывается до рабочего размера.
  useEffect(() => {
    if (!startupEnabled) {
      WindowSetSize(mainSize.width, mainSize.height);
      WindowSetMinSize(minSize.width, minSize.height);
      WindowCenter();
      return;
    }
    let cancelled = false, timer = 0, finish = 0, raf = 0;
    const expand = () => {
      const started = performance.now(), duration = 460;
      const frame = (now: number) => {
        if (cancelled) return;
        const p = Math.min((now - started) / duration, 1), e = 1 - Math.pow(1 - p, 4);
        WindowSetSize(Math.round(introSize.width + (mainSize.width - introSize.width) * e), Math.round(introSize.height + (mainSize.height - introSize.height) * e));
        WindowCenter();
        if (p < 1) raf = requestAnimationFrame(frame);
        else WindowSetMinSize(minSize.width, minSize.height);
      };
      raf = requestAnimationFrame(frame);
    };
    const next = (index: number) => {
      timer = window.setTimeout(() => {
        if (cancelled) return;
        if (index < startupSteps.length - 1) { setStep(index + 1); next(index + 1); return; }
        setScreen("leaving");
        expand();
        finish = window.setTimeout(() => setScreen("main"), 520);
      }, 760);
    };
    WindowCenter();
    next(0);
    return () => { cancelled = true; window.clearTimeout(timer); window.clearTimeout(finish); cancelAnimationFrame(raf); };
  }, []);

  // Смена темы: волна от переключателя. Фон перетекает в шейдере, интерфейс —
  // через View Transition с тем же центром и той же кривой.
  const switchTheme = (event: React.MouseEvent<HTMLButtonElement>) => {
    if (switching.current) return;
    const next: Theme = theme === "black" ? "light" : "black";
    const rect = event.currentTarget.getBoundingClientRect();
    const x = rect.left + rect.width / 2, y = rect.top + rect.height / 2;
    const doc = document as ViewTransitionDoc;
    if (!motion || typeof doc.startViewTransition !== "function") { setTheme(next); return; }
    switching.current = true;
    const w = window.innerWidth, h = window.innerHeight;
    const far = Math.hypot(Math.max(x, w - x), Math.max(y, h - y)) + h * 0.25;
    backdrop.current?.ripple(next === "black", x / w, y / h, RIPPLE_MS);
    document.documentElement.dataset.switching = "true";
    const transition = doc.startViewTransition(() => { flushSync(() => setTheme(next)); document.documentElement.dataset.theme = next; });
    void transition.ready.then(() => {
      document.documentElement.animate({ clipPath: [`circle(0px at ${x}px ${y}px)`, `circle(${far}px at ${x}px ${y}px)`] }, { duration: RIPPLE_MS, easing: "cubic-bezier(.65,0,.35,1)", pseudoElement: "::view-transition-new(root)" });
    }).catch(() => {});
    void transition.finished.finally(() => { switching.current = false; delete document.documentElement.dataset.switching; });
  };

  const phase = engine.state?.engine.phase ?? "stopped";
  const status = engine.state ? (phase === "stopped" && engine.state.telegram?.running ? `Telegram: ${telegramPhase[engine.state.telegram.phase]}` : phaseLabel[phase]) : "Загрузка";
  const progress = ((step + 1) / startupSteps.length) * 100;

  const renderPage = () => {
    switch (page) {
      case "services": return <ServicesScreen state={engine.state} />;
      case "games": return <GamesScreen onNavigate={setPage} />;
      case "telegram": return <TelegramScreen state={engine.state?.telegram} onRefresh={engine.refresh} />;
      case "diagnostics": return <DiagnosticsScreen />;
      case "settings": return <SettingsScreen motion={motion} startup={startupEnabled} skin={skin} onMotion={setMotion} onStartup={setStartupEnabled} onSkin={setSkin} baseDir={engine.state?.baseDir} />;
      default: return <HomeScreen engine={engine} onConnect={requestConnect} onNavigate={setPage} />;
    }
  };

  return (
    <main className={`app app--${screen}`} data-phase={phase}>
      <Backdrop ref={backdrop} dark={theme === "black"} motion={motion} skin={skin} />
      <div className="veil" aria-hidden="true" />
      <FilterDefs />

      <header className="titlebar">
        {screen === "main" && <>
          <div className="brand" aria-label="Evasion"><Mark /><span>evasion</span></div>
          <div className="titlebar__status" data-phase={phase}><i />{status}</div>
          <div className="titlebar__tools">
            <button type="button" className="themer" data-theme-now={theme} aria-label={theme === "black" ? "Включить светлую тему" : "Включить тёмную тему"} title="Сменить тему" onClick={switchTheme}>
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" aria-hidden="true">
                <mask id="moon-cut"><rect width="24" height="24" fill="#fff" /><circle className="themer__cut" cx="17" cy="8" r="6.2" fill="#000" /></mask>
                <circle className="themer__disc" cx="12" cy="12" r="4.6" fill="currentColor" mask="url(#moon-cut)" />
                <g className="themer__rays"><path d="M12 2.5v2M12 19.5v2M2.5 12h2M19.5 12h2M5.3 5.3l1.4 1.4M17.3 17.3l1.4 1.4M5.3 18.7l1.4-1.4M17.3 6.7l1.4-1.4" /></g>
              </svg>
            </button>
            <div className="wincontrols">
              <button type="button" aria-label="Свернуть" onClick={WindowMinimise}><svg width="11" height="11" viewBox="0 0 11 11"><path d="M1.5 5.5h8" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" /></svg></button>
              <button type="button" aria-label="Развернуть или восстановить" onClick={WindowToggleMaximise}><svg width="11" height="11" viewBox="0 0 11 11"><rect x="1.8" y="1.8" width="7.4" height="7.4" rx="1.6" fill="none" stroke="currentColor" strokeWidth="1.2" /></svg></button>
              <button type="button" className="wincontrols__close" aria-label="Закрыть" onClick={() => setClosing(true)}><svg width="11" height="11" viewBox="0 0 11 11"><path d="m2 2 7 7M9 2 2 9" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" /></svg></button>
            </div>
          </div>
        </>}
      </header>

      {screen !== "main" && (
        <section className={`splash${screen === "leaving" ? " splash--leaving" : ""}${motion ? " splash--particles" : ""}`} aria-live="polite">
          <div className="splash__glass">
            <StartupParticles exploding={screen === "leaving"} motion={motion} />
            <div className="splash__inner">
              {!motion && <span className="splash__mark"><Mark size={34} /></span>}
              <h1>{greeting}</h1>
              <p className="splash__step" key={step}>{startupSteps[step]}</p>
              <div className="splash__track" role="progressbar" aria-valuenow={Math.round(progress)} aria-valuemin={0} aria-valuemax={100}><span style={{ transform: `scaleX(${progress / 100})` }} /></div>
            </div>
          </div>
        </section>
      )}

      {screen === "main" && (
        <div className="shell">
          <nav className="dock glass glass--lens" aria-label="Разделы приложения" ref={dock}>
            {drop && <span className="dock__drop" style={{ transform: `translateY(${drop.y}px)`, height: drop.h }} aria-hidden="true" />}
            {pages.map((p) => (
              <button key={p.id} type="button" data-page={p.id} className={`dock__item${page === p.id ? " dock__item--active" : ""}`} aria-label={p.title} aria-current={page === p.id ? "page" : undefined} onClick={() => setPage(p.id)}>
                <Icon name={p.icon} size={19} /><span className="dock__tip">{p.title}</span>
              </button>
            ))}
          </nav>
          <section className="stage" ref={viewport}><div className="page" key={page}><Boundary resetKey={page}>{renderPage()}</Boundary></div></section>
        </div>
      )}

      <Dialog open={closing} onClose={() => setClosing(false)} icon="power" title="Что сделать с приложением?" text="Свернуть в трей и оставить обход работать — или полностью закрыть.">
        <button type="button" className="choice" onClick={() => { setClosing(false); void api.minimiseToTray(); }}><Icon name="tray" size={17} /><span><strong>Свернуть в трей</strong><small>Окно скроется, значок останется у часов</small></span></button>
        <button type="button" className="choice choice--quit" onClick={() => void api.exitApplication()}><Icon name="power" size={17} /><span><strong>Закрыть приложение</strong><small>Остановить движок и выйти</small></span></button>
      </Dialog>
      <Dialog open={pending !== null} onClose={() => setPending(null)} icon="send" title="Включить Telegram-прокси?" text="Запустить вместе с обходом. При первом включении подтвердите подключение в Telegram. Ответ можно запомнить в параметрах подключения.">
        <Button kind="ghost" onClick={() => { const o = pending; setPending(null); if (o) void engine.connect(o, false); }}>Нет, только обход</Button>
        <Button kind="solid" data-autofocus onClick={() => { const o = pending; setPending(null); if (o) void engine.connect(o, true); }}>Да, включить</Button>
      </Dialog>
    </main>
  );
}
