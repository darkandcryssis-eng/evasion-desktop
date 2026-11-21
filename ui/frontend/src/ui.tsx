// Accessible, familiar controls shared by the desktop screens.
import { Component, useEffect, useId, useLayoutEffect, useRef, useState, type CSSProperties, type ReactNode } from "react";
import { House, Layers, Gamepad2, Send, Activity, Settings, Power, RefreshCw, ChevronDown, Copy, ExternalLink, Folder, Trash2, Plus, Shield, TriangleAlert, Download, Search, Eye, X, ArrowDownLeft, ArrowUpRight, PanelBottom, Info, Play, Zap, Route, Sun, Moon, Minus, Square } from "lucide-react";

const glyphs = {
  home: House, layers: Layers, game: Gamepad2, send: Send, pulse: Activity,
  settings: Settings, power: Power, refresh: RefreshCw, chevron: ChevronDown, copy: Copy,
  external: ExternalLink, folder: Folder, trash: Trash2, plus: Plus, shield: Shield,
  alert: TriangleAlert, download: Download, search: Search, eye: Eye, x: X,
  down: ArrowDownLeft, up: ArrowUpRight, tray: PanelBottom, info: Info, play: Play, bolt: Zap, route: Route, sun: Sun, moon: Moon, minus: Minus, square: Square,
};
export type IconName = keyof typeof glyphs;
export function Icon({ name, size = 18, stroke = 1.7, className = "" }: { name: IconName; size?: number; stroke?: number; className?: string }) {
  const Glyph = glyphs[name];
  return <Glyph size={size} strokeWidth={stroke} className={className} aria-hidden="true" focusable="false" />;
}

/* ───────────── SVG-фильтры: жидкое стекло и «гу» ───────────── */
// lg-* — преломление фона по краю элемента (работает в Chromium/WebView2 через
// backdrop-filter:url()). goo — слияние капель для морфинга кнопок.
export function FilterDefs() {
  return (
    <svg className="fx-defs" width="0" height="0" aria-hidden="true" focusable="false">
      <defs>
        <filter id="goo" x="-20%" y="-60%" width="140%" height="220%" colorInterpolationFilters="sRGB">
          <feGaussianBlur in="SourceGraphic" stdDeviation="7" result="b" />
          <feColorMatrix in="b" mode="matrix" values="1 0 0 0 0  0 1 0 0 0  0 0 1 0 0  0 0 0 22 -9" result="g" />
          <feComposite in="SourceGraphic" in2="g" operator="atop" />
        </filter>
        <filter id="lg" x="0%" y="0%" width="100%" height="100%" colorInterpolationFilters="sRGB">
          <feTurbulence type="fractalNoise" baseFrequency="0.008 0.012" numOctaves="2" seed="7" result="n" />
          <feGaussianBlur in="n" stdDeviation="2" result="nb" />
          <feDisplacementMap in="SourceGraphic" in2="nb" scale="28" xChannelSelector="R" yChannelSelector="G" result="d" />
          <feGaussianBlur in="d" stdDeviation="5" />
        </filter>
      </defs>
    </svg>
  );
}

/* ───────────── Примитивы ───────────── */
export type Tone = "neutral" | "accent" | "success" | "warning";

export function Badge({ tone = "neutral", children, pulse }: { tone?: Tone; children: ReactNode; pulse?: boolean }) {
  return <span className={`badge badge--${tone}${pulse ? " badge--pulse" : ""}`} role="status"><i />{children}</span>;
}

export function Glass({ className = "", children, as: Tag = "section", style, ...rest }: { className?: string; children: ReactNode; as?: "section" | "article" | "div" | "aside"; style?: CSSProperties } & Record<string, unknown>) {
  return <Tag className={`glass ${className}`} style={style} {...rest}>{children}</Tag>;
}

export function Toggle({ checked, onChange, label, disabled }: { checked: boolean; onChange: (v: boolean) => void; label: string; disabled?: boolean }) {
  return (
    <button type="button" role="switch" aria-checked={checked} aria-label={label} disabled={disabled} className={`toggle${checked ? " toggle--on" : ""}`} onClick={() => onChange(!checked)}>
      <span className="toggle__drop" />
    </button>
  );
}

export function Button({ children, icon, kind = "soft", ...rest }: { children?: ReactNode; icon?: IconName; kind?: "soft" | "solid" | "ghost" | "danger" } & React.ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button type="button" {...rest} className={`btn btn--${kind} ${rest.className ?? ""}`}>
      {icon && <Icon name={icon} size={15} />}{children && <span>{children}</span>}
    </button>
  );
}

// Сегментированный выбор с «каплей», переезжающей между вариантами.
export function Segmented<T extends string>({ value, options, onChange, label, disabled }: { value: T; options: { id: T; label: string; hint?: string }[]; onChange: (v: T) => void; label: string; disabled?: boolean }) {
  const root = useRef<HTMLDivElement>(null);
  const [box, setBox] = useState<{ left: number; width: number } | null>(null);
  useLayoutEffect(() => {
    const measure = () => {
      const el = root.current?.querySelector<HTMLButtonElement>(`[data-id="${value}"]`);
      if (el) setBox({ left: el.offsetLeft, width: el.offsetWidth });
    };
    measure();
    const ro = typeof ResizeObserver === "undefined" ? null : new ResizeObserver(measure);
    if (ro && root.current) ro.observe(root.current);
    return () => ro?.disconnect();
  }, [value, options.length]);
  return (
    <div className="segmented" role="radiogroup" aria-label={label} ref={root} data-disabled={disabled || undefined}>
      {box && <span className="segmented__drop" style={{ transform: `translateX(${box.left}px)`, width: box.width }} />}
      {options.map((o) => (
        <button key={o.id} type="button" role="radio" data-id={o.id} aria-checked={o.id === value} title={o.hint} disabled={disabled} onClick={() => onChange(o.id)}>{o.label}</button>
      ))}
    </div>
  );
}

// Плавное раскрытие по высоте (grid 0fr → 1fr).
export function Collapse({ open, children }: { open: boolean; children: ReactNode }) {
  return <div className={`collapse${open ? " collapse--open" : ""}`} aria-hidden={!open}><div className="collapse__inner">{children}</div></div>;
}

export function Disclosure({ icon, title, note, children, defaultOpen = false, className = "" }: { icon: IconName; title: string; note?: ReactNode; children: ReactNode; defaultOpen?: boolean; className?: string }) {
  const [open, setOpen] = useState(defaultOpen);
  const id = useId();
  return (
    <Glass className={`disclosure ${className}${open ? " disclosure--open" : ""}`}>
      <button type="button" className="disclosure__head" aria-expanded={open} aria-controls={id} onClick={() => setOpen(!open)}>
        <span className="disclosure__icon"><Icon name={icon} /></span>
        <span className="disclosure__text"><strong>{title}</strong>{note && <small>{note}</small>}</span>
        <Icon name="chevron" size={15} className="disclosure__chev" />
      </button>
      <div id={id}><Collapse open={open}><div className="disclosure__body">{children}</div></Collapse></div>
    </Glass>
  );
}

export function Row({ title, note, children }: { title: ReactNode; note?: ReactNode; children?: ReactNode }) {
  return <div className="row"><div className="row__text"><strong>{title}</strong>{note && <small>{note}</small>}</div>{children && <div className="row__side">{children}</div>}</div>;
}

export function Note({ children, tone, icon }: { children: ReactNode; tone?: "warn"; icon?: IconName }) {
  return <p className={`note${tone ? ` note--${tone}` : ""}`} role={tone ? "alert" : undefined}>{icon && <Icon name={icon} size={14} />}<span>{children}</span></p>;
}

export function PageHead({ kicker, title, note, action }: { kicker?: string; title: string; note?: string; action?: ReactNode }) {
  return (
    <header className="pagehead">
      <div>{kicker && <span className="kicker">{kicker}</span>}<h1>{title}</h1>{note && <p>{note}</p>}</div>
      {action && <div className="pagehead__action">{action}</div>}
    </header>
  );
}

// Число, которое «докатывается» до нового значения.
export function Ticker({ value, format }: { value: number; format?: (n: number) => string }) {
  const [shown, setShown] = useState(value);
  const from = useRef(value);
  useEffect(() => {
    const start = performance.now(), a = from.current, b = value;
    if (a === b || document.documentElement.dataset.motion === "reduced") { from.current = b; setShown(b); return; }
    let raf = 0;
    const step = (now: number) => {
      const p = Math.min(1, (now - start) / 520), e = 1 - Math.pow(1 - p, 3);
      const v = a + (b - a) * e;
      from.current = v; setShown(v);
      if (p < 1) raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [value]);
  const n = Math.round(shown);
  return <>{format ? format(n) : n.toLocaleString("ru")}</>;
}

/* ───────────── Диалог ───────────── */
export function Dialog({ open, onClose, title, text, icon, children }: { open: boolean; onClose: () => void; title: string; text?: string; icon: IconName; children: ReactNode }) {
  const root = useRef<HTMLElement>(null);
  const close = useRef(onClose);
  close.current = onClose;
  const id = useId();
  useEffect(() => {
    if (!open) return;
    const previous = document.activeElement as HTMLElement | null;
    const buttons = () => Array.from(root.current?.querySelectorAll<HTMLButtonElement>("button:not([disabled])") ?? []);
    (root.current?.querySelector<HTMLButtonElement>("[data-autofocus]") ?? buttons()[1])?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") close.current();
      if (e.key !== "Tab") return;
      const list = buttons();
      if (!list.length) return;
      if (e.shiftKey && document.activeElement === list[0]) { e.preventDefault(); list[list.length - 1].focus(); }
      else if (!e.shiftKey && document.activeElement === list[list.length - 1]) { e.preventDefault(); list[0].focus(); }
    };
    window.addEventListener("keydown", onKey);
    return () => { window.removeEventListener("keydown", onKey); previous?.focus(); };
  }, [open]);
  if (!open) return null;
  return (
    <div className="scrim" onMouseDown={onClose}>
      <section ref={root} className="dialog glass glass--lens" role="dialog" aria-modal="true" aria-labelledby={id} onMouseDown={(e) => e.stopPropagation()}>
        <button type="button" className="dialog__x" aria-label="Отмена" onClick={onClose}><Icon name="x" size={14} /></button>
        <span className="dialog__mark"><Icon name={icon} size={20} /></span>
        <h2 id={id}>{title}</h2>
        {text && <p>{text}</p>}
        <div className="dialog__actions">{children}</div>
      </section>
    </div>
  );
}

/* ───────────── Журнал ───────────── */
export type FeedLine = { at: string; level: string; msg: string; attrs: string };

export function Feed({ logs, limit = 80, empty = "Здесь появятся события" }: { logs: FeedLine[]; limit?: number; empty?: string }) {
  const box = useRef<HTMLDivElement>(null);
  const stick = useRef(true);
  const shown = logs.slice(-limit);
  useEffect(() => { const el = box.current; if (el && stick.current) el.scrollTop = el.scrollHeight; }, [shown.length, shown[shown.length - 1]?.at]);
  if (!shown.length) return <p className="feed feed--empty">{empty}</p>;
  return (
    <div className="feed" ref={box} onScroll={(e) => { const el = e.currentTarget; stick.current = el.scrollHeight - el.scrollTop - el.clientHeight < 24; }} tabIndex={0} aria-label="Журнал событий">
      {shown.map((l, i) => {
        const t = Date.parse(l.at);
        const lvl = l.level.toUpperCase();
        return (
          <div className={`feed__line feed__line--${lvl === "ERROR" ? "err" : lvl === "WARN" ? "warn" : "info"}`} key={`${l.at}-${i}`} title={l.attrs || undefined}>
            <time>{Number.isFinite(t) ? new Date(t).toLocaleTimeString("ru", { hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "—"}</time>
            <span>{l.msg}{l.attrs && <em> {l.attrs}</em>}</span>
          </div>
        );
      })}
    </div>
  );
}

export function traffic(bytes: number) {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 Б";
  const units = ["Б", "КБ", "МБ", "ГБ"];
  const index = Math.min(3, Math.floor(Math.log(bytes) / Math.log(1024)));
  return `${(bytes / 1024 ** index).toLocaleString("ru", { maximumFractionDigits: index ? 1 : 0 })} ${units[index]}`;
}

export function fileName(path: string) { return path.split(/[\\/]/).pop() || path; }

/* ───────────── Защита от падения рендера ───────────── */
// Ошибка в одном разделе не гасит всё окно: показываем карточку и даём повторить.
export class Boundary extends Component<{ children: ReactNode; resetKey?: string }, { error: string }> {
  state = { error: "" };
  static getDerivedStateFromError(e: unknown) { return { error: e instanceof Error ? e.message : String(e) }; }
  componentDidUpdate(prev: { resetKey?: string }) { if (prev.resetKey !== this.props.resetKey && this.state.error) this.setState({ error: "" }); }
  render() {
    if (!this.state.error) return this.props.children;
    return (
      <div className="page-body">
        <section className="glass card">
          <header className="card-head"><span className="kicker">Раздел не загрузился</span></header>
          <p className="lead">Что-то пошло не так при отрисовке.</p>
          <p className="note note--warn"><span className="mono">{this.state.error}</span></p>
          <div className="inline"><button type="button" className="btn btn--solid" onClick={() => this.setState({ error: "" })}><span>Повторить</span></button></div>
        </section>
      </div>
    );
  }
}
