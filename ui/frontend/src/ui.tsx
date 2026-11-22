// Accessible, familiar controls shared by the desktop screens.
import { Component, useEffect, useId, useLayoutEffect, useRef, useState, type CSSProperties, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { line as outline, solid as bold } from "./icons";

/* Service marks (paths: Simple Icons, CC0). */
const brands = {
  discord: { d: "M20.317 4.3698a19.7913 19.7913 0 00-4.8851-1.5152.0741.0741 0 00-.0785.0371c-.211.3753-.4447.8648-.6083 1.2495-1.8447-.2762-3.68-.2762-5.4868 0-.1636-.3933-.4058-.8742-.6177-1.2495a.077.077 0 00-.0785-.037 19.7363 19.7363 0 00-4.8852 1.515.0699.0699 0 00-.0321.0277C.5334 9.0458-.319 13.5799.0992 18.0578a.0824.0824 0 00.0312.0561c2.0528 1.5076 4.0413 2.4228 5.9929 3.0294a.0777.0777 0 00.0842-.0276c.4616-.6304.8731-1.2952 1.226-1.9942a.076.076 0 00-.0416-.1057c-.6528-.2476-1.2743-.5495-1.8722-.8923a.077.077 0 01-.0076-.1277c.1258-.0943.2517-.1923.3718-.2914a.0743.0743 0 01.0776-.0105c3.9278 1.7933 8.18 1.7933 12.0614 0a.0739.0739 0 01.0785.0095c.1202.099.246.1981.3728.2924a.077.077 0 01-.0066.1276 12.2986 12.2986 0 01-1.873.8914.0766.0766 0 00-.0407.1067c.3604.698.7719 1.3628 1.225 1.9932a.076.076 0 00.0842.0286c1.961-.6067 3.9495-1.5219 6.0023-3.0294a.077.077 0 00.0313-.0552c.5004-5.177-.8382-9.6739-3.5485-13.6604a.061.061 0 00-.0312-.0286zM8.02 15.3312c-1.1825 0-2.1569-1.0857-2.1569-2.419 0-1.3332.9555-2.4189 2.157-2.4189 1.2108 0 2.1757 1.0952 2.1568 2.419 0 1.3332-.9555 2.4189-2.1569 2.4189zm7.9748 0c-1.1825 0-2.1569-1.0857-2.1569-2.419 0-1.3332.9554-2.4189 2.1569-2.4189 1.2108 0 2.1757 1.0952 2.1568 2.419 0 1.3332-.946 2.4189-2.1568 2.4189Z" },
  youtube: { d: "M23.498 6.186a3.016 3.016 0 0 0-2.122-2.136C19.505 3.545 12 3.545 12 3.545s-7.505 0-9.377.505A3.017 3.017 0 0 0 .502 6.186C0 8.07 0 12 0 12s0 3.93.502 5.814a3.016 3.016 0 0 0 2.122 2.136c1.871.505 9.376.505 9.376.505s7.505 0 9.377-.505a3.015 3.015 0 0 0 2.122-2.136C24 15.93 24 12 24 12s0-3.93-.502-5.814zM9.545 15.568V8.432L15.818 12l-6.273 3.568z" },
  telegram: { d: "M16.906 7.224c.1-.002.321.023.465.14a.506.506 0 0 1 .171.325c.016.093.036.306.02.472-.18 1.898-.962 6.502-1.36 8.627-.168.9-.499 1.201-.82 1.23-.696.065-1.225-.46-1.9-.902-1.056-.693-1.653-1.124-2.678-1.8-1.185-.78-.417-1.21.258-1.91.177-.184 3.247-2.977 3.307-3.23.007-.032.014-.15-.056-.212s-.174-.041-.249-.024c-.106.024-1.793 1.14-5.061 3.345-.48.33-.913.49-1.302.48-.428-.008-1.252-.241-1.865-.44-.752-.245-1.349-.374-1.297-.789.027-.216.325-.437.893-.663 3.498-1.524 5.83-2.529 6.998-3.014 3.332-1.386 4.025-1.627 4.476-1.635z" },
};
export type BrandName = keyof typeof brands;
/* On the service tiles the marks are drawn in the interface's own ink. */
const boxes: Record<BrandName, string> = { discord: "0 0 24 24", youtube: "0 0 24 24", telegram: "4.47 5.62 14 14" };
export function BrandIcon({ name, size = 18 }: { name: BrandName; size?: number }) {
  return <svg width={size} height={size} viewBox={boxes[name]} fill="currentColor" aria-hidden="true" focusable="false"><path d={brands[name].d} /></svg>;
}
/* The same marks in the services' own colours, for the orbit behind the power ring. */
export function BrandLogo({ name, size = 28 }: { name: BrandName; size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" aria-hidden="true" focusable="false">
      {name === "discord" && <path fill="#5865f2" d={brands.discord.d} />}
      {name === "youtube" && <><path fill="#fff" d="M9 8h7.5v8H9z" /><path fill="#f03" d={brands.youtube.d} /></>}
      {name === "telegram" && <><circle cx="12" cy="12" r="12" fill="#26a5e4" /><path fill="#fff" d={brands.telegram.d} /></>}
    </svg>
  );
}
/* Telegram's own plane in the interface's ink, scaled to the icon grid: outlined like the rest of the set, solid for the current item. */
const fit = "translate(-4.39 -6.03) scale(1.4286)";
const line = { ...outline, send: <path fill="none" stroke="currentColor" strokeWidth="1.05" strokeLinejoin="round" transform={fit} d={brands.telegram.d} /> };
const solid: Partial<Record<keyof typeof line, ReactNode>> = { ...bold, send: <path fill="currentColor" transform={fit} d={brands.telegram.d} /> };
export type IconName = keyof typeof line;
/* One icon family for the whole interface: Solar, 1.5px outline; the bold cut marks the current navigation item.
   Sizes: 14 inside text and chips, 16 in controls, 18 in the navigation, 20 in icon boxes. */
export function Icon({ name, size = 20, fill = false, className = "" }: { name: IconName; size?: number; fill?: boolean; className?: string }) {
  return <svg width={size} height={size} viewBox="0 0 24 24" className={className} aria-hidden="true" focusable="false">{(fill && solid[name]) || line[name]}</svg>;
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
      {icon && <Icon name={icon} size={16} />}{children && <span>{children}</span>}
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
        <button key={o.id} type="button" role="radio" data-id={o.id} aria-checked={o.id === value} data-tip={o.hint} disabled={disabled} onClick={() => onChange(o.id)}>{o.label}</button>
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
        <Icon name="chevron" size={14} className="disclosure__chev" />
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
  const clock = (at: string) => { const t = Date.parse(at); return Number.isFinite(t) ? new Date(t).toLocaleTimeString("ru", { hour: "2-digit", minute: "2-digit", second: "2-digit" }) : ""; };
  return (
    <div className="feed" ref={box} onScroll={(e) => { const el = e.currentTarget; stick.current = el.scrollHeight - el.scrollTop - el.clientHeight < 24; }} tabIndex={0} aria-label="Журнал событий">
      {shown.map((l, i) => {
        const lvl = l.level.toUpperCase();
        const time = clock(l.at);
        // The time is printed once per second of events, not on every line.
        const first = i === 0 || clock(shown[i - 1].at) !== time;
        return (
          <div className={`feed__line feed__line--${lvl === "ERROR" ? "err" : lvl === "WARN" ? "warn" : "info"}`} key={`${l.at}-${i}`}>
            <time>{first ? time : ""}</time>
            <p><span>{l.msg}</span>{l.attrs && <em>{l.attrs}</em>}</p>
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

// Hover hints drawn by the app instead of the system tooltip: any element with data-tip gets one.
export function Tips() {
  const [tip, setTip] = useState<{ text: string; at: DOMRect } | null>(null);
  const bubble = useRef<HTMLDivElement>(null);
  const [place, setPlace] = useState<CSSProperties>({ visibility: "hidden" });
  useEffect(() => {
    let timer = 0, anchor: Element | null = null, shown: DOMRect | null = null;
    const quiet = () => { window.clearTimeout(timer); shown = null; setTip(null); };
    const hide = () => { quiet(); anchor = null; };
    const show = (target: EventTarget | null, delay: number) => {
      const el = target instanceof Element ? target.closest("[data-tip]") : null;
      if (el === anchor) return;
      hide();
      if (!el) return;
      anchor = el;
      timer = window.setTimeout(() => {
        const text = el.getAttribute("data-tip");
        if (!text || !el.isConnected) return;
        shown = el.getBoundingClientRect();
        setTip({ text, at: shown });
      }, delay);
    };
    const over = (e: PointerEvent) => show(e.target, 420);
    // Focus brings a hint up only when the keyboard moved it there, not when the app places focus itself.
    let tabbed = false;
    const focus = (e: FocusEvent) => { if (tabbed) show(e.target, 120); };
    const key = (e: KeyboardEvent) => { tabbed = e.key === "Tab"; if (e.key === "Escape") quiet(); };
    const press = () => { tabbed = false; quiet(); };
    // A hint does not follow its element: once that scrolls away under the pointer, the hint goes.
    const scroll = (e: Event) => {
      if (!anchor || !shown || !(e.target instanceof Node) || !e.target.contains(anchor)) return;
      const now = anchor.getBoundingClientRect();
      if (Math.abs(now.top - shown.top) > 6 || Math.abs(now.left - shown.left) > 6) hide();
    };
    document.addEventListener("pointerover", over);
    document.addEventListener("pointermove", over);
    document.addEventListener("focusin", focus);
    document.addEventListener("focusout", hide);
    document.addEventListener("pointerdown", press);
    document.documentElement.addEventListener("mouseleave", hide);
    document.addEventListener("keydown", key);
    window.addEventListener("scroll", scroll, true);
    window.addEventListener("blur", hide);
    window.addEventListener("resize", hide);
    return () => {
      window.clearTimeout(timer);
      document.removeEventListener("pointerover", over);
      document.removeEventListener("pointermove", over);
      document.removeEventListener("focusin", focus);
      document.removeEventListener("focusout", hide);
      document.removeEventListener("pointerdown", press);
      document.documentElement.removeEventListener("mouseleave", hide);
      document.removeEventListener("keydown", key);
      window.removeEventListener("scroll", scroll, true);
      window.removeEventListener("blur", hide);
      window.removeEventListener("resize", hide);
    };
  }, []);
  useLayoutEffect(() => {
    const el = bubble.current;
    if (!tip || !el) { setPlace({ visibility: "hidden" }); return; }
    const { width, height } = el.getBoundingClientRect(), gap = 8, edge = 8;
    const below = tip.at.bottom + gap + height <= window.innerHeight - edge;
    const left = Math.min(Math.max(tip.at.left + tip.at.width / 2 - width / 2, edge), window.innerWidth - width - edge);
    setPlace({ left, top: below ? tip.at.bottom + gap : Math.max(edge, tip.at.top - gap - height) });
  }, [tip]);
  if (!tip) return null;
  return createPortal(<div className="tip" role="tooltip" ref={bubble} style={place}>{tip.text}</div>, document.body);
}
