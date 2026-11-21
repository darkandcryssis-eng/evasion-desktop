import { useEffect, useLayoutEffect, useRef, useState } from "react";
import type { LogLine } from "../api";

const TAB_HEIGHT = 34, TAB_WIDTH = 124, TAB_RADIUS = 16, NOTCH = 18, RADIUS = 22, LINES = 16;

// Tab, notch and body as one outline: separate pieces would overlap at the joints and tint them twice.
function outline(w: number, h: number): string {
  const t = TAB_RADIUS, n = NOTCH, r = RADIUS;
  return `M0 ${t}A${t} ${t} 0 0 1 ${t} 0H${TAB_WIDTH - t}A${t} ${t} 0 0 1 ${TAB_WIDTH} ${t}A${n} ${n} 0 0 0 ${TAB_WIDTH + n} ${TAB_HEIGHT}H${w - r}A${r} ${r} 0 0 1 ${w} ${TAB_HEIGHT + r}V${h - r}A${r} ${r} 0 0 1 ${w - r} ${h}H${r}A${r} ${r} 0 0 1 0 ${h - r}Z`;
}

function clock(at: string): string {
  const t = Date.parse(at);
  return Number.isFinite(t) ? new Date(t).toLocaleTimeString("ru", { hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "";
}
function tone(level: string): string {
  const l = level.toUpperCase();
  return l === "ERROR" ? " wm--err" : l === "WARN" ? " wm--warn" : "";
}

// The newest line is typed out; the ones above it are already history.
function Typed({ line, motion }: { line: LogLine; motion: boolean }) {
  const length = line.msg.length + (line.attrs ? line.attrs.length + 1 : 0);
  const [typed, setTyped] = useState(motion ? 0 : length);
  useEffect(() => {
    if (!motion) { setTyped(length); return; }
    let n = 0;
    setTyped(0);
    const id = window.setInterval(() => { n += 2; setTyped(n); if (n >= length) window.clearInterval(id); }, 22);
    return () => window.clearInterval(id);
  }, [line.at, line.msg, line.attrs, length, motion]);
  const attrs = typed > line.msg.length ? line.attrs.slice(0, typed - line.msg.length - 1) : "";
  return <p className={`wm wm--now${tone(line.level)}`}><time>{clock(line.at)}</time>{line.msg.slice(0, typed)}{attrs && <em> {attrs}</em>}<i className="wm__caret" /></p>;
}

export function LogShowcase({ logs, motion }: { logs: LogLine[]; motion: boolean }) {
  const box = useRef<HTMLDivElement>(null);
  const [[w, h], setSize] = useState<[number, number]>([0, 0]);
  useLayoutEffect(() => {
    const el = box.current;
    if (!el) return;
    const measure = () => setSize([el.clientWidth, el.clientHeight]);
    measure();
    if (typeof ResizeObserver === "undefined") return;
    const watch = new ResizeObserver(measure);
    watch.observe(el);
    return () => watch.disconnect();
  }, []);
  const d = w > TAB_WIDTH + NOTCH + RADIUS && h > TAB_HEIGHT + RADIUS * 2 ? outline(w, h) : "";
  // A mask, not clip-path: Chromium does not clip backdrop-filter to a clip-path.
  const shape = `url("data:image/svg+xml,${encodeURIComponent(`<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}"><path d="${d}"/></svg>`)}")`;
  const shown = logs.slice(-LINES);
  const last = shown.length - 1;

  return (
    <div className="pane" ref={box}>
      <div className="pane__glass" style={d ? { WebkitMaskImage: shape, maskImage: shape } : { borderRadius: RADIUS }} />
      {d && (
        <svg className="pane__rim" width={w} height={h} aria-hidden="true">
          <defs>
            <linearGradient id="pane-rim" x1="0" y1="0" x2=".5" y2=".7"><stop stopColor="#fff" stopOpacity=".3" /><stop offset=".55" stopColor="#fff" stopOpacity="0" /></linearGradient>
            <clipPath id="pane-shape"><path d={d} /></clipPath>
          </defs>
          <path d={d} clipPath="url(#pane-shape)" />
        </svg>
      )}
      <div className="pane__tab"><i aria-hidden="true" />Журнал</div>
      {/* Decorative: the readable journal is the disclosure below. The rim is a highlight on the lit corner, not an outline. */}
      <div className="pane__log" aria-hidden="true">
        {shown.length === 0 && <p className="wm wm--idle">Журнал появится, когда обход заработает</p>}
        {shown.map((l, i) => i === last
          ? <Typed key="now" line={l} motion={motion} />
          : <p className={`wm${tone(l.level)}`} key={i}><time>{clock(l.at)}</time>{l.msg}{l.attrs && <em> {l.attrs}</em>}</p>)}
      </div>
    </div>
  );
}
