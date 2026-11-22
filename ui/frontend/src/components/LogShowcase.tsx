import { useEffect, useLayoutEffect, useRef, useState, type ReactNode } from "react";
import type { LogLine } from "../api";
import { advance, emptyFlow, resume, STEP } from "../logFlow";
import { phrases } from "../logPhrases";

const TAB_HEIGHT = 34, TAB_WIDTH = 124, TAB_RADIUS = 16, NOTCH = 18, RADIUS = 22;

// Tab, notch and body as one outline: separate pieces would overlap at the joints and tint them twice.
function outline(w: number, h: number): string {
  const t = TAB_RADIUS, n = NOTCH, r = RADIUS;
  return `M0 ${t}A${t} ${t} 0 0 1 ${t} 0H${TAB_WIDTH - t}A${t} ${t} 0 0 1 ${TAB_WIDTH} ${t}A${n} ${n} 0 0 0 ${TAB_WIDTH + n} ${TAB_HEIGHT}H${w - r}A${r} ${r} 0 0 1 ${w} ${TAB_HEIGHT + r}V${h - r}A${r} ${r} 0 0 1 ${w - r} ${h}H${r}A${r} ${r} 0 0 1 0 ${h - r}Z`;
}

const ROW = 26;
let flow = emptyFlow();

// The journal drifts up behind the glass, one line at a time; while nothing new arrives the recent lines come round again.
export function LogStream({ logs, live, motion, session = "" }: { logs: LogLine[]; live: boolean; motion: boolean; session?: string }) {
  const lines = phrases(logs, 24);
  const source = useRef(lines);
  source.current = lines;
  // Back on the screen: the run is already where it would have drifted to, and its last line glides in at once.
  const [rows, setRows] = useState(() => {
    if (!live || flow.session !== session || !flow.rows.length) return [];
    flow = resume(flow, session, lines, Date.now());
    return flow.rows.slice(0, -1);
  });
  // Lines that were on screen before the tab switch come back without the fade-in.
  const kept = useRef(rows[rows.length - 1]?.id ?? -1);
  useEffect(() => {
    if (!live) { flow = emptyFlow(); kept.current = -1; setRows([]); return; }
    flow = resume(flow, session, source.current, Date.now());
    setRows(flow.rows);
    const timer = window.setInterval(() => { flow = advance(flow, source.current, Date.now()); setRows(flow.rows); }, STEP);
    return () => window.clearInterval(timer);
  }, [live, session]);
  return (
    <div className="stream" aria-hidden="true" data-still={!motion || undefined}>
      <div className="stream__run" style={{ transform: `translateY(${-(rows[rows.length - 1]?.id ?? 0) * ROW}px)` }}>
        {rows.map((row) => <p key={row.id} data-kept={row.id <= kept.current || undefined} style={{ top: row.id * ROW }}>{row.text}</p>)}
      </div>
    </div>
  );
}

export function LogShowcase({ children }: { children: ReactNode }) {
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

  return (
    <div className="pane" ref={box}>
      <div className="pane__glass" style={d ? { WebkitMaskImage: shape, maskImage: shape } : { borderRadius: RADIUS }} />
      {/* A highlight on the lit corner, not an outline. */}
      {d && (
        <svg className="pane__rim" width={w} height={h} aria-hidden="true">
          <defs>
            <linearGradient id="pane-rim" x1="0" y1="0" x2=".5" y2=".7"><stop stopColor="#fff" stopOpacity=".3" /><stop offset=".55" stopColor="#fff" stopOpacity="0" /></linearGradient>
            <clipPath id="pane-shape"><path d={d} /></clipPath>
          </defs>
          <path d={d} clipPath="url(#pane-shape)" />
        </svg>
      )}
      <div className="pane__tab">Сессия</div>
      <div className="pane__body">{children}</div>
    </div>
  );
}
