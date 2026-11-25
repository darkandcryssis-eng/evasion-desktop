import { useEffect, useRef, useState } from "react";
import { startVisibleLoop } from "./windowActivity";

// Периодический опрос Go-API: без наложения запросов и без работы в скрытом окне.
export function usePoll<T>(load: () => Promise<T>, ms: number, enabled = true) {
  const [value, setValue] = useState<T>();
  const [error, setError] = useState("");
  const fn = useRef(load);
  fn.current = load;
  const tick = useRef<() => Promise<void>>(async () => {});
  useEffect(() => {
    if (!enabled) return;
    let alive = true;
    const loop = startVisibleLoop(async () => {
      try { const next = await fn.current(); if (alive) { setValue(next); setError(""); } }
      catch (e) { if (alive) setError(String(e)); }
    }, ms);
    tick.current = loop.run;
    return () => { alive = false; loop.stop(); };
  }, [ms, enabled]);
  return { value, error, refresh: () => tick.current(), set: setValue };
}

// Секундомер от момента запуска.
export function useElapsed(startedAt: string | undefined, active: boolean) {
  const [, force] = useState(0);
  useEffect(() => {
    if (!active) return;
    return startVisibleLoop(() => force((n) => n + 1), 1000).stop;
  }, [active]);
  const start = startedAt ? Date.parse(startedAt) : NaN;
  if (!active || !Number.isFinite(start)) return "00:00:00";
  const s = Math.max(0, Math.floor((Date.now() - start) / 1000));
  const p = (n: number) => String(n).padStart(2, "0");
  return `${p(Math.floor(s / 3600))}:${p(Math.floor(s / 60) % 60)}:${p(s % 60)}`;
}
