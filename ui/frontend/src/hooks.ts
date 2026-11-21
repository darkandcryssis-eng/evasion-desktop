import { useEffect, useRef, useState } from "react";

// Периодический опрос Go-API: без наложения запросов и без работы в скрытом окне.
export function usePoll<T>(load: () => Promise<T>, ms: number, enabled = true) {
  const [value, setValue] = useState<T>();
  const [error, setError] = useState("");
  const fn = useRef(load);
  fn.current = load;
  const tick = useRef<() => Promise<void>>(async () => {});
  useEffect(() => {
    if (!enabled) return;
    let alive = true, pending = false;
    const run = async () => {
      if (pending || (typeof document !== "undefined" && document.hidden)) return;
      pending = true;
      try { const next = await fn.current(); if (alive) { setValue(next); setError(""); } }
      catch (e) { if (alive) setError(String(e)); }
      finally { pending = false; }
    };
    tick.current = run;
    void run();
    const timer = window.setInterval(() => void run(), ms);
    return () => { alive = false; window.clearInterval(timer); };
  }, [ms, enabled]);
  return { value, error, refresh: () => tick.current(), set: setValue };
}

// Секундомер от момента запуска.
export function useElapsed(startedAt: string | undefined, active: boolean) {
  const [, force] = useState(0);
  useEffect(() => {
    if (!active) return;
    const timer = window.setInterval(() => force((n) => n + 1), 1000);
    return () => window.clearInterval(timer);
  }, [active]);
  const start = startedAt ? Date.parse(startedAt) : NaN;
  if (!active || !Number.isFinite(start)) return "00:00:00";
  const s = Math.max(0, Math.floor((Date.now() - start) / 1000));
  const p = (n: number) => String(n).padStart(2, "0");
  return `${p(Math.floor(s / 3600))}:${p(Math.floor(s / 60) % 60)}:${p(s % 60)}`;
}
