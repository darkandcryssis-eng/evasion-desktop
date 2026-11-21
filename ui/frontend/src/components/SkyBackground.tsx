import { type CSSProperties, useEffect, useRef } from "react";
import type { Theme } from "../types";

const rain = Array.from({ length: 38 }, (_, i) => ({
  left: `${((i * 73) % 127) - 6}%`,
  "--rain-duration": `${1.8 + (i % 7) * .28}s`,
  "--rain-delay": `${-((i * 17) % 41) * .27}s`,
  "--rain-length": `${22 + (i % 5) * 11}px`,
  "--rain-position": `${(i * 31) % 100}%`,
  "--rain-alpha": .12 + (i % 4) * .045,
} as CSSProperties));

const sparks = Array.from({ length: 18 }, (_, i) => ({
  left: `${i % 2 ? 78 + (i * 7) % 20 : 2 + (i * 7) % 21}%`,
  top: `${12 + (i * 19) % 78}%`,
  "--spark-duration": `${3.8 + (i % 5) * .7}s`,
  "--spark-delay": `${-i * .43}s`,
  "--spark-size": `${i % 3 ? 2 : 3}px`,
} as CSSProperties));

export function SkyBackground({ motion, theme }: { motion: boolean; theme: Theme }) {
  const rootRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const root = rootRef.current;
    if (!root) return;

    const preference = window.matchMedia("(prefers-reduced-motion: reduce)");
    let focused = document.hasFocus();
    let enabled = motion && !preference.matches && !document.hidden && focused;
    root.dataset.animated = String(enabled);
    let frame = 0;
    let lastTime = 0;
    let x = 0;
    let y = 0;
    let targetX = 0;
    let targetY = 0;

    const paint = () => {
      root.style.setProperty("--sky-x", x.toFixed(5));
      root.style.setProperty("--sky-y", y.toFixed(5));
    };

    const animate = (time: number) => {
      const elapsed = lastTime ? Math.min(time - lastTime, 64) : 16;
      const ease = 1 - Math.exp(-elapsed / 110);
      lastTime = time;
      x += (targetX - x) * ease;
      y += (targetY - y) * ease;

      if (Math.abs(targetX - x) + Math.abs(targetY - y) < 0.001) {
        x = targetX;
        y = targetY;
        frame = 0;
        lastTime = 0;
      } else {
        frame = requestAnimationFrame(animate);
      }
      paint();
    };

    const queue = () => {
      if (!frame && enabled) frame = requestAnimationFrame(animate);
    };

    const onMove = (event: PointerEvent) => {
      if (!enabled || event.pointerType !== "mouse") return;
      targetX = Math.max(-1, Math.min(1, (event.clientX / window.innerWidth) * 2 - 1));
      targetY = Math.max(-1, Math.min(1, (event.clientY / window.innerHeight) * 2 - 1));
      queue();
    };

    const centre = () => {
      targetX = 0;
      targetY = 0;
      queue();
    };

    const onLeave = (event: PointerEvent) => {
      if (!event.relatedTarget) centre();
    };

    const reset = () => {
      cancelAnimationFrame(frame);
      frame = lastTime = x = y = targetX = targetY = 0;
      paint();
    };

    const onPreferenceChange = () => {
      enabled = motion && !preference.matches && !document.hidden && focused;
      root.dataset.animated = String(enabled);
      reset();
    };
    const onFocus = () => { focused = true; onPreferenceChange(); };
    const onBlur = () => { focused = false; onPreferenceChange(); };

    window.addEventListener("pointermove", onMove, { passive: true });
    window.addEventListener("pointerout", onLeave, { passive: true });
    window.addEventListener("blur", onBlur);
    window.addEventListener("focus", onFocus);
    window.addEventListener("resize", reset);
    preference.addEventListener("change", onPreferenceChange);
    document.addEventListener("visibilitychange", onPreferenceChange);

    return () => {
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerout", onLeave);
      window.removeEventListener("blur", onBlur);
      window.removeEventListener("focus", onFocus);
      window.removeEventListener("resize", reset);
      preference.removeEventListener("change", onPreferenceChange);
      document.removeEventListener("visibilitychange", onPreferenceChange);
      reset();
    };
  }, [motion]);

  return (
    <div className="sky-background" ref={rootRef} aria-hidden="true" data-animated="false">
      {theme === "light" && <div className="sky-sun"><div className="sky-sun__halo" /><div className="sky-sun__disc" /></div>}
      <div className="sky-cloud sky-cloud--far" />
      <div className="sky-cloud sky-cloud--left" />
      <div className="sky-cloud sky-cloud--right" />
      {theme === "black" && <div className="storm-atmosphere">
        <div className="storm-mist storm-mist--upper" />
        <div className="storm-mist storm-mist--lower" />
        <div className="storm-light storm-light--right" />
        <div className="storm-light storm-light--left" />
        <svg className="storm-lightning" viewBox="0 0 1000 800" preserveAspectRatio="none" fill="none">
          <g className="storm-bolt storm-bolt--right">
            <path className="storm-bolt__glow" d="M902-16 887 53 905 71 866 128 887 136 849 207 866 221 824 306 850 291 811 380 828 369 791 462" />
            <path className="storm-bolt__core" d="M902-16 887 53 905 71 866 128 887 136 849 207 866 221 824 306 850 291 811 380 828 369 791 462" />
            <path className="storm-bolt__branch" d="m866 128 45 20 21 37 35 10m-118 12-43 42 7 28-24 35m35-6 52 16 15 33 40 18" />
          </g>
          <g className="storm-bolt storm-bolt--left">
            <path className="storm-bolt__glow" d="M95-20 132 51 109 82 152 151 139 171 173 225 150 253 204 330 180 346 225 420" />
            <path className="storm-bolt__core" d="M95-20 132 51 109 82 152 151 139 171 173 225 150 253 204 330 180 346 225 420" />
            <path className="storm-bolt__branch" d="m132 51-38 25-10 38-25 14m80 43 54 17 13 31 32 14m-88 20-38 27-12 38-29 18" />
          </g>
        </svg>
        <div className="storm-sparks">{sparks.map((style, i) => <i key={i} style={style} />)}</div>
        <div className="storm-rain">{rain.map((style, i) => <i key={i} style={style} />)}</div>
      </div>}
    </div>
  );
}
