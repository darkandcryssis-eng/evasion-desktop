// Главная кнопка: кольцо из световых волокон на canvas. В покое — тонкий обод с
// дышащими прядями; при нажатии кольцо делится на две капли (как клетка) и
// сливается обратно; во время работы — полное сияющее кольцо.
import { useEffect, useRef } from "react";
import { Icon } from "../ui";
import { startVisibleLoop, watchWindowActivity } from "../windowActivity";

export type OrbPhase = "stopped" | "starting" | "running" | "stopping" | "failed";

type Fiber = { a: number; len: number; ph: number; sp: number; tint: number; lobe: number; sw: number };

// Палитры волокон под фоны: лаванда и луч для тёмной, мох и солнце для светлой.
const PALETTES: Record<"black" | "light", Record<"idle" | "live" | "fail", [number, number, number][]>> = {
  black: {
    idle: [[255, 255, 255], [255, 228, 238], [255, 240, 226], [240, 228, 255]],
    live: [[255, 240, 246], [255, 160, 200], [255, 120, 175], [255, 236, 210]],
    fail: [[255, 240, 220], [255, 196, 120], [255, 160, 110], [255, 226, 190]],
  },
  light: {
    idle: [[255, 255, 255], [255, 232, 240], [250, 244, 230], [236, 246, 226]],
    live: [[255, 244, 248], [255, 170, 205], [255, 130, 180], [214, 236, 170]],
    fail: [[255, 240, 220], [255, 190, 110], [255, 150, 90], [255, 222, 180]],
  },
};

function makeFibers(n: number): Fiber[] {
  let seed = 20261115;
  const rnd = () => { seed = (seed * 1664525 + 1013904223) >>> 0; return seed / 4294967296; };
  return Array.from({ length: n }, (_, i) => ({ a: (i / n) * Math.PI * 2 + rnd() * 0.02, len: 0.35 + rnd() * 0.65, ph: rnd() * Math.PI * 2, sp: 0.5 + rnd() * 1.4, tint: Math.floor(rnd() * 4), lobe: i % 2, sw: (rnd() - 0.5) * 0.9 }));
}

export function Orb({ phase, busy, disabled, label, onPress }: { phase: OrbPhase; busy: boolean; disabled: boolean; label: string; onPress: () => void }) {
  const canvas = useRef<HTMLCanvasElement>(null);
  const live = useRef({ phase, busy, hover: 0, press: 0, kick: 0 });
  live.current.phase = phase;
  live.current.busy = busy;

  useEffect(() => {
    const el = canvas.current;
    const ctx = el?.getContext("2d");
    if (!el || !ctx) return;
    const fibers = makeFibers(560);
    let raf = 0, last = 0, t = 0, split = 0, vel = 0, energy = 0.25, hover = 0, spin = 0, disposed = false, tintMix = 0, failMix = 0;
    const draw = (now: number) => {
      raf = 0;
      if (disposed) return;
      const reduced = document.documentElement.dataset.motion === "reduced";
      const dt = Math.min(48, now - (last || now)) / 1000;
      last = now;
      t += dt;
      const L = live.current;
      const transit = L.phase === "starting" || L.phase === "stopping" || L.busy;
      // Цель деления: во время перехода капли расходятся и сходятся; в покое — одно кольцо.
      const target = transit && !reduced ? 0.5 - 0.5 * Math.cos((t * Math.PI * 2) / 1.9) : 0;
      // Пружина + импульс от клика.
      vel += ((target - split) * 60 - vel * 9) * dt + L.kick;
      L.kick = 0;
      split = Math.max(0, Math.min(1.08, split + vel * dt));
      const wantEnergy = L.phase === "running" ? 1 : transit ? 0.85 : L.phase === "failed" ? 0.42 : 0.26;
      energy += (wantEnergy - energy) * Math.min(1, dt * 3);
      hover += (L.hover - hover) * Math.min(1, dt * 7);
      tintMix += ((L.phase === "running" ? 1 : transit ? 0.5 : 0) - tintMix) * Math.min(1, dt * 2.5);
      failMix += ((L.phase === "failed" ? 1 : 0) - failMix) * Math.min(1, dt * 3);
      spin += dt * (0.12 + energy * 0.25 + (transit ? 0.5 : 0));

      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      const size = el.clientWidth;
      if (el.width !== Math.round(size * dpr)) { el.width = el.height = Math.round(size * dpr); }
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, size, size);
      const cx = size / 2, cy = size / 2;
      const R = size * 0.335 * (1 - L.press * 0.045 + hover * 0.012);
      const s = Math.min(1, split);
      const r = R * (1 - 0.46 * s);
      const d = s * R * 0.5;
      const ax = Math.cos(spin * 0.7 + 0.6), ay = Math.sin(spin * 0.7 + 0.6);
      const lobes = s > 0.015 ? [[cx - ax * d, cy - ay * d], [cx + ax * d, cy + ay * d]] : [[cx, cy]];
      const e = Math.min(1.15, energy + hover * 0.28);

      ctx.globalCompositeOperation = "lighter";
      ctx.lineCap = "round";
      const TINTS = PALETTES[document.documentElement.dataset.theme === "light" ? "light" : "black"];
      const pick = (i: number): [number, number, number] => {
        const a = TINTS.idle[i], b = TINTS.live[i], f = TINTS.fail[i];
        return [0, 1, 2].map((k) => (a[k] + (b[k] - a[k]) * tintMix) * (1 - failMix) + f[k] * failMix) as [number, number, number];
      };
      const tint = [pick(0), pick(1), pick(2), pick(3)];
      for (let i = 0; i < fibers.length; i++) {
        const f = fibers[i];
        const lobe = lobes.length === 2 ? f.lobe : 0;
        const [lx, ly] = lobes[lobe];
        const a = f.a + spin * (lobe ? -1 : 1) * 0.35;
        const px = lx + Math.cos(a) * r, py = ly + Math.sin(a) * r;
        if (lobes.length === 2) {
          const [ox, oy] = lobes[1 - lobe];
          if ((px - ox) * (px - ox) + (py - oy) * (py - oy) < r * r * 0.9) continue;
        }
        // Маска «серпов»: волокна собираются дугами, которые ползут по ободу.
        const crescent = 0.5 + 0.5 * Math.sin(a - t * 0.55 + lobe * 2.1) * Math.cos(a * 2 + t * 0.27);
        const flick = 0.55 + 0.45 * Math.sin(t * f.sp * 1.7 + f.ph);
        const amount = Math.max(0, crescent * 1.25 - (1 - e) * 0.72) * flick + e * 0.06;
        if (amount < 0.02) continue;
        const len = r * (0.1 + 0.62 * f.len * amount * (0.55 + 0.45 * e));
        const sw = f.sw * (0.35 + 0.4 * Math.sin(t * 0.6 + f.ph));
        const dx = -Math.cos(a) + -Math.sin(a) * sw, dy = -Math.sin(a) + Math.cos(a) * sw;
        const c = tint[f.tint];
        const alpha = Math.min(0.5, 0.05 + amount * 0.3);
        ctx.strokeStyle = `rgba(${c[0] | 0},${c[1] | 0},${c[2] | 0},${alpha})`;
        ctx.lineWidth = 0.7;
        ctx.beginPath();
        ctx.moveTo(px, py);
        ctx.lineTo(px + dx * len * 0.45, py + dy * len * 0.45);
        ctx.stroke();
        ctx.strokeStyle = `rgba(${c[0] | 0},${c[1] | 0},${c[2] | 0},${alpha * 0.4})`;
        ctx.beginPath();
        ctx.moveTo(px + dx * len * 0.45, py + dy * len * 0.45);
        ctx.lineTo(px + dx * len, py + dy * len);
        ctx.stroke();
      }
      // Обод(а).
      const rim = tint[0];
      for (const [lx, ly] of lobes) {
        ctx.strokeStyle = `rgba(${rim[0] | 0},${rim[1] | 0},${rim[2] | 0},${0.55 + 0.4 * e})`;
        ctx.lineWidth = 1.1;
        ctx.beginPath();
        ctx.arc(lx, ly, r, 0, Math.PI * 2);
        ctx.stroke();
        ctx.strokeStyle = `rgba(${rim[0] | 0},${rim[1] | 0},${rim[2] | 0},${0.1 + 0.14 * e})`;
        ctx.lineWidth = 5;
        ctx.beginPath();
        ctx.arc(lx, ly, r, 0, Math.PI * 2);
        ctx.stroke();
      }
      ctx.globalCompositeOperation = "source-over";
      el.parentElement?.style.setProperty("--orb-split", s.toFixed(3));
      const settled = Math.abs(vel) < 0.01 && Math.abs(target - split) < 0.004;
      if (!reduced || !settled || Math.abs(wantEnergy - energy) > 0.01) schedule();
    };
    const schedule = () => { if (!raf && !disposed && !document.hidden) raf = requestAnimationFrame(draw); };
    const unwatch = watchWindowActivity((active) => {
      if (!active) { cancelAnimationFrame(raf); raf = 0; }
      else last = 0;
    });
    const poke = startVisibleLoop(schedule, 400);
    return () => { disposed = true; cancelAnimationFrame(raf); poke.stop(); unwatch(); };
  }, []);

  const transit = phase === "starting" || phase === "stopping" || busy;
  return (
    <button
      type="button"
      className={`orb orb--${phase}${transit ? " orb--transit" : ""}`}
      aria-label={label}
      aria-keyshortcuts="Control+Enter"
      aria-busy={transit}
      disabled={disabled}
      onPointerEnter={() => { live.current.hover = 1; }}
      onPointerLeave={() => { live.current.hover = 0; live.current.press = 0; }}
      onPointerDown={() => { live.current.press = 1; }}
      onPointerUp={() => { live.current.press = 0; }}
      onClick={() => { live.current.kick += 5.5; onPress(); }}
    >
      <span className="orb__rings" aria-hidden="true"><i /><i /><i /></span>
      <span className="orb__lens" aria-hidden="true" />
      <canvas ref={canvas} className="orb__fibers" aria-hidden="true" />
      <span className="orb__glyph" aria-hidden="true"><Icon name="power" size={30} /></span>
    </button>
  );
}
