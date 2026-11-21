import { useEffect, useRef } from "react";

type Particle = [number, number, number, number];
const glyphs = " .,:;=+*#%@";

// An original closed knot, sampled as a tube. Its surface is made only of type.
function knot(): Particle[] {
  const particles: Particle[] = [];
  for (let i = 0; i < 600; i++) {
    const t = i / 600 * Math.PI * 2;
    const r = 1.65 + .56 * Math.cos(3 * t);
    const x = r * Math.cos(2 * t), y = r * Math.sin(2 * t), z = .64 * Math.sin(3 * t);
    for (let j = 0; j < 22; j++) {
      const v = j / 22 * Math.PI * 2;
      const tube = .22;
      particles.push([x + tube * Math.cos(v) * Math.cos(2 * t), y + tube * Math.cos(v) * Math.sin(2 * t), z + tube * Math.sin(v), .35 + .65 * (.5 + .5 * Math.cos(v - t))]);
    }
  }
  return particles;
}
const particles = knot();

export function AsciiBloom({ motion, active = false }: { motion: boolean; active?: boolean }) {
  const canvas = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const el = canvas.current;
    if (!el) return;
    const ctx = el.getContext("2d");
    if (!ctx) return;
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)");
    let frame = 0, previous = -100, width = 0, height = 0;
    let targetX = 0, targetY = 0, pointerX = 0, pointerY = 0;
    const animated = () => motion && !reduced.matches && !document.hidden;
    const draw = (now: number) => {
      frame = 0;
      if (document.hidden) return;
      if (animated()) frame = requestAnimationFrame(draw);
      if (now - previous < 33) return;
      previous = now;
      const time = motion && !reduced.matches ? now / 1000 : 0;
      pointerX += (targetX - pointerX) * .055;
      pointerY += (targetY - pointerY) * .055;
      const cw = 5.3, ch = 8, cols = Math.ceil(width / cw), rows = Math.ceil(height / ch);
      if (!cols || !rows) return;
      const depth = new Float32Array(cols * rows).fill(-Infinity);
      const light = new Float32Array(cols * rows);
      const turn = .55 + time * (active ? .14 : .075) + pointerX * .2;
      const tilt = .6 + Math.sin(time * .18) * .15 + pointerY * .15;
      const scale = Math.min(width / 5.2, height / 4.6);
      for (const [px, py, pz, brightness] of particles) {
        const x = px * Math.cos(turn) - pz * Math.sin(turn);
        const z = px * Math.sin(turn) + pz * Math.cos(turn);
        const y = py * Math.cos(tilt) - z * Math.sin(tilt);
        const dz = py * Math.sin(tilt) + z * Math.cos(tilt);
        const col = Math.round((width * .5 + x * scale * 1.35) / cw);
        const row = Math.round((height * .5 - y * scale) / ch);
        if (col < 0 || col >= cols || row < 0 || row >= rows) continue;
        const n = row * cols + col;
        if (dz > depth[n]) { depth[n] = dz; light[n] = Math.min(1, brightness * .68 + (dz + 2.4) * .065); }
      }
      ctx.clearRect(0, 0, width, height);
      ctx.fillStyle = getComputedStyle(el).color;
      ctx.font = "8px ui-monospace, 'Cascadia Mono', Consolas, monospace";
      ctx.textBaseline = "top";
      // A quiet typographic field establishes the grid, not fake telemetry.
      ctx.globalAlpha = .19;
      for (let row = 2; row < rows; row += 6) for (let col = 3; col < cols; col += 11) {
        ctx.fillText((row + col) % 3 ? "." : "+", col * cw, row * ch);
      }
      for (let row = 0; row < rows; row++) for (let col = 0; col < cols; col++) {
        const n = row * cols + col;
        if (depth[n] === -Infinity) continue;
        ctx.globalAlpha = .36 + light[n] * .64;
        ctx.fillText(glyphs[Math.max(1, Math.floor(light[n] * (glyphs.length - 1)))], col * cw, row * ch);
      }
      ctx.globalAlpha = 1;
    };
    const refresh = () => {
      cancelAnimationFrame(frame);
      previous = -100;
      frame = requestAnimationFrame(draw);
    };
    const resize = () => {
      const rect = el.getBoundingClientRect(), dpr = Math.min(window.devicePixelRatio || 1, 2);
      width = rect.width; height = rect.height;
      el.width = Math.round(width * dpr); el.height = Math.round(height * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      refresh();
    };
    const pointer = (e: PointerEvent) => {
      if (!animated()) return;
      const rect = el.getBoundingClientRect();
      targetX = (e.clientX - rect.left) / rect.width - .5;
      targetY = (e.clientY - rect.top) / rect.height - .5;
    };
    const leave = () => { targetX = 0; targetY = 0; };
    const observer = new ResizeObserver(resize);
    observer.observe(el);
    const themeObserver = new MutationObserver(refresh);
    themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    document.addEventListener("visibilitychange", refresh);
    reduced.addEventListener("change", refresh);
    el.addEventListener("pointermove", pointer);
    el.addEventListener("pointerleave", leave);
    resize();
    return () => {
      cancelAnimationFrame(frame); observer.disconnect(); themeObserver.disconnect();
      document.removeEventListener("visibilitychange", refresh); reduced.removeEventListener("change", refresh);
      el.removeEventListener("pointermove", pointer); el.removeEventListener("pointerleave", leave);
    };
  }, [motion, active]);
  return <div className="ascii-bloom" aria-hidden="true"><span className="ascii-bloom__coordinate">[ СВЯЗЬ НЕ ИМЕЕТ ФОРМЫ ]</span><canvas ref={canvas} /><span className="ascii-bloom__caption">FIG. 01 — БЕСКОНЕЧНОСТЬ ИЗ СИМВОЛОВ</span><span className="ascii-bloom__number">↗ + ∞</span></div>;
}
