import { useEffect, useRef } from "react";

type Point = [number, number, number, number];
const glyphs = " .,:;+=*#%@";

// A small, original point-cloud sculpture. No video, WebGL or downloaded artwork.
function sculpture(): Point[] {
  const points: Point[] = [];
  for (let petal = 0; petal < 15; petal++) {
    const angle = petal / 15 * Math.PI * 2;
    for (let i = 0; i < 45; i++) {
      const t = i / 44, length = 1.05 + .17 * Math.sin(petal * 7.3);
      for (let j = -9; j <= 9; j++) {
        const side = j / 9, radius = .24 + t * length;
        const width = .22 * Math.pow(Math.sin(Math.PI * t), .65) * side;
        const z = .27 * Math.sin(t * Math.PI) + .24 * side * side - .25 * t * t;
        points.push([Math.cos(angle) * radius - Math.sin(angle) * width, Math.sin(angle) * radius + Math.cos(angle) * width + .45, z, .35 + .6 * (1 - Math.abs(side))]);
      }
    }
  }
  for (let i = 0; i < 1500; i++) {
    const r = .32 * Math.sqrt(i / 1500), a = i * 2.39996;
    points.push([r * Math.cos(a), r * Math.sin(a) + .45, .14 + .21 * Math.sqrt(1 - (r / .33) ** 2), .55 + .45 * Math.sin(i * 3.4) ** 2]);
  }
  for (let i = 0; i < 250; i++) {
    const t = i / 249;
    for (let j = 0; j < 4; j++) points.push([.2 * Math.sin(t * 3) + j * .012, .3 - t * 2.8, -.12 + j * .008, .4 + j * .12]);
  }
  for (let leaf = 0; leaf < 2; leaf++) {
    const direction = leaf ? -1 : 1;
    for (let i = 0; i < 45; i++) for (let j = -8; j <= 8; j++) {
      const t = i / 44, s = j / 8;
      points.push([.15 + direction * t * .8, -.95 - leaf * .6 + t * .4 + s * .15 * Math.sin(t * Math.PI), -.1 + s * .12, .4 + .4 * (1 - Math.abs(s))]);
    }
  }
  return points;
}
const points = sculpture();

export function AsciiBloom({ motion, active = false }: { motion: boolean; active?: boolean }) {
  const canvas = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const el = canvas.current;
    if (!el) return;
    const ctx = el.getContext("2d");
    if (!ctx) return;
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)");
    let frame = 0, previous = -100, time = 0, width = 0, height = 0;
    const draw = (now: number) => {
      frame = requestAnimationFrame(draw);
      if (document.hidden || now - previous < 65) return;
      if ((!motion || reduced.matches) && previous >= 0) return;
      previous = now;
      time = motion && !reduced.matches ? now / 1000 : 0;
      const cellX = 5.1, cellY = 7.5, cols = Math.ceil(width / cellX), rows = Math.ceil(height / cellY);
      if (!cols || !rows) return;
      const depth = new Float32Array(cols * rows).fill(-Infinity);
      const light = new Float32Array(cols * rows);
      const turn = .45 + Math.sin(time * .18) * .3, tilt = -.35, spin = -.37 + Math.sin(time * .12) * .08;
      const scale = Math.min(width / 3.6, height / 4.15);
      for (const [px, py, pz, brightness] of points) {
        const sway = Math.sin(time * .6 + py * 1.8) * .035;
        const x = px * Math.cos(spin) - py * Math.sin(spin) + sway;
        const y = px * Math.sin(spin) + py * Math.cos(spin);
        const tx = x * Math.cos(turn) + pz * Math.sin(turn);
        const tz = pz * Math.cos(turn) - x * Math.sin(turn);
        const ty = y * Math.cos(tilt) - tz * Math.sin(tilt);
        const z = y * Math.sin(tilt) + tz * Math.cos(tilt);
        const col = Math.round((width * .48 + tx * scale) / cellX);
        const row = Math.round((height * .43 - ty * scale) / cellY);
        if (col < 0 || col >= cols || row < 0 || row >= rows) continue;
        const idx = row * cols + col;
        if (z > depth[idx]) { depth[idx] = z; light[idx] = Math.min(1, brightness * .8 + (z + .4) * .22); }
      }
      ctx.clearRect(0, 0, width, height);
      const style = getComputedStyle(el);
      ctx.fillStyle = style.color;
      ctx.font = "7px 'Cascadia Mono', Consolas, monospace";
      ctx.textBaseline = "top";
      for (let row = 0; row < rows; row++) for (let col = 0; col < cols; col++) {
        const i = row * cols + col;
        if (depth[i] === -Infinity) continue;
        ctx.globalAlpha = .28 + light[i] * .72;
        ctx.fillText(glyphs[Math.max(1, Math.floor(light[i] * (glyphs.length - 1)))], col * cellX, row * cellY);
      }
      ctx.globalAlpha = 1;
    };
    const resize = () => {
      const rect = el.getBoundingClientRect(), ratio = Math.min(window.devicePixelRatio || 1, 2);
      width = rect.width; height = rect.height;
      el.width = Math.round(width * ratio); el.height = Math.round(height * ratio);
      ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
      previous = -100;
    };
    const observer = new ResizeObserver(resize);
    observer.observe(el);
    // Redraw a static sculpture when its theme changes too.
    const themeObserver = new MutationObserver(() => { previous = -100; });
    themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    resize(); frame = requestAnimationFrame(draw);
    return () => { cancelAnimationFrame(frame); observer.disconnect(); themeObserver.disconnect(); };
  }, [motion, active]);
  return <div className={`ascii-bloom${active ? " ascii-bloom--active" : ""}`} aria-hidden="true"><span className="ascii-bloom__coordinate">FIG. 001 / DIGITAL NATURE</span><span className="ascii-bloom__cross">+</span><canvas ref={canvas} /><span className="ascii-bloom__caption">СВОБОДА В ПРИРОДЕ ВЕЩЕЙ</span><span className="ascii-bloom__number">[ &infin; ]</span></div>;
}
