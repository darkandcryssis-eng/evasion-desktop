import { useEffect, useRef } from "react";

type RGB = [number, number, number];
type Particle = { x: number; y: number; vx: number; vy: number; r: number; seed: number; absorbed: boolean };
type Streak = { x: number; y: number; vx: number; vy: number; born: number; life: number; width: number; white: boolean };

const rgba = (c: RGB, alpha: number) => `rgba(${c[0]},${c[1]},${c[2]},${alpha})`;
const color = (value: string, fallback: RGB): RGB => {
  const match = value.trim().match(/^#([\da-f]{6})$/i);
  if (!match) return fallback;
  const n = Number.parseInt(match[1], 16);
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
};

export function StartupParticles({ exploding, motion }: { exploding: boolean; motion: boolean }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const explodingRef = useRef(exploding);
  useEffect(() => { explodingRef.current = exploding; }, [exploding]);

  useEffect(() => {
    if (!motion || !canvasRef.current) return;
    const canvas = canvasRef.current;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    const styles = getComputedStyle(document.documentElement);
    const accent = color(styles.getPropertyValue("--accent"), [255, 173, 203]);
    const white: RGB = [255, 252, 254];
    let width = 420, height = 300, raf = 0, last = performance.now(), burstAt = 0;
    let particles: Particle[] = [];
    let streaks: Streak[] = [];
    let absorbed = 0;

    const resize = () => {
      const rect = canvas.getBoundingClientRect();
      width = Math.max(1, rect.width);
      height = Math.max(1, rect.height);
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = Math.round(width * dpr);
      canvas.height = Math.round(height * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };
    const observer = new ResizeObserver(resize);
    observer.observe(canvas);
    resize();

    const cx = () => width / 2;
    const cy = () => height * 0.42;
    for (let i = 0; i < 44; i++) {
      const angle = Math.random() * Math.PI * 2;
      const radius = 45 + Math.random() * 105;
      particles.push({
        x: cx() + Math.cos(angle) * radius,
        y: cy() + Math.sin(angle) * radius * 0.62,
        vx: 0, vy: 0, r: 1.8 + Math.random() * 2.2,
        seed: Math.random() * 10, absorbed: false,
      });
    }

    const explode = (now: number, x: number, y: number) => {
      burstAt = now;
      streaks = particles.map((p) => {
        const angle = Math.random() * Math.PI * 2;
        const speed = 4.5 + Math.random() * 8;
        return { x, y, vx: Math.cos(angle) * speed, vy: Math.sin(angle) * speed, born: now, life: 360 + Math.random() * 240, width: p.r * 0.65, white: Math.random() > 0.35 };
      });
      for (let i = 0; i < 18; i++) {
        const angle = (i / 18) * Math.PI * 2 + Math.random() * 0.15;
        const speed = 8 + Math.random() * 6;
        streaks.push({ x, y, vx: Math.cos(angle) * speed, vy: Math.sin(angle) * speed, born: now, life: 300 + Math.random() * 180, width: 0.8 + Math.random(), white: i % 3 === 0 });
      }
    };

    const started = performance.now();
    const frame = (now: number) => {
      const dt = Math.min(2, (now - last) / 16.667) || 1;
      last = now;
      const t = (now - started) / 1000;
      ctx.clearRect(0, 0, width, height);
      ctx.globalCompositeOperation = "lighter";

      const gather = 1 - Math.pow(1 - Math.min(1, t / 1.8), 3);
      const targetX = cx() + Math.sin(t * 4.1) * 66 * (1 - gather);
      const targetY = cy() + Math.sin(t * 6.3) * 34 * (1 - gather);
      const coreRadius = 3.5 + absorbed * 0.115;

      if (!explodingRef.current) {
        for (const p of particles) {
          if (p.absorbed) continue;
          const dx = targetX - p.x, dy = targetY - p.y;
          const distance = Math.hypot(dx, dy) || 1;
          const pull = t < 0.2 ? 0.0008 : 0.004 + Math.min(t, 2) * 0.002;
          const swirl = Math.sin(p.seed + t * 2) * 0.0018 * (1 - gather * 0.75);
          p.vx += (dx * pull - dy * swirl) * dt;
          p.vy += (dy * pull + dx * swirl) * dt;
          p.vx *= Math.pow(0.91, dt);
          p.vy *= Math.pow(0.91, dt);
          p.x += p.vx * dt;
          p.y += p.vy * dt;
          if (distance < coreRadius + p.r + 2 && t > 0.25) { p.absorbed = true; absorbed++; continue; }
          ctx.strokeStyle = rgba(accent, 0.24);
          ctx.lineWidth = p.r * 0.55;
          ctx.beginPath(); ctx.moveTo(p.x - p.vx * 2.4, p.y - p.vy * 2.4); ctx.lineTo(p.x, p.y); ctx.stroke();
          ctx.fillStyle = rgba(white, 0.92);
          ctx.shadowColor = rgba(accent, 0.9); ctx.shadowBlur = 10;
          ctx.beginPath(); ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2); ctx.fill();
        }
        ctx.shadowBlur = 0;
        const pulse = 1 + Math.sin(t * 9) * 0.08;
        const glow = ctx.createRadialGradient(targetX, targetY, 0, targetX, targetY, coreRadius * 7);
        glow.addColorStop(0, rgba(white, 0.95)); glow.addColorStop(0.18, rgba(accent, 0.62)); glow.addColorStop(1, rgba(accent, 0));
        ctx.fillStyle = glow; ctx.beginPath(); ctx.arc(targetX, targetY, coreRadius * 7, 0, Math.PI * 2); ctx.fill();
        ctx.fillStyle = rgba(white, 1); ctx.beginPath(); ctx.arc(targetX, targetY, coreRadius * pulse, 0, Math.PI * 2); ctx.fill();
      } else {
        if (!burstAt) explode(now, targetX, targetY);
        const elapsed = now - burstAt;
        for (const s of streaks) {
          const age = now - s.born;
          if (age > s.life) continue;
          const alpha = Math.pow(1 - age / s.life, 1.6);
          s.x += s.vx * dt; s.y += s.vy * dt;
          s.vx *= Math.pow(1.018, dt); s.vy *= Math.pow(1.018, dt);
          ctx.strokeStyle = rgba(s.white ? white : accent, alpha);
          ctx.lineWidth = s.width * alpha + 0.25;
          ctx.shadowColor = rgba(accent, alpha); ctx.shadowBlur = 8;
          ctx.beginPath(); ctx.moveTo(s.x - s.vx * 3.8, s.y - s.vy * 3.8); ctx.lineTo(s.x, s.y); ctx.stroke();
        }
        ctx.shadowBlur = 0;
        const ringRadius = elapsed * 0.36;
        ctx.strokeStyle = rgba(accent, Math.max(0, 0.7 - elapsed / 600));
        ctx.lineWidth = Math.max(0.4, 2.4 - elapsed / 240);
        ctx.beginPath(); ctx.arc(targetX, targetY, ringRadius, 0, Math.PI * 2); ctx.stroke();
        if (elapsed < 150) {
          const flash = ctx.createRadialGradient(targetX, targetY, 0, targetX, targetY, 75 + elapsed);
          flash.addColorStop(0, rgba(white, 0.8 * (1 - elapsed / 150))); flash.addColorStop(1, rgba(accent, 0));
          ctx.fillStyle = flash; ctx.beginPath(); ctx.arc(targetX, targetY, 75 + elapsed, 0, Math.PI * 2); ctx.fill();
        }
      }
      ctx.globalCompositeOperation = "source-over";
      raf = requestAnimationFrame(frame);
    };
    raf = requestAnimationFrame(frame);
    return () => { cancelAnimationFrame(raf); observer.disconnect(); particles = []; streaks = []; };
  }, [motion]);

  if (!motion) return null;
  return <canvas className="splash__particles" ref={canvasRef} aria-hidden="true" />;
}
