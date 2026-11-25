// The power control: a luminous ring drawn on canvas. Turning on, the ring grows
// from a seed at the bottom, a liquid drop climbs from it and settles as the centre
// dot; turning off, the ring tips over like a coin and breaks into fading arcs.
import { useEffect, useRef } from "react";
import { watchWindowActivity } from "../windowActivity";

export type OrbMode = "off" | "on" | "busy" | "failed";

const W = 300, H = 348, CX = W / 2, CY = 150, R = 80, STROKE = 3.3, DOT = 7;
const ON_MS = 1750, OFF_MS = 1600;
const INK = "#f1efff", CORE = "118,110,255", HALO = "84,70,255";

const clamp = (v: number, a = 0, b = 1) => Math.min(b, Math.max(a, v));
const span = (v: number, a: number, b: number) => clamp((v - a) / (b - a));
const lerp = (a: number, b: number, t: number) => a + (b - a) * t;
const easeOut = (t: number) => 1 - Math.pow(1 - t, 3);
const easeInOut = (t: number) => (t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2);
const easeIn = (t: number) => t * t;

type Scene = { stage: "off" | "toOn" | "on" | "toOff"; t: number; want: boolean; busy: number; warm: number; hover: number; clock: number };

function glowStroke(c: CanvasRenderingContext2D, path: () => void, alpha: number, dpr: number, width = STROKE, boost = 1) {
  if (alpha <= 0.004) return;
  c.save();
  c.lineCap = "round";
  c.globalAlpha = alpha;
  c.shadowColor = `rgba(${HALO},${Math.min(1, 0.9 * boost)})`; c.shadowBlur = 34 * dpr; c.strokeStyle = `rgba(${HALO},.38)`; c.lineWidth = width * 2.1; path(); c.stroke();
  c.shadowColor = `rgba(${CORE},1)`; c.shadowBlur = 11 * dpr; c.strokeStyle = `rgba(${CORE},.8)`; c.lineWidth = width * 1.3; path(); c.stroke();
  c.shadowBlur = 0; c.strokeStyle = INK; c.lineWidth = width; path(); c.stroke();
  c.restore();
}

function glowFill(c: CanvasRenderingContext2D, path: () => void, alpha: number, dpr: number) {
  if (alpha <= 0.004) return;
  c.save();
  c.globalAlpha = alpha;
  c.shadowColor = `rgba(${CORE},1)`; c.shadowBlur = 18 * dpr; c.fillStyle = INK; path(); c.fill();
  c.shadowBlur = 5 * dpr; path(); c.fill();
  c.restore();
}

function disc(c: CanvasRenderingContext2D, alpha: number) {
  if (alpha <= 0.004) return;
  c.save();
  c.globalAlpha = alpha;
  const g = c.createRadialGradient(CX, CY - R * 0.55, R * 0.1, CX, CY, R);
  g.addColorStop(0, "#1c1c2a"); g.addColorStop(0.6, "#111119"); g.addColorStop(1, "#0b0b11");
  c.fillStyle = g; c.beginPath(); c.arc(CX, CY, R - 1, 0, Math.PI * 2); c.fill();
  c.restore();
}

function track(c: CanvasRenderingContext2D, alpha: number, warm: number, clock: number, hover: number) {
  if (alpha <= 0.004) return;
  c.save();
  c.globalAlpha = alpha;
  const tint = warm > 0.01 ? `rgba(255,${Math.round(lerp(255, 132, warm))},${Math.round(lerp(255, 104, warm))},${lerp(0.2, 0.5, warm) + hover * 0.16})` : `rgba(226,224,255,${0.2 + hover * 0.2})`;
  c.strokeStyle = tint; c.lineWidth = 1.6; c.beginPath(); c.arc(CX, CY, R, 0, Math.PI * 2); c.stroke();
  const pulse = 0.5 + 0.5 * Math.sin(clock / 620);
  c.shadowColor = warm > 0.01 ? "rgba(255,120,90,.9)" : `rgba(${CORE},1)`; c.shadowBlur = (8 + pulse * 10 + hover * 8);
  c.fillStyle = warm > 0.01 ? "#ffd9cf" : INK; c.globalAlpha = alpha * (0.62 + pulse * 0.38);
  c.beginPath(); c.arc(CX, CY + R, 2.5 + pulse * 0.5 + hover * 0.7, 0, Math.PI * 2); c.fill();
  c.restore();
}

function drawOn(c: CanvasRenderingContext2D, t: number, dpr: number, s: Scene) {
  const by = CY + R;
  disc(c, easeOut(span(t, 0.12, 0.42)));
  track(c, 1 - span(t, 0, 0.2), s.warm, s.clock, s.hover);
  // The ring grows from the bottom up both sides and closes at the top.
  const a = easeInOut(span(t, 0, 0.34)) * Math.PI;
  const breath = t >= 1 ? 1 + 0.07 * Math.sin(s.clock / 900) : 1;
  glowStroke(c, () => { c.beginPath(); c.arc(CX, CY, R, Math.PI / 2 - a, Math.PI / 2 + a); }, span(t, 0, 0.05) * (1 - 0.74 * s.busy), dpr, STROKE, breath + s.hover * 0.25);
  // The connection is still being established: the ring dims and a bright comet orbits it.
  if (s.busy > 0.01) {
    const head = (s.clock / 1150) * Math.PI * 2;
    for (let i = 0; i < 22; i++) {
      c.save(); c.globalAlpha = s.busy * (1 - i / 22) ** 1.6; c.lineCap = "round"; c.strokeStyle = "#fff"; c.lineWidth = STROKE + 2.2 - i * 0.07;
      c.shadowColor = `rgba(${CORE},1)`; c.shadowBlur = 18 * dpr;
      c.beginPath(); c.arc(CX, CY, R, head - i * 0.085 - 0.09, head - i * 0.085); c.stroke(); c.restore();
    }
    c.save(); c.globalAlpha = s.busy; c.fillStyle = "#fff"; c.shadowColor = `rgba(${CORE},1)`; c.shadowBlur = 22 * dpr;
    c.beginPath(); c.arc(CX + Math.cos(head) * R, CY + Math.sin(head) * R, STROKE + 1.3, 0, Math.PI * 2); c.fill(); c.restore();
  }
  // A swell at the base of the ring feeds the drop.
  const swell = Math.sin(Math.PI * span(t, 0.24, 0.86)) ** 0.7;
  const u = span(t, 0.34, 0.82);
  if (swell > 0.01 && t < 0.9) {
    const bw = 15 * swell, bh = 7.5 * swell;
    glowFill(c, () => { c.beginPath(); c.moveTo(CX - bw, by - 0.6); c.bezierCurveTo(CX - bw * 0.45, by - 1, CX - bw * 0.4, by - bh, CX, by - bh); c.bezierCurveTo(CX + bw * 0.4, by - bh, CX + bw * 0.45, by - 1, CX + bw, by - 0.6); c.closePath(); }, 1, dpr);
  }
  if (t > 0.34) {
    const rise = easeInOut(u);
    const hy = lerp(by - 9, CY, rise);
    const hr = t >= 1 ? DOT : lerp(4.4, DOT * 1.12, span(u, 0, 0.55)) - span(u, 0.7, 1) * DOT * 0.12 + Math.sin(span(t, 0.82, 1) * Math.PI) * 0.9;
    const neck = lerp(3.3, 0, easeIn(span(u, 0.2, 0.66)));
    if (neck > 0.25) {
      // Still attached: a tapering stem joins the head to the base.
      const wb = 6.4, m1 = lerp(by, hy, 0.38), m2 = lerp(by, hy, 0.72);
      glowFill(c, () => {
        c.beginPath(); c.moveTo(CX - wb, by - 2);
        c.bezierCurveTo(CX - wb * 0.35, by - 5, CX - neck, m1 + 4, CX - neck, m1);
        c.lineTo(CX - neck, m2);
        c.bezierCurveTo(CX - neck, hy + hr * 1.5, CX - hr, hy + hr * 1.15, CX - hr, hy);
        c.arc(CX, hy, hr, Math.PI, 0);
        c.bezierCurveTo(CX + hr, hy + hr * 1.15, CX + neck, hy + hr * 1.5, CX + neck, m2);
        c.lineTo(CX + neck, m1);
        c.bezierCurveTo(CX + neck, m1 + 4, CX + wb * 0.35, by - 5, CX + wb, by - 2);
        c.closePath();
      }, 1, dpr);
    } else {
      // Pinched off: a teardrop whose tail retracts as it settles into the dot.
      const tail = (1 - easeOut(span(u, 0.66, 1))) * 21;
      glowFill(c, () => {
        c.beginPath(); c.moveTo(CX, hy + hr + tail);
        c.bezierCurveTo(CX - 0.6, hy + hr * 1.25 + tail * 0.35, CX - hr, hy + hr * 0.95, CX - hr, hy);
        c.arc(CX, hy, hr, Math.PI, 0);
        c.bezierCurveTo(CX + hr, hy + hr * 0.95, CX + 0.6, hy + hr * 1.25 + tail * 0.35, CX, hy + hr + tail);
        c.closePath();
      }, 1, dpr);
    }
  }
}

function drawOff(c: CanvasRenderingContext2D, q: number, dpr: number, s: Scene) {
  const by = CY + R;
  disc(c, 1 - span(q, 0, 0.3));
  track(c, easeOut(span(q, 0.8, 1)), s.warm, s.clock, s.hover);
  // The ring tips over like a coin while its axis swings round, then breaks into two arcs.
  const tilt = easeInOut(span(q, 0, 0.78)) * Math.PI * 0.66;
  const minor = Math.max(0.012, Math.abs(Math.cos(tilt)));
  const axis = lerp(Math.PI / 2, -Math.PI / 9, easeInOut(span(q, 0.02, 0.8)));
  const gap = easeInOut(span(q, 0.4, 0.9));
  const half = (Math.PI / 2) * (1 - gap);
  const alpha = 1 - span(q, 0.76, 0.93);
  const spin = q * 1.9;
  if (gap <= 0) glowStroke(c, () => { c.beginPath(); c.ellipse(CX, CY, R, R * minor, axis, 0, Math.PI * 2); }, alpha, dpr);
  else if (gap < 0.999) for (const mid of [spin + 0.5, spin + 0.5 + Math.PI]) {
    glowStroke(c, () => { c.beginPath(); c.ellipse(CX, CY, R, R * minor, axis, mid - half, mid + half); }, alpha, dpr, lerp(STROKE, STROKE * 0.72, gap));
  }
  // The dot shrinks to a point, sends out one ripple, and sinks back to the base.
  const ripple = span(q, 0.26, 0.66);
  if (ripple > 0 && ripple < 1) {
    c.save(); c.globalAlpha = (1 - ripple) * 0.75; c.strokeStyle = INK; c.lineWidth = 1;
    c.beginPath(); c.arc(CX, CY, lerp(4, 27, easeOut(ripple)), 0, Math.PI * 2); c.stroke(); c.restore();
  }
  const r = lerp(DOT, 2.2, easeInOut(span(q, 0.12, 0.46)));
  const y = lerp(CY, by, easeInOut(span(q, 0.5, 0.94)));
  glowFill(c, () => { c.beginPath(); c.arc(CX, y, r, 0, Math.PI * 2); }, 1 - span(q, 0.9, 1), dpr);
}

function render(c: CanvasRenderingContext2D, layer: HTMLCanvasElement, s: Scene, dpr: number) {
  const l = layer.getContext("2d");
  if (!l) return;
  l.setTransform(dpr, 0, 0, dpr, 0, 0); l.clearRect(0, 0, W, H);
  if (s.stage === "off") track(l, 1, s.warm, s.clock, s.hover);
  else if (s.stage === "toOff") drawOff(l, s.t, dpr, s);
  else drawOn(l, s.stage === "on" ? 1 : s.t, dpr, s);
  c.setTransform(1, 0, 0, 1, 0, 0); c.clearRect(0, 0, c.canvas.width, c.canvas.height);
  // A faint, squashed reflection on the floor under the ring.
  const floor = CY + R + 26;
  c.save();
  c.setTransform(dpr, 0, 0, -dpr * 0.5, 0, (floor + (CY + R) * 0.5 + 4) * dpr);
  c.globalAlpha = 0.4; c.filter = `blur(${2.2 * dpr}px)`;
  c.drawImage(layer, 0, 0, W, H);
  c.restore();
  c.save(); c.setTransform(dpr, 0, 0, dpr, 0, 0); c.globalCompositeOperation = "destination-out";
  const fade = c.createLinearGradient(0, floor, 0, floor + 36);
  fade.addColorStop(0, "rgba(0,0,0,.1)"); fade.addColorStop(1, "rgba(0,0,0,1)");
  c.fillStyle = fade; c.fillRect(0, floor - 6, W, H - floor + 6);
  c.restore();
  c.save(); c.setTransform(dpr, 0, 0, dpr, 0, 0);
  c.beginPath(); c.rect(0, 0, W, floor - 5); c.clip();
  c.drawImage(layer, 0, 0, W, H);
  c.restore();
}

export function PowerOrb({ mode, motion = true }: { mode: OrbMode; motion?: boolean }) {
  const canvas = useRef<HTMLCanvasElement>(null);
  const live = useRef({ mode, motion });
  live.current = { mode, motion };

  useEffect(() => {
    const el = canvas.current;
    const c = el?.getContext("2d");
    if (!el || !c) return;
    const layer = document.createElement("canvas");
    let dpr = 0;
    const initial = live.current.mode === "on" || live.current.mode === "busy";
    const s: Scene = { stage: initial ? "on" : "off", t: 1, want: initial, busy: 0, warm: 0, hover: 0, clock: 0 };
    const reduced = () => !live.current.motion || window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    let hovering = false, raf = 0, last = performance.now(), was = live.current.mode;
    const enter = () => { hovering = true; }, leave = () => { hovering = false; };
    const host = el.closest("button") ?? el;
    host.addEventListener("pointerenter", enter); host.addEventListener("pointerleave", leave);
    host.addEventListener("focus", enter); host.addEventListener("blur", leave);

    const frame = (now: number) => {
      raf = requestAnimationFrame(frame);
      const dt = Math.min(64, now - last); last = now;
      const next = Math.min(3, Math.max(1, window.devicePixelRatio || 1));
      if (next !== dpr) { dpr = next; for (const cv of [el, layer]) { cv.width = Math.round(W * dpr); cv.height = Math.round(H * dpr); } }
      const { mode: m } = live.current;
      s.want = m === "on" || m === "busy";
      const still = reduced();
      s.clock = still ? 0 : now;
      if (still) { s.stage = s.want ? "on" : "off"; s.t = 1; }
      // A failed start must not finish the connect animation and then play the disconnect one.
      else if (m === "failed" && (s.stage === "toOn" || was === "busy")) { s.stage = "off"; s.t = 1; }
      else if (s.stage === "off" && s.want) { s.stage = "toOn"; s.t = 0; }
      else if (s.stage === "on" && !s.want) { s.stage = "toOff"; s.t = 0; }
      else if (s.stage === "toOn") { s.t += (dt / ON_MS) * (s.want ? 1 : 2.6); if (s.t >= 1) { s.stage = "on"; s.t = 1; } }
      else if (s.stage === "toOff") { s.t += (dt / OFF_MS) * (s.want ? 2.6 : 1); if (s.t >= 1) { s.stage = "off"; s.t = 1; } }
      was = m;
      const k = still ? 1 : 1 - Math.exp(-dt / 160);
      s.busy += ((m === "busy" && s.stage === "on" && !still ? 1 : 0) - s.busy) * k;
      s.warm += ((m === "failed" ? 1 : 0) - s.warm) * k;
      s.hover += ((hovering ? 1 : 0) - s.hover) * k;
      render(c, layer, s, dpr);
    };
    const unwatch = watchWindowActivity((active) => {
      if (!active) { cancelAnimationFrame(raf); return; }
      last = performance.now();
      raf = requestAnimationFrame(frame);
    });
    return () => {
      unwatch();
      cancelAnimationFrame(raf);
      host.removeEventListener("pointerenter", enter); host.removeEventListener("pointerleave", leave);
      host.removeEventListener("focus", enter); host.removeEventListener("blur", leave);
    };
  }, []);

  return <canvas ref={canvas} className="orb" width={W} height={H} style={{ width: W, height: H }} aria-hidden="true" />;
}
