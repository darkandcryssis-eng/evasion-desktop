// Живой фон: два зацикленных ролика (дневная сакура для светлой темы, ночная —
// для тёмной) как текстуры одного WebGL-шейдера. Параллакс, а смена темы — волна,
// расходящаяся от переключателя и преломляющая картинку на фронте.
import { forwardRef, useEffect, useImperativeHandle, useRef } from "react";
import { EventsOn } from "../../wailsjs/runtime/runtime";
import lightUrl from "../assets/bg-light.jpg";
import darkUrl from "../assets/bg-dark.jpg";
import naturalLightUrl from "../assets/bg-natural-light.jpg";
import naturalDarkUrl from "../assets/bg-natural-dark.jpg";
import lightVideo from "../assets/bg-light.mp4";
import darkVideo from "../assets/bg-dark.mp4";
import type { Skin } from "../types";

export type BackdropHandle = { ripple: (toDark: boolean, x: number, y: number, ms: number) => void };

const VERT = `attribute vec2 p;varying vec2 v;void main(){v=p*.5+.5;v.y=1.-v.y;gl_Position=vec4(p,0.,1.);}`;

const FRAG = `precision highp float;
varying vec2 v;
uniform sampler2D A,B;uniform vec2 R,M,O;uniform vec3 W;uniform float T,X,P,aA,aB,K;
float h(vec2 p){p=fract(p*vec2(123.34,456.21));p+=dot(p,p+45.32);return fract(p.x*p.y);}
float n(vec2 p){vec2 i=floor(p),f=fract(p);f=f*f*(3.-2.*f);return mix(mix(h(i),h(i+vec2(1,0)),f.x),mix(h(i+vec2(0,1)),h(i+1.),f.x),f.y);}
float fbm(vec2 p){float a=.5,s=0.;for(int i=0;i<4;i++){s+=a*n(p);p=p*2.03+17.;a*=.5;}return s;}
vec2 cov(vec2 u,float ta){float sa=R.x/R.y;vec2 s=sa>ta?vec2(1.,ta/sa):vec2(sa/ta,1.);return (u-.5)*s/1.09+.5;}
vec3 day(vec2 u){
  float d=smoothstep(0.,1.,u.y);
  vec2 q=cov(u,aA)+M*vec2(.014,.01)*(.35+d);
  vec3 c=texture2D(A,q).rgb;
  c=mix(c,vec3(1.,.98,.97),.08);
  return c;
}
vec3 night(vec2 u){
  float d=smoothstep(0.,1.,u.y);
  vec2 q=cov(u,aB)+M*vec2(.014,.009)*(.3+d);
  vec3 c=texture2D(B,q).rgb;
  return c*.92;
}
void main(){
  vec2 u=v;float asp=R.x/R.y;
  vec2 dv=(u-O)*vec2(asp,1.);float dist=length(dv);
  float far=length(max(O,1.-O)*vec2(asp,1.))+.25;
  float front=P*far;
  float e=(dist-front)/.16;
  float wave=exp(-e*e)*step(.0005,P)*step(P,.9995);
  u-=normalize(dv+1e-5)/vec2(asp,1.)*wave*.035*sin(e*3.1416);
  float inside=smoothstep(front+.02,front-.08,dist);
  float to=X>.5?1.:0.;
  float m=mix(1.-to,to,P>=.9995?1.:inside);
  vec3 c=mix(day(u),night(u),m);
  c+=wave*mix(W,mix(W,vec3(1.),.35),1.-m)*.24;
  float vg=smoothstep(1.25,.35,length((v-.5)*vec2(1.1,1.)));
  c*=mix(.86,1.,vg);
  c+=(h(v*R+T)-.5)*.012;
  gl_FragColor=vec4(c,1.);
}`;

function ease(t: number) { return t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2; }

export const Backdrop = forwardRef<BackdropHandle, { dark: boolean; motion: boolean; skin: Skin }>(function Backdrop({ dark, motion, skin }, ref) {
  const canvas = useRef<HTMLCanvasElement>(null);
  const state = useRef({ dark, motion, ripple: null as null | { to: number; x: number; y: number; start: number; ms: number }, settled: dark ? 1 : 0, wake: () => {} });
  state.current.motion = motion;

  useImperativeHandle(ref, () => ({
    ripple(toDark, x, y, ms) {
      const s = state.current;
      s.ripple = { to: toDark ? 1 : 0, x, y, start: performance.now(), ms };
      s.wake();
    },
  }), []);

  // Тема сменилась без волны (первый кадр, сокращённые анимации) — просто выставить.
  useEffect(() => {
    const s = state.current;
    s.dark = dark;
    if (!s.ripple) { s.settled = dark ? 1 : 0; s.wake(); }
  }, [dark]);

  useEffect(() => {
    const el = canvas.current;
    if (!el) return;
    const gl = el.getContext("webgl", { antialias: false, alpha: false, powerPreference: "low-power", preserveDrawingBuffer: false });
    if (!gl) { el.dataset.fallback = "true"; return; }
    const sh = (type: number, src: string) => { const o = gl.createShader(type)!; gl.shaderSource(o, src); gl.compileShader(o); return o; };
    const prog = gl.createProgram()!;
    gl.attachShader(prog, sh(gl.VERTEX_SHADER, VERT));
    gl.attachShader(prog, sh(gl.FRAGMENT_SHADER, FRAG));
    gl.linkProgram(prog);
    if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) { el.dataset.fallback = "true"; return; }
    gl.useProgram(prog);
    const buf = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, buf);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 1, -1, -1, 1, 1, 1]), gl.STATIC_DRAW);
    const loc = gl.getAttribLocation(prog, "p");
    gl.enableVertexAttribArray(loc);
    gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);
    const U = (name: string) => gl.getUniformLocation(prog, name);
    const u = { A: U("A"), B: U("B"), R: U("R"), M: U("M"), O: U("O"), W: U("W"), T: U("T"), X: U("X"), P: U("P"), aA: U("aA"), aB: U("aB"), K: U("K") };
    const aspects = [16 / 9, 16 / 9];
    let loaded = 0;
    const load = (url: string, unit: number) => {
      const tex = gl.createTexture();
      gl.activeTexture(gl.TEXTURE0 + unit);
      gl.bindTexture(gl.TEXTURE_2D, tex);
      gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, 1, 1, 0, gl.RGBA, gl.UNSIGNED_BYTE, new Uint8Array(unit ? [10, 14, 13, 255] : [214, 222, 222, 255]));
      const img = new Image();
      img.onload = () => {
        gl.activeTexture(gl.TEXTURE0 + unit);
        gl.bindTexture(gl.TEXTURE_2D, tex);
        gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, gl.RGBA, gl.UNSIGNED_BYTE, img);
        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR);
        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
        aspects[unit] = img.width / img.height;
        if (++loaded === 2) el.dataset.ready = "true";
        s.wake();
      };
      img.src = url;
      return tex;
    };
    const texs = [load(skin === "natural" ? naturalLightUrl : lightUrl, 0), load(skin === "natural" ? naturalDarkUrl : darkUrl, 1)];
    const videos: (HTMLVideoElement | null)[] = skin === "natural"
      ? [null, null] // у природных фонов только статика с параллаксом
      : [lightVideo, darkVideo].map((src, unit) => {
          const v = document.createElement("video");
          v.muted = true; v.loop = true; v.playsInline = true; v.preload = "auto"; v.src = src;
          v.addEventListener("loadeddata", () => { aspects[unit] = v.videoWidth / v.videoHeight; s.wake(); });
          return v;
        });
    const want = [false, false];
    let suspended = false; // окно в трее: GPU-декодер и цикл рендера стоят
    const sync = () => {
      const dark = s.ripple ? s.ripple.to : s.settled;
      for (let i = 0; i < 2; i++) {
        const v = videos[i];
        if (!v) continue;
        const on = !suspended && s.motion && !document.hidden && (!!s.ripple || (i === 1) === (dark > 0.5));
        if (on !== want[i]) { want[i] = on; if (on) void v.play().catch(() => {}); else v.pause(); }
      }
    };
    const upload = () => {
      for (let i = 0; i < 2; i++) {
        const v = videos[i];
        if (!v || v.readyState < 2 || (!want[i] && uploaded[i])) continue;
        gl.activeTexture(gl.TEXTURE0 + i);
        gl.bindTexture(gl.TEXTURE_2D, texs[i]);
        gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, gl.RGBA, gl.UNSIGNED_BYTE, v);
        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR);
        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
        uploaded[i] = true;
      }
    };
    const uploaded = [false, false];
    gl.uniform1i(u.A, 0);
    gl.uniform1i(u.B, 1);

    const s = state.current;
    const mouse = { x: 0, y: 0, tx: 0, ty: 0 };
    let raf = 0, last = 0, clock = 0, running = false, disposed = false;
    const resize = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, 1.5);
      const w = Math.max(2, Math.round(el.clientWidth * dpr)), hgt = Math.max(2, Math.round(el.clientHeight * dpr));
      if (el.width !== w || el.height !== hgt) { el.width = w; el.height = hgt; gl.viewport(0, 0, w, hgt); }
    };
    const frame = (now: number) => {
      raf = 0;
      if (disposed || suspended) { running = false; return; }
      const rippling = !!s.ripple;
      // Спокойный фон идёт на ~30 к/с, волна и движение мыши — на полной частоте.
      const moving = Math.abs(mouse.tx - mouse.x) + Math.abs(mouse.ty - mouse.y) > 0.002;
      if (!rippling && !moving && now - last < 32) { schedule(); return; }
      const dt = Math.min(64, now - (last || now));
      last = now;
      if (s.motion) clock += dt / 1000;
      mouse.x += (mouse.tx - mouse.x) * Math.min(1, dt / 220);
      mouse.y += (mouse.ty - mouse.y) * Math.min(1, dt / 220);
      resize();
      sync();
      upload();
      let P = 1, X = s.settled, ox = 0.5, oy = 0.5;
      if (s.ripple) {
        const t = Math.min(1, (now - s.ripple.start) / s.ripple.ms);
        P = ease(t); X = s.ripple.to; ox = s.ripple.x; oy = s.ripple.y;
        if (t >= 1) { s.settled = s.ripple.to; s.ripple = null; }
      }
      gl.uniform2f(u.R, el.width, el.height);
      gl.uniform2f(u.M, s.motion ? mouse.x : 0, s.motion ? mouse.y : 0);
      gl.uniform2f(u.O, ox, oy);
      gl.uniform1f(u.T, clock);
      gl.uniform1f(u.X, X);
      gl.uniform1f(u.P, P);
      gl.uniform1f(u.aA, aspects[0]);
      gl.uniform1f(u.aB, aspects[1]);
      gl.uniform1f(u.K, s.motion ? 1 : 0);
      gl.uniform3f(u.W, ...(skin === "natural" ? [1, 0.85, 0.55] : [1, 0.5, 0.72]) as [number, number, number]);
      gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);
      if (s.motion || s.ripple || moving) schedule();
      else running = false;
    };
    const schedule = () => { if (!raf && !disposed && !suspended && !document.hidden) { running = true; raf = requestAnimationFrame(frame); } };
    s.wake = () => { last = 0; schedule(); };
    const offWindowEvent = EventsOn("evasion:window", (state: unknown) => {
      suspended = state === "hidden";
      if (suspended) {
        cancelAnimationFrame(raf);
        raf = 0;
        running = false;
        sync();
      } else {
        last = 0;
        sync();
        upload();
        s.wake();
      }
    });
    const onMove = (e: PointerEvent) => { mouse.tx = (e.clientX / window.innerWidth) * 2 - 1; mouse.ty = (e.clientY / window.innerHeight) * 2 - 1; if (!running) schedule(); };
    const onLeave = () => { mouse.tx = 0; mouse.ty = 0; };
    const onVisible = () => { sync(); if (!document.hidden) s.wake(); };
    window.addEventListener("pointermove", onMove, { passive: true });
    document.documentElement.addEventListener("pointerleave", onLeave);
    document.addEventListener("visibilitychange", onVisible);
    window.addEventListener("resize", s.wake);
    schedule();
    return () => {
      disposed = true;
      offWindowEvent();
      cancelAnimationFrame(raf);
      videos.forEach((v) => { if (v) { v.pause(); v.removeAttribute("src"); v.load(); } });
      window.removeEventListener("pointermove", onMove);
      document.documentElement.removeEventListener("pointerleave", onLeave);
      document.removeEventListener("visibilitychange", onVisible);
      window.removeEventListener("resize", s.wake);
      s.wake = () => {};
    };
  }, [skin]);

  useEffect(() => { state.current.wake(); }, [motion]);

  return <canvas ref={canvas} className="backdrop" aria-hidden="true" />;
});
