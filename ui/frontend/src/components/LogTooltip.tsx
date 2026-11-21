import { type ReactNode, useEffect, useId, useLayoutEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import type { LogLine } from "../api";

type LogTooltipProps = {
  line: LogLine;
  tone: string;
  time: string;
  className: string;
  children: ReactNode;
};

export function LogTooltip({ line, tone, time, className, children }: LogTooltipProps) {
  const id = useId();
  const trigger = useRef<HTMLDivElement>(null);
  const tip = useRef<HTMLDivElement>(null);
  const timers = useRef<{ show?: number; hide?: number }>({});
  const hovered = useRef(false);
  const focused = useRef(false);
  const [open, setOpen] = useState(false);
  const [position, setPosition] = useState({ left: 0, top: 0, ready: false });

  const clearTimers = () => {
    window.clearTimeout(timers.current.show);
    window.clearTimeout(timers.current.hide);
    timers.current = {};
  };
  const close = () => { clearTimers(); setOpen(false); };
  const show = () => { clearTimers(); setOpen(true); };
  const enter = () => {
    hovered.current = true;
    clearTimers();
    if (!open) timers.current.show = window.setTimeout(show, 160);
  };
  const leave = () => {
    hovered.current = false;
    clearTimers();
    if (!focused.current) timers.current.hide = window.setTimeout(close, 120);
  };

  useEffect(() => clearTimers, []);

  useLayoutEffect(() => {
    if (!open) return;
    const place = () => {
      if (!trigger.current || !tip.current) return;
      const anchor = trigger.current.getBoundingClientRect();
      const rect = tip.current.getBoundingClientRect();
      const left = Math.max(12, Math.min(anchor.left, window.innerWidth - rect.width - 12));
      const below = anchor.bottom + 10;
      const preferred = below + rect.height <= window.innerHeight - 12 ? below : anchor.top - rect.height - 10;
      const top = Math.max(12, Math.min(preferred, window.innerHeight - rect.height - 12));
      setPosition({ left, top, ready: true });
    };
    const onScroll = (event: Event) => {
      if (event.target instanceof Node && tip.current?.contains(event.target)) return;
      close();
    };
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") { event.preventDefault(); event.stopPropagation(); close(); }
    };
    const onOutside = (event: PointerEvent) => {
      if (event.target instanceof Node && !trigger.current?.contains(event.target) && !tip.current?.contains(event.target)) close();
    };
    place();
    const observer = new ResizeObserver(place);
    if (trigger.current) observer.observe(trigger.current);
    if (tip.current) observer.observe(tip.current);
    window.addEventListener("resize", place);
    window.addEventListener("blur", close);
    window.addEventListener("scroll", onScroll, true);
    document.addEventListener("keydown", onKey, true);
    document.addEventListener("pointerdown", onOutside, true);
    return () => {
      observer.disconnect();
      window.removeEventListener("resize", place);
      window.removeEventListener("blur", close);
      window.removeEventListener("scroll", onScroll, true);
      document.removeEventListener("keydown", onKey, true);
      document.removeEventListener("pointerdown", onOutside, true);
    };
  }, [open, line.msg, line.attrs]);

  const host = trigger.current?.closest(".app");
  const label = ({ info: "Событие", warn: "Предупреждение", error: "Ошибка" } as Record<string, string>)[tone] || "Подробности";

  return <>
    <div ref={trigger} className={className} tabIndex={0} aria-describedby={open ? id : undefined}
      onPointerEnter={(event) => { if (event.pointerType === "mouse") enter(); }} onPointerLeave={leave}
      onFocus={() => { focused.current = true; show(); }}
      onBlur={() => { focused.current = false; if (!hovered.current) close(); }}>
      {children}
    </div>
    {open && host && createPortal(
      <div ref={tip} id={id} role="tooltip" className={`log-tooltip log-tooltip--${tone}`}
        style={{ left: position.left, top: position.top, visibility: position.ready ? "visible" : "hidden" }}
        onPointerEnter={enter} onPointerLeave={leave}>
        <div className="log-tooltip__heading"><span className="log-tooltip__kind"><i />{label}</span>{time && <time>{time}</time>}</div>
        <div className="log-tooltip__message">{line.msg}</div>
        {line.attrs && <div className="log-tooltip__details">{line.attrs}</div>}
      </div>, host)}
  </>;
}
