import { useEffect, useRef } from "react";
import type { LogLine } from "../api";
import { LogTooltip } from "./LogTooltip";

// condense превращает многословные сообщения движка в короткую метку (2–3
// слова) — лента должна читаться мгновенно. Неизвестные сообщения обрезаются
// до первых слов; полный текст доступен во всплывающей подсказке.
function condense(line: LogLine): string {
  const m = line.msg;
  const map: Record<string, string> = {
    "журнал событий поднят": "журнал запущен",
    "журнал событий не поднялся, работаем без него": "журнал недоступен",
    "стратегия по группе": "стратегия задана",
    "стратегия по группе (ротация)": "ротация стратегии",
    "перехват: разбор ClientHello": "разбор ClientHello",
    "переклейка RTC-портов включена": "RTC-переклейка",
    "контрольные цели не заданы: killswitch по связности отключён": "killswitch выкл.",
    "точка наблюдения определена частично": "vantage частично",
    "transport_fallback: применён блок": "hosts применён",
    "transport_fallback: блок уже в hosts, пропуск": "hosts на месте",
  };
  if (map[m]) return map[m];
  const words = m.replace(/[:：].*$/, "").split(/\s+/).slice(0, 3).join(" ");
  return words.length > 30 ? words.slice(0, 30) + "…" : words;
}

function tone(level: string): string {
  switch (level) {
    case "ERROR":
    case "TEXT":
      return "error";
    case "WARN":
      return "warn";
    case "INFO":
      return "info";
    default:
      return "muted";
  }
}

function hhmmss(at: string): string {
  const d = new Date(at);
  return Number.isNaN(d.getTime()) ? "" : d.toLocaleTimeString("ru-RU", { hour12: false });
}

type LogFeedProps = {
  logs: LogLine[];
  motion: boolean;
};

const MAX = 7;

export function LogFeed({ logs, motion }: LogFeedProps) {
  const shown = logs.slice(-MAX);
  const bottomRef = useRef<HTMLDivElement>(null);
  const seenRef = useRef(0);

  useEffect(() => {
    const feed = bottomRef.current?.parentElement;
    feed?.scrollTo({ top: feed.scrollHeight, behavior: motion ? "smooth" : "auto" });
  }, [logs.length, motion]);

  const total = logs.length;
  const firstNew = total - (total - seenRef.current);
  useEffect(() => {
    seenRef.current = total;
  }, [total]);

  return (
    <div className="log-feed" aria-live="polite" aria-label="Журнал движка">
      {shown.length === 0 && <div className="log-feed__idle">Журнал появится после запуска движка</div>}
      {shown.map((l, i) => {
        const globalIdx = total - shown.length + i;
        const isNew = motion && globalIdx >= firstNew;
        const kind = tone(l.level);
        const time = hhmmss(l.at);
        return (
          <LogTooltip
            key={`${l.at}-${globalIdx}`}
            className={`log-line log-line--${kind}${isNew ? " log-line--new" : ""}`}
            line={l} tone={kind} time={time}
          >
            <span className="log-line__dot" />
            <span className="log-line__time">{time}</span>
            <span className="log-line__msg">{condense(l)}</span>
          </LogTooltip>
        );
      })}
      <div ref={bottomRef} />
    </div>
  );
}
