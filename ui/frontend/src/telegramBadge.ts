import type { TelegramState } from "./api";

export const telegramPhase: Record<TelegramState["phase"], string> = {
  stopped: "Выключен", waiting: "Ожидает Telegram", connecting: "Выбираем маршрут…", online: "Есть обмен данными", degraded: "Возобновление",
};

export function telegramBadge(state: Pick<TelegramState, "phase" | "running" | "connections" | "failures">): { label: string; tone: "success" | "warning" | "neutral" } {
  if (!state.running) return { label: telegramPhase.stopped, tone: "neutral" };
  if (state.phase === "online") return { label: telegramPhase.online, tone: "success" };
  if (state.phase === "degraded" || (state.phase === "connecting" && (state.connections > 0 || state.failures > 0))) {
    return { label: "Возобновление", tone: "warning" };
  }
  return { label: telegramPhase[state.phase] || "Получаем состояние…", tone: "neutral" };
}
