import type { GameFilterView } from "./api";
export function gameStatus(view: GameFilterView | undefined, busy: boolean): string {
 if (busy) return "Применение…";
 if (view?.error) return "Нужна проверка";
 if (!view?.engineRunning || view.activeMode === "off") return "Выключен";
 if (!view.fresh) return "Ожидаем движок";
 const transportStatus: Record<string,string> = { tcp_unanswered: "Нет ответа на TCP-подключение", tls_unanswered: "Нет ответа на TLS-запрос", tls_closed: "TLS-соединение прервано", tcp_closed: "TCP-соединение прервано" };
 if (view.transport && transportStatus[view.transport.stage]) return transportStatus[view.transport.stage];
 if (view.stats?.tunnel) return view.transport?.responding ? "Есть обмен через игровой маршрут" : "Игровой маршрут готов";
 if (view.adaptive.helping) return "Помогаем подключиться";
 if (view.adaptive.responsive) return "Обнаружен сетевой обмен";
 return view.targets.length ? "Игра / лаунчер обнаружены" : "Ожидаем игру";
}

export function gameConnectionNote(view: GameFilterView | undefined): string {
 if (!view?.engineRunning || !view.fresh || view.activeMode === "off" || view.error) return "";
 if (view.stats?.tunnel && ["tcp_unanswered","tls_unanswered","tls_closed","tcp_closed"].includes(view.transport?.stage??"")) return "Игровой маршрут не получил ответ. Проверьте доступность подписки; затем перезапустите лаунчер.";
 switch (view.transport?.stage) {
  case "tcp_unanswered": return "Есть TCP-подключения без ответа. Обработка TLS ещё не началась: возможны фильтрация адреса или недоступный маршрут.";
  case "tls_unanswered": return "TCP установлен, но на TLS-запросы нет данных от сервера. Если помогает только VPN, нужен резервный маршрут.";
  case "tls_closed": return "TLS-рукопожатие прервано до ответа. На следующей попытке Evasion выберет другой вариант обработки.";
  case "tcp_closed": return "Соединение закрыто до получения данных от сервера. Наличие запущенного движка не означает доступность игры.";
  default: return "";
 }
}
