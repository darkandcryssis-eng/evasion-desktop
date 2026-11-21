import { useState } from "react";
import { BrowserOpenURL } from "../wailsjs/runtime/runtime";
import { api, type UpdateState } from "./api";
import { usePoll } from "./hooks";
import { Button, Glass, Row } from "./ui";

function useUpdate() {
  const poll = usePoll<UpdateState>(() => api.getUpdate(), 1500);
  const [error, setError] = useState("");
  const run = (fn: () => Promise<unknown>) => { setError(""); void fn().catch((e) => setError(String(e))).finally(() => void poll.refresh()); };
  return { state: poll.value, error: error || poll.value?.error || "", install: () => run(api.installUpdate), check: () => run(api.checkUpdate) };
}

// Для значка «!» в навигации: есть ли неустановленное обновление.
export function useUpdateAvailable() {
  return usePoll<UpdateState>(() => api.getUpdate(), 5000).value?.available ?? false;
}

function InstallButton({ state, onInstall }: { state: UpdateState; onInstall: () => void }) {
  return <Button kind="solid" icon="download" disabled={state.downloading} onClick={onInstall}>{state.downloading ? `Скачиваем… ${state.progress}%` : "Обновить"}</Button>;
}

// Плашка поверх любой страницы: ничего не ставится, пока пользователь не нажмёт «Обновить».
export function UpdateBanner() {
  const { state, error, install } = useUpdate();
  const [hidden, setHidden] = useState("");
  if (!state?.available || (hidden === state.latest && !state.downloading)) return null;
  return (
    <aside className="update-banner" role="status">
      <div className="update-banner__text">
        <strong>Доступно обновление {state.latest}</strong>
        <small>{error || `У вас ${state.current}. Evasion перезапустится, включённый обход вернётся сам.`}</small>
      </div>
      <Button kind="ghost" icon="external" onClick={() => BrowserOpenURL(state.url)}>Что нового</Button>
      {!state.downloading && <Button kind="ghost" onClick={() => setHidden(state.latest)}>Позже</Button>}
      <InstallButton state={state} onInstall={install} />
    </aside>
  );
}

export function UpdateCard() {
  const { state, error, install, check } = useUpdate();
  if (!state) return null;
  const dev = state.current === "dev";
  const note = error || (dev ? "Локальная сборка: обновления не проверяются."
    : state.available ? `Доступна версия ${state.latest}`
    : state.checkedAt ? `Установлена последняя версия · проверено в ${new Date(state.checkedAt).toLocaleTimeString("ru", { hour: "2-digit", minute: "2-digit" })}`
    : "Проверяется автоматически после запуска и каждые две минуты.");
  return (
    <Glass className="card">
      <header className="card-head"><span className="kicker">Обновления</span></header>
      <Row title={`Версия ${state.current}`} note={note}>
        {state.available ? <InstallButton state={state} onInstall={install} />
          : <Button icon="refresh" disabled={dev || state.checking} onClick={check}>{state.checking ? "Проверяем…" : "Проверить"}</Button>}
      </Row>
    </Glass>
  );
}
