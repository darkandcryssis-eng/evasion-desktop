import { useCallback, useEffect, useRef, useState } from "react";
import { api, type AppState, type StartOptions } from "./api";
import { readPreference, savePreference } from "./preferences";

export function useEngine() {
  const [state, setState] = useState<AppState | null>(null);
  const [pollError, setPollError] = useState("");
  const [actionError, setActionError] = useState("");
  const [busy, setBusy] = useState(false);
  const mounted = useRef(false);
  const acting = useRef(false);
  const version = useRef(0);

  const refresh = useCallback(async () => {
    const request = ++version.current;
    try {
      const next = await api.getState();
      if (mounted.current && request === version.current) {
        setState(next);
        setPollError("");
      }
      return next;
    } catch (e) {
      if (mounted.current && request === version.current) setPollError(String(e));
      return null;
    }
  }, []);

  useEffect(() => {
    mounted.current = true;
    let cancelled = false;
    let timer: number | undefined;
    const tick = async () => {
      const next = acting.current ? null : await refresh();
      if (cancelled) return;
      const fast = next?.engine.phase === "starting" || next?.engine.phase === "stopping";
      timer = window.setTimeout(tick, fast ? 500 : 2000);
    };
    void tick();
    return () => {
      cancelled = true;
      mounted.current = false;
      ++version.current;
      window.clearTimeout(timer);
    };
  }, [refresh]);

  const run = useCallback(async (action: () => Promise<unknown>) => {
    if (acting.current) return;
    acting.current = true;
    ++version.current;
    setBusy(true);
    setActionError("");
    try {
      await action();
    } catch (e) {
      if (mounted.current) setActionError(String(e));
    } finally {
      await refresh();
      acting.current = false;
      if (mounted.current) setBusy(false);
    }
  }, [refresh]);

  const start = useCallback((opts: StartOptions) => run(() => api.startEngine(opts)), [run]);
  const stop = useCallback(() => run(() => api.stopConnection()), [run]);
  const connect = useCallback((opts: StartOptions, telegram: boolean) => run(async () => {
    await api.connectWithTelegram(opts, telegram);
    if (telegram && readPreference("evasion-telegram-link-offered") !== "true") {
      await api.openTelegramProxy();
      savePreference("evasion-telegram-link-offered", "true");
    }
  }), [run]);
  const reconnect = useCallback(() => run(async () => {
    if (!state || state.engine.phase !== "running") return;
    await api.stopEngine();
    await api.startEngine({ ...state.engine.options, restartDiscord: false });
  }), [run, state]);
  const restartDiscord = useCallback(() => run(() => api.restartDiscord()), [run]);

  return { state, error: actionError || pollError || state?.engine.error || "", busy, start, connect, stop, reconnect, restartDiscord, refresh };
}

export type EngineController = ReturnType<typeof useEngine>;
