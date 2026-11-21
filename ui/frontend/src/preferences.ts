import { useState } from "react";
import type { StartOptions } from "./api";

export function readPreference(key: string): string | null {
  try { return window.localStorage.getItem(key); } catch { return null; }
}

export function savePreference(key: string, value: string) {
  try {
    window.localStorage.setItem(key, value);
    if (key === "evasion-connection-options" && typeof window.dispatchEvent === "function") window.dispatchEvent(new Event("evasion:options-changed"));
  } catch { /* Keep working when storage is unavailable. */ }
}

export const defaultOptions: StartOptions = { voice: "ttl", quic: "off", observe: false, restartDiscord: true, boost: true };

export function loadOptions(): StartOptions {
  try {
    const value = JSON.parse(readPreference("evasion-connection-options") || "null");
    return {
      voice: ["off", "ttl", "badsum", "ttl-quic", "badsum-quic"].includes(value?.voice) ? value.voice : defaultOptions.voice,
      quic: ["off", "block", "desync"].includes(value?.quic) ? value.quic : defaultOptions.quic,
      observe: typeof value?.observe === "boolean" ? value.observe : defaultOptions.observe,
      restartDiscord: typeof value?.restartDiscord === "boolean" ? value.restartDiscord : defaultOptions.restartDiscord,
      boost: typeof value?.boost === "boolean" ? value.boost : defaultOptions.boost,
    };
  } catch { return { ...defaultOptions }; }
}

export function useConnectionOptions() {
  const [options, setOptions] = useState(loadOptions);
  const update = (patch: Partial<StartOptions>) => setOptions((current) => {
    const next = { ...current, ...patch };
    savePreference("evasion-connection-options", JSON.stringify(next));
    return next;
  });
  return [options, update] as const;
}
