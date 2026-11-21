import { Power, Send } from "lucide-react";
import { useState } from "react";
import { api, type TelegramState } from "../api";
import { PageHeader } from "../components/PageHeader";
import { TelegramStatus } from "../components/TelegramStatus";
import { Disclosure } from "../components/Disclosure";
import { Toggle } from "../components/Toggle";
import { SpeedGraph, RoutePanel } from "../components/TelegramInsights";

export function TelegramScreen({ state, motion, onRefresh }: { state?: TelegramState; motion: boolean; onRefresh: () => unknown }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [port, setPort] = useState<string | null>(null);
  const [community, setCommunity] = useState<boolean | null>(null);
  const toggle = async () => {
    if (busy) return;
    setBusy(true); setError("");
    try {
      if (state?.running) await api.stopTelegramProxy();
      else {
        const value = Number(port ?? state?.port ?? 17655);
        if (!Number.isInteger(value) || value < 1024 || value > 65535) throw new Error("Укажите порт от 1024 до 65535");
        await api.setTelegramOptions(value, community ?? state?.community ?? true);
        await api.startTelegramProxy(value);
        await api.openTelegramProxy();
      }
      onRefresh();
    } catch (e) { setError(String(e)); onRefresh(); }
    finally { setBusy(false); }
  };
  return (
    <div className="screen">
      <PageHeader title="Telegram" description="Встроенный прокси. Подключение, трафик и состояние каналов." action={<button className="secondary-button telegram-primary" type="button" disabled={busy || !state} onClick={() => void toggle()}><Power size={14} />{busy ? "Подождите…" : state?.running ? "Выключить" : "Включить Telegram"}</button>} />
      {error && <div className="info-banner info-banner--warn" role="alert">{error}</div>}
      <TelegramStatus state={state} motion={motion} onRefresh={onRefresh} />
      <SpeedGraph samples={state?.speeds} running={!!state?.running} />
      <RoutePanel />
      <Disclosure summary={<><Send size={17} /><span><strong>Параметры подключения</strong><small>Обычно менять не требуется</small></span></>}>
        <div className="disclosure__body"><label className="control-row"><span>Локальный порт</span><input className="telegram-port-input" type="number" min={1024} max={65535} value={port ?? state?.port ?? 17655} disabled={state?.running || busy} onChange={(e) => setPort(e.target.value)} /></label><div className="setting-row"><div><strong>Резервные узлы сообщества</strong><small>Использовать, если прямой маршрут заблокирован. Сообщения защищены шифрованием Telegram.</small></div><Toggle checked={community ?? state?.community ?? true} disabled={state?.running || busy} label="Резервные узлы сообщества" onChange={setCommunity} /></div><p className="local-note">Прокси доступен только на этом компьютере. Он не меняет параметры стороннего TgWsProxy.</p></div>
      </Disclosure>
      <p className="local-note">Трафик сообщений остаётся зашифрованным Telegram. После обрыва повреждённый канал закрывается, чтобы клиент переподключился через доступный маршрут.</p>
    </div>
  );
}
