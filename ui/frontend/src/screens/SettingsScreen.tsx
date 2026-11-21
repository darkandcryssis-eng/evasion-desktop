import { NetworkTuning } from "../components/NetworkTuning";
import { FolderOpen } from "lucide-react";
import { useEffect, useState } from "react";
import { PageHeader } from "../components/PageHeader";
import { Toggle } from "../components/Toggle";
import { api } from "../api";
import { loadOptions } from "../preferences";

type SettingsScreenProps = {
  motionEnabled: boolean;
  startupEnabled: boolean;
  onMotionEnabledChange: (enabled: boolean) => void;
  onStartupEnabledChange: (enabled: boolean) => void;
};

export function SettingsScreen({
  motionEnabled,
  startupEnabled,
  onMotionEnabledChange,
  onStartupEnabledChange,
}: SettingsScreenProps) {
  return (
    <div className="screen">
      <PageHeader title="Настройки" description="Сделайте Evasion удобным для себя" />

      <section className="settings-section settings-section--compact">
        <div className="setting-row">
          <div><strong>Мягкие анимации</strong><small>Плавные переходы и индикаторы</small></div>
          <Toggle checked={motionEnabled} label="Мягкие анимации" onChange={onMotionEnabledChange} />
        </div>
        <div className="setting-row">
          <div><strong>Стартовый экран</strong><small>Изменение действует при следующем запуске</small></div>
          <Toggle checked={startupEnabled} label="Стартовый экран" onChange={onStartupEnabledChange} />
        </div>
      </section>

      <NetworkTuning />
      <AutoStartSection />
      <DataFolderSection />
    </div>
  );
}

function AutoStartSection() {
  const [enabled, setEnabled] = useState(false);
  const [busy, setBusy] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let alive = true;
    void api.getAutoStart().then((value) => { if (alive) setEnabled(value); })
      .catch((e) => { if (alive) setError(String(e)); })
      .finally(() => { if (alive) setBusy(false); });
    return () => { alive = false; };
  }, []);

  const change = async (value: boolean) => {
    setBusy(true);
    setError("");
    try {
      await api.setAutoStart(value, loadOptions());
      setEnabled(await api.getAutoStart());
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="settings-section settings-section--compact" aria-busy={busy}>
      <div className="setting-row">
        <div><strong>Автозапуск с Windows</strong><small>Запускать эту копию Evasion после входа и сразу подключаться</small></div>
        <Toggle checked={enabled} disabled={busy} label="Автозапуск с Windows и подключение" onChange={(value) => void change(value)} />
      </div>
      {error && <p className="local-note" role="alert">{error}</p>}
    </section>
  );
}

// DataFolderSection — доступ к папке, где движок хранит state\ (память голоса,
// lock), runtime\ (движок, WinDivert) и конфиг. Путь — %LOCALAPPDATA%\Evasion.
function DataFolderSection() {
  const [dir, setDir] = useState("");

  useEffect(() => {
    let alive = true;
    void api.getState().then((s) => {
      if (alive) setDir(s.baseDir);
    }).catch(() => {});
    return () => {
      alive = false;
    };
  }, []);

  return (
    <section className="settings-section settings-section--compact">
      <div className="setting-row">
        <div>
          <strong>Папка данных</strong>
          <small className="path-ellipsis">{dir || "%LOCALAPPDATA%\\Evasion"}</small>
        </div>
        <button className="secondary-button" type="button" onClick={() => void api.openDataFolder()}>
          <FolderOpen size={14} />Открыть
        </button>
      </div>
    </section>
  );
}

