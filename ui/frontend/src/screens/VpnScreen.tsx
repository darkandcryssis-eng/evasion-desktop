import { ShieldEllipsis } from "lucide-react";
import { PageHeader } from "../components/PageHeader";

export function VpnScreen() {
  return (
    <div className="screen">
      <PageHeader title="VPN" description="Отдельный раздел приложения" badge="Позже" />

      <div className="vpn-placeholder">
        <div className="vpn-placeholder__icon"><ShieldEllipsis size={25} strokeWidth={1.45} /></div>
        <strong>Позже…</strong>
        <p>Раздел появится в одном из следующих обновлений интерфейса.</p>
      </div>
    </div>
  );
}
