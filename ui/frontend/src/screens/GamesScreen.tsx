import { useEffect, useState } from "react";
import { Activity, FolderPlus, Gamepad2, Power, ShieldCheck, Trash2 } from "lucide-react";
import { api, type GameFilterSettings, type GameFilterView } from "../api";
import { loadOptions } from "../preferences";
import { gameStatus, gameConnectionNote } from "../gameStatus";
import { PageHeader } from "../components/PageHeader";
import { StatusBadge } from "../components/StatusBadge";

const defaults: GameFilterSettings = { adaptive: true, mode: "auto", protocol: "both", albion: true, ubisoft: true, executables: [], onDemand: true };
export function GamesScreen({onDiagnosticsRequested}:{onDiagnosticsRequested:()=>void}) {
 const [view,setView]=useState<GameFilterView>();
 const [busy,setBusy]=useState(false);
 const [error,setError]=useState("");
 const [routeInput,setRouteInput]=useState("");
 const settings=view?.settings??defaults;
 const active=Boolean(view?.engineRunning && view.activeMode!=="off");
 const status=gameStatus(view,busy);
 const connectionNote=gameConnectionNote(view);
 const albion=(view?.processes??[]).find(p=>p.family==="albion");
 useEffect(()=>{
  let alive=true;
  const refresh=async()=>{try{const next=await api.getGameFilter();if(alive)setView(next)}catch(e){if(alive)setError(String(e))}};
  void refresh();const timer=window.setInterval(()=>void refresh(),1500);
  return()=>{alive=false;window.clearInterval(timer)};
 },[]);
 const persist=async(patch:Partial<GameFilterSettings>,start:boolean)=>{
  setBusy(true);setError("");
  try {
   await api.setGameFilter({...settings,...patch,mode:"auto",adaptive:true,albion:true,ubisoft:true});
   if(start)await api.applyGameFilter(loadOptions());
   const next=await api.getGameFilter();setView(next);if(next.error)throw new Error(next.error);
  } catch(e){setError(String(e));setView(await api.getGameFilter().catch(()=>undefined))}finally{setBusy(false)}
 };
 const toggle=async()=>{
  if(!active){await persist({},true);return}
  setBusy(true);setError("");try{await api.stopGameFilter();setView(await api.getGameFilter())}catch(e){setError(String(e))}finally{setBusy(false)}
 };
 const importRoute=async()=>{
  setBusy(true);setError("");
  try{await api.importGameRoute(routeInput);setRouteInput("");if(active)await api.applyGameFilter(loadOptions());setView(await api.getGameFilter())}catch(e){setError(String(e))}finally{setBusy(false)}
 };
 const removeRoute=async()=>{
  setBusy(true);setError("");try{await api.removeGameRoute();if(active)await api.applyGameFilter(loadOptions());setView(await api.getGameFilter())}catch(e){setError(String(e))}finally{setBusy(false)}
 };
 const add=async()=>{try{const path=await api.selectGameExecutable();if(path&&!settings.executables.some(p=>p.toLowerCase()===path.toLowerCase()))await persist({executables:[...settings.executables,path]},active)}catch(e){setError(String(e))}};
 return <div className="screen games-screen">
  <PageHeader title="Игровой обход" description="Включите — остальное Evasion подберёт автоматически" action={<StatusBadge tone="neutral">{status}</StatusBadge>}/>
  <section className="settings-section game-launch-bar" aria-label="Управление игровым обходом" aria-busy={busy}>
   <div><span className="game-eyebrow">GAME FILTER · AUTO</span><strong>{status}</strong></div>
   <button className="primary-button" type="button" disabled={!view||busy} onClick={()=>void toggle()}><Power size={16}/>{busy?"Подождите…":active?"Выключить":"Включить"}</button>
  </section>
  <section className="settings-section game-controls" aria-label="Параметры соединения">
   <div className="setting-row"><div><strong>Тип соединения</strong><small>Режим помощи выбирается автоматически. Изменения применяются сразу.</small></div>
    <select className="game-select" aria-label="Игровые протоколы" value={settings.protocol} disabled={!view||busy} onChange={e=>void persist({protocol:e.target.value},active)}><option value="both">TCP + UDP</option><option value="tcp">TCP</option><option value="udp">UDP</option></select>
   </div>
   <p className="local-note"><ShieldCheck size={13}/> Только выбранные игры и лаунчеры. Общий обход и Telegram управляются отдельно.</p>
   {(error||view?.error)&&<div className="local-note" role="alert"><p>{error||view?.error}</p>{(error||view?.error||"").toLowerCase().includes("windivert")&&<button className="quiet-button" type="button" onClick={onDiagnosticsRequested}>Диагностика драйвера</button>}</div>}
  </section>
  <section className="settings-section game-live" aria-label="Активность игрового обхода">
   <div className="game-section-heading"><Activity size={16}/><strong>Что происходит</strong></div>
   {active&&connectionNote&&<p className="local-note" role="status">{connectionNote}</p>}
   {active&&albion&&!connectionNote&&<p className="local-note" role="status">{albion.clients>0?"Процесс клиента Albion обнаружен. Вход в игру ещё не подтверждён.":"Обнаружен лаунчер Albion; процесс клиента игры пока не обнаружен. Если зависает после «Играть», проверьте запуск клиента и сообщения BattlEye."}</p>}
   <div className="game-live__numbers"><div><strong>{view?.stats.connections??0}</strong><small>{view?.stats.tunnel?"соединений через маршрут":"соединений обработано"}</small></div><div><strong>{view?.stats.udp??0}</strong><small>UDP-обработок</small></div><div><strong>{view?.stats.errors??0}</strong><small>ошибок подключения</small></div></div>
   {view?.stats.tunnel&&<p className="local-note">Получено {((view.stats.tunnelReceived??0)/1024).toLocaleString("ru",{maximumFractionDigits:1})} КБ · Отправлено {((view.stats.tunnelSent??0)/1024).toLocaleString("ru",{maximumFractionDigits:1})} КБ</p>}
   <p className="local-note">{view?.stats.tunnel?"Через сервер идут только выбранные игры и лаунчеры. Вход в игру проверяется в самой игре.":"Сетевой обмен не подтверждает запуск игры или вход в аккаунт. Внешний IP не меняется."}</p>
  </section>
  <details className="settings-section game-extra"><summary><ShieldCheck size={16}/>Личный игровой маршрут{view?.route?.configured?" · подключён":""}</summary>
   <p className="local-note">Для сетей, где игра работает только через VPN. Добавьте свою подписку VLESS/Reality один раз — дальше используется основная кнопка. Профиль сохраняется только на этом компьютере.</p>
   {view?.route?.configured&&<div className="setting-row"><div><strong>Сервер выбирается автоматически</strong><small>Серверов в профиле: {view.route.nodes}</small></div><button className="quiet-button" disabled={busy} onClick={()=>void removeRoute()}>Убрать маршрут</button></div>}
   <div className="setting-row"><input className="game-select" type="password" autoComplete="off" spellCheck={false} aria-label="Подписка, VLESS или JSON из Happ" placeholder="Подписка, VLESS или JSON из Happ" value={routeInput} disabled={busy} onChange={e=>setRouteInput(e.target.value)}/><button className="secondary-button" type="button" disabled={busy||!routeInput.trim()} onClick={()=>void importRoute()}>{view?.route?.configured?"Заменить профиль":"Добавить профиль"}</button></div>
  </details>
  <details className="settings-section game-extra"><summary><Gamepad2 size={16}/>Другие игры</summary><p className="local-note">Albion и Ubisoft добавлять не требуется. Для другой игры выберите её .exe один раз.</p>
   {settings.executables.map(path=><div className="game-executable" key={path}><span><strong>{path.split(/[\\/]/).pop()}</strong><small>{path}</small></span><button className="quiet-button" type="button" disabled={busy} aria-label={`Убрать ${path.split(/[\\/]/).pop()}`} onClick={()=>void persist({executables:settings.executables.filter(item=>item!==path)},active)}><Trash2 size={14}/></button></div>)}
   <button className="secondary-button" type="button" disabled={!view||busy||settings.executables.length>=16} onClick={()=>void add()}><FolderPlus size={14}/>Добавить игру</button>
  </details>
 </div>
}
