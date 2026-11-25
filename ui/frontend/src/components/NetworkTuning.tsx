import { useEffect, useState } from "react";
import { Activity, ShieldCheck } from "lucide-react";
import { api, NetworkTuningView } from "../api";
import { loadOptions } from "../preferences";
import { startVisibleLoop } from "../windowActivity";
import { Toggle } from "./Toggle";
import { StatusBadge } from "./StatusBadge";

const profiles: Record<string,string> = {current:"Базовый способ","media-sld":"Защита видеоподключений","split-sld":"Разделение домена","fake-sld":"Защита домена",split:"Разделение соединения","split-forward":"Совместимый способ",overlap:"Альтернативный способ","fake-forward":"Совместимая защита","fake-split":"Дополнительная защита","fake-overlap":"Альтернативная защита"};
const phases: Record<string,string> = {waiting:"Проверка запускается",awaiting_media:"Сайт доступен — откройте видео для проверки видеосервера",stopped:"Начнёт работу после включения обхода",disabled:"YouTube исключён из текущего обхода",checking:"Проверяем соединение",healthy:"Проверенные подключения доступны",degraded:"Перепроверяем сбой",recovering:"Подбираем рабочий способ в фоне",recovered:"Рабочий способ заменён и проверен",network_down:"Контрольные сайты тоже недоступны",unavailable:"Проверенные способы пока не помогли — повторим автоматически"};
const targets: Record<string,string> = {site:"YouTube",image:"Изображения",media_transport:"Видеосеть"};

const stages: Record<string,string> = {dns:"не найден адрес",tcp:"нет соединения",tls:"не отвечает HTTPS",http:"нет ответа"};

export function NetworkTuning() {
 const [view,setView]=useState<NetworkTuningView>();
 const [pending,setPending]=useState(false);
 const [error,setError]=useState("");
 useEffect(()=>{let alive=true;const loop=startVisibleLoop(async()=>{try{const next=await api.getNetworkTuning(loadOptions());if(alive)setView(next)}catch(e){if(alive)setError(String(e))}},1500);return()=>{alive=false;loop.stop()}},[]);
 const health=view?.health;
 const phase=health?.phase??"waiting";
 const changeTelegram=async(enabled:boolean)=>{setPending(true);setError("");try{await api.setNetworkTuningSettings(true,enabled);setView(await api.getNetworkTuning(loadOptions()))}catch(e){setError(String(e))}finally{setPending(false)}};
 return <section className="settings-section network-tuning" aria-label="Автоматическое восстановление">
  <div className="network-tuning__heading"><Activity size={17}/><div><strong>Восстановление без ручного подбора</strong><small>YouTube проверяется в фоне при включённом обходе</small></div></div>
  <div className="setting-row"><div><strong>Автоматическое восстановление YouTube</strong><small>При повторном сбое Evasion проверяет другие способы на тестовых соединениях. Подходящий вариант применяется сразу; неудачная замена откатывается.</small></div><StatusBadge tone={phase==="healthy"||phase==="recovered"?"success":phase==="unavailable"||phase==="network_down"?"warning":"neutral"}>Автоматически</StatusBadge></div>
  <div className="network-tuning__result" role="status"><ShieldCheck size={15}/><span>{phases[phase]??"Проверка недоступна"}{health?.fresh&&<small>{profiles[health.profile]??"Способ проверяется"} · {health.checkedAt?new Date(health.checkedAt).toLocaleTimeString([],{hour:"2-digit",minute:"2-digit"}):"проверяется"}{health.switches>0?` · замен: ${health.switches}`:""}</small>}</span></div>
  {health?.fresh&&health.checks.length>0&&<div className="network-tuning__actions">{health.checks.map(check=><StatusBadge key={check.target} tone={check.target==="media_transport"&&!health.mediaObserved?"neutral":check.ok?"success":"warning"}>{`${targets[check.target]??"Проверка"}: ${check.target==="media_transport"&&!health.mediaObserved?"ожидаем видео":check.ok?"доступно":stages[check.stage]??"не проверено"}`}</StatusBadge>)}</div>}
  <p className="local-note">Проверяются сайт, настоящая миниатюра и соединение с видеосетью. Это не замер скорости ролика. При недоступном интернете стратегии не переключаются вслепую.</p>
  <div className="setting-row"><div><strong>Память проверенных маршрутов Telegram</strong><small>Ускоряет следующий запуск. Доступность каналов проверяется заново; при сбое Telegram выбирает другой маршрут автоматически.</small></div><Toggle label="Память маршрутов Telegram" checked={view?.telegram??true} disabled={!view||pending} onChange={value=>void changeTelegram(value)}/></div>
  {error&&<p className="local-note" role="alert">{error}</p>}
 </section>;
}
