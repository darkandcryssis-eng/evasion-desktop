// Тонкая обёртка над Go-API оболочки (Wails-биндинги в wailsjs/go/main/App).
// Экраны зовут эти функции, а не демо-данные. Биндинги генерирует Wails при
// сборке (wails build / wails generate module) — файлы лежат в .gitignore.
import {
  ImportGameRoute, RemoveGameRoute, StopGameFilter, GetGameFilter, SetGameFilter, ApplyGameFilter, SelectGameExecutable,
  GetNetworkTuning, SetNetworkTuningSettings, RunYouTubeTuning, CancelYouTubeTuning,
	ExitApplication,
	SetTrayPreferences,
	GetServiceDiagnostics, RunServiceDiagnostics, GetTelegramRoutes, CheckTelegramRoutes, ExportDiagnosticReport,
  GetDiagnostics,
  GetAutoStart,
  GetUpdate,
  CheckUpdate,
  InstallUpdate,
  GetTelegramState,
  StartTelegramProxy,
  StopTelegramProxy,
  ConnectWithTelegram,
  StopConnection,
  OpenTelegramProxy,
  SetTelegramOptions,
  GetPortfolio,
  GetState,
  GetTargets,
  GetCustomIPs,
  SetCustomIPs,
  MinimiseToTray,
  OpenDataFolder,
  RestartDiscord,
  RunDoctor,
  StartEngine,
  StopEngine,
  SetAutoStart,
} from "../wailsjs/go/main/App";

export type EnginePhase = "stopped" | "starting" | "running" | "stopping" | "failed";

export type LogLine = { at: string; level: string; msg: string; attrs: string };

export type HelloStats = {
  at: string;
  complete: number;
  assembled: number;
  skipped: number;
  retransmits: number;
  reasons: string;
};

export type GroupStrategy = { group: string; strategy: string };

export type StartOptions = {
  voice: string;
  quic: string;
  observe: boolean;
  restartDiscord: boolean;
  boost: boolean;
};

export type EngineState = {
  phase: EnginePhase;
  pid: number;
  startedAt: string;
  options: StartOptions;
  error: string;
  filter: string;
  quicMode: string;
  strategies: GroupStrategy[];
  hello?: HelloStats;
  discord: string;
  logs: LogLine[];
  // Сторож оболочки: сколько раз движок поднят заново после внезапного выхода.
  restarts?: number;
  guard?: string;
};

export type PayloadInfo = { engine: boolean; config: boolean; windivert: boolean };

export type UpdateState = {
  current: string;
  latest: string;
  available: boolean;
  url: string;
  checking: boolean;
  downloading: boolean;
  progress: number;
  error: string;
  checkedAt: string;
};

export type AppState = {
  telegram?: TelegramState;
  engine: EngineState;
  elevated: boolean;
  payload: PayloadInfo;
  baseDir: string;
  configPath: string;
  userConfig: boolean;
  // Российские домены, убранные защитой из пользовательского конфига.
  ruGuard?: string[];
};

export type TelegramDisconnect = {
  at: string;
  route: string;
  routeLabel: string;
  transport: string;
  dc: number;
  media: boolean;
  stage: string;
  cause: string;
  detail?: string;
  durationMs: number;
  bytesUp: number;
  bytesDown: number;
  recovered: boolean;
  replacementRoute?: string;
};

export type TelegramState = {
	 speeds: SpeedSample[];
  community: boolean;
  running: boolean;
  phase: "stopped" | "waiting" | "connecting" | "online" | "degraded";
  enabled: boolean;
  port: number;
  address: string;
  link: string;
  active: number;
  connections: number;
  bytesUp: number;
  bytesDown: number;
  failures: number;
  switches?: number;
  rejected: number;
  route: string;
  dialMs: number;
  lastDataAt: string;
  error: string;
  logs: LogLine[];
  disconnects?: TelegramDisconnect[];
};

export type CustomIPs = { text: string; count: number; path: string };

export type TargetGroup = {
  name: string;
  domains: string[];
  ownStrategy: boolean;
  active: string;
};

export type DiagnosticTone = "success" | "warning" | "neutral" | "accent";
export type DiagnosticItem = { name: string; status: string; tone: DiagnosticTone; detail: string };

export type DoctorCheck = { id: string; status: string; reason: string };

export type SpeedSample = { at: string; up: number; down: number };
export type ServiceStep = { id: string; status: string; ms: number; code: string; detail: string; advice: string };
export type ServiceDiagnostic = { id: string; name: string; status: string; summary: string; advice: string; checkedAt: string; steps: ServiceStep[] };
export type TelegramRoute = { id: string; host: string; kind: string; status: string; code: string; reason: string; latencyMs: number; failures: number; stability?: number; drops?: number; checkedAt: string; retryAt: string };

export type PortfolioHolder = {
  strategy_id: string;
  status: string;
  observations: number;
  targets: number;
};

export type PortfolioView = { found: boolean; updatedAt: string; holdings: PortfolioHolder[] };

export type NetworkTuningView = { health?: { running: boolean; fresh: boolean; phase: string; profile: string; checkedAt: string; switches: number; rollbacks: number; failures: number; mediaObserved: boolean; checks: { target: string; stage: string; ok: boolean; code: number; ms: number; dns?: string }[] }; youtube: boolean; telegram: boolean; busy: boolean; phase: string; profile: string; quic: string; checkedAt: string; error: string };

export type GameFilterSettings = { adaptive: boolean; mode: string; protocol: string; executables: string[]; onDemand: boolean };
export type GameRouteView = { configured: boolean; nodes: number };
export type GameFilterView = { armed?: boolean; route?: GameRouteView; transport?: { stage: string; connecting: number; tlsWaiting: number; responding: number; noTCPReply: number; noTLSReply: number; tlsClosed: number; tcpClosed: number }; processes?: {family: string; launchers: number; clients: number; helpers: number}[]; adaptive: { stage?: string; watching: number; helping: number; responsive: number }; settings: GameFilterSettings; activeMode: string; activeProtocol: string; pending: boolean; engineRunning: boolean; fresh: boolean; targets: string[]; stats: { tunnel?: boolean; tunnelReceived?: number; tunnelSent?: number; connections: number; udp: number; tcp: number; decoys: number; errors: number; limited: number; tlsApplied?: number; tlsFailed?: number; preparedTLSIPs?: number }; error: string };

// Go отдаёт пустые срезы как null — приводим к массивам, чтобы UI не падал.
const arr = <T,>(v: T[] | null | undefined): T[] => (Array.isArray(v) ? v : []);
function normState(s: AppState): AppState {
  if (!s) return s;
  const engine = { ...s.engine, strategies: arr(s.engine?.strategies), logs: arr(s.engine?.logs) };
  const telegram = s.telegram ? { ...s.telegram, logs: arr(s.telegram.logs), speeds: arr(s.telegram.speeds), disconnects: arr(s.telegram.disconnects) } : s.telegram;
  return { ...s, engine, telegram, ruGuard: arr(s.ruGuard) };
}
function normGame(v: GameFilterView): GameFilterView {
  if (!v) return v;
  const settings = v.settings ? { ...v.settings, executables: arr(v.settings.executables) } : v.settings;
  return { ...v, settings, processes: arr(v.processes), targets: arr(v.targets), stats: v.stats ?? ({} as GameFilterView["stats"]), adaptive: v.adaptive ?? ({} as GameFilterView["adaptive"]) };
}
function normTuning(v: NetworkTuningView): NetworkTuningView {
  if (!v || !v.health) return v;
  return { ...v, health: { ...v.health, checks: arr(v.health.checks) } };
}
const normServices = (list: ServiceDiagnostic[]) => arr(list).map((d) => ({ ...d, steps: arr(d.steps) }));

export const api = {
 importGameRoute: (input: string): Promise<GameRouteView> => ImportGameRoute(input),
 removeGameRoute: (): Promise<void> => RemoveGameRoute(),
 stopGameFilter: (): Promise<void> => StopGameFilter(),
 getGameFilter: (): Promise<GameFilterView> => GetGameFilter().then((v) => normGame(v as GameFilterView)),
 setGameFilter: (settings: GameFilterSettings): Promise<void> => SetGameFilter(settings),
 applyGameFilter: (opts: StartOptions): Promise<void> => ApplyGameFilter(opts),
 selectGameExecutable: (): Promise<string> => SelectGameExecutable(),
  getNetworkTuning: (opts: StartOptions): Promise<NetworkTuningView> => GetNetworkTuning(opts).then((v) => normTuning(v as NetworkTuningView)),
  setNetworkTuningSettings: (youtube: boolean, telegram: boolean): Promise<void> => SetNetworkTuningSettings(youtube, telegram),
  runYouTubeTuning: (opts: StartOptions): Promise<void> => RunYouTubeTuning(opts),
  cancelYouTubeTuning: (): Promise<void> => CancelYouTubeTuning(),
	exitApplication: (): Promise<void> => ExitApplication(),
	setTrayPreferences: (theme: string, options: StartOptions, skin: string): Promise<void> => SetTrayPreferences(theme,options,skin),
	getServiceDiagnostics: (): Promise<ServiceDiagnostic[]> => GetServiceDiagnostics().then((v) => normServices(v as ServiceDiagnostic[])),
	runServiceDiagnostics: (): Promise<ServiceDiagnostic[]> => RunServiceDiagnostics().then((v) => normServices(v as ServiceDiagnostic[])),
	getTelegramRoutes: (): Promise<TelegramRoute[]> => GetTelegramRoutes().then((v) => arr(v as TelegramRoute[])),
	checkTelegramRoutes: (): Promise<TelegramRoute[]> => CheckTelegramRoutes().then((v) => arr(v as TelegramRoute[])),
	exportDiagnosticReport: (): Promise<string> => ExportDiagnosticReport(),
  getTelegramState: (): Promise<TelegramState> => (GetTelegramState() as Promise<TelegramState>).then((t) => (t ? { ...t, logs: arr(t.logs), speeds: arr(t.speeds), disconnects: arr(t.disconnects) } : t)),
  startTelegramProxy: (port = 0): Promise<void> => StartTelegramProxy(port),
  stopTelegramProxy: (): Promise<void> => StopTelegramProxy(),
  connectWithTelegram: (options: StartOptions, telegram: boolean): Promise<void> => ConnectWithTelegram(options as never, telegram),
  stopConnection: (): Promise<void> => StopConnection(),
  openTelegramProxy: (): Promise<void> => OpenTelegramProxy(),
  setTelegramOptions: (port: number, community: boolean): Promise<void> => SetTelegramOptions(port, community),
  getAutoStart: (): Promise<boolean> => GetAutoStart(),
  getUpdate: (): Promise<UpdateState> => GetUpdate() as Promise<UpdateState>,
  checkUpdate: (): Promise<UpdateState> => CheckUpdate() as Promise<UpdateState>,
  installUpdate: (): Promise<void> => InstallUpdate(),
  setAutoStart: (enabled: boolean, options: StartOptions): Promise<void> => SetAutoStart(enabled, options as never),
  getState: (): Promise<AppState> => (GetState() as Promise<AppState>).then(normState),
  getTargets: (): Promise<TargetGroup[]> => (GetTargets() as Promise<TargetGroup[]>).then((list) => arr(list).map((g) => ({ ...g, domains: arr(g.domains) }))),
  getCustomIPs: (): Promise<CustomIPs> => GetCustomIPs() as Promise<CustomIPs>,
  setCustomIPs: (text: string): Promise<CustomIPs> => SetCustomIPs(text) as Promise<CustomIPs>,
  getDiagnostics: (): Promise<DiagnosticItem[]> => (GetDiagnostics() as Promise<DiagnosticItem[]>).then(arr),
  getPortfolio: (): Promise<PortfolioView> => (GetPortfolio() as Promise<PortfolioView>).then((p) => ({ ...p, holdings: arr(p?.holdings) })),
  runDoctor: (): Promise<DoctorCheck[]> => (RunDoctor() as Promise<DoctorCheck[]>).then(arr),
  startEngine: (opts: StartOptions): Promise<void> => StartEngine(opts as never),
  stopEngine: (): Promise<void> => StopEngine(),
  restartDiscord: (): Promise<string> => RestartDiscord(),
  minimiseToTray: (): Promise<void> => MinimiseToTray(),
  openDataFolder: (): Promise<string> => OpenDataFolder(),
};

export const phaseLabel: Record<EnginePhase, string> = {
  stopped: "Остановлен",
  starting: "Запускается",
  running: "Работает",
  stopping: "Останавливается",
  failed: "Ошибка",
};

export const phaseTone: Record<EnginePhase, DiagnosticTone> = {
  stopped: "neutral",
  starting: "accent",
  running: "success",
  stopping: "accent",
  failed: "warning",
};
