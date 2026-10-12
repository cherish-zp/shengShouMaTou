// Typed wrappers around Tauri invoke/listen. The command names and payload
// shapes MUST match src-tauri/src/commands.rs.

import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  Backend,
  BinaryStatus,
  CfAccount,
  CfProvisionInput,
  CfZone,
  DeployProgressEvent,
  DeployResult,
  Diagnosis,
  ServerConfig,
  ServerInput,
  ServerStatus,
  TunnelConfig,
  TunnelLogEvent,
  TunnelState,
  TunnelStateEvent,
  TunnelStats,
} from "@/types/tunnel";
import type { StorageUsage } from "@/types/storage";

export type { StorageUsage };

export const TUNNEL_STATE_EVENT = "tunnel://state";
export const TUNNEL_LOG_EVENT = "tunnel://log";
export const TUNNEL_STATS_EVENT = "tunnel://stats";
export const DEPLOY_PROGRESS_EVENT = "deploy://progress";
export const DEPLOY_DONE_EVENT = "deploy://done";

export const api = {
  listTunnels: () => invoke<TunnelConfig[]>("list_tunnels"),
  createTunnel: (config: TunnelConfig) =>
    invoke<TunnelConfig>("create_tunnel", { config }),
  updateTunnel: (config: TunnelConfig) =>
    invoke<TunnelConfig>("update_tunnel", { config }),
  deleteTunnel: (id: string) => invoke<void>("delete_tunnel", { id }),
  startTunnel: (id: string) => invoke<TunnelState>("start_tunnel", { id }),
  stopTunnel: (id: string) => invoke<TunnelState>("stop_tunnel", { id }),
  getState: (id: string) => invoke<TunnelState>("get_state", { id }),
  listStates: () => invoke<TunnelState[]>("list_states"),
  readBinaryStatus: () => invoke<BinaryStatus>("read_binary_status"),
  installBinary: (backend: Backend) =>
    invoke<BinaryStatus>("install_binary", { backend }),
  // 手动导入本地已有的引擎二进制（失败 reject 中文错误）。
  importEngineBinary: (backend: Backend, path: string) =>
    invoke<BinaryStatus>("import_engine_binary", { backend, path }),

  // M2: servers / import / diagnosis
  listServers: () => invoke<ServerConfig[]>("list_servers"),
  addServer: (input: ServerInput) => invoke<ServerConfig>("add_server", { input }),
  removeServer: (id: string) => invoke<void>("remove_server", { id }),
  testServer: (id: string) => invoke<ServerStatus>("test_server", { id }),
  deployServer: (id: string) => invoke<DeployResult>("deploy_server", { id }),
  undeployServer: (id: string) => invoke<void>("undeploy_server", { id }),
  getServerStatus: (id: string) => invoke<ServerStatus>("get_server_status", { id }),
  importFrpcConfig: (text: string, serverId?: string) =>
    invoke<TunnelConfig[]>("import_frpc_config", { text, serverId }),
  diagnoseTunnel: (id: string) => invoke<Diagnosis>("diagnose_tunnel", { id }),
  setTunnelAuth: (id: string, password: string | null) =>
    invoke<void>("set_tunnel_auth", { id, password }),

  // v0.2.0: Cloudflare Named Tunnel (fixed hostnames)
  cfVerifyToken: (token: string) => invoke<CfAccount[]>("cf_verify_token", { token }),
  cfListZones: (token: string) => invoke<CfZone[]>("cf_list_zones", { token }),
  cfProvision: (input: CfProvisionInput) => invoke<TunnelConfig>("cf_provision", { input }),
  cfDeprovision: (id: string, deleteDns: boolean) =>
    invoke<void>("cf_deprovision", { id, deleteDns }),
  cfUpdateHostname: (args: { id: string; zoneId: string; subdomain: string }) =>
    invoke<TunnelConfig>("cf_update_hostname", args),
  cfGetApiToken: (id: string) => invoke<string>("cf_get_api_token", { id }),
  cfListZonesStored: (id: string) => invoke<CfZone[]>("cf_list_zones_stored", { id }),

  // Historical log replay for the log panel (oldest first).
  getTunnelLogs: (tunnelId: string, limit?: number) =>
    invoke<TunnelLogEvent[]>("get_tunnel_logs", { id: tunnelId, limit }),

  // 日志清理 + 存储占用统计（clear 返回清掉的行数/释放的字节数）。
  clearTunnelLogs: (id: string) => invoke<number>("clear_tunnel_logs", { id }),
  clearAllTunnelLogs: () => invoke<number>("clear_all_tunnel_logs"),
  getStorageUsage: () => invoke<StorageUsage>("get_storage_usage"),
  clearCache: () => invoke<number>("clear_cache"),
};

export function onTunnelState(
  handler: (state: TunnelState) => void,
): Promise<UnlistenFn> {
  return listen<TunnelStateEvent>(TUNNEL_STATE_EVENT, (event) =>
    handler(event.payload.state),
  );
}

export function onTunnelLog(
  handler: (log: TunnelLogEvent) => void,
): Promise<UnlistenFn> {
  return listen<TunnelLogEvent>(TUNNEL_LOG_EVENT, (event) =>
    handler(event.payload),
  );
}

export function onDeployProgress(
  handler: (progress: DeployProgressEvent) => void,
): Promise<UnlistenFn> {
  return listen<DeployProgressEvent>(DEPLOY_PROGRESS_EVENT, (event) =>
    handler(event.payload),
  );
}

export function onDeployDone(
  handler: (result: DeployResult) => void,
): Promise<UnlistenFn> {
  return listen<DeployResult>(DEPLOY_DONE_EVENT, (event) =>
    handler(event.payload),
  );
}

export function onTunnelStats(
  handler: (stats: TunnelStats) => void,
): Promise<UnlistenFn> {
  return listen<TunnelStats>(TUNNEL_STATS_EVENT, (event) =>
    handler(event.payload),
  );
}
