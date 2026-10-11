// Tauri command layer — thin bridge between the frontend and the engine.
// Command names/args MUST stay in sync with src/lib/tauri.ts:
//   list_tunnels / create_tunnel / update_tunnel / delete_tunnel /
//   start_tunnel / stop_tunnel / get_state / list_states /
//   read_binary_status / install_binary

use std::path::PathBuf;
use std::sync::Arc;

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};

use crate::engine::{Engine, TunnelLogEvent};
use crate::models::{Backend, BinaryStatus, TunnelConfig, TunnelState, TunnelStatus, TunnelType};
use crate::store::Store;

/// tunnels.json 发生任何变更（增/改/删）时发出。托盘监听它刷新菜单，
/// 替代旧的「1s 全量序列化指纹」轮询；前端目前不消费该事件。
pub const TUNNELS_CONFIG_EVENT: &str = "tunnels://config-changed";

pub struct AppState {
    pub app: AppHandle,
    pub store: Arc<Store>,
    pub engine: Arc<Engine>,
}

/// tunnels.json 变更成功后统一发出配置变更事件（托盘据此刷新菜单）。
/// 每个 mutation 调用点的成功路径都必须调用，不得有遗漏。
fn emit_config_changed(state: &State<'_, AppState>) {
    let _ = state.app.emit(TUNNELS_CONFIG_EVENT, ());
}

impl AppState {
    /// Build the application state. Unlike the skeleton stub, `new` takes the
    /// `AppHandle`: both the engine (event emission, binary resolution) and
    /// the store (app data dir) are bound to it, and an `AppHandle` cannot be
    /// fabricated outside the Tauri runtime. Nothing else in the codebase
    /// calls the no-arg form.
    pub fn new(app: AppHandle) -> Self {
        let store = Arc::new(Store::new(data_dir(&app).join("tunnels.json")));
        let engine = Arc::new(Engine::new(app.clone()));
        Self { app, store, engine }
    }
}

/// `<app_data_dir>`, with a best-effort fallback so the app still runs if the
/// path cannot be resolved.
fn data_dir(app: &AppHandle) -> PathBuf {
    app.path().app_data_dir().unwrap_or_else(|e| {
        eprintln!("[pier] app data dir unavailable ({e}); using fallback location");
        dirs::data_dir()
            .map(|d| d.join(crate::brand::DISPLAY_NAME_ZH))
            .unwrap_or_else(std::env::temp_dir)
    })
}


/// One-time migration: copy every keychain secret we can address from the
/// local config files (tunnels + servers) into the SQLite secret store.
/// Reading the keychain may show ONE final authorization prompt; after this
/// the app never touches the keychain again.
fn migrate_keychain_secrets(app: &AppHandle) {
    use crate::servers_store as ss;


    // Direct keyring reads — the ss::/cloudflare:: helpers now read the
    // SQLite store, so the migration must go to the source itself.
    fn legacy_get(account: &str) -> Option<String> {
        let entry = keyring::Entry::new("com.masterfulhands.pier", account).ok()?;
        match entry.get_password() {
            Ok(v) => Some(v),
            Err(keyring::Error::NoEntry) => None,
            Err(_) => None,
        }
    }

    let mut migrated = 0usize;
    // SSH secrets + frps tokens per server
    for srv in ss::load_servers(app) {
        for account in [
            ss::ssh_secret_account(&srv.id),
            ss::frps_token_account(&srv.id),
        ] {
            if let Some(v) = legacy_get(&account) {
                if crate::secrets_store::try_get(&account).ok().flatten().is_none() {
                    let _ = crate::secrets_store::set(&account, &v);
                    migrated += 1;
                }
            }
        }
    }
    // Tunnel auth passwords + Cloudflare tokens per tunnel
    let tunnels_path = data_dir(app).join("tunnels.json");
    if let Ok(text) = std::fs::read_to_string(&tunnels_path) {
        if let Ok(configs) = serde_json::from_str::<Vec<crate::models::TunnelConfig>>(&text) {
            for cfg in configs {
                let entries = [
                    format!("tunnel-auth-{}", cfg.id),
                    format!("cf-{}", cfg.id),
                    format!("cf-tunnel-token-{}", cfg.id),
                    format!("frps-token-cf-{}", cfg.id),
                ];
                for account in entries {
                    if let Some(v) = legacy_get(&account) {
                        if crate::secrets_store::try_get(&account).ok().flatten().is_none() {
                            let _ = crate::secrets_store::set(&account, &v);
                            migrated += 1;
                        }
                    }
                }
            }
        }
    }
    eprintln!("[pier] 钥匙串迁移完成：{migrated} 条秘密已迁入本地秘密库");
}

/// Called from `lib.rs` on `RunEvent::Exit`: stop every running tunnel process
/// so the app never leaks child processes.
pub fn shutdown(app: &AppHandle) {
    if let Some(state) = app.try_state::<AppState>() {
        tauri::async_runtime::block_on(state.engine.stop_all());
    }
}

/// v0.1.1 更名（Pier → 圣手码头）迁移：bundle identifier 变更后
/// `app_data_dir` 从 `com.masterfulhands.pier` 变为新路径，把旧目录中的
/// 隧道/服务器配置与引擎二进制搬过来。幂等：新目录已有配置则跳过。
/// keyring 的服务名是固定字符串（不随 identifier 变），SSH 密码与
/// frps token / 隧道鉴权密码无需迁移。
fn migrate_legacy_data_dir(app: &AppHandle) {
    let new_dir = data_dir(app);
    if new_dir.join("tunnels.json").exists() || new_dir.join("servers.json").exists() {
        return;
    }
    let Some(legacy_dir) = dirs::data_dir().map(|d| d.join(crate::brand::LEGACY_IDENTIFIER))
    else {
        return;
    };
    if !legacy_dir.exists() {
        return;
    }
    let entries = match std::fs::read_dir(&legacy_dir) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("[pier] legacy data dir unreadable: {e}");
            return;
        }
    };
    let _ = std::fs::create_dir_all(&new_dir);
    for entry in entries.flatten() {
        let target = new_dir.join(entry.file_name());
        if target.exists() {
            continue;
        }
        if let Err(e) = std::fs::rename(entry.path(), &target) {
            // Cross-device fallback: copy instead of rename.
            if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                let _ = copy_dir_all(&entry.path(), &target);
            } else if let Err(e2) = std::fs::copy(entry.path(), &target) {
                eprintln!("[pier] migrate {}: {e} / copy: {e2}", entry.path().display());
            }
        }
    }
    let _ = std::fs::remove_dir_all(&legacy_dir);
    eprintln!(
        "[pier] migrated legacy data dir {} → {}",
        legacy_dir.display(),
        new_dir.display()
    );
}

fn copy_dir_all(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let target = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir_all(&entry.path(), &target)?;
        } else {
            std::fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
}

/// Called once from `lib.rs` setup: build + manage `AppState`, then kick off
/// auto-start for tunnels flagged `auto_start` (async, non-blocking).
pub fn init_runtime(app: &AppHandle) -> Result<(), Box<dyn std::error::Error>> {
    migrate_legacy_data_dir(app);
    // v0.2.0: secrets live in local SQLite now — pull any pre-existing
    // keychain entries over once (may prompt once for keychain access),
    // then the app never touches the keychain again.
    crate::secrets_store::init(app);
    migrate_keychain_secrets(app);
    std::fs::create_dir_all(data_dir(app))?;

    let state = AppState::new(app.clone());
    let store = state.store.clone();
    let engine = state.engine.clone();
    if !app.manage(state) {
        eprintln!("[pier] AppState was already managed; keeping the existing instance");
    }

    tauri::async_runtime::spawn(async move {
        for cfg in store.load() {
            if cfg.auto_start {
                if let Err(e) = engine.clone().start(cfg).await {
                    eprintln!("[pier] auto-start failed: {e}");
                }
            }
        }
    });
    Ok(())
}

fn validate_and_fill(cfg: &mut TunnelConfig) -> Result<(), String> {
    if cfg.local_port == 0 {
        return Err("localPort must be between 1 and 65535".into());
    }
    let host = cfg.local_host.trim();
    if host.is_empty() {
        cfg.local_host = "127.0.0.1".into();
    } else {
        cfg.local_host = host.to_string();
    }
    if cfg.name.trim().is_empty() {
        cfg.name = format!("port-{}", cfg.local_port);
    }
    // UDP typed-port tunnels are frp-only (bore is TCP-only, Cloudflare has
    // no plain-UDP ingress) and need a remote port on the server.
    if cfg.tunnel_type == TunnelType::Udp {
        if cfg.backend != Backend::Frp {
            return Err(
                "UDP 端口转发仅支持自建服务器通道 (UDP forwarding requires the frp backend)".into(),
            );
        }
        if cfg.remote_port.is_none() {
            return Err("UDP 隧道缺少远程端口 (remotePort is required for udp tunnels)".into());
        }
    }
    Ok(())
}

#[tauri::command]
pub fn list_tunnels(state: State<'_, AppState>) -> Vec<TunnelConfig> {
    state.store.load()
}

#[tauri::command]
pub fn create_tunnel(
    state: State<'_, AppState>,
    mut config: TunnelConfig,
) -> Result<TunnelConfig, String> {
    validate_and_fill(&mut config)?;
    config.id = uuid::Uuid::new_v4().to_string();
    config.created_at = chrono::Utc::now().to_rfc3339();
    state.store.add(config.clone())?;
    emit_config_changed(&state);
    Ok(config)
}

/// 新旧配置是否仅 `auto_start` 不同（两边序列化后把 autoStart 归一成相同值
/// 再比较）。true 表示运行中的隧道无需因本次更新而停止。序列化失败按
/// 「有变更」处理，回退到原有 stop 行为。
fn equal_ignoring_auto_start(old: &TunnelConfig, new: &TunnelConfig) -> bool {
    let (Ok(mut a), Ok(mut b)) = (serde_json::to_value(old), serde_json::to_value(new)) else {
        return false;
    };
    let normalize = |v: &mut serde_json::Value| {
        if let Some(obj) = v.as_object_mut() {
            obj.insert("autoStart".into(), serde_json::Value::Bool(false));
        }
    };
    normalize(&mut a);
    normalize(&mut b);
    a == b
}

#[tauri::command]
pub async fn update_tunnel(
    state: State<'_, AppState>,
    mut config: TunnelConfig,
) -> Result<TunnelConfig, String> {
    validate_and_fill(&mut config)?;
    // store.update 会覆盖旧配置，先取出来比较。
    let old = state.store.get(&config.id)?;
    let auto_start_only = old
        .as_ref()
        .map(|old| equal_ignoring_auto_start(old, &config))
        .unwrap_or(false);
    if !state.store.update(config.clone())? {
        return Err(format!("tunnel not found: {}", config.id));
    }
    // A running tunnel keeps using the old config until restarted; stop it so
    // the change takes effect on the next explicit start. 仅切换 auto_start
    // 标记时不打断运行中的隧道。
    if let Some(st) = state.engine.snapshot(&config.id) {
        if !auto_start_only && !matches!(st.status, TunnelStatus::Stopped | TunnelStatus::Error) {
            let _ = state.engine.stop(&config.id).await;
        }
    }
    emit_config_changed(&state);
    Ok(config)
}

#[tauri::command]
pub async fn delete_tunnel(state: State<'_, AppState>, id: String) -> Result<(), String> {
    if let Some(st) = state.engine.snapshot(&id) {
        if !matches!(st.status, TunnelStatus::Stopped | TunnelStatus::Error) {
            let _ = state.engine.stop(&id).await;
        }
    }
    if !state.store.remove(&id)? {
        return Err(format!("tunnel not found: {id}"));
    }
    state.engine.remove_handle(&id);
    emit_config_changed(&state);
    Ok(())
}

#[tauri::command]
pub async fn start_tunnel(
    state: State<'_, AppState>,
    id: String,
) -> Result<TunnelState, String> {
    let cfg = state
        .store
        .get(&id)?
        .ok_or_else(|| format!("tunnel not found: {id}"))?;
    state.engine.clone().start(cfg).await
}

#[tauri::command]
pub async fn stop_tunnel(state: State<'_, AppState>, id: String) -> Result<TunnelState, String> {
    match state.engine.stop(&id).await {
        Ok(st) => Ok(st),
        Err(_) => {
            // Never started in this session: report the default state instead
            // of an error, as long as the tunnel exists.
            if state.store.get(&id)?.is_some() {
                Ok(TunnelState::new(&id))
            } else {
                Err(format!("tunnel not found: {id}"))
            }
        }
    }
}

#[tauri::command]
pub fn get_state(state: State<'_, AppState>, id: String) -> Result<TunnelState, String> {
    if let Some(st) = state.engine.snapshot(&id) {
        return Ok(st);
    }
    if state.store.get(&id)?.is_some() {
        return Ok(TunnelState::new(&id));
    }
    Err(format!("tunnel not found: {id}"))
}

#[tauri::command]
pub fn list_states(state: State<'_, AppState>) -> Vec<TunnelState> {
    state
        .store
        .load()
        .into_iter()
        .map(|t| state.engine.snapshot(&t.id).unwrap_or_else(|| TunnelState::new(&t.id)))
        .collect()
}

#[tauri::command]
pub async fn read_binary_status(
    _app: AppHandle,
    state: State<'_, AppState>,
) -> Result<BinaryStatus, String> {
    // read_status 会逐个 spawn 引擎二进制跑 `--version` 探测，放阻塞线程。
    let app = state.app.clone();
    tauri::async_runtime::spawn_blocking(move || crate::binman::read_status(&app))
        .await
        .map_err(|e| format!("read_binary_status task failed: {e}"))?
}

#[tauri::command]
pub async fn install_binary(
    _app: AppHandle,
    backend: Backend,
    state: State<'_, AppState>,
) -> Result<BinaryStatus, String> {
    // The download flow belongs to the system-integration milestone and the
    // stub currently errors. Report the outcome in logs, but always answer
    // with the fresh binary status so the UI can render it.
    // 下载 ~40MB 引擎包：阻塞体放专用线程池，避免冻住 UI（原实现同步
    // recv，主线程被拖住几十秒）。
    let app = state.app.clone();
    let result = tauri::async_runtime::spawn_blocking(move || {
        if let Err(e) = crate::binman::install(&app, backend) {
            eprintln!("[pier] install {backend:?} engine failed: {e}");
        }
        crate::binman::read_status(&app)
    })
    .await
    .map_err(|e| format!("install_binary task failed: {e}"))?;
    result
}

// ---------------------------------------------------------------------------
// M2: servers (self-hosted frps), frpc import, diagnosis
// ---------------------------------------------------------------------------

use crate::models::{DeployResult, Diagnosis, ServerConfig, ServerInput, ServerStatus};

#[tauri::command]
pub fn list_servers(app: AppHandle) -> Vec<ServerConfig> {
    crate::servers_store::load_servers(&app)
}

#[tauri::command]
pub fn add_server(app: AppHandle, input: ServerInput) -> Result<ServerConfig, String> {
    if input.host.trim().is_empty() || input.username.trim().is_empty() {
        return Err("host and username are required".into());
    }
    let server = ServerConfig {
        id: uuid::Uuid::new_v4().to_string(),
        name: if input.name.trim().is_empty() {
            input.host.clone()
        } else {
            input.name.trim().to_string()
        },
        host: input.host.trim().to_string(),
        port: input.port,
        username: input.username.trim().to_string(),
        auth_kind: input.auth_kind,
        frps_bind_port: input.frps_bind_port.unwrap_or(7000),
        frps_vhost_http_port: input.frps_vhost_http_port.unwrap_or(8080),
        frps_vhost_https_port: input.frps_vhost_https_port.unwrap_or(8443),
        frps_dashboard_port: input.frps_dashboard_port.unwrap_or(7500),
        subdomain_host: input.subdomain_host.map(|s| s.trim().to_string()),
        frps_proxy_port_start: input.frps_proxy_port_start,
        frps_proxy_port_end: input.frps_proxy_port_end,
        deployed: false,
        frps_version: None,
        created_at: chrono::Utc::now().to_rfc3339(),
    };
    // A proxy port range must be well-formed: start <= end inside 1..=65535.
    if let (Some(start), Some(end)) = (server.frps_proxy_port_start, server.frps_proxy_port_end) {
        if start == 0 || start > end {
            return Err(
                "转发端口段无效 (proxy port range is invalid: need 1 <= start <= end <= 65535)"
                    .into(),
            );
        }
    }
    crate::servers_store::set_ssh_secret(&server.id, &input.secret)?;
    crate::servers_store::save_server(&app, &server)?;
    Ok(server)
}

#[tauri::command]
pub fn remove_server(app: AppHandle, id: String) -> Result<(), String> {
    crate::servers_store::remove_server(&app, &id).map(|_| ())
}

#[tauri::command]
pub async fn test_server(app: AppHandle, id: String) -> Result<ServerStatus, String> {
    let server = crate::servers_store::load_servers(&app)
        .into_iter()
        .find(|s| s.id == id)
        .ok_or_else(|| "server not found".to_string())?;
    // Connection probe lives in the SSH layer; deploy module owns it.
    let reachable = crate::frp_deploy::status(&app, server).await.is_ok();
    Ok(ServerStatus {
        server_id: id,
        reachable,
        frps_running: false,
        frps_version: None,
        detail: None,
    })
}

/// Kick off deployment in the background; progress arrives via the
/// "deploy://progress" events and completion via "deploy://done".
#[tauri::command]
pub async fn deploy_server(app: AppHandle, id: String) -> Result<DeployResult, String> {
    let server = crate::servers_store::load_servers(&app)
        .into_iter()
        .find(|s| s.id == id)
        .ok_or_else(|| "server not found".to_string())?;
    let handle = tauri::async_runtime::spawn(crate::frp_deploy::deploy(app.clone(), server));
    handle
        .await
        .map_err(|e| format!("deploy task failed: {e}"))
}

#[tauri::command]
pub async fn undeploy_server(app: AppHandle, id: String) -> Result<(), String> {
    let server = crate::servers_store::load_servers(&app)
        .into_iter()
        .find(|s| s.id == id)
        .ok_or_else(|| "server not found".to_string())?;
    crate::frp_deploy::undeploy(&app, server).await
}

#[tauri::command]
pub async fn get_server_status(app: AppHandle, id: String) -> Result<ServerStatus, String> {
    let server = crate::servers_store::load_servers(&app)
        .into_iter()
        .find(|s| s.id == id)
        .ok_or_else(|| "server not found".to_string())?;
    let frps_running = crate::frp_deploy::status(&app, server.clone()).await.unwrap_or(false);
    Ok(ServerStatus {
        server_id: id,
        reachable: true,
        frps_running,
        frps_version: server.frps_version,
        detail: None,
    })
}

#[tauri::command]
pub fn import_frpc_config(text: String, server_id: Option<String>) -> Result<Vec<TunnelConfig>, String> {
    crate::frp_import::parse_frpc_config(&text, server_id.as_deref())
}

#[tauri::command]
pub fn diagnose_tunnel(state: State<'_, AppState>, id: String) -> Result<Diagnosis, String> {
    let snap = state.engine.snapshot(&id).ok_or("tunnel not found")?;
    let logs = state.engine.recent_logs(&id, 200);
    Ok(crate::diagnostics::diagnose(&id, snap.error.as_deref(), &logs))
}

/// 打开日志面板时拉取历史：从引擎环形缓冲回放结构化日志（最老在前），
/// 载荷与实时事件 `tunnel://log` 同构（tunnelId/level/line/ts）。
/// `limit` 为 None 时返回整个缓冲（上限 ring cap 200 条）。同步轻量
/// （Mutex 锁一下即返回），无需 spawn_blocking。
#[tauri::command]
pub async fn get_tunnel_logs(
    state: State<'_, AppState>,
    id: String,
    limit: Option<u32>,
) -> Result<Vec<TunnelLogEvent>, String> {
    Ok(state.engine.tunnel_logs(&id, limit))
}

// ---------------------------------------------------------------------------
// 日志清理 + 存储占用统计
// ---------------------------------------------------------------------------

/// 存储占用统计（serde camelCase：logLines/logsBytes/cacheBytes/dataBytes/
/// totalBytes）。`total_bytes = logs_bytes + cache_bytes + data_bytes`，
/// 与前端 src/lib/tauri.ts 的 StorageUsage 接口逐字段对应。
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageUsage {
    /// 全部隧道缓冲的总行数。
    pub log_lines: u64,
    /// 日志缓冲内存估算（行字节累加 + 每行固定开销估值）。
    pub logs_bytes: u64,
    /// 缓存目录递归大小（app_cache_dir 的 frpc 生成配置 + binman 管理的
    /// `<app_data_dir>/bin` 引擎二进制——统计别漏后者）。
    pub cache_bytes: u64,
    /// app_data_dir 内 tunnels.json / servers.json / secrets.db（连带
    /// -wal/-shm，存在才计）的大小之和。
    pub data_bytes: u64,
    /// = logs_bytes + cache_bytes + data_bytes。
    pub total_bytes: u64,
}

/// `<app_cache_dir>`（frpc 生成配置所在）。解析失败退回用户缓存目录下的
/// 同名子目录，与 `data_dir` 的兜底策略一致——统计与清理必须指向同一个
/// 确定位置。
fn cache_dir(app: &AppHandle) -> PathBuf {
    app.path().app_cache_dir().unwrap_or_else(|e| {
        eprintln!("[pier] app cache dir unavailable ({e}); using fallback location");
        dirs::cache_dir()
            .map(|d| d.join(crate::brand::DISPLAY_NAME_ZH))
            .unwrap_or_else(std::env::temp_dir)
    })
}

/// 递归求目录大小（best-effort）：无权限/已消失的项跳过计 0，符号链接不
/// 追随（DirEntry 的 file_type/metadata 均为 lstat 语义，不会成环）。
fn dir_size(path: &std::path::Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(path) else {
        return 0;
    };
    let mut total = 0u64;
    for entry in entries.flatten() {
        let Ok(ft) = entry.file_type() else { continue };
        if ft.is_dir() {
            total += dir_size(&entry.path());
        } else {
            total += entry.metadata().map(|m| m.len()).unwrap_or(0);
        }
    }
    total
}

/// 清空 `dir` 内的全部条目（保留目录本身）。逐项 best-effort：单项失败
/// 只打日志不中断（缓存清理不该被一个顽固文件卡死），返回成功释放的字节。
fn clear_dir_contents(dir: &std::path::Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    let mut freed = 0u64;
    for entry in entries.flatten() {
        let path = entry.path();
        let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
        let size = if is_dir {
            dir_size(&path)
        } else {
            entry.metadata().map(|m| m.len()).unwrap_or(0)
        };
        let removed = if is_dir {
            std::fs::remove_dir_all(&path)
        } else {
            std::fs::remove_file(&path)
        };
        match removed {
            Ok(()) => freed += size,
            Err(e) => eprintln!("[pier] clear cache: {}: {e}", path.display()),
        }
    }
    freed
}

/// cache_bytes：app_cache_dir 全量 + 引擎二进制目录。注意引擎二进制实际
/// 由 binman 管理在 `<app_data_dir>/bin`（见 binman.rs），不在 cache 目录，
/// 统计时必须一并计入。
fn cache_bytes(app: &AppHandle) -> u64 {
    let mut total = dir_size(&cache_dir(app));
    if let Ok(bin) = crate::binman::bin_dir(app) {
        total += dir_size(&bin);
    }
    total
}

/// data_bytes：只统计三个已知文件（tunnels.json / servers.json /
/// secrets.db）；secrets.db 的 -wal / -shm 伴生文件存在才算上。
fn data_bytes(app: &AppHandle) -> u64 {
    let dir = data_dir(app);
    [
        "tunnels.json",
        "servers.json",
        "secrets.db",
        "secrets.db-wal",
        "secrets.db-shm",
    ]
    .iter()
    .filter_map(|name| std::fs::metadata(dir.join(name)).ok())
    .filter(|m| m.is_file())
    .map(|m| m.len())
    .sum()
}

/// 存储占用统计（同步轻量）：内存日志缓冲 + 缓存目录 + 数据文件。缓存侧
/// 只是元数据遍历（几十个目录项），主线程可承受，无需 spawn_blocking。
#[tauri::command]
pub fn get_storage_usage(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<StorageUsage, String> {
    let (log_lines, logs_bytes) = state.engine.storage_usage();
    let cache_bytes = cache_bytes(&app);
    let data_bytes = data_bytes(&app);
    Ok(StorageUsage {
        log_lines,
        logs_bytes,
        total_bytes: logs_bytes + cache_bytes + data_bytes,
        cache_bytes,
        data_bytes,
    })
}

/// 清空缓存内容，返回释放的字节数。范围与 `cache_bytes` 一致：
/// app_cache_dir 全部内容（frpc 生成配置等）+ 引擎二进制目录
/// `<app_data_dir>/bin`。两者均可自动恢复：frpc 配置在每次启动尝试前
/// 重新生成（providers.rs）；引擎二进制缺失时所有启动路径（UI/托盘/自启）
/// 都有 binman 自动下载自愈（engine.rs run_attempt 的 self-heal 分支），
/// 清掉后无需用户手动重装。
///
/// 存在任何非 Stopped/Error 状态的隧道时返回 Err：运行中的 frpc 正读着
/// 生成配置、引擎二进制可能正被执行，此时删除会打断隧道。
#[tauri::command]
pub async fn clear_cache(state: State<'_, AppState>) -> Result<u64, String> {
    let any_active = state
        .store
        .load()
        .iter()
        .filter_map(|t| state.engine.snapshot(&t.id))
        .any(|st| !matches!(st.status, TunnelStatus::Stopped | TunnelStatus::Error));
    if any_active {
        return Err("有隧道正在运行，请先停止全部隧道后再清理缓存".to_string());
    }
    let app = state.app.clone();
    // 删引擎二进制是真实磁盘 I/O（几十 MB 级），放阻塞线程池。
    tauri::async_runtime::spawn_blocking(move || {
        let mut freed = clear_dir_contents(&cache_dir(&app));
        if let Ok(bin) = crate::binman::bin_dir(&app) {
            freed += clear_dir_contents(&bin);
        }
        Ok(freed)
    })
    .await
    .map_err(|e| format!("clear_cache task failed: {e}"))?
}

/// 清空指定隧道的内存日志缓冲，返回清掉的行数。隧道必须真实存在
/// （tunnels.json 里有）；存在但本会话从未启动过则没有缓冲，返回 0 行
/// 而不是报错——前端「清理」按钮对这种状态同样应当成功。
#[tauri::command]
pub fn clear_tunnel_logs(state: State<'_, AppState>, id: String) -> Result<u64, String> {
    if state.store.get(&id)?.is_none() {
        return Err(format!("隧道不存在：{id}"));
    }
    if state.engine.snapshot(&id).is_none() {
        return Ok(0);
    }
    state.engine.clear_logs(&id)
}

/// 清空全部隧道的内存日志缓冲，返回清掉的总行数。
#[tauri::command]
pub fn clear_all_tunnel_logs(state: State<'_, AppState>) -> Result<u64, String> {
    Ok(state.engine.clear_all_logs())
}

/// Set (Some) or clear (None) a tunnel's basic-auth password. The password
/// never enters tunnels.json — only the OS keychain. （密码只进本地秘密库，
/// 不改 tunnels.json，因此这里不发配置变更事件。）
#[tauri::command]
pub async fn set_tunnel_auth(
    _app: AppHandle,
    id: String,
    password: Option<String>,
) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || match password {
        Some(p) if !p.is_empty() => crate::servers_store::set_tunnel_auth_password(&id, &p),
        _ => crate::servers_store::delete_tunnel_auth_password(&id),
    })
    .await
    .map_err(|e| format!("set_tunnel_auth task failed: {e}"))?
}

// ---------------------------------------------------------------------------
// Cloudflare Named Tunnel (v0.2.0) — fixed hostnames
// ---------------------------------------------------------------------------

use crate::models::{CfAccount, CfProvisionInput, CfZone};

/// HTTP / 秘密库操作都是阻塞调用，统一放 spawn_blocking，避免冻住 UI。
#[tauri::command]
pub async fn cf_verify_token(token: String) -> Result<Vec<CfAccount>, String> {
    tauri::async_runtime::spawn_blocking(move || crate::cloudflare::verify_token(&token))
        .await
        .map_err(|e| format!("cf_verify_token task failed: {e}"))?
}

#[tauri::command]
pub async fn cf_list_zones(token: String) -> Result<Vec<CfZone>, String> {
    tauri::async_runtime::spawn_blocking(move || crate::cloudflare::list_zones(&token))
        .await
        .map_err(|e| format!("cf_list_zones task failed: {e}"))?
}

/// Provision a fixed-hostname tunnel end-to-end and store it. The API token
/// and the tunnel-run token both go to the OS keychain, never into
/// tunnels.json.
#[tauri::command]
pub async fn cf_provision(
    state: State<'_, AppState>,
    input: CfProvisionInput,
) -> Result<TunnelConfig, String> {
    if input.subdomain.trim().is_empty() {
        return Err("subdomain is required".into());
    }
    // 建 Cloudflare API 侧的隧道对象 + 写 ingress + CNAME，全程是阻塞 HTTP。
    let cfg = tauri::async_runtime::spawn_blocking(move || -> Result<TunnelConfig, String> {
        let cfg = crate::cloudflare::provision(&input)?;
        let run_token = crate::cloudflare::get_tunnel_run_token(&cfg.id)?;
        crate::cloudflare::set_api_token(&cfg.id, &input.token)?;
        crate::cloudflare::set_tunnel_run_token(&cfg.id, &run_token)?;
        Ok(cfg)
    })
    .await
    .map_err(|e| format!("cf_provision task failed: {e}"))??;
    state.store.add(cfg.clone())?;
    emit_config_changed(&state);
    Ok(cfg)
}

/// Change a named tunnel's fixed hostname. Uses the stored API token; the
/// remote ingress + CNAME are re-pointed and the local config updated.
#[tauri::command]
pub async fn cf_update_hostname(
    state: State<'_, AppState>,
    id: String,
    zone_id: String,
    subdomain: String,
) -> Result<TunnelConfig, String> {
    let subdomain = subdomain.trim().to_lowercase();
    if subdomain.is_empty() {
        return Err("subdomain is required".into());
    }
    let mut cfg = state
        .store
        .load()
        .into_iter()
        .find(|c| c.id == id)
        .ok_or("tunnel not found")?;
    let old_hostname = cfg
        .cf_hostname
        .clone()
        .ok_or("tunnel is not a Cloudflare fixed-hostname tunnel")?;
    let account_id = cfg
        .cf_account_id
        .clone()
        .ok_or("tunnel is not a Cloudflare fixed-hostname tunnel")?;
    let cf_tunnel_id = cfg
        .cf_tunnel_id
        .clone()
        .ok_or("tunnel is not a Cloudflare fixed-hostname tunnel")?;
    // 远端 ingress 改写 + CNAME 换绑 + 账户重解析：全程阻塞 HTTP。
    let subdomain_for_api = subdomain.clone();
    let (new_hostname, resolved_account_id) =
        tauri::async_runtime::spawn_blocking(move || -> Result<(String, String), String> {
            let token = crate::cloudflare::stored_api_token(&id)?;
            let new_hostname = crate::cloudflare::update_hostname(
                &token,
                &account_id,
                &cf_tunnel_id,
                &zone_id,
                &old_hostname,
                &subdomain_for_api,
            )?;
            // zone may live under a different account than before — re-resolve
            let account = crate::cloudflare::zone_account(&token, &zone_id);
            Ok((new_hostname, account))
        })
        .await
        .map_err(|e| format!("cf_update_hostname task failed: {e}"))??;

    cfg.cf_hostname = Some(new_hostname.clone());
    cfg.name = subdomain;
    cfg.cf_account_id = Some(resolved_account_id);
    state.store.update(cfg.clone())?;
    emit_config_changed(&state);
    Ok(cfg)
}

/// Stored API token for a tunnel (frontend eye-reveal).
#[tauri::command]
pub async fn cf_get_api_token(id: String) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || crate::cloudflare::stored_api_token(&id))
        .await
        .map_err(|e| format!("cf_get_api_token task failed: {e}"))?
}

/// Zones visible to a STORED tunnel's API token (edit-mode dropdown).
#[tauri::command]
pub async fn cf_list_zones_stored(id: String) -> Result<Vec<crate::models::CfZone>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let token = crate::cloudflare::stored_api_token(&id)?;
        crate::cloudflare::list_zones(&token)
    })
    .await
    .map_err(|e| format!("cf_list_zones_stored task failed: {e}"))?
}

/// Tear down the remote tunnel (and optionally its DNS record) and remove
/// the local tunnel config.
#[tauri::command]
pub async fn cf_deprovision(
    state: State<'_, AppState>,
    id: String,
    delete_dns: bool,
) -> Result<(), String> {
    let cfg = state
        .store
        .load()
        .into_iter()
        .find(|c| c.id == id)
        .ok_or("tunnel not found")?;
    if cfg.backend != crate::models::Backend::CloudflareNamed {
        return Err("only Cloudflare fixed-hostname tunnels have cloud resources".into());
    }
    let hostname = cfg
        .cf_hostname
        .clone()
        .ok_or("tunnel is not a Cloudflare fixed-hostname tunnel")?;
    let cf_tunnel_id = cfg
        .cf_tunnel_id
        .clone()
        .ok_or("tunnel is not a Cloudflare fixed-hostname tunnel")?;
    let remote_id = id.clone();
    tauri::async_runtime::spawn_blocking(move || -> Result<(), String> {
        let token = crate::cloudflare::stored_api_token(&remote_id)?;
        let zone_id = crate::cloudflare::resolve_zone_id(&token, &hostname)?;
        crate::cloudflare::deprovision(&token, &zone_id, &cf_tunnel_id, delete_dns)?;
        crate::cloudflare::delete_stored_tokens(&remote_id);
        Ok(())
    })
    .await
    .map_err(|e| format!("cf_deprovision task failed: {e}"))??;
    state.store.remove(&id)?;
    emit_config_changed(&state);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(id: &str) -> TunnelConfig {
        TunnelConfig {
            id: id.to_string(),
            name: format!("test-{id}"),
            tunnel_type: TunnelType::Http,
            backend: Backend::Cloudflare,
            local_host: "127.0.0.1".to_string(),
            local_port: 8080,
            auto_start: false,
            created_at: "2026-10-10T00:00:00+00:00".to_string(),
            server_id: None,
            subdomain: None,
            remote_port: None,
            auth: None,
            ip_allowlist: Vec::new(),
            cf_tunnel_id: None,
            cf_hostname: None,
            cf_account_id: None,
        }
    }

    #[test]
    fn only_auto_start_change_skips_stop() {
        let mut new = sample("t1");
        new.auto_start = true;
        assert!(equal_ignoring_auto_start(&sample("t1"), &new));
    }

    #[test]
    fn other_field_change_requires_stop() {
        let mut new = sample("t1");
        new.local_port = 9090;
        assert!(!equal_ignoring_auto_start(&sample("t1"), &new));
        let mut renamed = sample("t1");
        renamed.name = "renamed".into();
        assert!(!equal_ignoring_auto_start(&sample("t1"), &renamed));
    }

    #[test]
    fn identical_configs_are_auto_start_only() {
        // 完全相同也走「不打断」分支：对运行中的隧道无副作用。
        assert!(equal_ignoring_auto_start(&sample("t1"), &sample("t1")));
    }

    /// dir_size 是 get_storage_usage / clear_cache 的缓存侧度量原语：
    /// 递归求和、普通文件按 len 计、缺目录计 0。
    #[test]
    fn dir_size_sums_files_recursively() {
        let dir = std::env::temp_dir().join(format!("pier-dirsizetest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub/deep")).unwrap();
        std::fs::write(dir.join("a.bin"), [0u8; 100]).unwrap();
        std::fs::write(dir.join("sub/b.toml"), [0u8; 30]).unwrap();
        std::fs::write(dir.join("sub/deep/c.txt"), [0u8; 5]).unwrap();

        assert_eq!(dir_size(&dir), 135, "三层数值应全部计入");
        assert_eq!(dir_size(&dir.join("missing")), 0, "不存在的目录计 0");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// clear_dir_contents 是 clear_cache 的删除原语：清空全部内容、保留
    /// 目录本身、返回释放字节；空目录/缺目录安全返回 0。
    #[test]
    fn clear_dir_contents_removes_everything_but_the_dir() {
        let dir = std::env::temp_dir().join(format!("pier-cleartest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("a.bin"), [0u8; 64]).unwrap();
        std::fs::write(dir.join("sub/b.toml"), [0u8; 32]).unwrap();

        assert_eq!(clear_dir_contents(&dir), 96, "应报告释放的字节");
        assert!(dir.is_dir(), "目录本身必须保留");
        assert!(
            std::fs::read_dir(&dir).unwrap().next().is_none(),
            "内容必须清空"
        );
        assert_eq!(clear_dir_contents(&dir), 0, "空目录返回 0");
        assert_eq!(
            clear_dir_contents(&dir.join("missing")),
            0,
            "缺目录安全返回 0"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
