// Tunnel engine — per-tunnel process supervision and the status state machine.
//
// Lifecycle of one tunnel (M1):
//
//   start -> Starting -> (public endpoint parsed from process output) -> Running
//         -> process exits unexpectedly -> Reconnecting
//            -> exponential backoff (1s, 2s, 4s ... capped at 30s, unlimited)
//            -> full start attempt again; backoff resets after an attempt that
//               had reached Running
//   user stop at ANY point -> Stopped (retry/backoff loop exits immediately)
//
// Design notes:
// * "One run attempt" (`run_attempt`) is a reentrant function so retries go
//   through the exact same path as the first start.
// * The child is killed through a `oneshot` kill switch owned by the attempt
//   task: kill first, then `wait()` to reap (no zombies).
// * Orphan protection: every child is spawned with `kill_on_drop(true)`, so a
//   dropped child (e.g. tokio runtime teardown at app exit) is killed instead
//   of leaking. `Engine::stop_all()` is provided for the integrator to wire
//   into a `RunEvent::Exit` hook later (lib.rs is outside this milestone).
// * Local forwarder (M3): the engine binary NEVER dials the user's service
//   directly. Before every attempt the engine makes sure the tunnel's local
//   forwarder is listening (127.0.0.1, random port) and rewrites the command /
//   frpc config to dial `127.0.0.1:{forwarder_port}` instead — that is where
//   traffic stats, basic auth and the IP allowlist are enforced. The same
//   forwarder is reused across attempts and restarts while its target matches;
//   its byte counters surface in `TunnelState.bytes_in/bytes_out` (snapshot
//   overlay) and in the throttled `tunnel://stats` event emitted by the
//   forwarder itself.

use std::collections::{HashMap, VecDeque};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use serde::Serialize;
use tauri::{AppHandle, Emitter};
use tokio::io::AsyncBufReadExt;
use tokio::sync::{oneshot, Notify};

use crate::binman;
use crate::cloudflare;
use crate::forwarder::{Forwarder, LogSink, TunnelForwarder};
use crate::models::{Backend, TunnelConfig, TunnelState, TunnelStatus, TunnelType};
use crate::providers;
use crate::servers_store;

/// Emitted on every status transition. Payload: `{ "state": TunnelState }`.
pub const TUNNEL_STATE_EVENT: &str = "tunnel://state";
/// Emitted per tunnel-process output line. Payload: `{ tunnelId, level, line, ts }`.
pub const TUNNEL_LOG_EVENT: &str = "tunnel://log";

const BASE_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(30);
/// How long `stop()` waits for the supervisor to confirm Stopped.
const STOP_WAIT_TIMEOUT: Duration = Duration::from_secs(3);
const STOP_POLL_INTERVAL: Duration = Duration::from_millis(50);
const ERROR_LINE_MAX_LEN: usize = 300;
/// Ring-buffer cap for per-tunnel log lines kept for the diagnostics engine.
const LOG_RING_CAP: usize = 200;
/// 每条日志事件的固定内存开销估值（字节）：TunnelLogEvent 的字段头
/// （tunnel_id/line/ts 三个 String 头 + level 胖指针）+ 堆上的 tunnel_id
/// （uuid 36 字节）与 ts（RFC3339 约 30 字节）+ VecDeque 槽位。精确值
/// 无法从外部测得，`logs_bytes` 只给量级正确的估算。
const LOG_LINE_FIXED_OVERHEAD: usize = 160;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct TunnelStateEvent {
    state: TunnelState,
}

/// 一条隧道日志（实时事件 `tunnel://log` 与历史回放 `get_tunnel_logs` 的
/// 统一载荷，serde camelCase：tunnelId/level/line/ts）。
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TunnelLogEvent {
    pub tunnel_id: String,
    pub level: &'static str,
    pub line: String,
    pub ts: String,
}

pub struct Engine {
    app: AppHandle,
    handles: Mutex<HashMap<String, Arc<TunnelHandle>>>,
}

struct TunnelHandle {
    /// This tunnel's id; stamped into every buffered log event.
    id: String,
    state: RwLock<TunnelState>,
    /// Set when the user asks for a stop; checked by the supervisor and every
    /// attempt so the retry loop unwinds immediately.
    stop_flag: AtomicBool,
    /// Guards against double-spawning the supervisor for one tunnel.
    supervising: AtomicBool,
    /// Kill switch for the currently running attempt (`Some` while a child
    /// process is alive). `stop()` sends `()` on it.
    kill_tx: Mutex<Option<oneshot::Sender<()>>>,
    /// Wakes the backoff sleep so a stop interrupts it instantly.
    notify: Notify,
    /// OS pid of the current child (0 when none). Informational.
    pid: AtomicU32,
    /// Ring buffer of the most recent structured log events (ANSI stripped,
    /// oldest first), consumed by `Engine::recent_logs` (diagnose) and
    /// `Engine::tunnel_logs` (frontend replay via `get_tunnel_logs`).
    logs: Mutex<VecDeque<TunnelLogEvent>>,
    /// This tunnel's local forwarder (stats + access control). `Some` from the
    /// first start attempt on; reused across attempts and restarts while its
    /// upstream target matches. Kept after stop so the card keeps showing the
    /// last run's cumulative traffic. Transport-agnostic: TCP for HTTP/TCP
    /// tunnels, UDP for typed-port tunnels.
    forwarder: Mutex<Option<TunnelForwarder>>,
}

impl TunnelHandle {
    fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            state: RwLock::new(TunnelState::new(id)),
            stop_flag: AtomicBool::new(false),
            supervising: AtomicBool::new(false),
            kill_tx: Mutex::new(None),
            notify: Notify::new(),
            pid: AtomicU32::new(0),
            logs: Mutex::new(VecDeque::with_capacity(LOG_RING_CAP)),
            forwarder: Mutex::new(None),
        }
    }

    /// 追加一条结构化日志到环形缓冲（满则丢弃最老）。ts 在 push 时固定，
    /// 保证历史回放与实时事件同构同源。
    fn push_log(&self, level: &'static str, line: &str) {
        let mut logs = self.logs.lock().unwrap_or_else(|e| e.into_inner());
        if logs.len() >= LOG_RING_CAP {
            logs.pop_front();
        }
        logs.push_back(TunnelLogEvent {
            tunnel_id: self.id.clone(),
            level,
            line: line.to_string(),
            ts: chrono::Utc::now().to_rfc3339(),
        });
    }

    /// 回放缓冲中最新的 `limit` 条（最老在前）；`None` = 全部（上限 ring cap）。
    /// `get_tunnel_logs` 命令的取数实现。
    fn log_replay(&self, limit: Option<u32>) -> Vec<TunnelLogEvent> {
        let logs = self.logs.lock().unwrap_or_else(|e| e.into_inner());
        let start = match limit {
            Some(n) => logs.len().saturating_sub(n as usize),
            None => 0,
        };
        logs.iter().skip(start).cloned().collect()
    }

    /// 清空环形缓冲，返回清掉的行数。`shrink_to_fit` 把 VecDeque 的已分配
    /// 内存一并还给分配器（clear 只重置长度不缩容）。
    fn clear_logs(&self) -> u64 {
        let mut logs = self.logs.lock().unwrap_or_else(|e| e.into_inner());
        let n = logs.len() as u64;
        logs.clear();
        logs.shrink_to_fit();
        n
    }

    /// 日志缓冲的内存占用估算（字节）：逐行 `line.len()` 累加 + 每行固定
    /// 开销估值。精确值无法从外部测得，此处只给量级正确的估算——固定开销
    /// 覆盖 TunnelLogEvent 的三个 String 头 + level 胖指针 + 堆上的
    /// tunnel_id（uuid 36 字节）与 ts（RFC3339 约 30 字节）+ VecDeque 槽位。
    fn logs_bytes(&self) -> u64 {
        let logs = self.logs.lock().unwrap_or_else(|e| e.into_inner());
        let bytes = logs.iter().map(|e| e.line.len() as u64).sum::<u64>();
        bytes + logs.len() as u64 * LOG_LINE_FIXED_OVERHEAD as u64
    }

    fn snapshot(&self) -> TunnelState {
        let mut st = self.state.read().unwrap_or_else(|e| e.into_inner()).clone();
        // The card shows the forwarder's cumulative counters for this run
        // (zeroed by `Engine::start`, kept after the tunnel stops).
        if let Some(fwd) = self
            .forwarder
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            st.bytes_in = fwd.bytes_in();
            st.bytes_out = fwd.bytes_out();
        }
        st
    }

    fn status(&self) -> TunnelStatus {
        self.state.read().unwrap_or_else(|e| e.into_inner()).status
    }

    fn update(&self, f: impl FnOnce(&mut TunnelState)) -> TunnelState {
        let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
        f(&mut state);
        state.clone()
    }
}

fn clear_to_stopped(s: &mut TunnelState) {
    s.status = TunnelStatus::Stopped;
    s.public_url = None;
    s.error = None;
    s.started_at = None;
}

fn truncate_line(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\u{2026}", &s[..end])
}

struct AttemptOutcome {
    /// The attempt had reached Running (a public endpoint was parsed).
    had_url: bool,
    /// Unrecoverable failure (binary missing / spawn failed) — the supervisor
    /// sets Error and stops retrying.
    fatal: Option<String>,
    /// Reason recorded in state.error when the attempt ends abnormally.
    error: Option<String>,
}

impl Engine {
    pub fn new(app: AppHandle) -> Self {
        Self {
            app,
            handles: Mutex::new(HashMap::new()),
        }
    }

    /// Current state snapshot for a tunnel that has a live handle in this
    /// session. `None` when the tunnel was never started here.
    pub fn snapshot(&self, id: &str) -> Option<TunnelState> {
        self.handles
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(id)
            .map(|h| h.snapshot())
    }

    /// Most recent `max` log lines for a tunnel (oldest first), for the
    /// diagnostics engine. Lines are the ANSI-stripped form; returns an empty
    /// Vec when the tunnel has no live handle in this session.
    pub fn recent_logs(&self, id: &str, max: usize) -> Vec<String> {
        let handles = self.handles.lock().unwrap_or_else(|e| e.into_inner());
        let Some(handle) = handles.get(id) else {
            return Vec::new();
        };
        let logs = handle.logs.lock().unwrap_or_else(|e| e.into_inner());
        let skip = logs.len().saturating_sub(max);
        logs.iter().skip(skip).map(|e| e.line.clone()).collect()
    }

    /// 结构化日志回放（命令 `get_tunnel_logs` 的数据源）：缓冲中最新的
    /// `limit` 条（最老在前）；`None` = 全部缓冲（上限 ring cap）。隧道在
    /// 本会话没有活动 handle 时返回空 Vec。
    pub fn tunnel_logs(&self, id: &str, limit: Option<u32>) -> Vec<TunnelLogEvent> {
        let handles = self.handles.lock().unwrap_or_else(|e| e.into_inner());
        match handles.get(id) {
            Some(handle) => handle.log_replay(limit),
            None => Vec::new(),
        }
    }

    /// 清空指定隧道的环形缓冲，返回清掉的行数。id 没有活动 handle（本会话
    /// 从未启动过）时返回 Err——命令层先用 store 判存在性，再决定报错还是
    /// 返回 0 行，这里保持「无 handle 即无缓冲」的严格语义。
    pub fn clear_logs(&self, id: &str) -> Result<u64, String> {
        let handle = self
            .handles
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(id)
            .cloned()
            .ok_or_else(|| format!("隧道不存在或本会话尚未运行过：{id}"))?;
        Ok(handle.clear_logs())
    }

    /// 清空全部隧道的环形缓冲，返回清掉的总行数。
    pub fn clear_all_logs(&self) -> u64 {
        // 短锁内只克隆 Arc 列表，清空动作在锁外逐个进行。
        let handles: Vec<Arc<TunnelHandle>> = self
            .handles
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .cloned()
            .collect();
        handles.iter().map(|h| h.clear_logs()).sum()
    }

    /// 全部隧道日志缓冲的（总行数, 字节估算）。命令 `get_storage_usage` 的
    /// 日志侧数据源。锁粒度：handles 锁只用来克隆 Arc 列表（快进快出），
    /// 之后逐个 handle 短锁取数，不长时间持锁阻塞日志写入/启动路径。
    pub fn storage_usage(&self) -> (u64, u64) {
        let handles: Vec<Arc<TunnelHandle>> = self
            .handles
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .cloned()
            .collect();
        Self::aggregate_log_usage(&handles)
    }

    /// `storage_usage` 的纯聚合逻辑（单独提出以便单测：`Engine` 需要
    /// `AppHandle`，单测无法构造）。逐个 handle 两次短锁取数（行数、字节
    /// 各一），handle 上的日志锁竞争极低（写路径只有单行 push）。
    fn aggregate_log_usage(handles: &[Arc<TunnelHandle>]) -> (u64, u64) {
        let mut lines = 0u64;
        let mut bytes = 0u64;
        for h in handles {
            lines += h.logs.lock().unwrap_or_else(|e| e.into_inner()).len() as u64;
            bytes += h.logs_bytes();
        }
        (lines, bytes)
    }

    /// Start (or resume retrying) a tunnel. Returns the state right after
    /// kickoff (usually Starting). No-op when already active.
    pub async fn start(self: Arc<Self>, cfg: TunnelConfig) -> Result<TunnelState, String> {
        // UDP typed-port tunnels are carried by frp only (bore is TCP-only,
        // Cloudflare tunnels have no plain-UDP ingress) and need a remote
        // port on the server.
        if cfg.tunnel_type == TunnelType::Udp {
            if cfg.backend != Backend::Frp {
                return Err(
                    "UDP 端口转发仅支持自建服务器通道 (UDP forwarding requires the frp backend)"
                        .into(),
                );
            }
            if cfg.remote_port.is_none() {
                return Err("UDP 隧道缺少远程端口 (remotePort is required for udp tunnels)".into());
            }
        }
        let handle = self.get_or_create(&cfg.id);
        if matches!(
            handle.status(),
            TunnelStatus::Starting | TunnelStatus::Running | TunnelStatus::Reconnecting
        ) {
            return Ok(handle.snapshot());
        }
        if handle.supervising.swap(true, Ordering::SeqCst) {
            return Ok(handle.snapshot());
        }
        // Fail fast (and surface the error to the caller) when the binary is
        // missing; run_attempt re-resolves on every retry.
        if let Err(e) = binman::resolve(&self.app, cfg.backend) {
            handle.supervising.store(false, Ordering::SeqCst);
            let st = handle.update(|s| {
                s.status = TunnelStatus::Error;
                s.error = Some(e.clone());
                s.public_url = None;
                s.started_at = None;
            });
            self.emit_state(&st);
            return Err(e);
        }
        handle.stop_flag.store(false, Ordering::SeqCst);
        // Fresh run: zero the forwarder's byte counters so the card shows this
        // run's totals (the forwarder itself may be reused across restarts;
        // `ensure_forwarder` replaces it when stopped or retargeted).
        if let Some(f) = handle
            .forwarder
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            f.reset_counters();
        }
        let st = handle.update(|s| {
            s.status = TunnelStatus::Starting;
            s.public_url = None;
            s.error = None;
            s.started_at = None;
            s.bytes_in = 0;
            s.bytes_out = 0;
        });
        self.emit_state(&st);

        let engine = self.clone();
        let h = handle.clone();
        tokio::spawn(async move {
            supervise(engine, h, cfg).await;
        });
        Ok(handle.snapshot())
    }

    /// Stop a tunnel: set the stop flag, kill the child (kill first, reap
    /// after), wake the backoff sleep, then wait briefly for Stopped.
    pub async fn stop(&self, id: &str) -> Result<TunnelState, String> {
        let handle = self
            .handles
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(id)
            .cloned()
            .ok_or_else(|| "tunnel is not running".to_string())?;

        match handle.status() {
            TunnelStatus::Stopped => return Ok(handle.snapshot()),
            TunnelStatus::Error => {
                // Nothing to kill; treat stop as acknowledging the error.
                let st = handle.update(clear_to_stopped);
                self.emit_state(&st);
                return Ok(st);
            }
            _ => {}
        }

        handle.stop_flag.store(true, Ordering::SeqCst);
        if let Some(tx) = handle
            .kill_tx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            let _ = tx.send(());
        }
        handle.notify.notify_one();

        let deadline = tokio::time::Instant::now() + STOP_WAIT_TIMEOUT;
        while tokio::time::Instant::now() < deadline {
            if handle.status() == TunnelStatus::Stopped {
                break;
            }
            tokio::time::sleep(STOP_POLL_INTERVAL).await;
        }
        // Tear the forwarder down synchronously with the user's stop request:
        // releases the listener, drops every proxied connection and emits the
        // final stats event. (The supervisor's exit path does the same;
        // `Forwarder::stop` is idempotent, so double-stopping is harmless.)
        stop_tunnel_forwarder(&handle).await;
        Ok(handle.snapshot())
    }

    /// Stop every running tunnel. Intended to be wired to app exit by the
    /// integrator (lib.rs is out of scope for this milestone); unused for now.
    #[allow(dead_code)]
    pub async fn stop_all(&self) {
        let ids: Vec<String> = self
            .handles
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .cloned()
            .collect();
        for id in ids {
            let _ = self.stop(&id).await;
            // App exit must not leave a forwarder (listener + proxy tasks)
            // behind even if its supervisor already settled — stop it directly.
            let handle = self
                .handles
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&id)
                .cloned();
            if let Some(handle) = handle {
                stop_tunnel_forwarder(&handle).await;
            }
        }
    }

    /// Drop the runtime bookkeeping for a tunnel (after delete).
    pub fn remove_handle(&self, id: &str) {
        let handle = self
            .handles
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(id);
        if let Some(handle) = handle {
            if let Some(fwd) = handle
                .forwarder
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
            {
                // Sync fn: detach the async teardown (idempotent stop).
                tauri::async_runtime::spawn(async move { fwd.stop().await });
            }
        }
    }

    fn get_or_create(&self, id: &str) -> Arc<TunnelHandle> {
        let mut handles = self.handles.lock().unwrap_or_else(|e| e.into_inner());
        handles
            .entry(id.to_string())
            .or_insert_with(|| Arc::new(TunnelHandle::new(id)))
            .clone()
    }

    fn emit_state(&self, st: &TunnelState) {
        let _ = self
            .app
            .emit(TUNNEL_STATE_EVENT, TunnelStateEvent { state: st.clone() });
    }

    fn emit_log(&self, tunnel_id: &str, level: &'static str, line: &str) {
        let _ = self.app.emit(
            TUNNEL_LOG_EVENT,
            TunnelLogEvent {
                tunnel_id: tunnel_id.to_string(),
                level,
                line: line.to_string(),
                ts: chrono::Utc::now().to_rfc3339(),
            },
        );
    }
}

/// Supervisor loop: run attempts until the user stops; on abnormal exit go to
/// Reconnecting and retry with exponential backoff (1s..30s, unlimited).
async fn supervise(engine: Arc<Engine>, handle: Arc<TunnelHandle>, cfg: TunnelConfig) {
    let mut backoff = BASE_BACKOFF;
    loop {
        let outcome = run_attempt(&engine, &handle, &cfg).await;

        if handle.stop_flag.load(Ordering::SeqCst) {
            let st = handle.update(clear_to_stopped);
            engine.emit_state(&st);
            break;
        }
        if let Some(fatal) = outcome.fatal {
            let msg = truncate_line(&fatal, ERROR_LINE_MAX_LEN);
            let st = handle.update(|s| {
                s.status = TunnelStatus::Error;
                s.error = Some(msg);
                s.public_url = None;
                s.started_at = None;
            });
            engine.emit_state(&st);
            break;
        }

        // Abnormal disconnect (or the process died before becoming ready).
        let err = outcome
            .error
            .as_ref()
            .map(|e| truncate_line(e, ERROR_LINE_MAX_LEN));
        let st = handle.update(|s| {
            s.status = TunnelStatus::Reconnecting;
            s.public_url = None;
            s.error = err;
        });
        engine.emit_state(&st);

        if !wait_backoff(backoff, &handle).await {
            let st = handle.update(clear_to_stopped);
            engine.emit_state(&st);
            break;
        }
        if outcome.had_url {
            backoff = BASE_BACKOFF;
        } else {
            backoff = (backoff * 2).min(MAX_BACKOFF);
        }
    }
    // Terminal for any reason (user stop, fatal, or stop during backoff):
    // shut the forwarder down too — it releases the listener, drops all
    // proxied connections and emits the final stats event.
    stop_tunnel_forwarder(&handle).await;
    handle.supervising.store(false, Ordering::SeqCst);
}

/// Backoff sleep that is interrupted immediately by a stop request.
/// Returns true when the retry loop should continue.
async fn wait_backoff(delay: Duration, handle: &TunnelHandle) -> bool {
    if handle.stop_flag.load(Ordering::SeqCst) {
        return false;
    }
    tokio::select! {
        _ = tokio::time::sleep(delay) => !handle.stop_flag.load(Ordering::SeqCst),
        _ = handle.notify.notified() => !handle.stop_flag.load(Ordering::SeqCst),
    }
}

/// One full run attempt: resolve binary -> spawn -> stream/parse output until
/// the process exits or the user stops it.
async fn run_attempt(
    engine: &Arc<Engine>,
    handle: &Arc<TunnelHandle>,
    cfg: &TunnelConfig,
) -> AttemptOutcome {
    if handle.stop_flag.load(Ordering::SeqCst) {
        return AttemptOutcome {
            had_url: false,
            fatal: None,
            error: None,
        };
    }
    // The tunnel binary dials Pier's local forwarder (traffic stats + access
    // control) instead of the user's service. Started once per run and reused
    // across attempts; replaced when stopped or retargeted.
    let forwarder = match ensure_forwarder(engine, handle, cfg).await {
        Ok(fwd) => fwd,
        Err(e) => {
            return AttemptOutcome {
                had_url: false,
                fatal: Some(e),
                error: None,
            }
        }
    };
    if handle.stop_flag.load(Ordering::SeqCst) {
        return AttemptOutcome {
            had_url: false,
            fatal: None,
            error: None,
        };
    }
    let binary = match binman::resolve(&engine.app, cfg.backend) {
        Ok(path) => path,
        Err(_) => {
            // Self-heal: the engine binary is missing (fresh install, new
            // machine). Download it on the spot instead of bouncing the user
            // to Settings — any start path (UI, tray, autostart) recovers.
            engine.emit_log(
                &cfg.id,
                "info",
                "engine binary not found; downloading automatically (首次使用正在自动下载引擎)…",
            );
            let app = engine.app.clone();
            let backend = cfg.backend;
            let installed = tauri::async_runtime::spawn_blocking(move || {
                binman::install(&app, backend)
            })
            .await
            .map_err(|e| format!("install task failed: {e}"))
            .and_then(|r| r);
            match installed {
                Ok(info) => engine.emit_log(
                    &cfg.id,
                    "info",
                    &format!(
                        "engine installed ({}) — starting tunnel",
                        info.version.unwrap_or_default()
                    ),
                ),
                Err(e) => engine.emit_log(
                    &cfg.id,
                    "error",
                    &format!("engine auto-install failed: {e}"),
                ),
            }
            match binman::resolve(&engine.app, cfg.backend) {
                Ok(path) => path,
                Err(e) => {
                    return AttemptOutcome {
                        had_url: false,
                        fatal: Some(e),
                        error: None,
                    };
                }
            }
        }
    };
    if handle.stop_flag.load(Ordering::SeqCst) {
        return AttemptOutcome {
            had_url: false,
            fatal: None,
            error: None,
        };
    }

    // Rewrite the dial target to the forwarder: 127.0.0.1:{forwarder port}.
    // Cloudflare gets `--url http://127.0.0.1:{port}` (the forwarder is local,
    // so cfg.local_host is irrelevant for the dial), bore gets the port as its
    // positional argument, and the frpc config gets localIP/localPort pointing
    // at it. Everything else in the config stays identical.
    let dial_cfg = with_forwarder_endpoint(cfg, forwarder.port());

    // Frp needs a generated config file and never prints its own public
    // endpoint, so both the command and the expected public URL are prepared
    // HERE, once per attempt: a rotated frps token or an edited server is
    // picked up on every retry. The config dials the FORWARDER (dial_cfg), so
    // all backends flow through the same stats/auth/allowlist path.
    // CloudflareNamed similarly prepares per attempt: both tokens are re-read
    // from the keychain and the remote ingress is retargeted to this
    // attempt's forwarder port before the command (with its precomputed fixed
    // URL) is returned.
    let (mut cmd, expected_url) = match cfg.backend {
        Backend::Frp => {
            let launch = match providers::prepare_frpc_config(&engine.app, &dial_cfg).await {
                Ok(launch) => launch,
                // Unbound server / missing token / unwritable cache: a
                // configuration failure the user must fix, so surface it as
                // Error instead of retrying forever.
                Err(e) => {
                    return AttemptOutcome {
                        had_url: false,
                        fatal: Some(e),
                        error: None,
                    };
                }
            };
            (
                providers::build_frpc_command(&binary, &launch.config_path),
                launch.public_url,
            )
        }
        Backend::CloudflareNamed => {
            match prepare_cf_named_attempt(cfg, &binary, forwarder.port()).await {
                Ok(prepared) => prepared,
                // Missing keychain tokens / expired API token / dashboard-
                // rewritten ingress: unrecoverable for this configuration,
                // surface as Error instead of retrying forever.
                Err(e) => {
                    return AttemptOutcome {
                        had_url: false,
                        fatal: Some(e),
                        error: None,
                    };
                }
            }
        }
        _ => (providers::build_command(&dial_cfg, &binary), None),
    };
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    // Do not flash a console window on Windows.
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);

    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            return AttemptOutcome {
                had_url: false,
                fatal: Some(format!("failed to start {}: {e}", binary.display())),
                error: None,
            }
        }
    };

    let pid = child.id().unwrap_or(0);
    handle.pid.store(pid, Ordering::SeqCst);

    // Install the kill switch for this attempt.
    let (kill_tx, mut kill_rx) = oneshot::channel::<()>();
    *handle.kill_tx.lock().unwrap_or_else(|e| e.into_inner()) = Some(kill_tx);
    if handle.stop_flag.load(Ordering::SeqCst) {
        // Stop raced in between; kill right away and unwind.
        *handle.kill_tx.lock().unwrap_or_else(|e| e.into_inner()) = None;
        let _ = child.start_kill();
        let _ = child.wait().await;
        handle.pid.store(0, Ordering::SeqCst);
        return AttemptOutcome {
            had_url: false,
            fatal: None,
            error: None,
        };
    }

    let st = handle.update(|s| {
        s.status = TunnelStatus::Starting;
        s.public_url = None;
        s.error = None;
        s.started_at = None;
    });
    engine.emit_state(&st);

    // Merge stdout+stderr through one channel, line by line.
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    if let Some(out) = child.stdout.take() {
        tokio::spawn(pump_lines(out, tx.clone()));
    }
    if let Some(err) = child.stderr.take() {
        tokio::spawn(pump_lines(err, tx.clone()));
    }
    drop(tx);

    let mut public_url: Option<String> = None;
    let mut last_error: Option<String> = None;
    let mut killed = false;

    loop {
        tokio::select! {
            maybe = rx.recv() => {
                let Some(raw) = maybe else { break };
                let line = raw.trim_end().to_string();
                if line.is_empty() {
                    continue;
                }
                // 环形缓冲保存与实时事件同构的结构化记录（ANSI 已剥离）。
                let level = providers::classify_level(cfg.backend, &line);
                handle.push_log(level, &providers::strip_ansi(&line));
                engine.emit_log(&cfg.id, level, &line);
                if level == "error" {
                    // Transient cloudflared errors are common while it dials
                    // the edge; remember the last one but keep running.
                    if handle.status() != TunnelStatus::Running {
                        let short = truncate_line(&line, ERROR_LINE_MAX_LEN);
                        handle.update(|s| s.error = Some(short));
                    }
                    last_error = Some(line.clone());
                }
                if public_url.is_none() {
                    let mut hit = providers::parse_public_endpoint(cfg.backend, &line);
                    // frpc never prints its public endpoint; bind the URL
                    // computed at config-prep time once frpc confirms the
                    // proxy started forwarding.
                    if hit.is_none()
                        && cfg.backend == Backend::Frp
                        && providers::frpc_proxy_started(&line)
                    {
                        hit = expected_url.clone();
                    }
                    // Named tunnels never print their URL either: the fixed
                    // hostname was precomputed at config-prep time and binds
                    // once cloudflared registers with the edge.
                    if hit.is_none()
                        && cfg.backend == Backend::CloudflareNamed
                        && providers::cf_named_tunnel_ready(&line)
                    {
                        hit = expected_url.clone();
                    }
                    if let Some(url) = hit {
                        public_url = Some(url.clone());
                        let st = handle.update(|s| {
                            s.status = TunnelStatus::Running;
                            s.public_url = Some(url);
                            s.error = None;
                            s.started_at = Some(chrono::Utc::now().to_rfc3339());
                        });
                        engine.emit_state(&st);
                    }
                }
                // frpc keeps running even when the server rejected the proxy
                // (name/port conflict: "start error: ..."); that attempt can
                // never become Running, so kill it and let the supervisor
                // reconnect with a freshly prepared config.
                if cfg.backend == Backend::Frp
                    && public_url.is_none()
                    && providers::frpc_start_error(&line)
                {
                    last_error = Some(line.clone());
                    break;
                }
            }
            _ = &mut kill_rx => {
                // User stop: kill first, then reap so nothing lingers.
                killed = true;
                let _ = child.kill().await;
                let _ = child.wait().await;
                break;
            }
        }
    }

    let pid_for_note = handle.pid.load(Ordering::SeqCst);
    handle.pid.store(0, Ordering::SeqCst);
    *handle.kill_tx.lock().unwrap_or_else(|e| e.into_inner()) = None;

    let mut exit_note: Option<String> = None;
    if !killed {
        // The readers hit EOF, so the child is gone (or daemonized its stdio);
        // make sure it is dead, then reap it.
        let _ = child.start_kill();
        match child.wait().await {
            Ok(status) => {
                exit_note = Some(format!(
                    "tunnel process (pid {pid_for_note}) exited ({status})"
                ))
            }
            Err(e) => exit_note = Some(format!("tunnel wait failed: {e}")),
        }
    }

    AttemptOutcome {
        had_url: public_url.is_some(),
        fatal: None,
        error: last_error
            .or(exit_note)
            .or_else(|| Some("tunnel process exited unexpectedly".to_string())),
    }
}

/// CloudflareNamed pre-spawn preparation, mirroring the frp prepare phase:
/// validate the provision-time fields, re-read both tokens from the
/// keychain, retarget the remote ingress to THIS attempt's forwarder port,
/// then build the command plus the precomputed fixed public URL
/// (`https://{cf_hostname}` — fixed at provision time, never changes).
async fn prepare_cf_named_attempt(
    cfg: &TunnelConfig,
    binary: &std::path::Path,
    forwarder_port: u16,
) -> Result<(tokio::process::Command, Option<String>), String> {
    let missing_field = |what: &str| {
        format!("固定域名隧道缺少 {what} 配置（数据不完整，请删除后重新绑定 Cloudflare 域名）")
    };
    let hostname = cfg
        .cf_hostname
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| missing_field("cf_hostname"))?;
    let account_id = cfg
        .cf_account_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| missing_field("cf_account_id"))?
        .to_string();
    let tunnel_id = cfg
        .cf_tunnel_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| missing_field("cf_tunnel_id"))?
        .to_string();

    // Both tokens live in the OS keychain under the LOCAL tunnel id (the
    // slots commands::cf_provision writes). Re-read on every attempt so a
    // re-provisioned tunnel is picked up without an app restart.
    let run_token =
        cloudflare::get_tunnel_run_token(&cfg.id).map_err(|e| format!("读取隧道运行 token 失败：{e}"))?;
    let api_token =
        cloudflare::get_api_token(&cfg.id).map_err(|e| format!("读取 Cloudflare API token 失败：{e}"))?;

    // The remote ingress service must dial THIS attempt's forwarder port.
    // Blocking HTTP round trip -> dedicated worker thread (spawn_blocking).
    // Failure (expired API token, unreachable API, dashboard-rewritten
    // config) is fatal: cloudflared would otherwise dial the placeholder
    // port from provisioning or a dead forwarder port from an older run.
    let update = tauri::async_runtime::spawn_blocking(move || {
        cloudflare::update_ingress_service(&api_token, &account_id, &tunnel_id, forwarder_port)
    })
    .await
    .map_err(|e| format!("ingress 更新任务执行失败：{e}"))
    .and_then(|r| r);
    if let Err(e) = update {
        return Err(format!(
            "更新 Cloudflare ingress 端口失败（API token 可能已过期或网络不可用）：{e}"
        ));
    }

    let cmd = providers::build_cf_command(cfg, binary, &run_token);
    Ok((cmd, Some(format!("https://{hostname}"))))
}

/// Forward one output stream to the shared line channel until EOF.
async fn pump_lines<R>(stream: R, tx: tokio::sync::mpsc::UnboundedSender<String>)
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    let mut reader = tokio::io::BufReader::new(stream);
    let mut buf = String::new();
    loop {
        buf.clear();
        match reader.read_line(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                if tx.send(buf.clone()).is_err() {
                    break;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Local forwarder wiring (M3)
// ---------------------------------------------------------------------------

/// Copy of `cfg` with the dial target rewritten to the local forwarder
/// (127.0.0.1:{port}). Used for the backend command (cloudflared `--url`,
/// bore positional port) and for the generated frpc config.
fn with_forwarder_endpoint(cfg: &TunnelConfig, forwarder_port: u16) -> TunnelConfig {
    let mut dial = cfg.clone();
    dial.local_host = "127.0.0.1".to_string();
    dial.local_port = forwarder_port;
    dial
}

/// Make sure this tunnel's local forwarder is up and return it.
///
/// * Reused across attempts AND restarts while it is still running and its
///   upstream target matches — the listening port stays stable, so frpc
///   config files regenerated per attempt keep the same localPort. Byte
///   counters keep accumulating across attempts of the same run.
/// * Replaced when it was stopped (previous run) or the tunnel's target was
///   edited. The counters of the replacement start at zero.
async fn ensure_forwarder(
    engine: &Arc<Engine>,
    handle: &Arc<TunnelHandle>,
    cfg: &TunnelConfig,
) -> Result<TunnelForwarder, String> {
    // Bind the clone to a local FIRST: the MutexGuard temporary must be gone
    // before any `.await` (std guards are not Send).
    let existing = handle
        .forwarder
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    if let Some(existing) = existing {
        if !existing.is_stopped() && existing.upstream_matches(&cfg.local_host, cfg.local_port) {
            return Ok(existing);
        }
        // Stale (stopped or retargeted): release it before making a new one.
        existing.stop().await;
    }

    // Basic-auth password lives in the OS keychain, never in config files. A
    // tunnel configured with auth but missing its keychain entry is a hard
    // configuration error — running it UNPROTECTED would be the worse failure.
    let auth_password = if cfg.auth.is_some() {
        match servers_store::get_tunnel_auth_password(&cfg.id) {
            Ok(Some(password)) => Some(password),
            Ok(None) => {
                return Err(format!(
                    "隧道开启了访问鉴权，但钥匙串中没有对应密码 (auth is enabled but no password is stored for tunnel {})",
                    cfg.id
                ));
            }
            Err(e) => {
                return Err(format!(
                    "读取访问鉴权密码失败 (failed to read the tunnel auth password): {e}"
                ));
            }
        }
    } else {
        None
    };

    // 转发器连接日志的统一出口：入环形缓冲 + emit 实时事件，两条路径与
    // 进程输出日志完全一致。级别由转发器给定（info/warn），文案为技术性
    // 英文（不进 i18n）。每连接固定两行，热路径不经过此闭包。
    let log_tunnel_id = cfg.id.clone();
    let log_handle = handle.clone();
    let log_engine = engine.clone();
    let log_sink: LogSink = Arc::new(move |level, line| {
        log_handle.push_log(level, &line);
        log_engine.emit_log(&log_tunnel_id, level, &line);
    });

    let (fwd, port) = match cfg.tunnel_type {
        TunnelType::Http | TunnelType::Tcp => {
            let (fwd, port) = Forwarder::start(
                engine.app.clone(),
                cfg.clone(),
                auth_password,
                Some(log_sink),
            )
            .await?;
            (TunnelForwarder::Tcp(fwd), port)
        }
        TunnelType::Udp => {
            let (fwd, port) = crate::forwarder::UdpForwarder::start(
                engine.app.clone(),
                cfg.clone(),
                Some(log_sink),
            )
            .await?;
            (TunnelForwarder::Udp(fwd), port)
        }
    };
    *handle.forwarder.lock().unwrap_or_else(|e| e.into_inner()) = Some(fwd.clone());
    let transport = match cfg.tunnel_type {
        TunnelType::Udp => "udp",
        _ => "tcp",
    };
    let line = format!(
        "{transport} forwarder: listening on 127.0.0.1:{port} -> {}:{}",
        cfg.local_host, cfg.local_port
    );
    handle.push_log("info", &line);
    engine.emit_log(&cfg.id, "info", &line);
    Ok(fwd)
}

/// Stop the tunnel's forwarder if one exists (idempotent, cheap when none).
async fn stop_tunnel_forwarder(handle: &TunnelHandle) {
    let fwd = handle
        .forwarder
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    if let Some(fwd) = fwd {
        fwd.stop().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{AuthKind, ServerConfig, TunnelType};

    fn sample_cfg(backend: Backend, local_port: u16) -> TunnelConfig {
        TunnelConfig {
            id: "t1".into(),
            name: "t".into(),
            tunnel_type: TunnelType::Http,
            backend,
            local_host: "192.168.1.10".into(),
            local_port,
            auto_start: false,
            created_at: String::new(),
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
    fn cloudflare_and_bore_dial_the_forwarder() {
        // The user's service lives on 192.168.1.10:8080; the tunnel binary must
        // dial the forwarder on loopback instead.
        let mut cfg = sample_cfg(Backend::Cloudflare, 8080);
        let dial = with_forwarder_endpoint(&cfg, 41234);
        assert_eq!(
            providers::build_args(&dial),
            vec![
                "tunnel".to_string(),
                "--url".to_string(),
                "http://127.0.0.1:41234".to_string(),
                "--protocol".to_string(),
                "http2".to_string(),
                "--no-autoupdate".to_string(),
            ]
        );
        cfg.backend = Backend::Bore;
        let dial = with_forwarder_endpoint(&cfg, 41234);
        assert_eq!(
            providers::build_args(&dial),
            vec![
                "local".to_string(),
                "--to".to_string(),
                providers::BORE_DEFAULT_SERVER.to_string(),
                "41234".to_string(),
            ]
        );
    }

    #[test]
    fn frp_config_dials_the_forwarder() {
        let mut cfg = sample_cfg(Backend::Frp, 9000);
        cfg.tunnel_type = TunnelType::Tcp;
        cfg.remote_port = Some(17001);
        cfg.server_id = Some("srv1".into());
        let dial = with_forwarder_endpoint(&cfg, 41234);
        let server = ServerConfig {
            id: "srv1".into(),
            name: "vps".into(),
            host: "vps.example.com".into(),
            port: 22,
            username: "root".into(),
            auth_kind: AuthKind::Password,
            frps_bind_port: 7000,
            frps_vhost_http_port: 8080,
            frps_vhost_https_port: 8443,
            frps_dashboard_port: 7500,
            subdomain_host: None,
            frps_proxy_port_start: None,
            frps_proxy_port_end: None,
            deployed: true,
            frps_version: None,
            created_at: String::new(),
        };
        let (text, _) = providers::build_frpc_toml(&dial, &server, "tok").unwrap();
        assert!(text.contains("localIP = \"127.0.0.1\""), "{text}");
        assert!(text.contains("localPort = 41234"), "{text}");
        assert!(!text.contains("localPort = 9000"), "{text}");
    }

    #[test]
    fn with_forwarder_endpoint_keeps_everything_else() {
        let mut cfg = sample_cfg(Backend::Frp, 9000);
        cfg.remote_port = Some(17001);
        let dial = with_forwarder_endpoint(&cfg, 41234);
        assert_eq!(dial.id, cfg.id);
        assert_eq!(dial.name, cfg.name);
        assert_eq!(dial.backend, cfg.backend);
        assert_eq!(dial.tunnel_type, cfg.tunnel_type);
        assert_eq!(dial.remote_port, cfg.remote_port);
        assert_eq!(dial.server_id, cfg.server_id);
        // Only the dial target changed.
        assert_eq!(dial.local_port, 41234);
        assert_eq!(dial.local_host, "127.0.0.1");
    }

    /// 打开日志面板前的历史回放：环形缓冲必须保存结构化记录（与实时事件
    /// tunnel://log 同构），命令 `commands::get_tunnel_logs` 经
    /// `Engine::tunnel_logs` 读的就是这里驱动的 handle 级实现。
    /// `State<'_, AppState>` 需要真实 Tauri 运行时，单测无法构造，故直接
    /// 对命令背后的取数函数断言（命令本体是一行委托）。
    #[test]
    fn test_tunnel_log_buffer_replays_structured() {
        let handle = TunnelHandle::new("t-log-replay");
        handle.push_log("info", "engine: tunnel t-log-replay starting");
        handle.push_log("error", "dial tcp 10.0.0.1:8080: connect refused");
        handle.push_log("info", "tcp forwarder: listening on 127.0.0.1:41234");

        // 默认（limit = None）：回放全部缓冲，最老在前。
        let replay = handle.log_replay(None);
        assert_eq!(replay.len(), 3, "应回放全部 3 条");
        for ev in &replay {
            assert_eq!(ev.tunnel_id, "t-log-replay");
            assert!(!ev.ts.is_empty(), "ts 必须非空");
        }
        assert_eq!(replay[0].level, "info");
        assert_eq!(replay[0].line, "engine: tunnel t-log-replay starting");
        assert_eq!(replay[1].level, "error");
        assert_eq!(replay[1].line, "dial tcp 10.0.0.1:8080: connect refused");
        assert_eq!(replay[2].level, "info");
        assert_eq!(
            replay[2].line,
            "tcp forwarder: listening on 127.0.0.1:41234"
        );

        // limit = 2：只取最新 2 条，仍是最老在前。
        let tail = handle.log_replay(Some(2));
        assert_eq!(tail.len(), 2);
        assert_eq!(tail[0].line, "dial tcp 10.0.0.1:8080: connect refused");
        assert_eq!(tail[1].line, "tcp forwarder: listening on 127.0.0.1:41234");

        // 缓冲写满（cap 200）后继续写入：最老记录被挤出，最新一条在末尾。
        for i in 0..=(LOG_RING_CAP as u32) {
            handle.push_log("info", &format!("filler line {i}"));
        }
        let all = handle.log_replay(None);
        assert_eq!(all.len(), LOG_RING_CAP);
        assert_eq!(
            all.last().unwrap().line,
            format!("filler line {LOG_RING_CAP}"),
            "最新一条必须在末尾"
        );
        assert_eq!(all[0].line, "filler line 1", "最老的记录应已被挤出");
    }

    /// 「清理日志」命令（commands::clear_tunnel_logs -> Engine::clear_logs ->
    /// TunnelHandle::clear_logs）的 handle 级语义：返回清掉的行数、缓冲彻底
    /// 变空（回放为空、字节估算归零），且清空后可以继续正常写入。
    #[test]
    fn test_clear_logs_empties_buffer_and_reports_count() {
        let handle = TunnelHandle::new("t-clear");
        handle.push_log("info", "first line");
        handle.push_log("error", "second line");
        handle.push_log("info", "third line");
        assert!(handle.logs_bytes() > 0, "清理前字节估算应大于 0");

        assert_eq!(handle.clear_logs(), 3, "应报告清掉 3 行");
        assert!(handle.log_replay(None).is_empty(), "清理后回放应为空");
        assert_eq!(handle.logs_bytes(), 0, "清理后字节估算应归零");
        assert_eq!(handle.clear_logs(), 0, "重复清理应报告 0 行");

        // 清空后缓冲仍可正常写入（环形容量语义不变）。
        handle.push_log("info", "after clear");
        let replay = handle.log_replay(None);
        assert_eq!(replay.len(), 1);
        assert_eq!(replay[0].line, "after clear");
    }

    /// 「存储占用统计」日志侧的聚合（Engine::aggregate_log_usage）：
    /// 总行数跨 handle 求和，字节估算 = 各 handle 行字节累加 + 每行固定
    /// 开销估值（口径与 TunnelHandle::logs_bytes 完全一致）。
    #[test]
    fn test_aggregate_log_usage_sums_lines_and_bytes() {
        let a = TunnelHandle::new("t-agg-a");
        a.push_log("info", "aaaa"); // 4 字节
        a.push_log("info", "bb"); // 2 字节
        let b = TunnelHandle::new("t-agg-b");
        b.push_log("info", "ccc"); // 3 字节

        let handles = vec![Arc::new(a), Arc::new(b)];
        let (lines, bytes) = Engine::aggregate_log_usage(&handles);
        assert_eq!(lines, 3, "两个 handle 的行数应求和");
        assert_eq!(
            bytes,
            (4 + 2 + 3) as u64 + 3 * LOG_LINE_FIXED_OVERHEAD as u64,
            "字节 = 各行 line.len() 累加 + 每行固定开销估值"
        );

        // 空集合返回 (0, 0)（命令层的 StorageUsage 各字段可安全归零）。
        assert_eq!(Engine::aggregate_log_usage(&[]), (0, 0));
    }
}
