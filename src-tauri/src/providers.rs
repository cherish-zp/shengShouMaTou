// Backend providers — command builders + output parsers for cloudflared/bore/frpc.
//
// Parsing rules below are calibrated against real binary output captured on
// macOS arm64 (cloudflared 2026.10.0, bore-cli 0.6.0 and 0.5.1):
//
// cloudflared (ALL logs go to stderr, quick tunnel URL inside ASCII-art bars):
//   2026-10-06T10:48:20Z INF |  https://vessels-arrow-kid-educated.trycloudflare.com   |
//   2026-10-06T10:48:20Z INF |  Your quick Tunnel has been created! Visit it at ...  |
//   2026-10-06T10:48:25Z ERR Failed to dial a quic connection error="..." connIndex=0
//   ^ NOTE: ERR lines are frequently transient — cloudflared retries on its
//     own, so they must NOT be treated as fatal by the engine.
//
// bore (logs go to stdout, WITH ANSI color escapes even when piped):
//   ESC[2m2026-10-06T10:48:08.904579Z ESC[0m ESC[32m INFO ESC[0m ... connected to server remote_port=62457
//   ESC[2m2026-10-06T10:48:08.905692Z ESC[0m ... listening at bore.pub:62457
//
// CLI shape (verified on v0.5.1 AND v0.6.0): `bore local` takes the local
// port as a POSITIONAL argument; there is no `--local-port` flag:
//   bore local --to bore.pub 8099          (correct)
//   bore local --local-port 8099 --to bore.pub   (error: unexpected argument)
//
// frpc (calibrated against frp 0.71.0 darwin arm64 against a real local frps;
// logs go to the console by default, WITH ANSI color per level — blue [I],
// yellow [W], red [E]):
//   ESC[1;34m2026-10-06 20:18:27.518 [I] [client/service.go:332] [8ffeba1af99c60df] login to server success, get run id [8ffeba1af99c60df]
//   ESC[1;34m2026-10-06 20:18:27.519 [I] [client/control.go:174] [8ffeba1af99c60df] [web-tcp] start proxy success
//   ESC[1;33m2026-10-06 20:18:02.936 [W] [client/service.go:323] connect to server error: token in login doesn't match token from configuration
//   login to the server failed: token in login doesn't match token from configuration. With loginFailExit enabled, no additional retries will be attempted
//   ESC[1;33m2026-10-06 20:19:35.272 [W] [client/control.go:172] [fbcb25fbd0d6eaab] [other-tcp] start error: port already used
//   ESC[1;31m2026-10-06 20:20:57.726 [E] [proxy/proxy.go:237] [8ffeba1af99c60df] [web-tcp] connect to local service [127.0.0.1:8080] error: dial tcp 127.0.0.1:8080: connect: connection refused
//   ^ IMPORTANT frpc behaviors observed:
//     * fatal login failures (bad token, unreachable server) are logged as
//       [W] "connect to server error: ..." plus a bare stderr line
//       "login to the server failed: ...", and the process EXITS
//       (loginFailExit defaults to true) — the engine's generic
//       process-exit -> Reconnecting path covers the retry.
//     * proxy rejection ("start error: proxy [x] already exists" /
//       "port already used") is [W] and the process KEEPS RUNNING while
//       being useless — the engine kills such an attempt and reconnects.
//     * frpc NEVER prints its public endpoint; the engine learns the
//       expected URL from `prepare_frpc_config` (see below) and binds it
//       when a "start proxy success" line arrives.
//
// frpc TOML config (both forms pass `frpc verify` on 0.71.0; we emit the
// dotted-key form):
//   serverAddr = "1.2.3.4" / serverPort = 7000 / auth.token = "..."
//   transport.tls.enable = true   ==   ["transport".tls] enable = true

use std::path::{Path, PathBuf};

use tauri::Manager;

use crate::models::{Backend, ServerConfig, TunnelConfig, TunnelType};
// TOML basic-string 转义与 frp_deploy.rs 共用（crate::util）。
use crate::util::toml_escape;

/// Public relay server used by the bore backend in M1 (config has no field
/// for it yet).
pub const BORE_DEFAULT_SERVER: &str = "bore.pub";

/// Build the argv (without the program itself) for the backend binary.
pub fn build_args(cfg: &TunnelConfig) -> Vec<String> {
    match cfg.backend {
        Backend::Cloudflare => vec![
            "tunnel".to_string(),
            "--url".to_string(),
            format!("http://{}:{}", cfg.local_host, cfg.local_port),
            // QUIC (UDP 443) is blocked on many networks (verified live:
            // auto mode keeps retrying and edge answers 530) while the
            // HTTP/2 fallback runs over TCP 443 almost everywhere.
            // cloudflared's own precheck suggests http2 in that case, so
            // default to it for reliability.
            "--protocol".to_string(),
            "http2".to_string(),
            "--no-autoupdate".to_string(),
        ],
        Backend::Bore => vec![
            "local".to_string(),
            "--to".to_string(),
            BORE_DEFAULT_SERVER.to_string(),
            cfg.local_port.to_string(),
        ],
        // Frp tunnels spawn `frpc -c <generated config file>`; the argv is
        // built by `build_frpc_command` (the config path is only known after
        // async config preparation, so this pure builder stays empty and the
        // engine routes Frp through the dedicated function).
        Backend::Frp => vec![],
        // Named tunnels run via `tunnel run`; the tunnel token reaches
        // cloudflared through the TUNNEL_TOKEN env var (set by the engine
        // from the keychain — never a CLI argument).
        // --protocol http2: same rationale as the quick-tunnel branch above —
        // QUIC (UDP 443) is blocked on many networks and cloudflared's auto
        // mode keeps retrying without degrading (live-verified).
        Backend::CloudflareNamed => vec![
            "tunnel".to_string(),
            "--protocol".to_string(),
            "http2".to_string(),
            "--no-autoupdate".to_string(),
            "run".to_string(),
        ],
    }
}

/// Build a tokio command that runs `binary` with the backend's arguments.
pub fn build_command(cfg: &TunnelConfig, binary: &Path) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(binary);
    cmd.args(build_args(cfg));
    cmd
}

/// Build a tokio command that runs `frpc` against a generated config file:
/// `frpc -c <path>`.
pub fn build_frpc_command(binary: &Path, config_path: &Path) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(binary);
    cmd.arg("-c").arg(config_path);
    cmd
}

/// Build a tokio command that runs a Cloudflare NAMED tunnel:
/// `cloudflared tunnel --no-autoupdate run` (args from `build_args`) with
/// the tunnel-run token injected as the TUNNEL_TOKEN environment variable —
/// the token must never appear in argv, where other local processes could
/// read it. The origin routing comes from the remote-managed ingress
/// (config_src=cloudflare), so no --url flag is needed.
pub fn build_cf_command(cfg: &TunnelConfig, binary: &Path, run_token: &str) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(binary);
    cmd.args(build_args(cfg));
    cmd.env("TUNNEL_TOKEN", run_token);
    cmd
}

/// Everything the engine needs to spawn one frpc attempt: the generated
/// config file plus the public URL the tunnel will expose once frpc reports
/// `start proxy success` (frpc never prints the endpoint itself).
#[derive(Debug, Clone)]
pub struct FrpcLaunch {
    pub config_path: PathBuf,
    pub public_url: Option<String>,
}

/// Generate the frpc TOML config for `cfg`, write it to
/// `<app_cache_dir>/tunnels/{id}.toml` and return the launch plan.
///
/// Called before EVERY spawn attempt (the engine retries through the same
/// path), so a rotated frps token or an edited server is always picked up.
pub async fn prepare_frpc_config(
    app: &tauri::AppHandle,
    cfg: &TunnelConfig,
) -> Result<FrpcLaunch, String> {
    let server_id = cfg
        .server_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "隧道未绑定服务器 (tunnel is not bound to a 圣手码头 server)".to_string())?;
    let server = crate::servers_store::load_servers(app)
        .into_iter()
        .find(|s| s.id == server_id)
        .ok_or_else(|| {
            format!("隧道绑定的服务器不存在 (bound server {server_id:?} was not found)")
        })?;
    let token = crate::servers_store::get_frps_token(server_id)
        .map_err(|e| format!("无法读取 frps token (failed to read the frps token): {e}"))?;

    let (text, public_url) = build_frpc_toml(cfg, &server, &token)?;

    let dir = app
        .path()
        .app_cache_dir()
        .map_err(|e| format!("failed to resolve the app cache dir: {e}"))?
        .join("tunnels");
    tokio::fs::create_dir_all(&dir)
        .await
        .map_err(|e| format!("failed to create {}: {e}", dir.display()))?;
    let path = dir.join(format!("{}.toml", sanitize_file_name(&cfg.id)));
    tokio::fs::write(&path, text)
        .await
        .map_err(|e| format!("failed to write {}: {e}", path.display()))?;

    Ok(FrpcLaunch {
        config_path: path,
        public_url,
    })
}

/// Pure config builder (unit-testable): render the frpc TOML text and the
/// expected public URL for `cfg` running against `server` with `token`.
///
/// URL shapes:
/// * tcp  -> `{server.host}:{remote_port}`
/// * udp  -> `udp://{server.host}:{remote_port}`
/// * http -> `http://{subdomain}.{server.subdomainHost}:{vhost_http_port}`;
///   when the server has no subdomainHost the endpoint degrades to
///   `http://{server.host}:{vhost_http_port}`; when `cfg.subdomain` already
///   looks like a full domain (contains a dot) it is emitted as a
///   customDomain and used verbatim.
pub fn build_frpc_toml(
    cfg: &TunnelConfig,
    server: &ServerConfig,
    token: &str,
) -> Result<(String, Option<String>), String> {
    let mut s = String::from("# Generated by 圣手码头 (ShengShouMaTou) — overwritten on every start; do not edit.\n");
    s.push_str(&format!("serverAddr = \"{}\"\n", toml_escape(&server.host)));
    s.push_str(&format!("serverPort = {}\n", server.frps_bind_port));
    s.push_str(&format!("auth.token = \"{}\"\n", toml_escape(token)));
    // Dotted keys verified against `frpc verify` on 0.71.0.
    s.push_str("transport.tls.enable = true\n");

    let name = toml_escape(&cfg.id);
    let (proxy_type, public_url) = match cfg.tunnel_type {
        TunnelType::Tcp | TunnelType::Udp => {
            let remote_port = cfg.remote_port.ok_or_else(|| {
                format!(
                    "{} 隧道缺少远程端口 (remotePort is required for frp {} tunnels)",
                    if cfg.tunnel_type == TunnelType::Udp {
                        "UDP"
                    } else {
                        "TCP"
                    },
                    if cfg.tunnel_type == TunnelType::Udp {
                        "udp"
                    } else {
                        "tcp"
                    }
                )
            })?;
            let scheme = if cfg.tunnel_type == TunnelType::Udp {
                "udp://"
            } else {
                ""
            };
            let url = if remote_port == 0 {
                None
            } else {
                Some(format!("{scheme}{}:{}", server.host, remote_port))
            };
            (
                if cfg.tunnel_type == TunnelType::Udp {
                    "udp"
                } else {
                    "tcp"
                },
                url,
            )
        }
        TunnelType::Http => {
            let sub = cfg
                .subdomain
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    "HTTP 隧道缺少子域名 (subdomain is required for frp http tunnels)".to_string()
                })?;
            let url = if sub.contains('.') {
                // Full domain the user owns: served via customDomains.
                Some(format!("http://{sub}:{}", server.frps_vhost_http_port))
            } else if server
                .subdomain_host
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .is_some()
            {
                let host = server.subdomain_host.as_deref().unwrap_or_default().trim();
                Some(format!("http://{sub}.{host}:{}", server.frps_vhost_http_port))
            } else {
                // No wildcard domain on the server: the vhost still answers on
                // host:port, but per-subdomain routing is unavailable.
                Some(format!("http://{}:{}", server.host, server.frps_vhost_http_port))
            };
            ("http", url)
        }
    };

    s.push_str(&format!("\n[[proxies]]\nname = \"{name}\"\n"));
    s.push_str(&format!("type = \"{proxy_type}\"\n"));
    s.push_str(&format!("localIP = \"{}\"\n", toml_escape(&cfg.local_host)));
    s.push_str(&format!("localPort = {}\n", cfg.local_port));
    match cfg.tunnel_type {
        TunnelType::Tcp | TunnelType::Udp => {
            if let Some(remote_port) = cfg.remote_port {
                s.push_str(&format!("remotePort = {remote_port}\n"));
            }
        }
        TunnelType::Http => {
            let sub = cfg.subdomain.as_deref().unwrap_or_default().trim();
            if sub.contains('.') {
                s.push_str(&format!("customDomains = [\"{}\"]\n", toml_escape(sub)));
            } else if !sub.is_empty() {
                s.push_str(&format!("subdomain = \"{}\"\n", toml_escape(sub)));
            }
        }
    }

    Ok((s, public_url))
}

/// Tunnel ids are uuids today, but keep cache file names safe regardless.
fn sanitize_file_name(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Parse the public endpoint from a process output line, per backend.
///
/// * cloudflare -> `https://<name>.trycloudflare.com`
/// * bore       -> `<host>:<port>` (e.g. `bore.pub:62457`)
/// * frp        -> always `None`: frpc never prints its public endpoint. The
///   engine instead takes the URL computed by `prepare_frpc_config` and binds
///   it when `frpc_proxy_started` sees a `start proxy success` line.
pub fn parse_public_endpoint(backend: Backend, line: &str) -> Option<String> {
    match backend {
        Backend::Cloudflare => extract_quick_tunnel_url(line),
        Backend::Bore => extract_bore_endpoint(line)
            .or_else(|| extract_remote_port(line).map(|p| format!("{BORE_DEFAULT_SERVER}:{p}"))),
        Backend::Frp => None,
        // Named-tunnel URLs are fixed at provision time (cf_hostname) — the
        // engine binds them the same way as the frp precomputed path.
        Backend::CloudflareNamed => None,
    }
}

/// True when an frpc line announces that a proxy is now forwarding:
/// `[I] [client/control.go:174] [runid] [name] start proxy success` (0.71.0).
pub fn frpc_proxy_started(line: &str) -> bool {
    strip_ansi(line)
        .to_ascii_lowercase()
        .contains("start proxy success")
}

/// True when a cloudflared line announces a named-tunnel connector has
/// registered with the edge:
/// `2026-10-07T08:00:00Z INF Registered tunnel connection connIndex=0 ...`.
/// This is the readiness signal for Backend::CloudflareNamed (the fixed URL
/// is known at provision time, so only the edge registration is awaited).
pub fn cf_named_tunnel_ready(line: &str) -> bool {
    strip_ansi(line)
        .to_ascii_lowercase()
        .contains("registered tunnel connection")
}

/// True when an frpc line reports that the server REJECTED a proxy:
/// `[W] ... [name] start error: port already used` (0.71.0). frpc keeps
/// running in that state while being useless, so the engine kills the
/// attempt and lets the supervisor reconnect.
pub fn frpc_start_error(line: &str) -> bool {
    strip_ansi(line)
        .to_ascii_lowercase()
        .contains("start error")
}

/// Remove ANSI escape sequences (CSI ... final-byte). bore colorizes its log
/// lines even when stdout is a pipe, so this runs before every parse.
pub fn strip_ansi(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            if chars.peek() == Some(&'[') {
                chars.next();
                // CSI sequence: consume parameters until the final byte
                // (0x40..=0x7E, e.g. `m` for SGR).
                for f in chars.by_ref() {
                    if ('\u{40}'..='\u{7e}').contains(&f) {
                        break;
                    }
                }
            }
            continue;
        }
        out.push(c);
    }
    out
}

fn is_host_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '.'
}

/// Loosely match `https://[a-z0-9-]+.trycloudflare.com` anywhere in the line.
/// cloudflared wraps the URL in ASCII-art `| ... |` table cells with padded
/// spaces, so we can't rely on exact token boundaries.
pub fn extract_quick_tunnel_url(line: &str) -> Option<String> {
    const SUFFIX: &str = ".trycloudflare.com";
    const NEEDLE: &str = "https://";
    // to_ascii_lowercase preserves byte offsets, so matching against the
    // lowercased line is safe for slicing.
    let lower = strip_ansi(line).to_ascii_lowercase();
    let mut from = 0usize;
    while let Some(idx) = lower[from..].find(NEEDLE) {
        let start = from + idx + NEEDLE.len();
        let host_len = lower[start..]
            .chars()
            .take_while(|c| is_host_char(*c))
            .map(char::len_utf8)
            .sum::<usize>();
        let host = lower[start..start + host_len].trim_end_matches('.');
        if let Some(label) = host.strip_suffix(SUFFIX) {
            if !label.is_empty()
                && label
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-')
            {
                return Some(format!("https://{host}"));
            }
        }
        from = start;
    }
    None
}

/// Parse `<host>:<port>` out of a single token. Returns the full endpoint.
fn parse_host_port(token: &str) -> Option<String> {
    let (host, port) = token.rsplit_once(':')?;
    if host.is_empty() || !host.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return None;
    }
    // Must look like a host (dotted or containing letters), not a bare number.
    if !host.contains('.') && !host.chars().any(|c| c.is_ascii_alphabetic()) {
        return None;
    }
    if port.is_empty() || !port.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let port: u16 = port.parse().ok()?;
    if port == 0 {
        return None;
    }
    Some(format!("{host}:{port}"))
}

/// Parse the bore public endpoint from a log line. Only lines that plausibly
/// announce the forwarding are considered, so the control-channel line
/// (`connected to server bore.pub:2200`) is never mistaken for the endpoint.
pub fn extract_bore_endpoint(line: &str) -> Option<String> {
    let plain = strip_ansi(line);
    let lower = plain.to_ascii_lowercase();
    let announces_forwarding = lower.contains("listening")
        || lower.contains("forwarding")
        || lower.contains("remote_port")
        || lower.contains("remote port");
    if !announces_forwarding {
        return None;
    }
    for token in plain.split(|c: char| {
        c.is_whitespace()
            || matches!(
                c,
                '|' | '"'
                    | '\''
                    | '('
                    | ')'
                    | '['
                    | ']'
                    | '<'
                    | '>'
                    | ','
                    | ';'
            )
    }) {
        let token = token.trim_matches(|c: char| c == '.' || c == ':');
        if let Some(ep) = parse_host_port(token) {
            return Some(ep);
        }
    }
    None
}

/// Fallback for older/phrased-differently bore output such as
/// `connected to server remote_port=62457` (no host in the line; the caller
/// combines the port with the known bore server).
pub fn extract_remote_port(line: &str) -> Option<u16> {
    let plain = strip_ansi(line);
    let lower = plain.to_ascii_lowercase();
    let idx = lower
        .find("remote_port=")
        .or_else(|| lower.find("remote port "))?;
    let digits: String = plain[idx..]
        .chars()
        .skip_while(|c| !c.is_ascii_digit())
        .take_while(|c| c.is_ascii_digit())
        .collect();
    if digits.is_empty() {
        return None;
    }
    digits.parse::<u16>().ok().filter(|p| *p != 0)
}

/// Substrings (lowercased) that mark an error-ish output line. These only
/// surface in `state.error` for display — the engine decides life/death by
/// process exit, never by a single log line.
const CLOUDFLARE_ERROR_MARKERS: &[&str] = &[
    "failed to connect",
    "could not start tunnel",
    "failed to serve",
    "failed to request quick tunnel",
    "unable to reach the origin",
    "connection refused",
    "failed to dial",
    "handshake failed",
    "dial tcp",
];

const BORE_ERROR_MARKERS: &[&str] = &[
    "error", "failed", "refused", "timed out", "panic", "denied", "invalid",
];

/// frpc log phrases (lowercased) that mark an error-ish line. Calibrated on
/// 0.71.0: note that fatal control-channel failures are logged as `[W]`
/// "connect to server error: ..." plus a bare "login to the server failed:"
/// stderr line, and that DNS resolution problems surface only as
/// "session shutdown" (the underlying resolver error is swallowed).
const FRP_ERROR_MARKERS: &[&str] = &[
    // fatal control-channel phrases (also promoted to error level below)
    "connect to server error",
    "login to the server failed",
    "login to server failed",
    "start error",
    // per-proxy / per-connection failures
    "proxy name conflict",
    "already exists",
    "port already used",
    "address already in use",
    "connect to local service",
    "connection refused",
    "dial tcp",
    "no such host",
    "i/o timeout",
    "session shutdown",
    "authentication failed",
    "user is disabled",
    "version mismatch",
    "incompatible",
    // generic fallbacks
    "error", "failed",
];

/// frpc phrases that are fatal for the attempt even though frpc logs them at
/// `[W]` (or as a bare stderr line with no level marker at all): after a
/// login failure frpc exits, and after a proxy rejection it stays alive but
/// serves nothing.
const FRP_FATAL_MARKERS: &[&str] = &[
    "connect to server error",
    "login to the server failed",
    "login to server failed",
    "start error",
];

pub fn is_error_line(backend: Backend, line: &str) -> bool {
    let lower = strip_ansi(line).to_ascii_lowercase();
    match backend {
        Backend::Cloudflare => CLOUDFLARE_ERROR_MARKERS.iter().any(|m| lower.contains(m)),
        Backend::Bore => BORE_ERROR_MARKERS.iter().any(|m| lower.contains(m)),
        Backend::Frp => FRP_ERROR_MARKERS.iter().any(|m| lower.contains(m)),
        Backend::CloudflareNamed => {
            lower.contains("err")
                || lower.contains("failed")
                || lower.contains("unable to reach the origin service")
        }
    }
}

/// Map one output line to a log level ("info" | "warn" | "error") for the
/// `tunnel://log` event. cloudflared prefixes INF/WRN/ERR; bore emits
/// INFO/WARN/ERROR tokens (wrapped in ANSI codes); frpc uses bracketed
/// `[I]`/`[W]`/`[E]` markers.
pub fn classify_level(backend: Backend, line: &str) -> &'static str {
    let plain = strip_ansi(line);
    if backend == Backend::Frp {
        if let Some(level) = classify_frpc_level(&plain) {
            return level;
        }
    }
    for token in plain.split(|c: char| !c.is_ascii_alphanumeric() && c != '_') {
        match token.to_ascii_lowercase().as_str() {
            "err" | "error" | "fatal" => return "error",
            "wrn" | "warn" | "warning" => return "warn",
            "inf" | "info" | "dbg" | "debug" | "trace" => return "info",
            _ => {}
        }
    }
    if is_error_line(backend, &plain) {
        "error"
    } else {
        "info"
    }
}

/// Classify one frpc line by its bracketed level marker, with fatal-phrase
/// promotion (see `FRP_FATAL_MARKERS`). `None` = no frpc marker found; the
/// caller falls back to the generic token/keyword logic.
fn classify_frpc_level(plain: &str) -> Option<&'static str> {
    let lower = plain.to_ascii_lowercase();
    if plain.contains("[E]") || FRP_FATAL_MARKERS.iter().any(|m| lower.contains(m)) {
        return Some("error");
    }
    if plain.contains("[W]") {
        return Some("warn");
    }
    if plain.contains("[I]") || plain.contains("[T]") || plain.contains("[D]") {
        return Some("info");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Backend, TunnelType};

    fn cfg(backend: Backend, port: u16) -> TunnelConfig {
        TunnelConfig {
            id: "t1".into(),
            name: "t".into(),
            tunnel_type: TunnelType::Http,
            backend,
            local_host: "127.0.0.1".into(),
            local_port: port,
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

    // --- command builders -------------------------------------------------

    #[test]
    fn cloudflare_args() {
        assert_eq!(
            build_args(&cfg(Backend::Cloudflare, 8080)),
            vec![
                "tunnel",
                "--url",
                "http://127.0.0.1:8080",
                "--protocol",
                "http2",
                "--no-autoupdate"
            ]
        );
    }

    #[test]
    fn bore_args_use_positional_port() {
        // Verified: `bore local --local-port N` is REJECTED by v0.5.1/v0.6.0;
        // the local port is a positional argument.
        assert_eq!(
            build_args(&cfg(Backend::Bore, 8099)),
            vec!["local", "--to", "bore.pub", "8099"]
        );
    }

    #[test]
    fn cf_named_args_run_without_url() {
        // Named tunnels get their routing from the remote-managed ingress;
        // the run token travels via TUNNEL_TOKEN, never argv.
        assert_eq!(
            build_args(&cfg(Backend::CloudflareNamed, 8080)),
            vec!["tunnel", "--protocol", "http2", "--no-autoupdate", "run"]
        );
    }

    #[test]
    fn cf_command_injects_tunnel_token_env() {
        let cmd = build_cf_command(&cfg(Backend::CloudflareNamed, 8080), Path::new("cloudflared"), "run-secret");
        let std_cmd = cmd.as_std();
        assert_eq!(
            std_cmd.get_envs().find(|(k, _)| *k == std::ffi::OsStr::new("TUNNEL_TOKEN")),
            Some((std::ffi::OsStr::new("TUNNEL_TOKEN"), Some(std::ffi::OsStr::new("run-secret"))))
        );
        // argv stays free of the token.
        assert_eq!(
            std_cmd.get_args().collect::<Vec<_>>(),
            vec![
                std::ffi::OsStr::new("tunnel"),
                std::ffi::OsStr::new("--protocol"),
                std::ffi::OsStr::new("http2"),
                std::ffi::OsStr::new("--no-autoupdate"),
                std::ffi::OsStr::new("run"),
            ]
        );
    }

    // --- cloudflared named-tunnel readiness ---------------------------------

    #[test]
    fn cf_named_tunnel_ready_on_registration_line() {
        assert!(cf_named_tunnel_ready(
            "2026-10-07T08:00:00Z INF Registered tunnel connection connIndex=0 id=abc-123"
        ));
        assert!(cf_named_tunnel_ready(
            "\u{1b}[2m2026-10-07T08:00:00Z\u{1b}[0m \u{1b}[32mINF\u{1b}[0m Registered tunnel connection connIndex=1"
        ));
        assert!(cf_named_tunnel_ready("registered tunnel connection (lowercase match)"));
        assert!(!cf_named_tunnel_ready(
            "2026-10-07T08:00:01Z INF Initiating graceful shutdown due to terminal disconnect"
        ));
        assert!(!cf_named_tunnel_ready(
            "2026-10-07T08:00:00Z INF Starting tunnel  |  https://x.trycloudflare.com"
        ));
        assert!(!cf_named_tunnel_ready("no signal here"));
    }

    // --- cloudflared URL parsing -------------------------------------------

    const CF_URL_LINE: &str = "2026-10-06T10:48:20Z INF |  https://vessels-arrow-kid-educated.trycloudflare.com                                      |";

    #[test]
    fn cloudflare_url_from_real_output_line() {
        assert_eq!(
            extract_quick_tunnel_url(CF_URL_LINE).as_deref(),
            Some("https://vessels-arrow-kid-educated.trycloudflare.com")
        );
    }

    #[test]
    fn cloudflare_url_bare_and_padded() {
        assert_eq!(
            extract_quick_tunnel_url("your url: https://a-b-c.trycloudflare.com").as_deref(),
            Some("https://a-b-c.trycloudflare.com")
        );
        assert_eq!(
            extract_quick_tunnel_url("https://word.trycloudflare.com, enjoy").as_deref(),
            Some("https://word.trycloudflare.com")
        );
        // trailing dot is tolerated
        assert_eq!(
            extract_quick_tunnel_url("https://word.trycloudflare.com.").as_deref(),
            Some("https://word.trycloudflare.com")
        );
    }

    #[test]
    fn cloudflare_ignores_non_quick_urls() {
        assert_eq!(
            extract_quick_tunnel_url(
                "INF pre-created named tunnel by following: https://developers.cloudflare.com/cloudflare-one/connections/connect-apps"
            ),
            None
        );
        assert_eq!(
            extract_quick_tunnel_url("INF Starting metrics server on 127.0.0.1:20241/metrics"),
            None
        );
        assert_eq!(extract_quick_tunnel_url("no urls here"), None);
    }

    #[test]
    fn cloudflare_rejects_lookalike_hosts() {
        // Suffix must be followed by the label; a sub-sub domain is not quick-tunnel.
        assert_eq!(
            extract_quick_tunnel_url("https://evil.com/u=https://good.trycloudflare.com.evil.com"),
            None
        );
        // Missing label before the suffix.
        assert_eq!(extract_quick_tunnel_url("https://.trycloudflare.com"), None);
        assert_eq!(extract_quick_tunnel_url("https://trycloudflare.com"), None);
    }

    // --- bore endpoint parsing ----------------------------------------------

    const BORE_LISTEN_LINE: &str = "\u{1b}[2m2026-10-06T10:48:08.905692Z\u{1b}[0m \u{1b}[32m INFO\u{1b}[0m \u{1b}[2mbore_cli::client\u{1b}[0m\u{1b}[2m:\u{1b}[0m listening at bore.pub:62457";
    const BORE_CONNECT_LINE: &str = "\u{1b}[2m2026-10-06T10:48:08.904579Z\u{1b}[0m \u{1b}[32m INFO\u{1b}[0m \u{1b}[2mbore_cli::client\u{1b}[0m\u{1b}[2m:\u{1b}[0m connected to server \u{1b}[3mremote_port\u{1b}[0m\u{1b}[2m=\u{1b}[0m62457";

    #[test]
    fn bore_endpoint_from_real_listening_line() {
        assert_eq!(
            extract_bore_endpoint(BORE_LISTEN_LINE).as_deref(),
            Some("bore.pub:62457")
        );
    }

    #[test]
    fn bore_endpoint_falls_back_to_remote_port() {
        // The "connected to server remote_port=N" line has no host:port token,
        // so extract_bore_endpoint misses it and the remote_port fallback kicks in.
        assert_eq!(extract_bore_endpoint(BORE_CONNECT_LINE), None);
        assert_eq!(extract_remote_port(BORE_CONNECT_LINE), Some(62457));
        assert_eq!(
            parse_public_endpoint(Backend::Bore, BORE_CONNECT_LINE).as_deref(),
            Some("bore.pub:62457")
        );
        assert_eq!(
            parse_public_endpoint(Backend::Bore, BORE_LISTEN_LINE).as_deref(),
            Some("bore.pub:62457")
        );
    }

    #[test]
    fn bore_accepts_forwarding_and_remote_port_phrases() {
        assert_eq!(
            extract_bore_endpoint("forwarding to bore.pub:15967").as_deref(),
            Some("bore.pub:15967")
        );
        assert_eq!(
            extract_bore_endpoint("remote port 12345 -> 10.0.0.1:8080").as_deref(),
            Some("10.0.0.1:8080")
        );
    }

    #[test]
    fn bore_ignores_control_channel_and_noise() {
        // Control connection port (2200) must never become the public endpoint.
        assert_eq!(
            extract_bore_endpoint("INFO bore_cli::client: connected to server bore.pub:2200"),
            None
        );
        assert_eq!(extract_bore_endpoint("ERROR connection refused"), None);
        assert_eq!(extract_bore_endpoint("plain text"), None);
        // "listening" gated but no host:port token present.
        assert_eq!(extract_bore_endpoint("listening for connections"), None);
    }

    // --- level classification -----------------------------------------------

    #[test]
    fn cloudflared_levels() {
        assert_eq!(
            classify_level(Backend::Cloudflare, "2026-10-06T10:48:20Z INF Version 2026.10.0"),
            "info"
        );
        assert_eq!(
            classify_level(
                Backend::Cloudflare,
                "2026-10-06T10:48:25Z ERR Failed to dial a quic connection error=\"timeout\" connIndex=0"
            ),
            "error"
        );
        assert_eq!(
            classify_level(Backend::Cloudflare, "2026-10-06T10:48:25Z WRN Retrying connection in up to 2s"),
            "warn"
        );
        // Level token absent -> keyword fallback.
        assert_eq!(
            classify_level(Backend::Cloudflare, "failed to connect to the origin"),
            "error"
        );
        assert_eq!(classify_level(Backend::Cloudflare, "just text"), "info");
    }

    #[test]
    fn bore_levels_with_ansi() {
        assert_eq!(classify_level(Backend::Bore, BORE_LISTEN_LINE), "info");
        assert_eq!(
            classify_level(
                Backend::Bore,
                "\u{1b}[31mERROR\u{1b}[0m \u{1b}[2mbore_cli::client\u{1b}[0m: connection refused"
            ),
            "error"
        );
        assert_eq!(
            classify_level(Backend::Bore, "\u{1b}[33m WARN\u{1b}[0m something"),
            "warn"
        );
    }

    #[test]
    fn strip_ansi_removes_all_sequences() {
        assert_eq!(strip_ansi(BORE_LISTEN_LINE), "2026-10-06T10:48:08.905692Z  INFO bore_cli::client: listening at bore.pub:62457");
        assert_eq!(strip_ansi("no escapes"), "no escapes");
        assert_eq!(strip_ansi("\u{1b}[1;32mgreen\u{1b}[0m"), "green");
        assert_eq!(strip_ansi("stray \u{1b} escape"), "stray  escape");
    }

    // --- frpc config generation ---------------------------------------------

    use crate::models::{AuthKind, ServerConfig};

    fn frps() -> ServerConfig {
        ServerConfig {
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
            subdomain_host: Some("mydomain.com".into()),
            frps_proxy_port_start: None,
            frps_proxy_port_end: None,
            deployed: true,
            frps_version: None,
            created_at: String::new(),
        }
    }

    fn frp_cfg(tunnel_type: TunnelType) -> TunnelConfig {
        TunnelConfig {
            id: "t-frp".into(),
            name: "t".into(),
            tunnel_type,
            backend: Backend::Frp,
            local_host: "127.0.0.1".into(),
            local_port: 9000,
            auto_start: false,
            created_at: String::new(),
            server_id: Some("srv1".into()),
            subdomain: None,
            remote_port: None,
            auth: None,
            ip_allowlist: Vec::new(),
            cf_tunnel_id: None,
            cf_hostname: None,
            cf_account_id: None,
        }
    }

    /// Real frpc 0.71.0 log lines (ANSI stripped), captured against a local
    /// frps with a matching token.
    const FRPC_LOGIN_LINE: &str = "2026-10-06 20:18:27.518 [I] [client/service.go:332] [8ffeba1af99c60df] login to server success, get run id [8ffeba1af99c60df]";
    const FRPC_PROXY_OK_LINE: &str = "2026-10-06 20:18:27.519 [I] [client/control.go:174] [8ffeba1af99c60df] [web-tcp] start proxy success";
    const FRPC_START_ERROR_LINE: &str = "2026-10-06 20:19:35.272 [W] [client/control.go:172] [fbcb25fbd0d6eaab] [other-tcp] start error: port already used";
    const FRPC_TOKEN_LINE: &str = "2026-10-06 20:18:02.936 [W] [client/service.go:323] connect to server error: token in login doesn't match token from configuration";
    const FRPC_BARE_LOGIN_FAILED_LINE: &str = "login to the server failed: token in login doesn't match token from configuration. With loginFailExit enabled, no additional retries will be attempted";
    const FRPC_REFUSED_LINE: &str = "2026-10-06 20:19:56.281 [W] [client/service.go:323] connect to server error: dial tcp 127.0.0.1:19999: connect: connection refused";
    const FRPC_SESSION_SHUTDOWN_LINE: &str = "2026-10-06 20:20:59.820 [W] [client/service.go:323] connect to server error: session shutdown";
    const FRPC_LOCAL_SERVICE_LINE: &str = "2026-10-06 20:20:57.726 [E] [proxy/proxy.go:237] [8ffeba1af99c60df] [web-tcp] connect to local service [127.0.0.1:8080] error: dial tcp 127.0.0.1:8080: connect: connection refused";

    #[test]
    fn frpc_toml_tcp_content_and_endpoint() {
        let mut cfg = frp_cfg(TunnelType::Tcp);
        cfg.remote_port = Some(17001);
        let (text, url) = build_frpc_toml(&cfg, &frps(), "secret").expect("tcp toml");
        for expected in [
            "serverAddr = \"vps.example.com\"",
            "serverPort = 7000",
            "auth.token = \"secret\"",
            "transport.tls.enable = true",
            "[[proxies]]",
            "name = \"t-frp\"",
            "type = \"tcp\"",
            "localIP = \"127.0.0.1\"",
            "localPort = 9000",
            "remotePort = 17001",
        ] {
            assert!(text.contains(expected), "missing {expected:?} in:\n{text}");
        }
        assert!(!text.contains("subdomain"));
        assert_eq!(url.as_deref(), Some("vps.example.com:17001"));
    }

    #[test]
    fn frpc_toml_http_subdomain_and_endpoint() {
        let mut cfg = frp_cfg(TunnelType::Http);
        cfg.subdomain = Some("app".into());
        let (text, url) = build_frpc_toml(&cfg, &frps(), "secret").expect("http toml");
        assert!(text.contains("type = \"http\""));
        assert!(text.contains("subdomain = \"app\""));
        assert!(text.contains("localPort = 9000"));
        assert!(!text.contains("remotePort"));
        assert_eq!(url.as_deref(), Some("http://app.mydomain.com:8080"));
    }

    #[test]
    fn frpc_toml_http_full_domain_becomes_custom_domain() {
        let mut cfg = frp_cfg(TunnelType::Http);
        cfg.subdomain = Some("app.other.com".into());
        let (text, url) = build_frpc_toml(&cfg, &frps(), "secret").expect("http toml");
        assert!(text.contains("customDomains = [\"app.other.com\"]"));
        assert!(!text.contains("subdomain ="));
        assert_eq!(url.as_deref(), Some("http://app.other.com:8080"));
    }

    #[test]
    fn frpc_toml_http_falls_back_to_server_host_without_subdomain_host() {
        let mut server = frps();
        server.subdomain_host = None;
        let mut cfg = frp_cfg(TunnelType::Http);
        cfg.subdomain = Some("app".into());
        let (_, url) = build_frpc_toml(&cfg, &server, "secret").expect("http toml");
        // Documented degradation: no wildcard domain -> endpoint is the bare
        // server host on the vhost port (per-subdomain routing unavailable).
        assert_eq!(url.as_deref(), Some("http://vps.example.com:8080"));
    }

    #[test]
    fn frpc_toml_requires_remote_port_for_tcp() {
        let cfg = frp_cfg(TunnelType::Tcp); // remote_port = None
        assert!(build_frpc_toml(&cfg, &frps(), "secret").is_err());
    }

    #[test]
    fn frpc_toml_udp_content_and_endpoint() {
        let mut cfg = frp_cfg(TunnelType::Udp);
        cfg.remote_port = Some(17002);
        cfg.local_host = "192.168.1.10".into();
        let (text, url) = build_frpc_toml(&cfg, &frps(), "secret").expect("udp toml");
        for expected in [
            "type = \"udp\"",
            "localIP = \"192.168.1.10\"",
            "localPort = 9000",
            "remotePort = 17002",
        ] {
            assert!(text.contains(expected), "missing {expected:?} in:\n{text}");
        }
        assert!(!text.contains("subdomain"));
        assert_eq!(url.as_deref(), Some("udp://vps.example.com:17002"));
    }

    #[test]
    fn frpc_toml_requires_remote_port_for_udp() {
        let cfg = frp_cfg(TunnelType::Udp); // remote_port = None
        assert!(build_frpc_toml(&cfg, &frps(), "secret").is_err());
    }

    #[test]
    fn frpc_toml_requires_subdomain_for_http() {
        let cfg = frp_cfg(TunnelType::Http); // subdomain = None
        assert!(build_frpc_toml(&cfg, &frps(), "secret").is_err());
    }

    #[test]
    fn frpc_toml_escapes_strings() {
        let mut server = frps();
        server.host = "v\"ps\\example.com".into();
        let mut cfg = frp_cfg(TunnelType::Tcp);
        cfg.remote_port = Some(1);
        let (text, _) =
            build_frpc_toml(&cfg, &server, "to\"ke\\n").expect("escaped toml");
        assert!(text.contains("serverAddr = \"v\\\"ps\\\\example.com\""));
        assert!(text.contains("auth.token = \"to\\\"ke\\\\n\""));
        // Must still be valid TOML.
        let value: toml::Value = toml::from_str(&text).expect("valid toml");
        assert_eq!(
            value["serverAddr"].as_str(),
            Some("v\"ps\\example.com")
        );
    }

    // --- frpc log parsing ----------------------------------------------------

    #[test]
    fn frpc_levels_from_real_output() {
        // Bracketed markers, ANSI stripped by classify_level itself.
        assert_eq!(classify_level(Backend::Frp, FRPC_LOGIN_LINE), "info");
        assert_eq!(classify_level(Backend::Frp, FRPC_PROXY_OK_LINE), "info");
        // Proxy rejection is [W] but fatal for the attempt -> error.
        assert_eq!(classify_level(Backend::Frp, FRPC_START_ERROR_LINE), "error");
        // Fatal control-channel failures are [W] -> promoted to error.
        assert_eq!(classify_level(Backend::Frp, FRPC_TOKEN_LINE), "error");
        assert_eq!(classify_level(Backend::Frp, FRPC_REFUSED_LINE), "error");
        assert_eq!(classify_level(Backend::Frp, FRPC_LOCAL_SERVICE_LINE), "error");
        // Bare stderr line (no marker, no timestamp) -> keyword fallback.
        assert_eq!(
            classify_level(Backend::Frp, FRPC_BARE_LOGIN_FAILED_LINE),
            "error"
        );
        // [I] line that merely mentions an error-ish word elsewhere stays info.
        assert_eq!(
            classify_level(
                Backend::Frp,
                "2026-10-06 20:18:27.515 [I] [sub/root.go:194] start frpc service for config file [gen.toml] with aggregated configuration"
            ),
            "info"
        );
    }

    #[test]
    fn frpc_levels_with_ansi() {
        let raw = "\u{1b}[1;31m2026-10-06 20:20:57.726 [E] [proxy/proxy.go:237] [x] connect to local service [127.0.0.1:8080] error: dial tcp: refused\u{1b}[0m";
        assert_eq!(classify_level(Backend::Frp, raw), "error");
        let warn = "\u{1b}[1;33m2026-10-06 20:18:02.936 [W] [client/service.go:323] something odd\u{1b}[0m";
        assert_eq!(classify_level(Backend::Frp, warn), "warn");
    }

    #[test]
    fn frpc_error_markers_from_real_output() {
        assert!(is_error_line(Backend::Frp, FRPC_TOKEN_LINE));
        assert!(is_error_line(Backend::Frp, FRPC_BARE_LOGIN_FAILED_LINE));
        assert!(is_error_line(Backend::Frp, FRPC_START_ERROR_LINE));
        assert!(is_error_line(Backend::Frp, FRPC_SESSION_SHUTDOWN_LINE));
        assert!(is_error_line(Backend::Frp, FRPC_LOCAL_SERVICE_LINE));
        // Success / noise lines must not be errors.
        assert!(!is_error_line(Backend::Frp, FRPC_LOGIN_LINE));
        assert!(!is_error_line(Backend::Frp, FRPC_PROXY_OK_LINE));
        assert!(!is_error_line(
            Backend::Frp,
            "2026-10-06 20:18:27.518 [I] [proxy/proxy_manager.go:183] [x] proxy added: [web-http web-tcp]"
        ));
    }

    #[test]
    fn frpc_proxy_started_detection() {
        assert!(frpc_proxy_started(FRPC_PROXY_OK_LINE));
        assert!(frpc_proxy_started(
            "\u{1b}[1;34m2026-10-06 20:18:27.519 [I] [client/control.go:174] [x] [web-http] start proxy success\u{1b}[0m"
        ));
        assert!(!frpc_proxy_started(FRPC_LOGIN_LINE));
        assert!(!frpc_proxy_started(FRPC_START_ERROR_LINE));
    }

    #[test]
    fn frpc_start_error_detection() {
        assert!(frpc_start_error(FRPC_START_ERROR_LINE));
        assert!(frpc_start_error(
            "2026-10-06 20:18:43.327 [W] [client/control.go:172] [x] [web-http] start error: proxy [web-http] already exists"
        ));
        assert!(!frpc_start_error(FRPC_PROXY_OK_LINE));
        assert!(!frpc_start_error(FRPC_TOKEN_LINE));
    }

    #[test]
    fn frp_endpoint_never_parsed_from_lines() {
        // The URL assembly needs server info (vhost port, subdomain host), so
        // pure line parsing always returns None for Frp; the engine uses the
        // expected URL from prepare_frpc_config instead.
        assert_eq!(parse_public_endpoint(Backend::Frp, FRPC_PROXY_OK_LINE), None);
    }
}
