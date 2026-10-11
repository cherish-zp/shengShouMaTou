// R3 IMPLEMENTS: persistent server registry (`servers.json`) + keychain
// storage for SSH passwords / frps tokens (keyring crate).
//
// The public signatures below are the contract the rest of the app codes
// against; keep them stable. Secrets NEVER live in servers.json nor cross
// the IPC boundary back to the frontend — they live in the OS keychain
// under the service name `com.masterfulhands.pier` with accounts
// `ssh-secret-{server_id}` / `frps-token-{server_id}`.
use std::fs;
use std::path::PathBuf;

use tauri::Manager;

use crate::models::ServerConfig;

/// OS keychain service name shared by every Pier secret.
/// v0.2.0 前的钥匙串 service 名——迁移逻辑用它寻址旧条目。
#[allow(dead_code)]
const KEYRING_SERVICE: &str = "com.masterfulhands.pier";
const SSH_SECRET_PREFIX: &str = "ssh-secret-";
const FRPS_TOKEN_PREFIX: &str = "frps-token-";

// ---------------------------------------------------------------------------
// File storage: `<app_data_dir>/servers.json`
// ---------------------------------------------------------------------------

/// `<app_data_dir>`, with a best-effort fallback so the app still works if
/// the path cannot be resolved (mirrors the logic in commands.rs).
fn data_dir(app: &tauri::AppHandle) -> PathBuf {
    app.path().app_data_dir().unwrap_or_else(|e| {
        eprintln!("[pier] app data dir unavailable ({e}); using fallback location");
        dirs::data_dir()
            .map(|d| d.join(crate::brand::DISPLAY_NAME_ZH))
            .unwrap_or_else(std::env::temp_dir)
    })
}

fn servers_path(app: &tauri::AppHandle) -> PathBuf {
    data_dir(app).join("servers.json")
}

/// Load all servers from `<app_data_dir>/servers.json`.
pub fn load_servers(app: &tauri::AppHandle) -> Vec<ServerConfig> {
    let path = servers_path(app);
    match fs::read_to_string(&path) {
        Ok(text) => match serde_json::from_str(&text) {
            Ok(servers) => servers,
            Err(e) => {
                eprintln!(
                    "[pier] {} is corrupted ({e}); treating as empty",
                    path.display()
                );
                Vec::new()
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => {
            eprintln!("[pier] failed to read {}: {e}", path.display());
            Vec::new()
        }
    }
}

/// Insert or replace a server entry (by id).
pub fn save_server(app: &tauri::AppHandle, server: &ServerConfig) -> Result<(), String> {
    let path = servers_path(app);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("failed to create data dir: {e}"))?;
    }
    let mut all = load_servers(app);
    match all.iter_mut().find(|s| s.id == server.id) {
        Some(existing) => *existing = server.clone(),
        None => all.push(server.clone()),
    }
    let text = serde_json::to_string_pretty(&all)
        .map_err(|e| format!("failed to serialize servers: {e}"))?;
    crate::util::write_json_atomic(&path, &text)
}

/// Remove a server entry and its keychain secrets. Returns true if removed.
pub fn remove_server(app: &tauri::AppHandle, id: &str) -> Result<bool, String> {
    let path = servers_path(app);
    let mut all = load_servers(app);
    let before = all.len();
    all.retain(|s| s.id != id);
    let removed = all.len() != before;

    if removed {
        let text = serde_json::to_string_pretty(&all)
            .map_err(|e| format!("failed to serialize servers: {e}"))?;
        crate::util::write_json_atomic(&path, &text)?;
    }

    // Best-effort keychain cleanup: a leftover secret would be orphaned but
    // harmless, and removal must not fail just because the keychain is busy.
    for (prefix, what) in [
        (SSH_SECRET_PREFIX, "SSH password"),
        (FRPS_TOKEN_PREFIX, "frps token"),
    ] {
        if let Err(e) = delete_keyring_secret(&format!("{prefix}{id}")) {
            eprintln!("[pier] keychain cleanup for {what} of server {id} failed: {e}");
        }
    }
    Ok(removed)
}

// ---------------------------------------------------------------------------
// Keychain storage (keyring crate)
// ---------------------------------------------------------------------------

// v0.2.0 起秘密统一存本地 SQLite（secrets_store）；这些函数保留原签名，
// 上层（SSH 密码 / frps token / 隧道鉴权密码）无感切换。旧钥匙串条目由
// commands::init_runtime 的迁移一次性搬入。
fn get_keyring_secret(account: &str) -> Result<String, String> {
    crate::secrets_store::get(account)
}

fn set_keyring_secret(account: &str, secret: &str) -> Result<(), String> {
    crate::secrets_store::set(account, secret)
}

fn delete_keyring_secret(account: &str) -> Result<(), String> {
    crate::secrets_store::delete(account)
}

pub fn ssh_secret_account(server_id: &str) -> String {
    format!("{SSH_SECRET_PREFIX}{server_id}")
}

pub fn frps_token_account(server_id: &str) -> String {
    format!("{FRPS_TOKEN_PREFIX}{server_id}")
}

/// Fetch the SSH secret straight from the keychain by server id. Exists for
/// the SSH layer, which authenticates from a `ServerConfig` alone and has no
/// `AppHandle` — the keyring is a global OS service so none is needed.
pub fn fetch_ssh_secret(server_id: &str) -> Result<String, String> {
    get_keyring_secret(&ssh_secret_account(server_id))
}

/// Store the SSH secret for a server.
pub fn set_ssh_secret(server_id: &str, secret: &str) -> Result<(), String> {
    set_keyring_secret(&ssh_secret_account(server_id), secret)
}

/// Store the frps auth token generated during deployment.
pub fn set_frps_token(server_id: &str, token: &str) -> Result<(), String> {
    set_keyring_secret(&frps_token_account(server_id), token)
}

/// Fetch the frps auth token for building frpc configs.
pub fn get_frps_token(server_id: &str) -> Result<String, String> {
    get_keyring_secret(&frps_token_account(server_id))
}

/// Fetch the frps token if present, `Ok(None)` when never stored. Used by the
/// deploy upgrade path, which must keep the existing token when re-deploying.
pub fn try_frps_token(server_id: &str) -> Result<Option<String>, String> {
    crate::secrets_store::try_get(&frps_token_account(server_id))
}


// ---------------------------------------------------------------------------
// Tunnel basic-auth passwords (M3) — same keychain pattern as above.
// R5 (local forwarder) owns the implementation below; signatures are frozen.
// ---------------------------------------------------------------------------

fn tunnel_auth_account(tunnel_id: &str) -> String {
    format!("tunnel-auth-{tunnel_id}")
}

/// Store (or replace) the basic-auth password for a tunnel.
pub fn set_tunnel_auth_password(tunnel_id: &str, password: &str) -> Result<(), String> {
    set_keyring_secret(&tunnel_auth_account(tunnel_id), password)
}

/// Fetch the basic-auth password for a tunnel, `Ok(None)` when not set.
pub fn get_tunnel_auth_password(tunnel_id: &str) -> Result<Option<String>, String> {
    crate::secrets_store::try_get(&tunnel_auth_account(tunnel_id))
}

/// Delete the basic-auth password when a tunnel's auth is removed.
pub fn delete_tunnel_auth_password(tunnel_id: &str) -> Result<(), String> {
    delete_keyring_secret(&tunnel_auth_account(tunnel_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(id: &str) -> ServerConfig {
        ServerConfig {
            id: id.to_string(),
            name: format!("srv-{id}"),
            host: "192.0.2.10".into(),
            port: 22,
            username: "root".into(),
            auth_kind: crate::models::AuthKind::Password,
            frps_bind_port: 7000,
            frps_vhost_http_port: 8080,
            frps_vhost_https_port: 8443,
            frps_dashboard_port: 7500,
            subdomain_host: None,
            frps_proxy_port_start: None,
            frps_proxy_port_end: None,
            deployed: false,
            frps_version: None,
            created_at: "2026-10-06T00:00:00+00:00".into(),
        }
    }

    // The file layer is pure std + serde, so it can be exercised without a
    // real AppHandle by pointing the keyring-touching functions aside; these
    // tests cover the JSON round-trip and atomicity-relevant behaviour.
    fn write_raw(path: &std::path::Path, text: &str) {
        fs::write(path, text).unwrap();
    }

    #[test]
    fn keyring_account_naming_is_stable() {
        // Accounts are part of the on-disk (keychain) contract: the deploy
        // flow and frpc config builder both resolve them by these names.
        assert_eq!(ssh_secret_account("abc"), "ssh-secret-abc");
        assert_eq!(frps_token_account("abc"), "frps-token-abc");
        assert_eq!(KEYRING_SERVICE, "com.masterfulhands.pier");
    }

    #[test]
    fn server_serialization_roundtrip_and_secret_keeping() {
        // Secrets must never be part of ServerConfig, so serializing a server
        // cannot leak one by construction. Verify no secret-looking KEY exists
        // (the auth_kind VALUE is the string "password" — that is fine).
        let s = sample("x1");
        let json = serde_json::to_string(&s).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(value.get("password").is_none());
        assert!(value.get("secret").is_none());
        assert!(value.get("token").is_none());
        assert_eq!(
            value.get("authKind").and_then(|v| v.as_str()),
            Some("password")
        );
        let back: ServerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "x1");
        assert_eq!(back.frps_bind_port, 7000);
    }

    #[test]
    fn corrupted_servers_json_is_not_our_format() {
        // Documents the degradation contract: garbage must fail parsing (and
        // load_servers then degrades to empty), never panic.
        let dir = std::env::temp_dir().join(format!("pier-store-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let p = dir.join("servers.json");
        write_raw(&p, "{ not valid json !!!");
        let parsed: Result<Vec<ServerConfig>, _> =
            serde_json::from_str(&fs::read_to_string(&p).unwrap());
        assert!(parsed.is_err());
        let _ = fs::remove_dir_all(&dir);
    }
}
