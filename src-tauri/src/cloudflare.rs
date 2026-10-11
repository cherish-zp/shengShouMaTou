// R7 IMPLEMENTS: Cloudflare API client for Named Tunnels.
//
// All functions take the user's API token explicitly (the API token also
// lives in the OS keychain under `cf-{tunnel_id}` per tunnel — see
// `commands::cf_provision` — and the tunnel-run token under
// `cf-tunnel-token-{tunnel_id}`). Endpoints per
// docs/FEATURE-cloudflare-named-tunnel.md §3.2, request/response shapes
// verified against Cloudflare's official OpenAPI schema (2026-10):
//
//   * PUT .../cfd_tunnel/{tid}/configurations takes `{"config": {"ingress":
//     [...]}}` — the ingress array is NESTED under a `config` key (the same
//     wrapper appears in the GET response's `result`).
//   * POST .../cfd_tunnel may omit the run `token` field in some API
//     revisions; `GET .../cfd_tunnel/{tid}/token` returns it as a bare
//     string and is used as the fallback.
//   * GET /zones/{zid}/dns_records supports server-side `name`/`content`/
//     `type`/`per_page`/`page` filters; zone objects carry
//     `account: {id, name}`.
//
// Public signatures below are frozen — commands.rs and providers.rs /
// engine.rs code against them.
//
// Blocking model: the sync tauri commands call these functions via
// `tauri::async_runtime::spawn_blocking` (see commands.rs). Every blocking
// entry point drives its async body the same way `binman::install` does — on
// a dedicated worker thread running a current-thread tokio runtime, result
// passed back over a channel. Keychain helpers are plain blocking calls (no
// runtime needed).

use std::time::Duration;

use serde::Deserialize;

use crate::models::{CfAccount, CfProvisionInput, CfZone, TunnelConfig};

const API_BASE: &str = "https://api.cloudflare.com/client/v4";
/// Whole-request cap: API payloads are small JSON — anything slower is a
/// hung connection and must not stall a tunnel start forever. Applied
/// per-request on top of the shared client (see util::http_client).
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Hard cap on zone-list pages (50/page => 2000 zones) so a misbehaving
/// server reporting an ever-growing `total_pages` cannot spin forever.
const MAX_ZONE_PAGES: u32 = 40;

/// Cloudflare API error codes meaning "a record with this name already
/// exists" — the CNAME-upsert reuse path triggers on either.
const DNS_NAME_CONFLICT_CODES: [i64; 2] = [81053, 81057];

// ---------------------------------------------------------------------------
// Blocking bridge (mirrors binman::install)
// ---------------------------------------------------------------------------

/// Run `fut` to completion on a dedicated worker thread with its own
/// current-thread runtime; safe to call from sync tauri commands (main
/// thread) or any thread. Returns the future's result.
fn run_blocking<F, T>(worker: &str, fut: F) -> Result<T, String>
where
    F: std::future::Future<Output = Result<T, String>> + Send + 'static,
    T: Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name(worker.to_string())
        .spawn(move || {
            let result = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| format!("failed to start async runtime: {e}"))
                .and_then(|rt| rt.block_on(fut));
            let _ = tx.send(result);
        })
        .map_err(|e| format!("failed to spawn worker thread: {e}"))?;
    rx.recv()
        .map_err(|_| "worker exited unexpectedly".to_string())?
}

// ---------------------------------------------------------------------------
// Secret storage (v0.2.0: local SQLite via secrets_store — see that module
// for why the macOS keychain was replaced). Account strings are unchanged.
// ---------------------------------------------------------------------------

const RUN_TOKEN_PREFIX: &str = "cf-tunnel-token-";
/// API token account: `cf-{tunnel_id}`.
const API_TOKEN_PREFIX: &str = "cf-";

fn keychain_set(account: &str, secret: &str) -> Result<(), String> {
    crate::secrets_store::set(account, secret)
}

fn keychain_delete(account: &str) -> Result<(), String> {
    crate::secrets_store::delete(account)
}

fn keychain_get(account: &str) -> Result<String, String> {
    crate::secrets_store::get(account)
}

fn run_token_account(tunnel_id: &str) -> String {
    format!("{RUN_TOKEN_PREFIX}{tunnel_id}")
}

fn api_token_account(tunnel_id: &str) -> String {
    format!("{API_TOKEN_PREFIX}{tunnel_id}")
}

// ---------------------------------------------------------------------------
// API response envelope + error type
// ---------------------------------------------------------------------------

/// One entry of the Cloudflare envelope `errors` array. `code` stays a raw
/// JSON value because some endpoints have been observed emitting string
/// codes; `code_i64` normalizes it.
#[derive(Debug, Clone, Deserialize)]
struct CfApiErrorEntry {
    #[serde(default)]
    code: Option<serde_json::Value>,
    #[serde(default)]
    message: Option<String>,
}

impl CfApiErrorEntry {
    fn code_i64(&self) -> Option<i64> {
        match &self.code {
            Some(serde_json::Value::Number(n)) => n.as_i64(),
            Some(serde_json::Value::String(s)) => s.parse().ok(),
            _ => None,
        }
    }

    fn message_str(&self) -> &str {
        self.message.as_deref().unwrap_or("unknown error")
    }
}

/// Human-readable rendering of the envelope errors: `[81053] message`.
fn format_cf_errors(errors: &[CfApiErrorEntry]) -> String {
    errors
        .iter()
        .map(|e| match e.code_i64() {
            Some(code) => format!("[{code}] {}", e.message_str()),
            None => e.message_str().to_string(),
        })
        .collect::<Vec<_>>()
        .join("；")
}

/// Every Cloudflare v4 response wraps its payload in this envelope.
#[derive(Debug, Deserialize)]
struct CfEnvelope {
    success: bool,
    #[serde(default)]
    errors: Vec<CfApiErrorEntry>,
    #[serde(default)]
    result: serde_json::Value,
    #[serde(default)]
    result_info: Option<CfPageInfo>,
}

#[derive(Debug, Deserialize)]
struct CfPageInfo {
    #[serde(default)]
    total_pages: u32,
}

/// Typed failure used internally by `cf_request` so callers can match on the
/// numeric API error code (e.g. 81053 CNAME conflicts) while `Display` still
/// yields the human-readable message.
#[derive(Debug)]
struct CfApiError {
    /// HTTP status; 0 = the request never got a response (network layer).
    status: u16,
    code: Option<i64>,
    message: String,
}

impl std::fmt::Display for CfApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl CfApiError {
    fn plain(message: String) -> Self {
        Self {
            status: 0,
            code: None,
            message,
        }
    }
}

// ---------------------------------------------------------------------------
// The one HTTP funnelling point
// ---------------------------------------------------------------------------

async fn cf_request(
    method: reqwest::Method,
    token: &str,
    path: &str,
    json: Option<serde_json::Value>,
) -> Result<CfEnvelope, CfApiError> {
    let url = format!("{API_BASE}{path}");
    let client = crate::util::http_client();
    let mut req = client
        .request(method, &url)
        .timeout(REQUEST_TIMEOUT)
        .bearer_auth(token);
    // reqwest runs without the `json` feature, so the payload is serialized
    // here with serde_json directly (same wire format either way).
    if let Some(body) = json {
        let bytes = serde_json::to_vec(&body)
            .map_err(|e| CfApiError::plain(format!("请求体序列化失败：{e}")))?;
        req = req
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(bytes);
    }
    let resp = req.send().await.map_err(|e| {
        CfApiError::plain(format!("请求 Cloudflare API 失败 ({url})：{e}"))
    })?;
    let status = resp.status().as_u16();
    let body = resp.bytes().await.map_err(|e| CfApiError {
        status,
        code: None,
        message: format!("读取 Cloudflare API 响应失败 ({url})：{e}"),
    })?;
    let envelope: CfEnvelope = serde_json::from_slice(&body).map_err(|e| CfApiError {
        status,
        code: None,
        message: format!("Cloudflare API 返回了无法解析的响应（HTTP {status}，{url}）：{e}"),
    })?;
    if !envelope.success {
        let message = format!("Cloudflare API 错误：{}", format_cf_errors(&envelope.errors));
        let code = envelope.errors.first().and_then(|e| e.code_i64());
        return Err(CfApiError {
            status,
            code,
            message,
        });
    }
    if !(200..300).contains(&status) {
        return Err(CfApiError {
            status,
            code: None,
            message: format!("Cloudflare API 返回 HTTP {status}，但响应声称成功（{url}）"),
        });
    }
    Ok(envelope)
}

// ---------------------------------------------------------------------------
// Raw API payloads (Cloudflare JSON -> local structs)
// ---------------------------------------------------------------------------

/// `GET /accounts` result entry: `{id, name}` — matches `CfAccount` directly.
#[derive(Debug, Deserialize)]
struct CfAccountRaw {
    id: String,
    #[serde(default)]
    name: String,
}

/// Zone JSON: `{id, name, account: {id, name}, ...}`. `CfZone.account_id`
/// must be filled from the nested account object, hence the raw shape.
#[derive(Debug, Deserialize)]
struct CfZoneRaw {
    id: String,
    name: String,
    #[serde(default)]
    account: Option<CfAccountRef>,
}

#[derive(Debug, Deserialize)]
struct CfAccountRef {
    id: String,
}

impl CfZoneRaw {
    fn into_model(self) -> CfZone {
        CfZone {
            account_id: self.account.map(|a| a.id).unwrap_or_default(),
            id: self.id,
            name: self.name,
        }
    }
}

/// Tunnel creation result: `{id, name, status, token?, ...}`. `token` (the
/// tunnel-run token) is optional across API revisions; see
/// `fetch_tunnel_token` for the fallback endpoint.
#[derive(Debug, Deserialize)]
struct CfTunnelCreated {
    id: String,
    #[serde(default)]
    token: Option<String>,
}

/// DNS record: `{id, name, type, content, ...}`.
#[derive(Debug, Clone, Deserialize)]
struct CfDnsRecord {
    id: String,
    name: String,
    #[serde(default)]
    r#type: String,
    #[serde(default)]
    content: String,
}

// ---------------------------------------------------------------------------
// Public API (frozen signatures)
// ---------------------------------------------------------------------------

/// Validate the API token; return the accounts it can see.
pub fn verify_token(token: &str) -> Result<Vec<CfAccount>, String> {
    let token = require_token(token)?;
    run_blocking("cf-verify-token", async move {
        verify_token_async(&token).await
    })
}

/// List zones (hosted domains) visible to the token, paging through the
/// full result set (50 per page).
pub fn list_zones(token: &str) -> Result<Vec<CfZone>, String> {
    let token = require_token(token)?;
    run_blocking("cf-list-zones", async move { list_zones_async(&token).await })
}

/// Full provisioning in one call:
///   create tunnel (config_src=cloudflare) -> write ingress (hostname +
///   catch-all 404) -> upsert CNAME (`<tunnel-id>.cfargotunnel.com`,
///   proxied). Returns the ready-to-store TunnelConfig
///   (Backend::CloudflareNamed, cf_tunnel_id/cf_hostname set, no token
///   inside — tokens go to the keychain by the caller).
pub fn provision(input: &CfProvisionInput) -> Result<TunnelConfig, String> {
    let input = input.clone();
    run_blocking("cf-provision", async move { provision_async(&input).await })
}

/// Store the tunnel-run token under keychain `cf-tunnel-token-{tunnel_id}`.
pub fn set_tunnel_run_token(tunnel_id: &str, tunnel_token: &str) -> Result<(), String> {
    keychain_set(&run_token_account(tunnel_id), tunnel_token)
}

/// Fetch the tunnel-run token (engine passes it to cloudflared via the
/// TUNNEL_TOKEN env var — never as a CLI argument).
pub fn get_tunnel_run_token(tunnel_id: &str) -> Result<String, String> {
    keychain_get(&run_token_account(tunnel_id))
}

pub fn get_api_token(tunnel_id: &str) -> Result<String, String> {
    match keychain_get(&api_token_account(tunnel_id)) {
        Ok(v) => Ok(v),
        // Migration: the first v0.2.0 build stored the API token under the
        // frp-style slot (`frps-token-cf-{id}`) by accident. Read it from
        // there, move it to the correct slot and delete the stray.
        Err(missing) => match keychain_get(&format!("frps-token-cf-{tunnel_id}")) {
            Ok(v) => {
                keychain_set(&api_token_account(tunnel_id), &v)?;
                let _ = keychain_delete(&format!("frps-token-cf-{tunnel_id}"));
                Ok(v)
            }
            Err(_) => Err(missing),
        },
    }
}

/// Store the Cloudflare API token under keychain `cf-{tunnel_id}`.
pub fn set_api_token(tunnel_id: &str, token: &str) -> Result<(), String> {
    keychain_set(&api_token_account(tunnel_id), token)
}

/// Remove both keychain slots for a tunnel (local delete cleanup).
pub fn delete_stored_tokens(tunnel_id: &str) {
    let _ = keychain_delete(&api_token_account(tunnel_id));
    let _ = keychain_delete(&format!("{RUN_TOKEN_PREFIX}{tunnel_id}"));
    let _ = keychain_delete(&format!("frps-token-cf-{tunnel_id}"));
}

/// Delete the remote tunnel object. `delete_dns` also removes the CNAME
/// record(s) pointing at this tunnel (Cloudflare does not clean them up on
/// tunnel deletion). Resolves the owning account automatically — the frozen
/// signature only carries the tunnel id.
pub fn deprovision(
    token: &str,
    zone_id: &str,
    tunnel_id: &str,
    delete_dns: bool,
) -> Result<(), String> {
    let token = require_token(token)?;
    let zone_id = zone_id.trim().to_string();
    let tunnel_id = tunnel_id.trim().to_string();
    run_blocking("cf-deprovision", async move {
        deprovision_async(&token, &zone_id, &tunnel_id, delete_dns).await
    })
}

/// Change a provisioned tunnel's fixed hostname to
/// `{subdomain}.{zone_name}`:
///   1. PUT configurations with the existing ingress rules but the first
///      hostname rule rewritten (port untouched),
///   2. upsert the new CNAME (conflict-reuse semantics),
///   3. delete the old CNAME (only when it pointed at this tunnel).
///
/// Returns the new full hostname. The tunnel object (and its run token)
/// stays the same, so `cloudflared` keeps running across the change.
pub fn update_hostname(
    token: &str,
    account_id: &str,
    tunnel_id: &str,
    zone_id: &str,
    old_hostname: &str,
    subdomain: &str,
) -> Result<String, String> {
    let token = token.trim().to_string();
    let account_id = account_id.trim().to_string();
    let tunnel_id = tunnel_id.trim().to_string();
    let zone_id = zone_id.trim().to_string();
    let subdomain = subdomain.trim().to_lowercase();
    let old_hostname = old_hostname.trim().to_string();
    run_blocking("cf-update-hostname", async move {
        // zone name for the new hostname
        let zone = cf_request(
            reqwest::Method::GET,
            &token,
            &format!("/zones/{zone_id}"),
            None,
        )
        .await
        .map_err(|e| format!("读取域名信息失败：{e}"))?;
        let zone_name = zone
            .result
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or("域名响应缺少 name 字段")?
            .to_string();
        let new_hostname = format!("{subdomain}.{zone_name}");

        // 1) rewrite the first hostname rule in the remote ingress
        let path = format!("/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations");
        let envelope = cf_request(reqwest::Method::GET, &token, &path, None)
            .await
            .map_err(|e| format!("读取远程 ingress 配置失败：{e}"))?;
        let config = envelope
            .result
            .get("config")
            .cloned()
            .unwrap_or_else(|| envelope.result.clone());
        let updated = apply_ingress_hostname(&config, &new_hostname)?;
        let body = serde_json::json!({ "config": updated });
        cf_request(reqwest::Method::PUT, &token, &path, Some(body))
            .await
            .map_err(|e| format!("写回远程 ingress 配置失败：{e}"))?;

        // 2) new CNAME (reuse on conflict), 3) drop the old one
        create_cname(&token, &zone_id, &new_hostname, &tunnel_id).await?;
        delete_cname(&token, &zone_id, &old_hostname, &tunnel_id).await?;

        Ok(new_hostname)
    })
}

/// Resolve the account that owns `zone_id`.
pub fn zone_account(token: &str, zone_id: &str) -> String {
    let token = token.trim().to_string();
    let zone_id = zone_id.trim().to_string();
    run_blocking("cf-zone-account", async move {
        let account = match cf_request(reqwest::Method::GET, &token, &format!("/zones/{zone_id}"), None).await {
            Ok(envelope) => envelope
                .result
                .pointer("/account/id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            Err(_) => String::new(),
        };
        Ok(account)
    })
    .unwrap_or_default()
}

/// Resolve the zone id whose name is the suffix of `hostname`
/// (e.g. hostname `t.lovezyp.online` -> zone `lovezyp.online`).
pub fn resolve_zone_id(token: &str, hostname: &str) -> Result<String, String> {
    let token = token.trim().to_string();
    let hostname = hostname.trim().to_lowercase();
    run_blocking("cf-resolve-zone", async move {
        let mut page = 1u32;
        loop {
            let envelope = cf_request(
                reqwest::Method::GET,
                &token,
                &format!("/zones?per_page=50&page={page}"),
                None,
            )
            .await
            .map_err(|e| format!("列出域名失败：{e}"))?;
            let zones = parse_vec::<serde_json::Value>(&envelope.result, "域名列表")?;
            for z in &zones {
                let name = z.get("name").and_then(|v| v.as_str()).unwrap_or("");
                if !name.is_empty() && hostname.ends_with(name) {
                    return Ok(z
                        .get("id")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string());
                }
            }
            let total_pages = envelope
                .result_info
                .as_ref()
                .map(|i| i.total_pages)
                .unwrap_or(1);
            if page >= total_pages || zones.is_empty() {
                return Err(format!(
                    "token 可见的域名中找不到 {} 的域名后缀（域名是否托管在 Cloudflare？）",
                    hostname
                ));
            }
            page += 1;
        }
    })
}

/// Read the stored API token for a tunnel (frontend "eye" reveal).
pub fn stored_api_token(tunnel_id: &str) -> Result<String, String> {
    keychain_get(&api_token_account(tunnel_id))
}

/// Retarget the first origin ingress rule of the tunnel's remote
/// configuration to `http://127.0.0.1:{fwd_port}` (the engine's local
/// forwarder). Called before EVERY start attempt so the fixed hostname
/// always routes through the forwarder (stats + auth + allowlist). Blocks;
/// call from a worker thread / spawn_blocking.
pub fn update_ingress_service(
    api_token: &str,
    account_id: &str,
    tunnel_id: &str,
    fwd_port: u16,
) -> Result<(), String> {
    let token = api_token.trim().to_string();
    let account_id = account_id.trim().to_string();
    let tunnel_id = tunnel_id.trim().to_string();
    run_blocking("cf-update-ingress", async move {
        update_ingress_service_async(&token, &account_id, &tunnel_id, fwd_port).await
    })
}

// ---------------------------------------------------------------------------
// Async internals
// ---------------------------------------------------------------------------

async fn verify_token_async(token: &str) -> Result<Vec<CfAccount>, String> {
    let envelope = cf_request(reqwest::Method::GET, token, "/accounts", None)
        .await
        .map_err(|e| e.to_string())?;
    parse_vec(&envelope.result, "accounts").map(|accounts: Vec<CfAccountRaw>| {
        accounts
            .into_iter()
            .map(|a| CfAccount { id: a.id, name: a.name })
            .collect()
    })
}

async fn list_zones_async(token: &str) -> Result<Vec<CfZone>, String> {
    let mut zones = Vec::new();
    let mut page = 1u32;
    loop {
        let envelope = cf_request(
            reqwest::Method::GET,
            token,
            &format!("/zones?per_page=50&page={page}"),
            None,
        )
        .await
        .map_err(|e| e.to_string())?;
        let raw: Vec<CfZoneRaw> = parse_vec(&envelope.result, "zones")?;
        zones.extend(raw.into_iter().map(CfZoneRaw::into_model));
        let total_pages = envelope
            .result_info
            .as_ref()
            .map(|i| i.total_pages)
            .unwrap_or(1);
        match next_page(page, total_pages) {
            Some(next) if page < MAX_ZONE_PAGES => page = next,
            _ => break,
        }
    }
    Ok(zones)
}

async fn provision_async(input: &CfProvisionInput) -> Result<TunnelConfig, String> {
    if input.local_port == 0 {
        return Err("localPort 必须在 1-65535 之间".into());
    }
    let subdomain = normalize_subdomain(&input.subdomain)?;

    // 1. Zone -> zone_name + owning account id. The tunnel object and the
    //    DNS zone MUST live in the same Cloudflare account, so the zone's
    //    own account is authoritative (more reliable than guessing among
    //    the token's accounts).
    // TODO(v0.3): let the user pick an account explicitly when a token sees
    // multiple ones (MVP ties everything to the zone's account).
    let zone_result = cf_request(
        reqwest::Method::GET,
        &input.token,
        &format!("/zones/{}", input.zone_id.trim()),
        None,
    )
    .await
    .map_err(|e| {
        format!("无法读取域名 {}（请确认 token 含 Zone:Read 权限且域名托管在 Cloudflare）：{e}", input.zone_id.trim())
    })?
    .result;
    let zone: CfZoneRaw = serde_json::from_value(zone_result).map_err(|e| {
        format!("域名 {} 不存在或响应无法解析：{e}", input.zone_id.trim())
    })?;
    let zone_name = zone.name.clone();
    let account_id = match zone.account.map(|a| a.id) {
        Some(id) if !id.is_empty() => id,
        _ => first_account_id(&input.token).await?,
    };

    // 2. Create the named tunnel (remote-managed: config_src=cloudflare).
    let create_body = serde_json::json!({
        "name": tunnel_object_name(&subdomain),
        "config_src": "cloudflare",
    });
    let created_result = cf_request(
        reqwest::Method::POST,
        &input.token,
        &format!("/accounts/{account_id}/cfd_tunnel"),
        Some(create_body),
    )
    .await
    .map_err(|e| format!("创建 Cloudflare 隧道失败：{e}"))?
    .result;
    let created: CfTunnelCreated = serde_json::from_value(created_result)
        .map_err(|e| format!("创建隧道成功但响应无法解析：{e}"))?;
    let tunnel_id = created.id;
    let run_token = match created.token {
        Some(t) if !t.is_empty() => t,
        _ => fetch_tunnel_token(&input.token, &account_id, &tunnel_id).await?,
    };

    // 3. Write the remote ingress: our hostname -> forwarder placeholder,
    //    then the mandatory catch-all. The engine rewrites the service port
    //    to the live forwarder port before every start attempt.
    let hostname = full_hostname(&subdomain, &zone_name);
    let config_body =
        serde_json::json!({ "config": build_ingress_config(&hostname) });
    cf_request(
        reqwest::Method::PUT,
        &input.token,
        &format!("/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations"),
        Some(config_body),
    )
    .await
    .map_err(|e| format!("写入隧道 ingress 配置失败：{e}"))?;

    // 4. CNAME `<subdomain>.<zone>` -> `<tunnel-id>.cfargotunnel.com`.
    create_cname(&input.token, input.zone_id.trim(), &hostname, &tunnel_id).await?;

    // 5. Run token -> keychain, keyed by the LOCAL tunnel id (the caller,
    //    commands::cf_provision, reads it back with the same id).
    let local_id = uuid::Uuid::new_v4().to_string();
    set_tunnel_run_token(&local_id, &run_token)?;

    Ok(TunnelConfig {
        id: local_id,
        name: subdomain.clone(),
        tunnel_type: crate::models::TunnelType::Http,
        backend: crate::models::Backend::CloudflareNamed,
        local_host: input.local_host.clone(),
        local_port: input.local_port,
        auto_start: input.auto_start,
        created_at: chrono::Utc::now().to_rfc3339(),
        server_id: None,
        subdomain: None,
        remote_port: None,
        auth: None,
        cf_tunnel_id: Some(tunnel_id),
        cf_hostname: Some(hostname),
        cf_account_id: Some(account_id),
        ip_allowlist: Vec::new(),
    })
}

/// CNAME creation with the 81053/81057 same-name reuse path: query the
/// existing record(s); if one already points at this tunnel, PATCH it into
/// shape (idempotent reuse); otherwise the subdomain is occupied by another
/// record and provisioning fails with a clear message.
/// Delete the CNAME record(s) named `name` that still point at `tunnel_id`
/// (content check prevents removing someone else's record).
async fn delete_cname(
    token: &str,
    zone_id: &str,
    name: &str,
    tunnel_id: &str,
) -> Result<(), String> {
    let envelope = cf_request(
        reqwest::Method::GET,
        token,
        &format!("/zones/{zone_id}/dns_records?type=CNAME&name={name}&per_page=50"),
        None,
    )
    .await
    .map_err(|e| format!("查询旧 DNS 记录失败：{e}"))?;
    let records = parse_vec::<serde_json::Value>(&envelope.result, "DNS 记录列表")?;
    for record in records {
        let points_at_us = record
            .get("content")
            .and_then(|c| c.as_str())
            .map(|c| c.contains(&format!("{tunnel_id}.cfargotunnel.com")))
            .unwrap_or(false);
        if let Some(id) = record.get("id").and_then(|v| v.as_str()) {
            if points_at_us {
                cf_request(reqwest::Method::DELETE, token, &format!("/zones/{zone_id}/dns_records/{id}"), None)
                    .await
                    .map_err(|e| format!("删除旧 DNS 记录失败：{e}"))?;
            }
        }
    }
    Ok(())
}

async fn create_cname(
    token: &str,
    zone_id: &str,
    hostname: &str,
    tunnel_id: &str,
) -> Result<(), String> {
    let body = cname_record_body(hostname, tunnel_id);
    if let Err(e) = cf_request(
        reqwest::Method::POST,
        token,
        &format!("/zones/{zone_id}/dns_records"),
        Some(body),
    )
    .await
    {
        if !is_dns_name_conflict(e.code) {
            return Err(format!("创建 DNS CNAME 记录失败：{e}"));
        }
        // Same-name conflict: inspect what occupies the name.
        let query_path = format!(
            "/zones/{zone_id}/dns_records?type=CNAME&name={hostname}&per_page=100&page=1"
        );
        let envelope = cf_request(reqwest::Method::GET, token, &query_path, None)
            .await
            .map_err(|q| format!("同名记录冲突后查询既有记录失败：{q}（原始错误：{e}）"))?;
        let records: Vec<CfDnsRecord> = parse_vec(&envelope.result, "dns records")?;
        let target = cname_target(tunnel_id);
        match resolve_cname_conflict(&records, hostname, &target) {
            CnameResolution::Reuse(record_id) => {
                // Reuse the existing record: make sure content + proxied
                // flag point at this tunnel (idempotent PATCH).
                cf_request(
                    reqwest::Method::PATCH,
                    token,
                    &format!("/zones/{zone_id}/dns_records/{record_id}"),
                    Some(serde_json::json!({ "content": target, "proxied": true })),
                )
                .await
                .map_err(|p| format!("复用同名 CNAME 记录时更新失败：{p}"))?;
                Ok(())
            }
            CnameResolution::Conflict(existing) => Err(format!(
                "子域名 {hostname} 已被其他记录占用（当前指向 {existing}）。\
                 请更换子域名，或在 Cloudflare 控制台删除该记录后重试。"
            )),
            CnameResolution::Missing => Err(format!(
                "子域名 {hostname} 存在同名冲突（A/AAAA 等其他类型的记录占用了该名称）。\
                 请更换子域名，或在 Cloudflare 控制台删除该记录后重试。"
            )),
        }
    } else {
        Ok(())
    }
}

async fn fetch_tunnel_token(token: &str, account_id: &str, tunnel_id: &str) -> Result<String, String> {
    let envelope = cf_request(
        reqwest::Method::GET,
        token,
        &format!("/accounts/{account_id}/cfd_tunnel/{tunnel_id}/token"),
        None,
    )
    .await
    .map_err(|e| format!("获取隧道运行 token 失败：{e}"))?;
    match envelope.result.as_str() {
        Some(t) if !t.is_empty() => Ok(t.to_string()),
        _ => Err("获取隧道运行 token 失败：响应中没有 token 字符串".into()),
    }
}

async fn deprovision_async(
    token: &str,
    zone_id: &str,
    tunnel_id: &str,
    delete_dns: bool,
) -> Result<(), String> {
    if delete_dns {
        // Find every CNAME in the zone pointing at this tunnel and delete
        // it (Cloudflare leaves the record behind on tunnel deletion).
        let target = cname_target(tunnel_id);
        let records = list_tunnel_cnames(token, zone_id, &target).await?;
        for record_id in find_tunnel_cname(&records, &target) {
            cf_request(
                reqwest::Method::DELETE,
                token,
                &format!("/zones/{zone_id}/dns_records/{record_id}"),
                None,
            )
            .await
            .map_err(|e| format!("删除 DNS 记录失败：{e}"))?;
        }
    }

    let account_id = resolve_account_for_tunnel(token, tunnel_id).await?;
    if let Err(e) = cf_request(
        reqwest::Method::DELETE,
        token,
        &format!("/accounts/{account_id}/cfd_tunnel/{tunnel_id}"),
        None,
    )
    .await
    {
        return Err(format!(
            "{e} —— 若该隧道正在运行，请先停止所有运行实例（隧道存在活跃连接时无法删除）"
        ));
    }
    Ok(())
}

async fn update_ingress_service_async(
    token: &str,
    account_id: &str,
    tunnel_id: &str,
    fwd_port: u16,
) -> Result<(), String> {
    let path = format!("/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations");
    let envelope = cf_request(reqwest::Method::GET, token, &path, None)
        .await
        .map_err(|e| format!("读取远程 ingress 配置失败：{e}"))?;
    // The GET result nests the actual config under `config`; tolerate both
    // shapes defensively.
    let config = envelope
        .result
        .get("config")
        .cloned()
        .unwrap_or_else(|| envelope.result.clone());
    let updated = apply_ingress_port(&config, fwd_port)?;
    // The PUT body must nest the ingress under `config` (official schema):
    // {"config": {"ingress": [...]}} — a bare ingress array fails with
    // Cloudflare error 1030 "missing field `config`".
    let body = serde_json::json!({ "config": updated });
    cf_request(reqwest::Method::PUT, token, &path, Some(body))
        .await
        .map_err(|e| format!("写回远程 ingress 配置失败：{e}"))?;
    Ok(())
}

/// Locate the Cloudflare account that owns `tunnel_id`:
/// * single-account token -> that account, no extra probe;
/// * multi-account token -> probe `GET .../cfd_tunnel/{tid}` per account
///   until one answers (404/403 = wrong account, keep probing).
async fn resolve_account_for_tunnel(token: &str, tunnel_id: &str) -> Result<String, String> {
    let accounts: Vec<CfAccountRaw> = parse_vec(
        &cf_request(reqwest::Method::GET, token, "/accounts", None)
            .await
            .map_err(|e| e.to_string())?
            .result,
        "accounts",
    )?;
    if accounts.is_empty() {
        return Err("API token 未授权任何 Cloudflare 账户（Account Cloudflare Tunnel:Edit 权限缺失？）".into());
    }
    if accounts.len() == 1 {
        return Ok(accounts.into_iter().next().expect("len checked").id);
    }
    for account in &accounts {
        match cf_request(
            reqwest::Method::GET,
            token,
            &format!("/accounts/{}/cfd_tunnel/{tunnel_id}", account.id),
            None,
        )
        .await
        {
            Ok(_) => return Ok(account.id.clone()),
            // Not in (or not visible from) this account — try the next one.
            Err(e) if e.status == 404 || e.status == 403 => continue,
            Err(e) => return Err(e.to_string()),
        }
    }
    Err(format!(
        "在 token 可见的 {} 个 Cloudflare 账户中都找不到隧道 {tunnel_id}",
        accounts.len()
    ))
}

async fn first_account_id(token: &str) -> Result<String, String> {
    let accounts: Vec<CfAccountRaw> = parse_vec(
        &cf_request(reqwest::Method::GET, token, "/accounts", None)
            .await
            .map_err(|e| e.to_string())?
            .result,
        "accounts",
    )?;
    match accounts.first() {
        Some(account) => Ok(account.id.clone()),
        None => Err("API token 未授权任何 Cloudflare 账户（Account Cloudflare Tunnel:Edit 权限缺失？）".into()),
    }
}

/// All CNAME records in `zone_id` the server reports for `content`
/// (server-side `content` filter + client-side exact re-check).
async fn list_tunnel_cnames(
    token: &str,
    zone_id: &str,
    content: &str,
) -> Result<Vec<CfDnsRecord>, String> {
    let mut records = Vec::new();
    let mut page = 1u32;
    loop {
        let envelope = cf_request(
            reqwest::Method::GET,
            token,
            &format!(
                "/zones/{zone_id}/dns_records?type=CNAME&content={content}&per_page=100&page={page}"
            ),
            None,
        )
        .await
        .map_err(|e| format!("查询隧道 CNAME 记录失败：{e}"))?;
        let batch: Vec<CfDnsRecord> = parse_vec(&envelope.result, "dns records")?;
        let fetched = batch.len();
        records.extend(
            batch
                .into_iter()
                .filter(|r| r.content.eq_ignore_ascii_case(content)),
        );
        let total_pages = envelope
            .result_info
            .as_ref()
            .map(|i| i.total_pages)
            .unwrap_or(1);
        match next_page(page, total_pages) {
            Some(next) if page < MAX_ZONE_PAGES && fetched > 0 => page = next,
            _ => break,
        }
    }
    Ok(records)
}

// ---------------------------------------------------------------------------
// Pure helpers (unit-tested below)
// ---------------------------------------------------------------------------

fn require_token(token: &str) -> Result<String, String> {
    let token = token.trim();
    if token.is_empty() {
        return Err("Cloudflare API token 不能为空".into());
    }
    Ok(token.to_string())
}

/// Trim + lowercase the user-supplied subdomain label(s).
fn normalize_subdomain(raw: &str) -> Result<String, String> {
    let sub = raw.trim().to_ascii_lowercase();
    if sub.is_empty() {
        return Err("子域名不能为空 (subdomain is required)".into());
    }
    if sub.chars().any(char::is_whitespace) {
        return Err(format!("子域名不能包含空白字符：{raw:?}"));
    }
    Ok(sub)
}

/// The fixed public hostname: `mac.example.com`.
fn full_hostname(subdomain: &str, zone_name: &str) -> String {
    format!("{}.{}", subdomain.trim_end_matches('.'), zone_name.trim_end_matches('.'))
}

/// Name given to the remote tunnel object in the Cloudflare dashboard.
fn tunnel_object_name(subdomain: &str) -> String {
    format!("圣手码头-{subdomain}")
}

/// The CNAME target for a tunnel: `<tunnel-id>.cfargotunnel.com`.
fn cname_target(tunnel_id: &str) -> String {
    format!("{tunnel_id}.cfargotunnel.com")
}

/// Next zone-list page to fetch; `None` when done. A missing/zero
/// `total_pages` (defensive) ends pagination after the current page.
fn next_page(current: u32, total_pages: u32) -> Option<u32> {
    let total = total_pages.max(current);
    if current < total {
        Some(current + 1)
    } else {
        None
    }
}

/// True when `code` is one of Cloudflare's "a record with this name already
/// exists" codes (the CNAME reuse path).
fn is_dns_name_conflict(code: Option<i64>) -> bool {
    code.map(|c| DNS_NAME_CONFLICT_CODES.contains(&c))
        .unwrap_or(false)
}

/// Remote ingress body for provisioning: our hostname first (service port
/// left as a placeholder the engine rewrites before every start), then the
/// mandatory catch-all. Returned unwrapped: the caller nests it under
/// `config` per the API schema.
fn build_ingress_config(hostname: &str) -> serde_json::Value {
    serde_json::json!({
        "ingress": [
            {
                "hostname": hostname,
                "service": "http://127.0.0.1:0",
            },
            {
                "service": "http_status:404",
            },
        ],
    })
}

/// CNAME creation body: `<hostname> -> <tunnel-id>.cfargotunnel.com`,
/// proxied (orange cloud) so TLS/HTTPS termination happens on the edge.
fn cname_record_body(hostname: &str, tunnel_id: &str) -> serde_json::Value {
    serde_json::json!({
        "type": "CNAME",
        "name": hostname,
        "content": cname_target(tunnel_id),
        "proxied": true,
    })
}

/// Outcome of inspecting same-name CNAME conflicts (error codes 81053/81057).
#[derive(Debug, Clone, PartialEq, Eq)]
enum CnameResolution {
    /// An existing CNAME already points at this tunnel — reuse it (PATCH).
    Reuse(String),
    /// The name is occupied by a different record; `String` is its content.
    Conflict(String),
    /// No CNAME with the name found (an A/AAAA record likely occupies it).
    Missing,
}

/// Pure conflict resolver for the 81053/81057 path: among `records`, find
/// the CNAME matching `hostname` (case-insensitive); reuse when its content
/// already targets this tunnel, report the conflicting content otherwise.
fn resolve_cname_conflict(
    records: &[CfDnsRecord],
    hostname: &str,
    tunnel_target: &str,
) -> CnameResolution {
    let existing = records.iter().find(|r| {
        r.r#type.eq_ignore_ascii_case("CNAME") && r.name.eq_ignore_ascii_case(hostname)
    });
    match existing {
        Some(rec) if rec.content.eq_ignore_ascii_case(tunnel_target) => {
            CnameResolution::Reuse(rec.id.clone())
        }
        Some(rec) => CnameResolution::Conflict(rec.content.clone()),
        None => CnameResolution::Missing,
    }
}

/// Pure deprovision helper: ids of all records pointing at
/// `<tunnel-id>.cfargotunnel.com` (content match, case-insensitive).
fn find_tunnel_cname(records: &[CfDnsRecord], tunnel_target: &str) -> Vec<String> {
    records
        .iter()
        .filter(|r| r.content.eq_ignore_ascii_case(tunnel_target))
        .map(|r| r.id.clone())
        .collect()
}

/// Pure ingress retarget: update the FIRST rule carrying a `hostname` (the
/// one provisioned by this app) to `http://127.0.0.1:{port}`. Rule order and
/// the trailing catch-all are preserved. Errors when no hostname rule exists
/// (e.g. the remote config was replaced in the Cloudflare dashboard).
fn apply_ingress_port(config: &serde_json::Value, port: u16) -> Result<serde_json::Value, String> {
    let mut updated = config.clone();
    let ingress = updated
        .get_mut("ingress")
        .and_then(|v| v.as_array_mut())
        .ok_or_else(|| "远程 ingress 配置缺少 ingress 数组（配置可能已在 Cloudflare 控制台被改坏）".to_string())?;
    for rule in ingress.iter_mut() {
        let has_hostname = rule
            .get("hostname")
            .map(|h| !h.is_null())
            .unwrap_or(false);
        if has_hostname {
            rule["service"] = serde_json::json!(format!("http://127.0.0.1:{port}"));
            return Ok(updated);
        }
    }
    Err("远程 ingress 配置中没有找到带 hostname 的转发规则（可能已在 Cloudflare 控制台被删除）；请在应用内删除该隧道后重新绑定".into())
}

/// Rewrite the first hostname rule's `hostname` in a remote ingress config
/// (service/port untouched). Mirrors `apply_ingress_port`.
fn apply_ingress_hostname(
    config: &serde_json::Value,
    new_hostname: &str,
) -> Result<serde_json::Value, String> {
    let mut updated = config.clone();
    let ingress = updated
        .get_mut("ingress")
        .and_then(|v| v.as_array_mut())
        .ok_or_else(|| "远程 ingress 配置缺少 ingress 数组（配置可能已在 Cloudflare 控制台被改坏）".to_string())?;
    for rule in ingress.iter_mut() {
        let has_hostname = rule
            .get("hostname")
            .map(|h| !h.is_null())
            .unwrap_or(false);
        if has_hostname {
            rule["hostname"] = serde_json::json!(new_hostname);
            return Ok(updated);
        }
    }
    Err("远程 ingress 配置中没有找到带 hostname 的转发规则（可能已在 Cloudflare 控制台被删除）；请在应用内删除该隧道后重新绑定".into())
}

/// Deserialize an envelope result expected to be an array of objects.
fn parse_vec<T: for<'de> Deserialize<'de>>(
    value: &serde_json::Value,
    what: &str,
) -> Result<Vec<T>, String> {
    serde_json::from_value(value.clone())
        .map_err(|e| format!("Cloudflare API 的 {what} 响应格式无法解析：{e}"))
}

// ---------------------------------------------------------------------------
// Tests (pure logic only — the HTTP path is funneled through `cf_request`
// and needs a real token, verified at integration time)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // --- envelope parsing ---------------------------------------------------

    #[test]
    fn envelope_success_parses_accounts() {
        let body = json!({
            "success": true,
            "errors": [],
            "messages": [],
            "result": [
                {"id": "acc1", "name": "Main Account"},
                {"id": "acc2", "name": "Second"}
            ]
        });
        let env: CfEnvelope = serde_json::from_value(body).unwrap();
        assert!(env.success);
        let accounts: Vec<CfAccountRaw> = parse_vec(&env.result, "accounts").unwrap();
        assert_eq!(accounts.len(), 2);
        assert_eq!(accounts[0].id, "acc1");
        assert_eq!(accounts[1].name, "Second");
    }

    #[test]
    fn envelope_error_formats_human_message() {
        let body = json!({
            "success": false,
            "errors": [
                {"code": 10000, "message": "Invalid API Token"},
                {"code": 9109, "message": "Unauthorized to access requested resource"}
            ],
            "result": null
        });
        let env: CfEnvelope = serde_json::from_value(body).unwrap();
        assert!(!env.success);
        let msg = format_cf_errors(&env.errors);
        assert!(msg.contains("[10000]"), "{msg}");
        assert!(msg.contains("Invalid API Token"), "{msg}");
        assert!(msg.contains("[9109] Unauthorized"), "{msg}");
        assert_eq!(env.errors[0].code_i64(), Some(10000));
    }

    #[test]
    fn error_code_accepts_string_or_number() {
        let numeric: CfApiErrorEntry = serde_json::from_value(json!({"code": 81053, "message": "x"})).unwrap();
        let textual: CfApiErrorEntry =
            serde_json::from_value(json!({"code": "81053", "message": "x"})).unwrap();
        let absent: CfApiErrorEntry = serde_json::from_value(json!({"message": "x"})).unwrap();
        assert_eq!(numeric.code_i64(), Some(81053));
        assert_eq!(textual.code_i64(), Some(81053));
        assert_eq!(absent.code_i64(), None);
    }

    #[test]
    fn dns_name_conflict_codes_are_matched() {
        assert!(is_dns_name_conflict(Some(81053)));
        assert!(is_dns_name_conflict(Some(81057)));
        assert!(!is_dns_name_conflict(Some(10000)));
        assert!(!is_dns_name_conflict(None));
    }

    // --- ingress body assembly ----------------------------------------------

    #[test]
    fn ingress_config_has_hostname_rule_and_catch_all() {
        let config = build_ingress_config("mac.example.com");
        let ingress = config["ingress"].as_array().unwrap();
        assert_eq!(ingress.len(), 2);
        assert_eq!(ingress[0]["hostname"], json!("mac.example.com"));
        // Service port is a placeholder; the engine rewrites it before start.
        assert_eq!(ingress[0]["service"], json!("http://127.0.0.1:0"));
        // Catch-all MUST be last and service-only.
        assert_eq!(ingress[1]["service"], json!("http_status:404"));
        assert!(ingress[1].get("hostname").is_none());
    }

    #[test]
    fn apply_ingress_port_updates_first_hostname_rule() {
        let config = json!({
            "ingress": [
                {"hostname": "mac.example.com", "service": "http://127.0.0.1:0"},
                {"service": "http_status:404"}
            ]
        });
        let updated = apply_ingress_port(&config, 51234).unwrap();
        let ingress = updated["ingress"].as_array().unwrap();
        assert_eq!(ingress[0]["service"], json!("http://127.0.0.1:51234"));
        assert_eq!(ingress[0]["hostname"], json!("mac.example.com"));
        // Catch-all untouched, order preserved.
        assert_eq!(ingress[1]["service"], json!("http_status:404"));
    }

    #[test]
    fn apply_ingress_port_tolerates_wrapped_config_and_keeps_other_rules() {
        // GET .../configurations result shape: config nested + extra rules
        // the user may have added in the dashboard.
        let result = json!({
            "tunnel_id": "tid",
            "version": 3,
            "config": {
                "ingress": [
                    {"hostname": "mac.example.com", "service": "http://localhost:9999"},
                    {"hostname": "other.example.com", "service": "http://localhost:80"},
                    {"service": "http_status:404"}
                ]
            }
        });
        let config = result.get("config").cloned().unwrap();
        let updated = apply_ingress_port(&config, 40001).unwrap();
        let ingress = updated["ingress"].as_array().unwrap();
        assert_eq!(ingress[0]["service"], json!("http://127.0.0.1:40001"));
        // Later hostname rules are left alone (only the first is app-managed).
        assert_eq!(ingress[1]["service"], json!("http://localhost:80"));
        assert_eq!(ingress[2]["service"], json!("http_status:404"));
    }

    #[test]
    fn apply_ingress_port_errors_without_hostname_rule() {
        let config = json!({"ingress": [{"service": "http_status:404"}]});
        assert!(apply_ingress_port(&config, 8080).is_err());
        assert!(apply_ingress_port(&json!({}), 8080).is_err());
    }

    // --- CNAME body + conflict reuse -----------------------------------------

    #[test]
    fn cname_record_body_shape() {
        let body = cname_record_body("mac.example.com", "tunnel-uuid");
        assert_eq!(body["type"], json!("CNAME"));
        assert_eq!(body["name"], json!("mac.example.com"));
        assert_eq!(body["content"], json!("tunnel-uuid.cfargotunnel.com"));
        assert_eq!(body["proxied"], json!(true));
    }

    #[test]
    fn cname_conflict_reuses_record_pointing_at_this_tunnel() {
        let records = vec![CfDnsRecord {
            id: "rec1".into(),
            name: "mac.example.com".into(),
            r#type: "CNAME".into(),
            content: "tunnel-uuid.cfargotunnel.com".into(),
        }];
        match resolve_cname_conflict(&records, "mac.example.com", "tunnel-uuid.cfargotunnel.com") {
            CnameResolution::Reuse(id) => assert_eq!(id, "rec1"),
            other => panic!("expected reuse, got {other:?}"),
        }
    }

    #[test]
    fn cname_conflict_reports_foreign_record() {
        let records = vec![CfDnsRecord {
            id: "rec2".into(),
            name: "MAC.EXAMPLE.COM".into(), // name match is case-insensitive
            r#type: "CNAME".into(),
            content: "other-tunnel.cfargotunnel.com".into(),
        }];
        match resolve_cname_conflict(&records, "mac.example.com", "tunnel-uuid.cfargotunnel.com") {
            CnameResolution::Conflict(content) => {
                assert_eq!(content, "other-tunnel.cfargotunnel.com")
            }
            other => panic!("expected conflict, got {other:?}"),
        }
    }

    #[test]
    fn cname_conflict_missing_when_no_cname_matches() {
        let records = vec![CfDnsRecord {
            id: "rec3".into(),
            name: "mac.example.com".into(),
            r#type: "A".into(),
            content: "203.0.113.7".into(),
        }];
        assert_eq!(
            resolve_cname_conflict(&records, "mac.example.com", "tunnel-uuid.cfargotunnel.com"),
            CnameResolution::Missing
        );
    }

    #[test]
    fn find_tunnel_cname_matches_by_content_only() {
        let records = vec![
            CfDnsRecord {
                id: "rec-a".into(),
                name: "mac.example.com".into(),
                r#type: "CNAME".into(),
                content: "tid.cfargotunnel.com".into(),
            },
            CfDnsRecord {
                id: "rec-b".into(),
                name: "old.example.com".into(),
                r#type: "CNAME".into(),
                content: "other.cfargotunnel.com".into(),
            },
            CfDnsRecord {
                id: "rec-c".into(),
                name: "alt.example.com".into(),
                r#type: "CNAME".into(),
                content: "TID.CFARGOTUNNEL.COM".into(),
            },
        ];
        assert_eq!(
            find_tunnel_cname(&records, "tid.cfargotunnel.com"),
            vec!["rec-a".to_string(), "rec-c".to_string()]
        );
    }

    // --- pagination + naming helpers ------------------------------------------

    #[test]
    fn zone_pagination_walks_then_stops() {
        assert_eq!(next_page(1, 3), Some(2));
        assert_eq!(next_page(3, 3), None);
        // Missing result_info (total_pages defaults to 1) ends after page 1.
        assert_eq!(next_page(1, 0), None);
        assert_eq!(next_page(1, 1), None);
        // Server under-reporting pages must not loop.
        assert_eq!(next_page(5, 2), None);
    }

    #[test]
    fn zone_json_maps_nested_account_id() {
        let zone: CfZoneRaw = serde_json::from_value(json!({
            "id": "z1",
            "name": "example.com",
            "status": "active",
            "account": {"id": "acc1", "name": "Main"}
        }))
        .unwrap();
        let model = zone.into_model();
        assert_eq!(model.id, "z1");
        assert_eq!(model.name, "example.com");
        assert_eq!(model.account_id, "acc1");
        // Zone without an account block degrades to an empty account id.
        let bare: CfZoneRaw =
            serde_json::from_value(json!({"id": "z2", "name": "bare.com"})).unwrap();
        assert_eq!(bare.into_model().account_id, "");
    }

    #[test]
    fn naming_helpers_are_stable() {
        assert_eq!(full_hostname("mac", "example.com"), "mac.example.com");
        // full_hostname only trims the trailing dot — the subdomain is
        // expected to be normalized (lowercased) by normalize_subdomain.
        assert_eq!(full_hostname("mac.", "example.com"), "mac.example.com");
        assert_eq!(tunnel_object_name("mac"), "圣手码头-mac");
        assert_eq!(cname_target("tid"), "tid.cfargotunnel.com");
        assert_eq!(normalize_subdomain("  Mac ").unwrap(), "mac");
        assert!(normalize_subdomain("  ").is_err());
        assert!(normalize_subdomain("a b").is_err());
    }

    #[test]
    fn keychain_account_naming_matches_the_callers_contract() {
        // commands::cf_provision stores the API token under `cf-{local_id}`
        // via servers_store::set_frps_token; the engine reads it back through
        // get_api_token — both sides must agree on the slot names.
        assert_eq!(run_token_account("t1"), "cf-tunnel-token-t1");
        assert_eq!(api_token_account("t1"), "cf-t1");
    }

    #[test]
    fn parsed_tunnel_creation_defaults() {
        // Create response may omit `token` (older API revisions) — the raw
        // struct must tolerate that and the fallback endpoint takes over.
        let created: CfTunnelCreated =
            serde_json::from_value(json!({"id": "tid", "name": "n", "status": "inactive"}))
                .unwrap();
        assert_eq!(created.id, "tid");
        assert!(created.token.is_none());
        let with_token: CfTunnelCreated =
            serde_json::from_value(json!({"id": "tid", "token": "tok"})).unwrap();
        assert_eq!(with_token.token.as_deref(), Some("tok"));
    }
}
