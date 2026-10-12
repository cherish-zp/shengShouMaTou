// Binary manager — locates and downloads the tunnel engine binaries.
//
// Public API (keep signatures stable):
//   * `resolve`          — find an installed engine binary
//   * `bin_dir`          — `<app_data_dir>/bin`
//   * `binary_file_name` — engine binary file name for the current platform
//   * `read_status`      — install state of both engines
//   * `install`          — download + unpack + swap-in an engine binary
//   * `import_binary`    — install a user-provided engine file (manual import)
//
// Download sources (see DOWNLOAD_SOURCE_TEMPLATES for the ordered list):
// every attempt goes direct first, then public GitHub mirrors; a source only
// counts as successful when download + unpack + magic check + `probe_version`
// all pass, otherwise the next source is tried. bore/frp resolve their latest
// tag via the GitHub API (direct only); when the API is unreachable they fall
// back to the last human-verified pinned tag (BORE_FALLBACK_TAG /
// FRP_FALLBACK_TAG) and a `releases/download/<tag>/<asset>` direct link.
// Asset naming (verified on 2026-10-06, all HTTP 200):
//   cloudflared: https://github.com/cloudflare/cloudflared/releases/latest/download/<asset>
//     - cloudflared-darwin-arm64.tgz  (contains `cloudflared` at archive root)
//     - cloudflared-darwin-amd64.tgz
//     - cloudflared-windows-amd64.exe (plain binary, no unpacking)
//   bore: https://github.com/ekzhang/bore/releases
//     - bore-v0.6.0-aarch64-apple-darwin.tar.gz  (contains `bore` at archive root)
//     - bore-v0.6.0-x86_64-apple-darwin.tar.gz
//     - bore-v0.6.0-x86_64-pc-windows-msvc.zip
//   frp: https://github.com/fatedier/frp/releases (tag v0.71.0 — note the
//   asset version carries NO `v` prefix while the tag does):
//     - frp_0.71.0_darwin_arm64.tar.gz
//     - frp_0.71.0_windows_amd64.zip / frp_0.71.0_windows_arm64.zip
//     - frp_0.71.0_linux_amd64.tar.gz / frp_0.71.0_linux_arm64.tar.gz
//   ^ frp archives have a TOP-LEVEL DIRECTORY `frp_<ver>_<os>_<arch>/` with
//   `frpc` (unix) / `frpc.exe` (windows) inside; the unpacker matches by file
//   name anywhere in the archive, so it sees through the wrapper directory.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use tauri::Manager;

use crate::models::{Backend, BinaryInfo, BinaryStatus};

const CLOUDFLARED_LATEST_URL: &str =
    "https://github.com/cloudflare/cloudflared/releases/latest/download";
const BORE_RELEASE_API_URL: &str = "https://api.github.com/repos/ekzhang/bore/releases/latest";
const FRP_RELEASE_API_URL: &str = "https://api.github.com/repos/fatedier/frp/releases/latest";

/// bore/frp 查不到最新版本时的兜底 tag：API 只走直连、不走镜像（公益镜像
/// 不保证代理 JSON API），API 不可达时改用这些「最近一次人工验证可用」的
/// tag 直拼 `releases/download/<tag>/<asset>` 直链。版本可能落后于最新，
/// 但始终可用；资产命名规则见 `bore_asset_name` / `frp_asset_name`。
const BORE_FALLBACK_TAG: &str = "v0.6.0";
const FRP_FALLBACK_TAG: &str = "v0.71.0";

/// 引擎下载源模板（有序，逐个回退）。`{url}` 占位符会被替换为完整原始
/// URL（asset 直链），空模板 = 直连 GitHub。顺序即优先级：先直连，再镜像。
///
/// 风险说明：gh-proxy.com / ghfast.top 是第三方公益镜像，随时可能失效、
/// 限速或返回 200 + HTML 错误页 —— 因此任一源「下载成功」都不算数，
/// 必须解包 + 魔数校验 + `probe_version` 探测全部通过才算安装成功，
/// 任一环节失败即清理暂存并自动换下一个源（循环天然构成重试）。
/// 增删镜像时只改这一处常量。
const DOWNLOAD_SOURCE_TEMPLATES: &[&str] = &[
    "",
    "https://gh-proxy.com/{url}",
    "https://ghfast.top/{url}",
    "https://ghproxy.net/{url}",
];

/// 单个源的下载整体超时（大文件 300s）：镜像挂起时不能卡死整条回退链。
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(300);
/// GitHub API（JSON 小响应）的整体超时（小文件 120s）。
const API_TIMEOUT: Duration = Duration::from_secs(120);

/// Filename of the engine binary for `backend` on the current platform.
pub fn binary_file_name(backend: Backend) -> &'static str {
    match backend {
        Backend::Cloudflare => {
            if cfg!(target_os = "windows") {
                "cloudflared.exe"
            } else {
                "cloudflared"
            }
        }
        Backend::Bore => {
            if cfg!(target_os = "windows") {
                "bore.exe"
            } else {
                "bore"
            }
        }
        Backend::Frp => {
            if cfg!(target_os = "windows") {
                "frpc.exe"
            } else {
                "frpc"
            }
        }
        // Named tunnels reuse the same cloudflared binary.
        Backend::CloudflareNamed => {
            if cfg!(target_os = "windows") {
                "cloudflared.exe"
            } else {
                "cloudflared"
            }
        }
    }
}

/// Name of the engine binary inside the downloaded archive. Cloudflare/Bore
/// archives always ship the Unix-style name (the Windows cloudflared asset is
/// a plain binary). frp is the exception: its Windows zip contains
/// `frpc.exe`, its unix tarballs contain `frpc` — hence the cfg! arm.
fn archive_inner_name(backend: Backend) -> &'static str {
    match backend {
        Backend::Cloudflare | Backend::CloudflareNamed => "cloudflared",
        Backend::Bore => "bore",
        Backend::Frp => {
            if cfg!(target_os = "windows") {
                "frpc.exe"
            } else {
                "frpc"
            }
        }
    }
}

/// GitHub asset name of the official cloudflared build for `os`/`arch`
/// (`std::env::consts::OS` / `ARCH` values). `None` = no official build.
fn cloudflared_asset_name(os: &str, arch: &str) -> Option<&'static str> {
    match (os, arch) {
        ("macos", "aarch64") => Some("cloudflared-darwin-arm64.tgz"),
        ("macos", "x86_64") => Some("cloudflared-darwin-amd64.tgz"),
        ("windows", "x86_64") => Some("cloudflared-windows-amd64.exe"),
        ("linux", "x86_64") => Some("cloudflared-linux-amd64"),
        ("linux", "aarch64") => Some("cloudflared-linux-arm64"),
        _ => None,
    }
}

/// Rust target triple used by the official bore builds for `os`/`arch`.
/// Note: bore publishes no `aarch64-pc-windows-msvc` asset.
fn bore_target_triple(os: &str, arch: &str) -> Option<&'static str> {
    match (os, arch) {
        ("macos", "aarch64") => Some("aarch64-apple-darwin"),
        ("macos", "x86_64") => Some("x86_64-apple-darwin"),
        ("windows", "x86_64") => Some("x86_64-pc-windows-msvc"),
        ("linux", "x86_64") => Some("x86_64-unknown-linux-musl"),
        ("linux", "aarch64") => Some("aarch64-unknown-linux-musl"),
        _ => None,
    }
}

/// GitHub asset name of the bore release `tag` for `os`/`arch`.
fn bore_asset_name(tag: &str, os: &str, arch: &str) -> Option<String> {
    let triple = bore_target_triple(os, arch)?;
    let ext = if os == "windows" { "zip" } else { "tar.gz" };
    Some(format!("bore-{tag}-{triple}.{ext}"))
}

/// GitHub asset name of the frp release `tag` for `os`/`arch`.
/// Verified against v0.71.0: the tag carries a `v` prefix (`v0.71.0`) but the
/// asset version does NOT (`frp_0.71.0_darwin_arm64.tar.gz`), Windows is a
/// zip (amd64 AND arm64), everything else is a tar.gz.
fn frp_asset_name(tag: &str, os: &str, arch: &str) -> Option<String> {
    let version = tag.strip_prefix('v')?;
    let frp_os = match os {
        "macos" => "darwin",
        "windows" => "windows",
        "linux" => "linux",
        _ => return None,
    };
    let frp_arch = match arch {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        _ => return None,
    };
    let ext = if os == "windows" { "zip" } else { "tar.gz" };
    Some(format!("frp_{version}_{frp_os}_{frp_arch}.{ext}"))
}

/// How a downloaded release asset must be unpacked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArchiveKind {
    /// The asset is the binary itself (e.g. `cloudflared-windows-amd64.exe`).
    Plain,
    /// gzip-compressed tarball containing the binary.
    TarGz,
    /// zip archive containing the binary.
    Zip,
}

fn archive_kind(asset_name: &str) -> ArchiveKind {
    if asset_name.ends_with(".tgz") || asset_name.ends_with(".tar.gz") {
        ArchiveKind::TarGz
    } else if asset_name.ends_with(".zip") {
        ArchiveKind::Zip
    } else {
        ArchiveKind::Plain
    }
}

/// Directory where Pier stores engine binaries: `<app_data_dir>/bin`.
pub fn bin_dir(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("failed to resolve app data dir: {e}"))?
        .join("bin");
    Ok(dir)
}

/// Resolve the binary path for `backend`.
///
/// Looks in `<app_data_dir>/bin` first, then the system PATH.
pub fn resolve(app: &tauri::AppHandle, backend: Backend) -> Result<PathBuf, String> {
    let name = binary_file_name(backend);
    if let Ok(dir) = bin_dir(app) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    // Fall back to the system PATH.
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    Err(format!(
        "engine binary for {backend:?} not found (looked in app data dir and PATH)"
    ))
}

/// Probe the version of the binary at `path` (best-effort).
fn probe_version(path: &Path) -> Option<String> {
    let mut cmd = std::process::Command::new(path);
    cmd.arg("--version");
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // Do not flash a console window when probing on Windows.
        cmd.creation_flags(0x0800_0000);
    }
    let out = cmd.output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let first = text.lines().next()?.trim().to_string();
    if first.is_empty() {
        None
    } else {
        Some(first)
    }
}

pub fn read_status(app: &tauri::AppHandle) -> Result<BinaryStatus, String> {
    let info = |backend: Backend| match resolve(app, backend) {
        Ok(path) => BinaryInfo {
            backend,
            version: probe_version(&path),
            path: Some(path.to_string_lossy().to_string()),
            installed: true,
        },
        Err(_) => BinaryInfo {
            backend,
            version: None,
            path: None,
            installed: false,
        },
    };
    Ok(BinaryStatus {
        cloudflare: info(Backend::Cloudflare),
        bore: info(Backend::Bore),
    })
}

/// Download & install the engine binary for `backend` into `<app_data_dir>/bin`.
///
/// Blocking: drives the async download pipeline on a dedicated worker thread
/// with its own runtime, so it is safe to call from any thread (sync tauri
/// commands run on the main thread, async ones on tokio workers).
pub fn install(app: &tauri::AppHandle, backend: Backend) -> Result<BinaryInfo, String> {
    let app = app.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("pier-binary-install".into())
        .spawn(move || {
            let result = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| format!("failed to start async runtime for download: {e}"))
                .and_then(|rt| rt.block_on(install_async(&app, backend)));
            let _ = tx.send(result);
        })
        .map_err(|e| format!("failed to spawn install worker: {e}"))?;
    rx.recv()
        .map_err(|_| "install worker exited unexpectedly".to_string())?
}

async fn install_async(app: &tauri::AppHandle, backend: Backend) -> Result<BinaryInfo, String> {
    let dir = bin_dir(app)?;
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("failed to create engine dir {}: {e}", dir.display()))?;
    let path = install_to_dir(&dir, backend).await?;
    Ok(BinaryInfo {
        backend,
        version: probe_version(&path),
        path: Some(path.to_string_lossy().to_string()),
        installed: true,
    })
}

/// 手动导入：把用户从官方渠道下载的引擎文件安装进 `<app_data_dir>/bin`。
///
/// 流程：路径校验 → 复制到 `<final>.staging`（不破坏用户原文件）→
/// 平台魔数校验 → chmod → `probe_version` 探测 → 原子换装（.bak 回滚
/// 保护）。探测失败返回中文 Err，由设置页如实提示。
pub fn import_binary(
    app: &tauri::AppHandle,
    backend: Backend,
    src: &str,
) -> Result<BinaryStatus, String> {
    let dir = bin_dir(app)?;
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("创建引擎目录 {} 失败：{e}", dir.display()))?;

    let src_path = PathBuf::from(src);
    if !src_path.is_file() {
        return Err(format!("所选路径不存在或不是文件：{src}"));
    }
    let final_name = binary_file_name(backend);
    let staged_path = dir.join(format!("{final_name}.staging"));

    // 清掉上次失败遗留的暂存文件，避免把旧数据当新文件探测。
    let _ = std::fs::remove_file(&staged_path);

    std::fs::copy(&src_path, &staged_path).map_err(|e| {
        format!(
            "复制 {} 到 {} 失败：{e}",
            src_path.display(),
            staged_path.display()
        )
    })?;

    let verified = (|| -> Result<(), String> {
        // 平台魔数先行：直接拦截 HTML 错误页、README、其他平台的二进制。
        validate_file_magic(&staged_path)?;
        make_executable(&staged_path)?;
        // 最终裁决：该文件必须真能以 <backend> 引擎的身份回答 --version。
        if probe_version(&staged_path).is_none() {
            return Err(format!(
                "该文件不是有效的 {final_name} 引擎可执行文件（--version 探测失败）"
            ));
        }
        Ok(())
    })();
    if let Err(e) = verified {
        let _ = std::fs::remove_file(&staged_path);
        return Err(e);
    }

    swap_staged_into_place(&dir, final_name, &staged_path)?;
    read_status(app)
}

/// GitHub `releases/download/<tag>/<asset>` 直链（pinned tag 兜底用）。
fn github_pinned_download_url(repo: &str, tag: &str, asset: &str) -> String {
    format!("https://github.com/{repo}/releases/download/{tag}/{asset}")
}

/// bore/frp 共用：查最新 release 取 asset 直链；API 不可达时不放弃，
/// 改用 `fallback_tag` 直拼 `releases/download/<tag>/<asset>` 直链
/// （资产命名规则固定，见 `bore_asset_name` / `frp_asset_name`）。
/// `asset_name_for(tag, os, arch)` 给出该平台对应的 asset 文件名。
async fn resolve_via_api_or_pinned(
    api_url: &str,
    project: &str,
    repo: &str,
    fallback_tag: &str,
    os: &str,
    arch: &str,
    asset_name_for: fn(&str, &str, &str) -> Option<String>,
) -> Result<(String, String), String> {
    let asset_for = |tag: &str| {
        asset_name_for(tag, os, arch)
            .ok_or_else(|| format!("{project} publishes no official build for this platform"))
    };
    match fetch_latest_github_release(api_url, project).await {
        Ok(release) => {
            let asset = asset_for(&release.tag_name)?;
            match release.assets.iter().find(|a| a.name == asset) {
                Some(a) => Ok((a.name.clone(), a.browser_download_url.clone())),
                None => {
                    let names: Vec<&str> = release.assets.iter().map(|a| a.name.as_str()).collect();
                    Err(format!(
                        "{project} release {} does not contain the expected asset {asset:?} \
                         (available: {})",
                        release.tag_name,
                        names.join(", ")
                    ))
                }
            }
        }
        Err(api_err) => {
            eprintln!(
                "[pier] {project} 最新版本查询失败（{api_err}），改用已验证版本 {fallback_tag} 的 GitHub 直链"
            );
            let asset = asset_for(fallback_tag)?;
            Ok((
                asset.clone(),
                github_pinned_download_url(repo, fallback_tag, &asset),
            ))
        }
    }
}

/// 解析 `backend` 的 GitHub asset（asset 文件名 + 下载 URL）。
///
/// cloudflared 本就无需 API（`releases/latest/download/<asset>` 直链）；
/// bore/frp 需要先查 API 拿最新 tag，API 失败时回退到已验证的 pinned tag。
async fn resolve_asset_url(backend: Backend) -> Result<(String, String), String> {
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;

    match backend {
        Backend::Cloudflare | Backend::CloudflareNamed => {
            let asset = cloudflared_asset_name(os, arch).ok_or_else(|| {
                "cloudflared publishes no official build for this platform".to_string()
            })?;
            let url = format!("{CLOUDFLARED_LATEST_URL}/{asset}");
            Ok((asset.to_string(), url))
        }
        // frp releases carry a top-level directory inside the archive; the
        // unpacker matches the binary by file name, so it sees through it.
        Backend::Frp => {
            resolve_via_api_or_pinned(
                FRP_RELEASE_API_URL,
                "frp",
                "fatedier/frp",
                FRP_FALLBACK_TAG,
                os,
                arch,
                frp_asset_name,
            )
            .await
        }
        Backend::Bore => {
            resolve_via_api_or_pinned(
                BORE_RELEASE_API_URL,
                "bore",
                "ekzhang/bore",
                BORE_FALLBACK_TAG,
                os,
                arch,
                bore_asset_name,
            )
            .await
        }
    }
}

/// 把下载源模板里的 `{url}` 占位符替换为完整原始 URL（镜像前缀拼在完整
/// 原始 URL 之前，形如 `https://gh-proxy.com/https://github.com/...`）。
/// 空模板 = 直连，原样返回。
fn apply_source_template(template: &str, url: &str) -> String {
    if template.is_empty() {
        url.to_string()
    } else {
        template.replace("{url}", url)
    }
}

/// 多源回退循环：按 `DOWNLOAD_SOURCE_TEMPLATES` 的顺序（直连 → 镜像）
/// 依次以拼接后的完整 URL 调用 `try_one`；任一源成功立即返回，
/// 全部失败返回中文错误，内含每个源的具体失败原因与「手动导入」建议。
async fn try_sources<T, F, Fut>(original_url: &str, mut try_one: F) -> Result<T, String>
where
    F: FnMut(String) -> Fut,
    Fut: std::future::Future<Output = Result<T, String>>,
{
    let mut failures: Vec<String> = Vec::new();
    for template in DOWNLOAD_SOURCE_TEMPLATES {
        let source = apply_source_template(template, original_url);
        match try_one(source.clone()).await {
            Ok(value) => return Ok(value),
            Err(e) => {
                eprintln!("[pier] 下载源失败 {source}：{e}，尝试下一个源");
                failures.push(format!("{source}（{e}）"));
            }
        }
    }
    Err(format!(
        "所有下载源均失败（共 {} 个）：{}。请检查网络后重试，或在设置页手动导入官方渠道下载的引擎文件。",
        failures.len(),
        failures.join("；")
    ))
}

/// Resolve the release asset for `backend`, download (with per-source
/// fallback), unpack, probe and swap it into `dir`. Returns the path of the
/// installed binary.
async fn install_to_dir(dir: &Path, backend: Backend) -> Result<PathBuf, String> {
    let (asset_name, url) = resolve_asset_url(backend).await?;
    let asset_name = &asset_name; // 借用即可被每个源的未来复制，闭包可重复调用
    let inner_name = archive_inner_name(backend);
    let final_name = binary_file_name(backend);

    // 成功标准 = 下载 + 解包 + 魔数校验 + `probe_version` 全部通过；
    // 任一环节失败都会清理暂存文件并由 try_sources 换下一个源。
    let staged_path = try_sources(&url, |source| async move {
        attempt_one_source(&source, asset_name, dir, inner_name, final_name).await
    })
    .await?;

    swap_staged_into_place(dir, final_name, &staged_path)
}

#[derive(Debug, Deserialize)]
struct GitHubRelease {
    tag_name: String,
    #[serde(default)]
    assets: Vec<GitHubAsset>,
}

#[derive(Debug, Deserialize)]
struct GitHubAsset {
    name: String,
    browser_download_url: String,
}

async fn fetch_latest_github_release(
    api_url: &str,
    project: &str,
) -> Result<GitHubRelease, String> {
    let body = crate::util::fetch_github_release_text(api_url, Some(API_TIMEOUT)).await?;
    serde_json::from_str(&body)
        .map_err(|e| format!("could not parse the {project} release info: {e}"))
}

/// 平台可执行文件的魔数校验（纯函数，便于测试）：只放行当前平台的
/// 可执行格式，优先、明确地拒绝 HTML 错误页与任意垃圾数据。
/// 注意用 `cfg!` 运行时分支而非 `#[cfg]`，三个平台分支都参与编译，
/// 测试在任何平台上都能覆盖全部魔数。
fn check_magic_bytes(header: &[u8]) -> Result<(), String> {
    // HTML 错误页是镜像/下载源失效时最常见的响应体（`<`/`<!` 开头均覆盖）。
    if header.first() == Some(&b'<') {
        return Err("文件内容是 HTML/文本（疑似下载源的错误页），不是可执行文件".to_string());
    }
    if cfg!(target_os = "macos") {
        // Mach-O 64 位（cf fa ed fe）与 universal/fat header（ca fe ba be）。
        if header.starts_with(&[0xCF, 0xFA, 0xED, 0xFE])
            || header.starts_with(&[0xCA, 0xFE, 0xBA, 0xBE])
        {
            return Ok(());
        }
        Err("不是有效的 macOS 可执行文件（Mach-O）".to_string())
    } else if cfg!(target_os = "windows") {
        if header.starts_with(b"MZ") {
            return Ok(());
        }
        Err("不是有效的 Windows 可执行文件（PE/MZ）".to_string())
    } else {
        if header.starts_with(&[0x7F, 0x45, 0x4C, 0x46]) {
            return Ok(());
        }
        Err("不是有效的 Linux 可执行文件（ELF）".to_string())
    }
}

/// 读取文件前 8 字节并做平台魔数校验（拦 HTML 错误页 / 非可执行数据）。
fn validate_file_magic(path: &Path) -> Result<(), String> {
    use std::io::Read;
    let mut file =
        std::fs::File::open(path).map_err(|e| format!("无法读取文件 {}：{e}", path.display()))?;
    let mut header = [0u8; 8];
    let n = file
        .read(&mut header)
        .map_err(|e| format!("读取文件头 {} 失败：{e}", path.display()))?;
    check_magic_bytes(&header[..n])
}

/// 单个下载源的完整尝试：下载 → 解包到暂存 → 魔数校验 → chmod →
/// `probe_version` 探测。成功返回暂存文件路径；任何一步失败都清理
/// 暂存文件并返回错误（由 `try_sources` 汇总后换下一个源）。
async fn attempt_one_source(
    source_url: &str,
    asset_name: &str,
    dir: &Path,
    inner_name: &str,
    final_name: &str,
) -> Result<PathBuf, String> {
    let download_path = dir.join(format!("{final_name}.download"));
    let staged_path = dir.join(format!("{final_name}.staging"));

    // 整体 300s 超时：镜像挂起时不能卡死整条回退链。
    if let Err(e) =
        crate::util::download_to_file(source_url, &download_path, Some(DOWNLOAD_TIMEOUT)).await
    {
        let _ = std::fs::remove_file(&download_path);
        return Err(e);
    }

    let unpacked = match archive_kind(asset_name) {
        ArchiveKind::Plain => {
            // The asset is the binary itself.
            std::fs::rename(&download_path, &staged_path)
                .map_err(|e| format!("移动已下载文件到暂存位置失败：{e}"))
        }
        ArchiveKind::TarGz => unpack_tar_gz(&download_path, inner_name, &staged_path),
        ArchiveKind::Zip => unpack_zip(&download_path, inner_name, &staged_path),
    };
    // The archive is no longer needed either way.
    let _ = std::fs::remove_file(&download_path);
    if let Err(e) = unpacked {
        let _ = std::fs::remove_file(&staged_path);
        return Err(e);
    }

    // 镜像失效时最常见的坑：200 + HTML 错误页被当二进制落盘，魔数先行拦截。
    if let Err(e) = validate_file_magic(&staged_path) {
        let _ = std::fs::remove_file(&staged_path);
        return Err(e);
    }

    make_executable(&staged_path)?;

    // 成功标准：--version 能给出非空输出。HTML 伪装、平台不对、包损坏
    // 都会在这一步暴露，然后由调用方换下一个源。
    if probe_version(&staged_path).is_none() {
        let _ = std::fs::remove_file(&staged_path);
        return Err(format!(
            "下载成功但 {final_name} --version 探测失败（疑似损坏或非本平台的可执行文件）"
        ));
    }
    Ok(staged_path)
}

/// 把暂存好的二进制原子换装到 `dir/<final_name>`：旧文件先挪 `.bak`，
/// rename 失败回滚 `.bak`，成功后删除。返回最终安装路径。
fn swap_staged_into_place(
    dir: &Path,
    final_name: &str,
    staged_path: &Path,
) -> Result<PathBuf, String> {
    let final_path = dir.join(final_name);
    let backup_path = dir.join(format!("{final_name}.bak"));
    let had_old = final_path.exists();
    if had_old {
        let _ = std::fs::remove_file(&backup_path);
        std::fs::rename(&final_path, &backup_path)
            .map_err(|e| format!("备份现有引擎文件 {} 失败：{e}", final_path.display()))?;
    }
    if let Err(e) = std::fs::rename(staged_path, &final_path) {
        // Keep the old binary usable if the swap fails.
        if had_old {
            let _ = std::fs::rename(&backup_path, &final_path);
        }
        let _ = std::fs::remove_file(staged_path);
        return Err(format!(
            "安装新引擎文件到 {} 失败：{e}",
            final_path.display()
        ));
    }
    let _ = std::fs::remove_file(&backup_path);

    Ok(final_path)
}

#[cfg(unix)]
fn make_executable(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = std::fs::metadata(path)
        .map_err(|e| format!("failed to stat {}: {e}", path.display()))?
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(path, permissions)
        .map_err(|e| format!("failed to chmod 0755 {}: {e}", path.display()))
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) -> Result<(), String> {
    // Windows marks executability by file extension; nothing to do.
    Ok(())
}

/// Extract the entry named `inner_name` from a gzip tarball.
///
/// The name is matched against the entry's FILE NAME at any depth, so
/// archives with a top-level wrapper directory (frp ships
/// `frp_<ver>_<os>_<arch>/frpc`) are handled. Path-traversal safety: the
/// entry path is never used as an extraction destination — the content is
/// streamed into the fixed `dest` — and only regular files qualify, so a
/// crafted `../../...` entry, directory entry or symlink cannot escape.
fn unpack_tar_gz(archive: &Path, inner_name: &str, dest: &Path) -> Result<(), String> {
    let file = std::fs::File::open(archive)
        .map_err(|e| format!("failed to open {}: {e}", archive.display()))?;
    let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(file));
    // Do not follow the archive's own path hints; we never extract paths.
    tar.set_preserve_permissions(false);
    let entries = tar
        .entries()
        .map_err(|e| format!("failed to read the tar archive {}: {e}", archive.display()))?;
    for entry in entries {
        let mut entry = entry.map_err(|e| format!("failed to read a tar entry: {e}"))?;
        if !entry.header().entry_type().is_file() {
            // Skips directories, symlinks, hardlinks, etc.
            continue;
        }
        let entry_path = entry
            .path()
            .map_err(|e| format!("failed to read a tar entry name: {e}"))?
            .to_path_buf();
        if entry_path.file_name() == Some(OsStr::new(inner_name)) {
            let mut out = std::fs::File::create(dest)
                .map_err(|e| format!("failed to create {}: {e}", dest.display()))?;
            std::io::copy(&mut entry, &mut out)
                .map_err(|e| format!("failed to unpack {inner_name:?}: {e}"))?;
            return Ok(());
        }
    }
    Err(format!(
        "the archive {} does not contain a file named {inner_name:?}",
        archive.display()
    ))
}

/// Extract the entry named `inner_name` from a zip archive (matched by file
/// name at any depth, regular files only — same traversal model as
/// `unpack_tar_gz`).
fn unpack_zip(archive: &Path, inner_name: &str, dest: &Path) -> Result<(), String> {
    let file = std::fs::File::open(archive)
        .map_err(|e| format!("failed to open {}: {e}", archive.display()))?;
    let mut zip =
        zip::ZipArchive::new(file).map_err(|e| format!("failed to read the zip archive: {e}"))?;
    for i in 0..zip.len() {
        let mut entry = zip
            .by_index(i)
            .map_err(|e| format!("failed to open zip entry #{i}: {e}"))?;
        if entry.is_dir() || entry.is_symlink() {
            continue;
        }
        let entry_path = Path::new(entry.name()).to_path_buf();
        if entry_path.file_name() == Some(OsStr::new(inner_name)) {
            let mut out = std::fs::File::create(dest)
                .map_err(|e| format!("failed to create {}: {e}", dest.display()))?;
            std::io::copy(&mut entry, &mut out)
                .map_err(|e| format!("failed to unpack {inner_name:?}: {e}"))?;
            return Ok(());
        }
    }
    Err(format!(
        "the archive {} does not contain a file named {inner_name:?}",
        archive.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloudflared_assets_map_by_platform() {
        assert_eq!(
            cloudflared_asset_name("macos", "aarch64"),
            Some("cloudflared-darwin-arm64.tgz")
        );
        assert_eq!(
            cloudflared_asset_name("macos", "x86_64"),
            Some("cloudflared-darwin-amd64.tgz")
        );
        assert_eq!(
            cloudflared_asset_name("windows", "x86_64"),
            Some("cloudflared-windows-amd64.exe")
        );
        assert_eq!(
            cloudflared_asset_name("linux", "x86_64"),
            Some("cloudflared-linux-amd64")
        );
        assert_eq!(cloudflared_asset_name("windows", "aarch64"), None);
        assert_eq!(cloudflared_asset_name("freebsd", "x86_64"), None);
    }

    #[test]
    fn bore_assets_map_by_platform() {
        assert_eq!(
            bore_asset_name("v0.6.0", "macos", "aarch64").as_deref(),
            Some("bore-v0.6.0-aarch64-apple-darwin.tar.gz")
        );
        assert_eq!(
            bore_asset_name("v0.6.0", "macos", "x86_64").as_deref(),
            Some("bore-v0.6.0-x86_64-apple-darwin.tar.gz")
        );
        assert_eq!(
            bore_asset_name("v0.6.0", "windows", "x86_64").as_deref(),
            Some("bore-v0.6.0-x86_64-pc-windows-msvc.zip")
        );
        assert_eq!(
            bore_asset_name("v0.6.0", "linux", "aarch64").as_deref(),
            Some("bore-v0.6.0-aarch64-unknown-linux-musl.tar.gz")
        );
        // bore ships no aarch64 windows build.
        assert_eq!(bore_asset_name("v0.6.0", "windows", "aarch64"), None);
    }

    #[test]
    fn frp_assets_map_by_platform() {
        // Tag carries the `v`, the asset version does not (verified on v0.71.0).
        assert_eq!(
            frp_asset_name("v0.71.0", "macos", "aarch64").as_deref(),
            Some("frp_0.71.0_darwin_arm64.tar.gz")
        );
        assert_eq!(
            frp_asset_name("v0.71.0", "macos", "x86_64").as_deref(),
            Some("frp_0.71.0_darwin_amd64.tar.gz")
        );
        assert_eq!(
            frp_asset_name("v0.71.0", "windows", "x86_64").as_deref(),
            Some("frp_0.71.0_windows_amd64.zip")
        );
        assert_eq!(
            frp_asset_name("v0.71.0", "windows", "aarch64").as_deref(),
            Some("frp_0.71.0_windows_arm64.zip")
        );
        assert_eq!(
            frp_asset_name("v0.71.0", "linux", "x86_64").as_deref(),
            Some("frp_0.71.0_linux_amd64.tar.gz")
        );
        assert_eq!(
            frp_asset_name("v0.71.0", "linux", "aarch64").as_deref(),
            Some("frp_0.71.0_linux_arm64.tar.gz")
        );
        assert_eq!(frp_asset_name("v0.71.0", "freebsd", "x86_64"), None);
        assert_eq!(frp_asset_name("v0.71.0", "android", "x86_64"), None);
        // frp tags always carry the v prefix; a bare version yields no asset.
        assert_eq!(frp_asset_name("0.71.0", "macos", "aarch64"), None);
    }

    #[test]
    fn frp_inner_name_matches_final_binary_name() {
        // frp is the one backend whose Windows archive ships the `.exe` name
        // (frp_0.71.0_windows_amd64/frpc.exe); the unpacker's file-name match
        // must agree with the final swap name on every platform.
        assert_eq!(
            archive_inner_name(Backend::Frp),
            binary_file_name(Backend::Frp)
        );
        if cfg!(target_os = "windows") {
            assert_eq!(archive_inner_name(Backend::Frp), "frpc.exe");
        } else {
            assert_eq!(archive_inner_name(Backend::Frp), "frpc");
        }
    }

    #[test]
    fn archive_kind_is_detected_from_extension() {
        assert_eq!(
            archive_kind("cloudflared-darwin-arm64.tgz"),
            ArchiveKind::TarGz
        );
        assert_eq!(
            archive_kind("bore-v0.6.0-aarch64-apple-darwin.tar.gz"),
            ArchiveKind::TarGz
        );
        assert_eq!(
            archive_kind("bore-v0.6.0-x86_64-pc-windows-msvc.zip"),
            ArchiveKind::Zip
        );
        assert_eq!(
            archive_kind("cloudflared-windows-amd64.exe"),
            ArchiveKind::Plain
        );
        assert_eq!(archive_kind("cloudflared-linux-amd64"), ArchiveKind::Plain);
    }

    #[test]
    fn binary_names_match_inner_archive_names_on_this_platform() {
        // The swap step renames the unpacked archive member to the platform
        // file name; make sure both sides agree about the current platform.
        for backend in [Backend::Cloudflare, Backend::Bore] {
            let final_name = binary_file_name(backend);
            if cfg!(target_os = "windows") {
                assert_eq!(final_name, format!("{}.exe", archive_inner_name(backend)));
            } else {
                assert_eq!(final_name, archive_inner_name(backend));
            }
        }
    }

    #[test]
    fn source_templates_build_direct_and_mirror_urls() {
        // 直连：空模板原样返回完整原始 URL。
        let raw = "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-darwin-arm64.tgz";
        assert_eq!(
            apply_source_template(DOWNLOAD_SOURCE_TEMPLATES[0], raw),
            raw
        );
        // 镜像：`{url}` 占位符替换为完整原始 URL（前缀拼在整条 URL 之前）。
        assert_eq!(
            apply_source_template("https://gh-proxy.com/{url}", raw),
            format!("https://gh-proxy.com/{raw}")
        );
        assert_eq!(
            apply_source_template("https://ghfast.top/{url}", raw),
            format!("https://ghfast.top/{raw}")
        );
        // API URL 同样适用（模板占位符语义与协议无关）。
        assert_eq!(
            apply_source_template("https://gh-proxy.com/{url}", BORE_RELEASE_API_URL),
            format!("https://gh-proxy.com/{BORE_RELEASE_API_URL}")
        );
        // 源列表本身有序：直连在前，其后逐个镜像（https 模板以 /{url} 结尾）。
        assert_eq!(DOWNLOAD_SOURCE_TEMPLATES.first(), Some(&""));
        assert!(DOWNLOAD_SOURCE_TEMPLATES[1..]
            .iter()
            .all(|t| t.starts_with("https://") && t.ends_with("/{url}")));
        // pinned tag 兜底直链的固定形态（bore/frp 的 API 不可达路径）。
        assert_eq!(
            github_pinned_download_url("fatedier/frp", "v0.71.0", "frp_0.71.0_darwin_arm64.tar.gz"),
            "https://github.com/fatedier/frp/releases/download/v0.71.0/frp_0.71.0_darwin_arm64.tar.gz"
        );
        assert_eq!(
            github_pinned_download_url("ekzhang/bore", BORE_FALLBACK_TAG, "bore"),
            format!("https://github.com/ekzhang/bore/releases/download/{BORE_FALLBACK_TAG}/bore")
        );
    }

    #[tokio::test]
    async fn try_sources_tries_every_source_in_order_and_reports_all_failures() {
        let mut seen: Vec<String> = Vec::new();
        let result: Result<&str, String> = try_sources(
            "https://github.com/x/y/releases/download/v1/eng",
            |source| {
                seen.push(source.clone());
                std::future::ready(Err(format!("fail {source}")))
            },
        )
        .await;
        // 顺序固定：直连 → gh-proxy → ghfast，全部尝试后才报错。
        assert_eq!(seen.len(), DOWNLOAD_SOURCE_TEMPLATES.len());
        assert_eq!(seen[0], "https://github.com/x/y/releases/download/v1/eng");
        assert_eq!(
            seen[1],
            "https://gh-proxy.com/https://github.com/x/y/releases/download/v1/eng"
        );
        assert_eq!(
            seen[2],
            "https://ghfast.top/https://github.com/x/y/releases/download/v1/eng"
        );
        // 全失败的错误必须中文、含源列表与手动导入建议。
        let err = result.unwrap_err();
        assert!(err.contains("所有下载源均失败"), "err: {err}");
        assert!(err.contains("gh-proxy.com"), "err: {err}");
        assert!(err.contains("ghfast.top"), "err: {err}");
        assert!(err.contains("手动导入"), "err: {err}");
        assert!(
            err.contains("fail"),
            "每个源的具体失败原因要在错误里: {err}"
        );
    }

    #[tokio::test]
    async fn try_sources_stops_at_first_success() {
        let mut calls = 0usize;
        let result: Result<String, String> = try_sources("https://github.com/a/b", |source| {
            calls += 1;
            if calls == 2 {
                // 第二个源（镜像）成功。
                std::future::ready(Ok(source))
            } else {
                std::future::ready(Err(format!("fail {source}")))
            }
        })
        .await;
        assert_eq!(
            result.unwrap(),
            "https://gh-proxy.com/https://github.com/a/b"
        );
        assert_eq!(calls, 2, "成功后不得再尝试后续源");
    }

    #[test]
    fn magic_check_rejects_html_and_garbage_on_every_platform() {
        // HTML 错误页（镜像失效的常见产物）一律拒绝。
        assert!(check_magic_bytes(b"<!DOCTYPE html><html>").is_err());
        assert!(check_magic_bytes(b"<html><body>404</body></html>").is_err());
        // 普通文本 / 空文件 / 短垃圾也必须拒绝。
        assert!(check_magic_bytes(b"OK").is_err());
        assert!(check_magic_bytes(&[]).is_err());
        assert!(check_magic_bytes(&[0x00, 0x01]).is_err());
    }

    #[test]
    fn magic_check_matches_current_platform_rules() {
        let macho64 = [0xCF, 0xFA, 0xED, 0xFE, 0x00, 0x00, 0x00, 0x01];
        let macho_fat = [0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x02];
        let elf = [0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00];
        let mz = b"MZ\x90\x00\x03\x00\x00\x00";
        let accepts = |h: &[u8]| check_magic_bytes(h).is_ok();

        if cfg!(target_os = "macos") {
            // 放行：Mach-O 64 位 + universal/fat。
            assert!(accepts(&macho64));
            assert!(accepts(&macho_fat));
            // 拒绝：其他平台格式。
            assert!(!accepts(&elf));
            assert!(!accepts(mz));
        } else if cfg!(target_os = "windows") {
            assert!(accepts(mz));
            assert!(!accepts(&macho64));
            assert!(!accepts(&macho_fat));
            assert!(!accepts(&elf));
        } else {
            assert!(accepts(&elf));
            assert!(!accepts(&macho64));
            assert!(!accepts(&macho_fat));
            assert!(!accepts(mz));
        }
    }

    /// Real end-to-end pipeline (download -> unpack -> chmod -> swap) against
    /// GitHub. Ignored by default because it downloads ~40 MB per backend
    /// (frp archives ship both frpc and frps).
    /// Run with: cargo test -- --ignored
    #[test]
    #[ignore = "downloads real cloudflared/bore/frp builds (~55 MB) from GitHub"]
    fn install_pipeline_downloads_unpacks_and_marks_executable() {
        let dir = std::env::temp_dir().join(format!("pier-binman-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create test dir");

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build runtime");

        for backend in [Backend::Cloudflare, Backend::Bore, Backend::Frp] {
            let path = rt
                .block_on(install_to_dir(&dir, backend))
                .unwrap_or_else(|e| panic!("{backend:?} install failed: {e}"));
            assert!(path.is_file(), "binary missing at {}", path.display());
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(&path)
                    .expect("stat binary")
                    .permissions()
                    .mode();
                assert_eq!(mode & 0o755, 0o755, "binary should be rwxr-xr-x");
            }
            // The freshly installed binary must answer --version.
            assert!(
                probe_version(&path).is_some(),
                "{backend:?} --version produced no output"
            );
        }

        // A second install must survive replacing an existing binary (.bak swap).
        let path = rt
            .block_on(install_to_dir(&dir, Backend::Bore))
            .expect("re-install bore");
        assert!(path.is_file());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
