// Binary manager — locates and downloads the tunnel engine binaries.
//
// Public API (keep signatures stable):
//   * `resolve`          — find an installed engine binary
//   * `bin_dir`          — `<app_data_dir>/bin`
//   * `binary_file_name` — engine binary file name for the current platform
//   * `read_status`      — install state of both engines
//   * `install`          — download + unpack + swap-in an engine binary
//
// Download sources (verified on 2026-10-06, all HTTP 200):
//   cloudflared: https://github.com/cloudflare/cloudflared/releases/latest/download/<asset>
//     - cloudflared-darwin-arm64.tgz  (contains `cloudflared` at archive root)
//     - cloudflared-darwin-amd64.tgz
//     - cloudflared-windows-amd64.exe (plain binary, no unpacking)
//   bore: https://github.com/ekzhang/bore/releases (resolved via the GitHub API)
//     - bore-v0.6.0-aarch64-apple-darwin.tar.gz  (contains `bore` at archive root)
//     - bore-v0.6.0-x86_64-apple-darwin.tar.gz
//     - bore-v0.6.0-x86_64-pc-windows-msvc.zip
//   frp: https://github.com/fatedier/frp/releases (resolved via the GitHub API;
//   asset names verified on 2026-10-06, all HTTP 200, tag v0.71.0 — note the
//   asset version carries NO `v` prefix while the tag does):
//     - frp_0.71.0_darwin_arm64.tar.gz
//     - frp_0.71.0_windows_amd64.zip / frp_0.71.0_windows_arm64.zip
//     - frp_0.71.0_linux_amd64.tar.gz / frp_0.71.0_linux_arm64.tar.gz
//   ^ frp archives have a TOP-LEVEL DIRECTORY `frp_<ver>_<os>_<arch>/` with
//   `frpc` (unix) / `frpc.exe` (windows) inside; the unpacker matches by file
//   name anywhere in the archive, so it sees through the wrapper directory.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use tauri::Manager;

use crate::models::{Backend, BinaryInfo, BinaryStatus};

const CLOUDFLARED_LATEST_URL: &str =
    "https://github.com/cloudflare/cloudflared/releases/latest/download";
const BORE_RELEASE_API_URL: &str = "https://api.github.com/repos/ekzhang/bore/releases/latest";
const FRP_RELEASE_API_URL: &str = "https://api.github.com/repos/fatedier/frp/releases/latest";

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
    let info = |backend: Backend| {
        match resolve(app, backend) {
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
        }
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

/// Resolve the release asset for `backend`, download, unpack and swap it into
/// `dir`. Returns the path of the installed binary.
async fn install_to_dir(dir: &Path, backend: Backend) -> Result<PathBuf, String> {
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;

    let (asset_name, url) = match backend {
        Backend::Cloudflare | Backend::CloudflareNamed => {
            let asset = cloudflared_asset_name(os, arch).ok_or_else(|| {
                "cloudflared publishes no official build for this platform".to_string()
            })?;
            let url = format!("{CLOUDFLARED_LATEST_URL}/{asset}");
            (asset.to_string(), url)
        }
        // frp releases carry a top-level directory inside the archive; the
        // unpacker matches the binary by file name, so it sees through it.
        Backend::Frp => {
            let release = fetch_latest_github_release(FRP_RELEASE_API_URL, "frp").await?;
            let asset = frp_asset_name(&release.tag_name, os, arch).ok_or_else(|| {
                "frp publishes no official build for this platform".to_string()
            })?;
            match release.assets.iter().find(|a| a.name == asset) {
                Some(a) => (a.name.clone(), a.browser_download_url.clone()),
                None => {
                    let names: Vec<&str> = release.assets.iter().map(|a| a.name.as_str()).collect();
                    return Err(format!(
                        "frp release {} does not contain the expected asset {asset:?} \
                         (available: {})",
                        release.tag_name,
                        names.join(", ")
                    ));
                }
            }
        }
        Backend::Bore => {
            let release = fetch_latest_bore_release().await?;
            let asset = bore_asset_name(&release.tag_name, os, arch).ok_or_else(|| {
                "bore publishes no official build for this platform".to_string()
            })?;
            match release.assets.iter().find(|a| a.name == asset) {
                Some(a) => (a.name.clone(), a.browser_download_url.clone()),
                None => {
                    let names: Vec<&str> = release.assets.iter().map(|a| a.name.as_str()).collect();
                    return Err(format!(
                        "bore release {} does not contain the expected asset {asset:?} \
                         (available: {})",
                        release.tag_name,
                        names.join(", ")
                    ));
                }
            }
        }
    };

    fetch_and_unpack(
        &url,
        &asset_name,
        dir,
        archive_inner_name(backend),
        binary_file_name(backend),
    )
    .await
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
    let body = crate::util::fetch_github_release_text(api_url, None).await?;
    serde_json::from_str(&body)
        .map_err(|e| format!("could not parse the {project} release info: {e}"))
}

async fn fetch_latest_bore_release() -> Result<GitHubRelease, String> {
    fetch_latest_github_release(BORE_RELEASE_API_URL, "bore").await
}

/// Stream `url` into `dest`, then unpack the engine binary into place.
///
/// Pipeline (all intermediates live next to the final binary):
///   1. stream download -> `<final>.download`
///   2. unpack           -> `<final>.staging` (+ chmod 0755 on unix)
///   3. existing binary  -> `<final>.bak`
///   4. rename staging   -> `<final>` (atomic; the backup is rolled back if
///      this fails, then removed on success)
async fn fetch_and_unpack(
    url: &str,
    asset_name: &str,
    dir: &Path,
    inner_name: &str,
    final_name: &str,
) -> Result<PathBuf, String> {
    let final_path = dir.join(final_name);
    let download_path = dir.join(format!("{final_name}.download"));
    let staged_path = dir.join(format!("{final_name}.staging"));

    // 大文件下载：不设整体超时，仅保留共享客户端的 30s 连接超时。
    crate::util::download_to_file(url, &download_path, None).await?;

    let unpack = match archive_kind(asset_name) {
        ArchiveKind::Plain => {
            // The asset is the binary itself.
            std::fs::rename(&download_path, &staged_path)
                .map_err(|e| format!("failed to move the downloaded file into place: {e}"))
        }
        ArchiveKind::TarGz => unpack_tar_gz(&download_path, inner_name, &staged_path),
        ArchiveKind::Zip => unpack_zip(&download_path, inner_name, &staged_path),
    };
    // The archive is no longer needed either way.
    let _ = std::fs::remove_file(&download_path);
    if let Err(e) = unpack {
        let _ = std::fs::remove_file(&staged_path);
        return Err(e);
    }

    make_executable(&staged_path)?;

    let backup_path = dir.join(format!("{final_name}.bak"));
    let had_old = final_path.exists();
    if had_old {
        let _ = std::fs::remove_file(&backup_path);
        std::fs::rename(&final_path, &backup_path).map_err(|e| {
            format!(
                "failed to back up the existing binary at {}: {e}",
                final_path.display()
            )
        })?;
    }
    if let Err(e) = std::fs::rename(&staged_path, &final_path) {
        // Keep the old binary usable if the swap fails.
        if had_old {
            let _ = std::fs::rename(&backup_path, &final_path);
        }
        let _ = std::fs::remove_file(&staged_path);
        return Err(format!(
            "failed to move the new binary into place at {}: {e}",
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
        let mut entry =
            entry.map_err(|e| format!("failed to read a tar entry: {e}"))?;
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
        assert_eq!(archive_kind("cloudflared-darwin-arm64.tgz"), ArchiveKind::TarGz);
        assert_eq!(
            archive_kind("bore-v0.6.0-aarch64-apple-darwin.tar.gz"),
            ArchiveKind::TarGz
        );
        assert_eq!(
            archive_kind("bore-v0.6.0-x86_64-pc-windows-msvc.zip"),
            ArchiveKind::Zip
        );
        assert_eq!(archive_kind("cloudflared-windows-amd64.exe"), ArchiveKind::Plain);
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
                let mode = std::fs::metadata(&path).expect("stat binary").permissions().mode();
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
