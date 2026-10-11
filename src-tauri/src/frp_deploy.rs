// R3 IMPLEMENTS: one-click frps deployment over SSH.
//
// Flow (every step emits "deploy://progress", completion emits "deploy://done"):
//   connect -> probe (sudo, arch, os-release, systemd) -> ports (ss -tlnp
//   precheck + cloud metadata detection) -> download (VPS-side curl from
//   GitHub with ghproxy mirrors, else local download + SFTP upload; sha256
//   checked against the GitHub API asset digest) -> config (random token ->
//   keychain, TOML frps.toml -> /opt/pier) -> systemd (pier-frps.service,
//   idempotent upgrade path, foreign-install detection) -> firewall (ufw /
//   firewalld; SELinux via semanage, never setenforce 0) -> verify (local
//   dashboard curl + systemctl is-active).
use std::time::Duration;

use tauri::{AppHandle, Emitter};

use crate::models::{DeployProgress, DeployResult, ServerConfig, StepStatus};
use crate::servers_store;
use crate::ssh::SshSession;
// TOML basic-string 转义与 providers.rs 共用（crate::util）。
use crate::util::toml_escape;

const PROGRESS_EVENT: &str = "deploy://progress";
const DONE_EVENT: &str = "deploy://done";

/// frp release assets, resolved against the GitHub API.
const RELEASE_API: &str = "https://api.github.com/repos/fatedier/frp/releases/latest";
/// User agent is mandatory for GitHub API requests (401 otherwise).
const USER_AGENT: &str = concat!("pier/", env!("CARGO_PKG_VERSION"));
/// Mirrors tried in order when the VPS cannot reach GitHub directly. Failure
/// of any mirror is non-fatal — the flow falls through to the next one and
/// finally to a local download + SFTP upload.
const GHPROXY_MIRRORS: &[&str] = &["https://ghproxy.com/", "https://mirror.ghproxy.com/"];
/// Where artifacts are staged on the VPS; /tmp is writable without root.
const TMP_TARBALL: &str = "/tmp/pier-frps.tar.gz";
const TMP_EXTRACT_DIR: &str = "/tmp/pier-frp";
const TMP_TOML: &str = "/tmp/pier-frps.toml";
const TMP_UNIT: &str = "/tmp/pier-frps.service";
/// Pier's install prefix on the VPS (never touched by other tools).
const REMOTE_DIR: &str = "/opt/pier";
const REMOTE_BIN: &str = "/opt/pier/frps";
const REMOTE_TOML: &str = "/opt/pier/frps.toml";
const REMOTE_UNIT: &str = "/etc/systemd/system/pier-frps.service";
const SERVICE: &str = "pier-frps";

/// Long-running steps get explicit budgets: the tarball download via curl and
/// the local download both must survive slow uplinks (14 MB asset).
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(300);
const LOCAL_DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(600);
/// Cloud metadata endpoints answer in ~1s or not at all (curl -m 1).
const METADATA_TIMEOUT: Duration = Duration::from_secs(10);

/// Step failure with the step slug for the final "fail" progress event.
struct DeployFailure {
    step: &'static str,
    message: String,
    /// Set once a token has been generated/stored so later failures can still
    /// report it in the done event.
    token: Option<String>,
}

fn progress(
    app: &AppHandle,
    server_id: &str,
    step: &str,
    status: StepStatus,
    message: Option<String>,
) {
    let _ = app.emit(
        PROGRESS_EVENT,
        DeployProgress {
            server_id: server_id.to_string(),
            step: step.to_string(),
            status,
            message,
        },
    );
}

/// Run the full deployment for `server`. Long-running; call from a spawned
/// task and report progress via the AppHandle. Idempotent: re-deploying
/// upgrades in place, and existing foreign frps installations are detected
/// and reported rather than clobbered.
pub async fn deploy(app: AppHandle, server: ServerConfig) -> DeployResult {
    let server_id = server.id.clone();
    let result = match deploy_steps(&app, &server).await {
        Ok((version, token)) => {
            if let Err(e) = update_server_record(&app, &server_id, |s| {
                s.deployed = true;
                s.frps_version = Some(version.clone());
            }) {
                eprintln!("[pier] deploy: servers.json update failed: {e}");
            }
            DeployResult { server_id, ok: true, error: None, token: Some(token) }
        }
        Err(fail) => {
            progress(
                &app,
                &server_id,
                fail.step,
                StepStatus::Fail,
                Some(fail.message.clone()),
            );
            DeployResult { server_id, ok: false, error: Some(fail.message), token: fail.token }
        }
    };
    let _ = app.emit(DONE_EVENT, &result);
    result
}

/// The eight steps, in order. Every step emits its own Running and its own
/// Ok/Skip; the deploy wrapper turns an Err into the Fail event for the step
/// that failed. Returns the deployed frps version and the frps token.
async fn deploy_steps(
    app: &AppHandle,
    server: &ServerConfig,
) -> Result<(String, String), DeployFailure> {
    // -- connect ------------------------------------------------------------
    progress(
        app,
        &server.id,
        "connect",
        StepStatus::Running,
        Some(format!("正在连接 {}:{}…", server.host, server.port)),
    );
    let mut ssh = match crate::ssh::connect(server).await {
        Ok(s) => s,
        Err(e) => {
            return Err(DeployFailure { step: "connect", message: e, token: None });
        }
    };
    progress(
        app,
        &server.id,
        "connect",
        StepStatus::Ok,
        Some(format!("已连接 {}（用户 {}）", server.host, server.username)),
    );

    // -- probe --------------------------------------------------------------
    progress(
        app,
        &server.id,
        "probe",
        StepStatus::Running,
        Some("正在检测系统环境…".to_string()),
    );
    let probe = match step_probe(&mut ssh, server).await {
        Ok(p) => {
            progress(app, &server.id, "probe", StepStatus::Ok, Some(p.summary.clone()));
            p
        }
        Err(e) => return Err(DeployFailure { step: "probe", message: e, token: None }),
    };

    // -- ports --------------------------------------------------------------
    progress(
        app,
        &server.id,
        "ports",
        StepStatus::Running,
        Some("正在检查端口占用…".to_string()),
    );
    let cloud = match step_ports(&mut ssh, server).await {
        Ok(c) => {
            progress(
                app,
                &server.id,
                "ports",
                StepStatus::Ok,
                Some(match c {
                    Some(cloud) => format!("端口检查通过；检测到{cloud}云主机（部署完成后请到云控制台放行端口）"),
                    None => "端口检查通过，未被占用".to_string(),
                }),
            );
            c
        }
        Err(e) => return Err(DeployFailure { step: "ports", message: e, token: None }),
    };

    // -- download -----------------------------------------------------------
    progress(
        app,
        &server.id,
        "download",
        StepStatus::Running,
        Some("正在获取 frp 发行包…".to_string()),
    );
    let download = match step_download(&mut ssh, probe.arch).await {
        Ok(d) => {
            progress(
                app,
                &server.id,
                "download",
                StepStatus::Ok,
                Some(format!("frp v{} 已就绪（{}）", d.version, d.source)),
            );
            d
        }
        Err(e) => return Err(DeployFailure { step: "download", message: e, token: None }),
    };

    // -- config -------------------------------------------------------------
    progress(
        app,
        &server.id,
        "config",
        StepStatus::Running,
        Some("正在生成配置…".to_string()),
    );
    let token = match step_config(&mut ssh, server, &download).await {
        Ok(t) => {
            progress(
                app,
                &server.id,
                "config",
                StepStatus::Ok,
                Some(if download.upgrade {
                    "已沿用现有配置与 token".to_string()
                } else {
                    format!("随机 token 已存入系统钥匙串，配置已写入 {REMOTE_TOML}")
                }),
            );
            t
        }
        Err(e) => return Err(DeployFailure { step: "config", message: e, token: None }),
    };

    // -- systemd ------------------------------------------------------------
    progress(
        app,
        &server.id,
        "systemd",
        StepStatus::Running,
        Some(if download.upgrade {
            "检测到已有圣手码头部署，正在升级…".to_string()
        } else {
            "正在安装 systemd 服务…".to_string()
        }),
    );
    if let Err(e) = step_systemd(&mut ssh, &download).await {
        return Err(DeployFailure { step: "systemd", message: e, token: Some(token.clone()) });
    }
    progress(
        app,
        &server.id,
        "systemd",
        StepStatus::Ok,
        Some(if download.upgrade {
            format!("{SERVICE} 服务已升级并重启")
        } else {
            format!("{SERVICE} 服务已启用并启动")
        }),
    );

    // -- firewall -----------------------------------------------------------
    progress(
        app,
        &server.id,
        "firewall",
        StepStatus::Running,
        Some("正在配置防火墙…".to_string()),
    );
    let warnings = match step_firewall(&mut ssh, server).await {
        Ok((name, warnings)) => {
            progress(
                app,
                &server.id,
                "firewall",
                name.map_or(StepStatus::Skip, |_| StepStatus::Ok),
                Some(match name {
                    Some(n) => format!("已通过 {n} 放行 TCP {}", ports_list(server)),
                    None => "未检测到启用的 ufw/firewalld，跳过".to_string(),
                }),
            );
            warnings
        }
        Err(e) => {
            return Err(DeployFailure { step: "firewall", message: e, token: Some(token.clone()) });
        }
    };

    // -- verify -------------------------------------------------------------
    progress(
        app,
        &server.id,
        "verify",
        StepStatus::Running,
        Some("正在验证服务状态…".to_string()),
    );
    let observed_version = match step_verify(&mut ssh, server, &download.version).await {
        Ok(v) => v,
        Err(e) => return Err(DeployFailure { step: "verify", message: e, token: Some(token.clone()) }),
    };
    let mut message = format!("frps {} 正在运行", observed_version);
    if !warnings.is_empty() {
        message.push_str("；注意：");
        message.push_str(&warnings.join("；"));
    }
    if let Some(cloud) = cloud {
        message.push_str(&cloud_security_group_hint(server, cloud));
    }
    progress(app, &server.id, "verify", StepStatus::Ok, Some(message));

    let _ = ssh
        .run(&format!(
            "rm -f {TMP_TARBALL} {TMP_TOML} {TMP_UNIT} && rm -rf {TMP_EXTRACT_DIR}"
        ))
        .await;
    ssh.close().await;

    Ok((observed_version, token))
}

// ---------------------------------------------------------------------------
// Steps
// ---------------------------------------------------------------------------

struct ProbeInfo {
    arch: &'static str,
    summary: String,
}

/// Root/sudo capability, CPU arch, distro and systemd presence.
async fn step_probe(ssh: &mut SshSession, server: &ServerConfig) -> Result<ProbeInfo, String> {
    let (code, user, err) = ssh.run("whoami").await?;
    if code != 0 {
        return Err(format!("无法获取登录用户：{err}"));
    }
    let user = user.trim().to_string();

    // Early sudo check: fail here with a clear message instead of mid-deploy.
    let (code, _, err) = ssh.run_sudo("true").await?;
    if code != 0 {
        return Err(format!(
            "无法通过 sudo 获取 root 权限：{err}。请确认密码正确（密码登录）或已配置免密 sudo，\
             也可以直接使用 root 登录。"
        ));
    }

    let (code, machine, err) = ssh.run("uname -m").await?;
    if code != 0 {
        return Err(format!("无法获取 CPU 架构：{err}"));
    }
    let arch = map_arch(&machine).ok_or_else(|| {
        format!("不支持的 CPU 架构：{}（仅支持 x86_64 / aarch64）", machine.trim())
    })?;

    // Non-fatal: only used for a friendlier message.
    let os_pretty = ssh
        .run("cat /etc/os-release 2>/dev/null")
        .await
        .ok()
        .and_then(|(c, out, _)| (c == 0).then_some(out))
        .and_then(|out| {
            out.lines().find_map(|l| l.strip_prefix("PRETTY_NAME=")).map(|v| {
                v.trim().trim_matches('"').to_string()
            })
        });

    let (code, out, _) = ssh
        .run("[ -d /run/systemd/system ] && echo yes || echo no")
        .await?;
    if code != 0 || out.trim() != "yes" {
        return Err(
            "目标服务器未运行 systemd（可能是容器或无 systemd 的最小化系统），\
             圣手码头依赖 systemd 托管 frps 服务"
                .to_string(),
        );
    }

    Ok(ProbeInfo {
        arch,
        summary: format!(
            "系统 {}（{}，{}），用户 {}，sudo 可用",
            os_pretty.as_deref().unwrap_or("Linux"),
            arch,
            server.host,
            user
        ),
    })
}

/// Check the four frps ports for conflicts, then probe the cloud vendor via
/// its metadata endpoint (for the security-group hint after deployment).
async fn step_ports(
    ssh: &mut SshSession,
    server: &ServerConfig,
) -> Result<Option<&'static str>, String> {
    let (code, out, _) = ssh
        .run("ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null")
        .await?;
    if code != 0 {
        return Err("无法检测端口占用（ss 与 netstat 均不可用）".to_string());
    }
    let wanted = distinct_ports(server);
    let occupied = parse_occupied_ports(&out);
    let conflicts: Vec<String> = occupied
        .iter()
        .filter(|(port, _)| wanted.contains(port))
        .map(|(port, proc_name)| format!("端口 {port}（{proc_name}）"))
        .collect();
    if !conflicts.is_empty() {
        return Err(format!(
            "{} 已被占用，请更换 frps 端口或停用对应服务后重试。",
            conflicts.join("、")
        ));
    }

    Ok(detect_cloud(ssh).await)
}

struct DownloadInfo {
    version: String,
    extract_dir: String,
    source: String,
    /// True when this is an in-place upgrade of an existing Pier install.
    upgrade: bool,
}

/// Resolve the latest frp release, fetch `frp_<ver>_linux_<arch>.tar.gz` onto
/// the VPS (direct curl -> ghproxy mirrors -> local download + SFTP), verify
/// sha256 against the GitHub API digest when available, and extract it.
async fn step_download(
    ssh: &mut SshSession,
    arch: &'static str,
) -> Result<DownloadInfo, String> {
    // Version + asset digest: prefer the VPS-side GitHub API call; if the VPS
    // cannot reach GitHub, fall back to querying from this machine.
    let release = ssh
        .run_with_timeout(
            &format!("curl -fsSL -m 15 -H 'User-Agent: {USER_AGENT}' '{RELEASE_API}'"),
            Duration::from_secs(25),
        )
        .await
        .ok()
        .filter(|(code, out, _)| *code == 0 && out.trim_start().starts_with('{'))
        .map(|(_, out, _)| out);
    let release = match release {
        Some(text) => Some(extract_release(&text, arch)?),
        None => match fetch_release_json().await {
            Some(text) => Some(extract_release(&text, arch)?),
            None => None,
        },
    };
    let Some((version, expected_sha256)) = release else {
        return Err(
            "无法获取 frp 最新版本：服务器与本机均无法访问 GitHub API（请检查网络或代理设置）"
                .to_string(),
        );
    };

    let asset = asset_name(&version, arch);
    let github_url = format!(
        "https://github.com/fatedier/frp/releases/download/v{version}/{asset}"
    );

    let mut source: Option<String> = None;
    let mut urls = vec![("GitHub 直连", github_url.clone())];
    for mirror in GHPROXY_MIRRORS {
        urls.push((mirror, format!("{mirror}{github_url}")));
    }
    for (label, url) in urls {
        let cmd = format!(
            "curl -fsSL -m {} -o {TMP_TARBALL} '{}' && test -s {TMP_TARBALL} && echo OK",
            DOWNLOAD_TIMEOUT.as_secs(),
            url
        );
        if let Ok((0, out, _)) = ssh.run_with_timeout(&cmd, DOWNLOAD_TIMEOUT + Duration::from_secs(30)).await {
            if out.contains("OK") {
                source = Some(label.to_string());
                break;
            }
        }
    }

    if source.is_none() {
        // Last resort: download on this machine and push over SFTP.
        let local = std::env::temp_dir().join(format!("pier-frp-{}-{asset}", uuid::Uuid::new_v4()));
        // 慢速上行也要能扛住：整体超时 600s（仅本机中转下载路径）。
        crate::util::download_to_file(&github_url, &local, Some(LOCAL_DOWNLOAD_TIMEOUT)).await?;
        ssh.upload_file(&local, TMP_TARBALL)
            .await
            .map_err(|e| format!("SFTP 上传安装包失败：{e}"))?;
        let _ = tokio::fs::remove_file(&local).await;
        source = Some("本机中转下载".to_string());
    }

    // sha256 verification: the GitHub API exposes an asset `digest` field on
    // current releases. When the field is absent (older API responses) the
    // check is skipped rather than failing the deploy.
    if let Some(expected) = expected_sha256 {
        let (code, out, _) = ssh
            .run_with_timeout(&format!("sha256sum {TMP_TARBALL} | cut -d' ' -f1"), Duration::from_secs(30))
            .await?;
        let actual = out.trim().to_string();
        if code != 0 || !actual.eq_ignore_ascii_case(&expected) {
            return Err(format!(
                "下载文件 sha256 校验失败：期望 {expected}，实际 {actual}"
            ));
        }
    }

    let extract_dir = format!("{TMP_EXTRACT_DIR}/frp_{version}_linux_{arch}");
    let (code, _, err) = ssh
        .run(&format!(
            "rm -rf {TMP_EXTRACT_DIR} && mkdir -p {TMP_EXTRACT_DIR} && tar -xzf {TMP_TARBALL} -C {TMP_EXTRACT_DIR}"
        ))
        .await?;
    if code != 0 {
        return Err(format!("解压 frp 安装包失败：{err}"));
    }
    let (code, _, _) = ssh.run(&format!("test -x {extract_dir}/frps && echo OK")).await?;
    if code != 0 {
        return Err(format!("解压后未找到 frps 可执行文件（预期 {extract_dir}/frps）"));
    }

    let upgrade = ssh
        .run(&format!("[ -f {REMOTE_UNIT} ] && echo yes || echo no"))
        .await?
        .1
        .trim()
        == "yes";

    Ok(DownloadInfo {
        version,
        extract_dir,
        source: source.unwrap_or_default(),
        upgrade,
    })
}

/// Generate (or reuse) the frps token, install the TOML config. Also fails
/// early when a foreign frps installation is present (the research flow puts
/// this in the systemd step, but failing here avoids touching /opt/pier at
/// all before we know the install is Pier's to manage).
async fn step_config(
    ssh: &mut SshSession,
    server: &ServerConfig,
    download: &DownloadInfo,
) -> Result<String, String> {
    let foreign = ssh
        .run(
            "if [ -f /etc/systemd/system/frps.service ] || [ -f /lib/systemd/system/frps.service ] \
             || [ -f /usr/lib/systemd/system/frps.service ] || [ -d /etc/frp ]; then echo yes; \
             else echo no; fi",
        )
        .await?
        .1
        .trim()
        == "yes";
    if foreign {
        return Err(
            "检测到已有 frps 安装（frps.service 或 /etc/frp 目录），暂不支持接管。\
             如需圣手码头管理，请先手动停止并移除现有 frps。"
                .to_string(),
        );
    }

    // Token resolution:
    //   fresh install            -> generate a new one;
    //   upgrade, keychain has it -> reuse (config stays untouched);
    //   upgrade, keychain empty  -> reuse the token from the remote TOML;
    //   upgrade, neither         -> generate and rewrite the config.
    let mut rewrite_config = !download.upgrade;
    let token = if download.upgrade {
        match servers_store::try_frps_token(&server.id)? {
            Some(existing) => existing,
            None => {
                let remote = ssh
                    .run(&format!(
                        "sed -n 's/^token[[:space:]]*=[[:space:]]*\"\\(.*\\)\"/\\1/p' {REMOTE_TOML} 2>/dev/null"
                    ))
                    .await?
                    .1
                    .trim()
                    .to_string();
                if remote.is_empty() {
                    rewrite_config = true;
                    generate_token()
                } else {
                    remote
                }
            }
        }
    } else {
        generate_token()
    };
    if !rewrite_config {
        // Keep an existing config only if it is actually still there.
        let present = ssh
            .run(&format!("[ -f {REMOTE_TOML} ] && echo yes || echo no"))
            .await?
            .1
            .trim()
            == "yes";
        rewrite_config = !present;
    }

    if rewrite_config {
        let toml = build_frps_toml(server, &token, &generate_dashboard_password());
        let local_tmp = std::env::temp_dir().join(format!("pier-frps-toml-{}", uuid::Uuid::new_v4()));
        tokio::fs::write(&local_tmp, toml)
            .await
            .map_err(|e| format!("写入本地临时配置失败：{e}"))?;
        ssh.upload_file(&local_tmp, TMP_TOML).await?;
        let _ = tokio::fs::remove_file(&local_tmp).await;
        let (code, _, err) = ssh
            .run_sudo(&format!("mkdir -p {REMOTE_DIR} && install -m 600 {TMP_TOML} {REMOTE_TOML}"))
            .await?;
        if code != 0 {
            return Err(format!("写入 {REMOTE_TOML} 失败：{err}"));
        }
    }

    servers_store::set_frps_token(&server.id, &token)?;
    Ok(token)
}

/// Install the binary, write the systemd unit and start the service. Upgrade
/// path: back up the binary, stop, replace, start — config and unit untouched.
async fn step_systemd(ssh: &mut SshSession, download: &DownloadInfo) -> Result<(), String> {
    if download.upgrade {
        for cmd in [
            format!("cp -a {REMOTE_BIN} {REMOTE_BIN}.bak"),
            format!("systemctl stop {SERVICE}"),
            format!("install -m 755 {}/frps {REMOTE_BIN}", download.extract_dir),
            format!("systemctl start {SERVICE}"),
        ] {
            let (code, _, err) = ssh.run_sudo(&cmd).await?;
            if code != 0 {
                return Err(format!("升级失败（{cmd}）：{err}"));
            }
        }
        return Ok(());
    }

    // Fresh install.
    let (code, _, err) = ssh
        .run_sudo(&format!("install -m 755 {}/frps {REMOTE_BIN}", download.extract_dir))
        .await?;
    if code != 0 {
        return Err(format!("安装 {REMOTE_BIN} 失败：{err}"));
    }

    let unit = build_systemd_unit();
    let local_tmp = std::env::temp_dir().join(format!("pier-frps-unit-{}", uuid::Uuid::new_v4()));
    tokio::fs::write(&local_tmp, unit)
        .await
        .map_err(|e| format!("写入本地临时 unit 失败：{e}"))?;
    ssh.upload_file(&local_tmp, TMP_UNIT).await?;
    let _ = tokio::fs::remove_file(&local_tmp).await;

    let (code, _, err) = ssh
        .run_sudo(&format!("install -m 644 {TMP_UNIT} {REMOTE_UNIT}"))
        .await?;
    if code != 0 {
        return Err(format!("写入 {REMOTE_UNIT} 失败：{err}"));
    }
    for cmd in [
        "systemctl daemon-reload".to_string(),
        format!("systemctl enable --now {SERVICE}"),
    ] {
        let (code, _, err) = ssh.run_sudo(&cmd).await?;
        if code != 0 {
            let hint = if cmd.contains("enable") {
                "（可用 journalctl -u pier-frps 查看服务日志）"
            } else {
                ""
            };
            return Err(format!("`{cmd}` 失败：{err}{hint}"));
        }
    }
    Ok(())
}

/// Open the four ports in ufw or firewalld when present; try SELinux semanage
/// per port but only warn on failure. Never disables SELinux (no setenforce 0).
/// Returns the firewall that was configured (None = nothing to do) plus any
/// non-fatal warnings for the final verify message.
async fn step_firewall(
    ssh: &mut SshSession,
    server: &ServerConfig,
) -> Result<(Option<&'static str>, Vec<String>), String> {
    let ports = distinct_ports(server);
    let mut warnings = Vec::new();
    let mut applied: Option<&'static str> = None;
    // Typed-port (TCP/UDP) tunnels claim remote ports inside this range; the
    // firewall must admit both protocols for it.
    let proxy_range = proxy_port_range(server);

    let has_ufw = ssh
        .run("command -v ufw >/dev/null 2>&1 && echo yes || echo no")
        .await?
        .1
        .trim()
        == "yes";
    if has_ufw {
        let active = ssh
            .run_sudo("ufw status | head -1")
            .await
            .map(|(_, out, _)| out.contains("Status: active"))
            .unwrap_or(false);
        if active {
            for port in &ports {
                let (code, _, err) = ssh.run_sudo(&format!("ufw allow {port}/tcp")).await?;
                if code != 0 {
                    warnings.push(format!("ufw 放行 {port}/tcp 失败：{err}"));
                }
            }
            if let Some((start, end)) = proxy_range {
                for proto in ["tcp", "udp"] {
                    let (code, _, err) =
                        ssh.run_sudo(&format!("ufw allow {start}:{end}/{proto}")).await?;
                    if code != 0 {
                        warnings.push(format!("ufw 放行 {start}:{end}/{proto} 失败：{err}"));
                    }
                }
            }
            applied = Some("ufw");
        }
    }

    if applied.is_none() {
        let has_firewalld = ssh
            .run("command -v firewall-cmd >/dev/null 2>&1 && echo yes || echo no")
            .await?
            .1
            .trim()
            == "yes";
        if has_firewalld {
            let running = ssh
                .run_sudo("firewall-cmd --state")
                .await
                .map(|(code, _, _)| code == 0)
                .unwrap_or(false);
            if running {
                for port in &ports {
                    let (code, _, err) = ssh
                        .run_sudo(&format!("firewall-cmd --permanent --add-port={port}/tcp"))
                        .await?;
                    if code != 0 {
                        warnings.push(format!("firewalld 放行 {port}/tcp 失败：{err}"));
                    }
                }
                if let Some((start, end)) = proxy_range {
                    for proto in ["tcp", "udp"] {
                        let (code, _, err) = ssh
                            .run_sudo(&format!(
                                "firewall-cmd --permanent --add-port={start}-{end}/{proto}"
                            ))
                            .await?;
                        if code != 0 {
                            warnings.push(format!(
                                "firewalld 放行 {start}-{end}/{proto} 失败：{err}"
                            ));
                        }
                    }
                }
                if let Err(e) = ssh.run_sudo("firewall-cmd --reload").await {
                    warnings.push(format!("firewalld reload 失败：{e}"));
                }
                applied = Some("firewalld");
            }
        }
    }

    // SELinux: attempt to label the ports; a failure (policy type mismatch,
    // semanage missing) is a warning only. We never disable SELinux.
    let selinux = ssh
        .run("command -v getenforce >/dev/null 2>&1 && getenforce 2>/dev/null")
        .await
        .map(|(_, out, _)| out.trim() == "Enforcing")
        .unwrap_or(false);
    if selinux {
        for port in &ports {
            let (code, _, err) = ssh
                .run_sudo(&format!("semanage port -a -t http_port_t -p tcp {port}"))
                .await?;
            if code != 0 {
                warnings.push(format!(
                    "SELinux 端口标签设置失败（{port}，服务仍可运行；如连接异常请检查 SELinux 策略）：{err}"
                ));
            }
        }
    }

    Ok((applied, warnings))
}

/// Dashboard HTTP check (401 is expected without credentials), systemd state
/// and the binary's self-reported version.
async fn step_verify(
    ssh: &mut SshSession,
    server: &ServerConfig,
    release_version: &str,
) -> Result<String, String> {
    tokio::time::sleep(Duration::from_secs(1)).await;

    let (code, head, err) = ssh
        .run(&format!(
            "curl -sI -m 5 http://127.0.0.1:{}/",
            server.frps_dashboard_port
        ))
        .await?;
    let status = parse_http_status(&head);
    if code != 0 || !matches!(status, Some(200) | Some(401)) {
        return Err(format!(
            "dashboard 无响应（HTTP {:?}）：frps 可能未正常启动，\
             请在服务器上执行 journalctl -u {SERVICE} 查看日志。{err}",
            status.unwrap_or(0)
        ));
    }

    let (_, out, _) = ssh.run(&format!("systemctl is-active {SERVICE}")).await?;
    if out.trim() != "active" {
        return Err(format!("{SERVICE} 未处于运行状态（{}）", out.trim()));
    }

    let version = ssh
        .run(&format!("{REMOTE_BIN} -v 2>/dev/null"))
        .await
        .ok()
        .and_then(|(c, out, _)| (c == 0).then_some(out))
        .and_then(|out| out.lines().next().map(str::trim).map(String::from))
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| release_version.to_string());
    Ok(version)
}

/// Stop and remove the Pier-managed frps service on the server.
///
/// Only Pier-owned names are touched: the `pier-frps` unit and the
/// `/opt/pier` prefix. A frps the user installed themselves (other unit
/// names, /etc/frp, /usr/local/bin) is never stopped or deleted.
pub async fn undeploy(app: &AppHandle, server: ServerConfig) -> Result<(), String> {
    let mut ssh = crate::ssh::connect(&server).await?;

    let pier_unit = ssh
        .run(&format!("[ -f {REMOTE_UNIT} ] && echo yes || echo no"))
        .await?
        .1
        .trim()
        == "yes";
    if pier_unit {
        for cmd in [
            format!("systemctl stop {SERVICE} 2>/dev/null || true"),
            format!("systemctl disable {SERVICE} 2>/dev/null || true"),
            format!("rm -f {REMOTE_UNIT}"),
            "systemctl daemon-reload".to_string(),
        ] {
            let (code, _, err) = ssh.run_sudo(&cmd).await?;
            if code != 0 && !cmd.contains("|| true") {
                ssh.close().await;
                return Err(format!("卸载失败（{cmd}）：{err}"));
            }
        }
    }

    // /opt/pier is Pier's exclusive namespace; removing these can never
    // affect a foreign frps installation.
    let (code, _, err) = ssh
        .run_sudo(&format!(
            "rm -f {REMOTE_BIN} {REMOTE_BIN}.bak {REMOTE_TOML} && rmdir {REMOTE_DIR} 2>/dev/null || true"
        ))
        .await?;
    if code != 0 {
        ssh.close().await;
        return Err(format!("清理 {REMOTE_DIR} 失败：{err}"));
    }

    // Best-effort firewall cleanup; a rule that was never added cannot be
    // removed and that must not fail the undeploy.
    for port in distinct_ports(&server) {
        let _ = ssh.run_sudo(&format!("ufw delete allow {port}/tcp 2>/dev/null || true")).await;
        let _ = ssh
            .run_sudo(&format!(
                "firewall-cmd --permanent --remove-port={port}/tcp 2>/dev/null || true"
            ))
            .await;
    }
    let _ = ssh.run_sudo("firewall-cmd --reload 2>/dev/null || true").await;

    ssh.close().await;
    update_server_record(app, &server.id, |s| {
        s.deployed = false;
        s.frps_version = None;
    })?;
    Ok(())
}

/// Query frps status (systemd is-active, version) on the server and refresh
/// the stored version. Returns whether frps is running.
pub async fn status(app: &AppHandle, server: ServerConfig) -> Result<bool, String> {
    let mut ssh = crate::ssh::connect(&server).await?;
    let (_, out, _) = ssh
        .run(&format!("systemctl is-active {SERVICE} 2>/dev/null"))
        .await?;
    let running = out.trim() == "active";

    let version = ssh
        .run(&format!("{REMOTE_BIN} -v 2>/dev/null"))
        .await
        .ok()
        .and_then(|(c, out, _)| (c == 0).then_some(out))
        .and_then(|out| out.lines().next().map(str::trim).map(String::from))
        .filter(|v| !v.is_empty());
    if let Some(v) = version {
        update_server_record(app, &server.id, |s| s.frps_version = Some(v))?;
    }
    ssh.close().await;
    Ok(running)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// The four frps listen ports, de-duplicated, in config order.
fn distinct_ports(server: &ServerConfig) -> Vec<u16> {
    let mut ports = Vec::new();
    for p in [
        server.frps_bind_port,
        server.frps_vhost_http_port,
        server.frps_vhost_https_port,
        server.frps_dashboard_port,
    ] {
        if !ports.contains(&p) {
            ports.push(p);
        }
    }
    ports
}

/// The configured TCP/UDP forwarding port range, when both bounds are set and
/// sane. Proxy tunnels (remotePort) live inside it.
pub(crate) fn proxy_port_range(server: &ServerConfig) -> Option<(u16, u16)> {
    let (start, end) = (server.frps_proxy_port_start?, server.frps_proxy_port_end?);
    (start > 0 && start <= end).then_some((start, end))
}

/// The distinct ports joined with commas, for progress messages.
fn ports_list(server: &ServerConfig) -> String {
    distinct_ports(server)
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

/// "请到云控制台放行 TCP …" hint appended after a successful deploy on a
/// detected cloud host: Pier can open the in-VM firewall but not the
/// provider's security group.
fn cloud_security_group_hint(server: &ServerConfig, cloud: &str) -> String {
    let mut hint = format!(
        "检测到{cloud}云主机：请到云控制台安全组放行 TCP {}",
        ports_list(server)
    );
    if let Some((start, end)) = proxy_port_range(server) {
        hint.push_str(&format!("；转发端口段请放行 TCP+UDP {start}-{end}"));
    }
    hint
}

/// uname -m -> frp asset arch.
fn map_arch(uname_m: &str) -> Option<&'static str> {
    match uname_m.trim() {
        "x86_64" | "amd64" => Some("amd64"),
        "aarch64" | "arm64" => Some("arm64"),
        _ => None,
    }
}

fn asset_name(version: &str, arch: &str) -> String {
    format!("frp_{version}_linux_{arch}.tar.gz")
}

/// 256-bit token: two UUIDv4s concatenated without hyphens (64 hex chars).
pub(crate) fn generate_token() -> String {
    format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}

/// Dashboard password: 128 bits of UUIDv4 hex.
pub(crate) fn generate_dashboard_password() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

/// TOML basic-string 转义与 providers.rs 共用（crate::util）。
fn toml_str(value: &str) -> String {
    format!("\"{}\"", toml_escape(value))
}

/// Generate the frps TOML config (frp >= 0.52 TOML syntax).
pub(crate) fn build_frps_toml(
    server: &ServerConfig,
    token: &str,
    dashboard_password: &str,
) -> String {
    let mut t = String::new();
    t.push_str("# Generated by Pier. Manual edits are overwritten on re-deploy.\n");
    t.push_str("bindAddr = \"0.0.0.0\"\n");
    t.push_str(&format!("bindPort = {}\n", server.frps_bind_port));
    t.push_str(&format!("vhostHTTPPort = {}\n", server.frps_vhost_http_port));
    t.push_str(&format!("vhostHTTPSPort = {}\n", server.frps_vhost_https_port));
    if let Some(host) = server
        .subdomain_host
        .as_deref()
        .map(str::trim)
        .filter(|h| !h.is_empty())
    {
        t.push_str(&format!("subdomainHost = {}\n", toml_str(host)));
    }
    // Typed-port (TCP/UDP) tunnels: restrict client remotePort claims to the
    // configured forwarding range when one is set.
    if let Some((start, end)) = proxy_port_range(server) {
        t.push_str("\n[[allowPorts]]\n");
        t.push_str(&format!("start = {}\n", start));
        t.push_str(&format!("end = {}\n", end));
    }
    t.push_str("\n[auth]\n");
    t.push_str(&format!("token = {}\n", toml_str(token)));
    t.push_str("\n[webServer]\n");
    t.push_str("addr = \"127.0.0.1\"\n");
    t.push_str(&format!("port = {}\n", server.frps_dashboard_port));
    t.push_str("user = \"admin\"\n");
    t.push_str(&format!("password = {}\n", toml_str(dashboard_password)));
    t
}

/// The systemd unit for the Pier-managed frps service.
pub(crate) fn build_systemd_unit() -> String {
    format!(
        "[Unit]\n\
         Description=Pier-managed frps (Fast Reverse Proxy Server)\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={REMOTE_BIN} -c {REMOTE_TOML}\n\
         Restart=on-failure\n\
         RestartSec=5\n\
         LimitNOFILE=1048576\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n"
    )
}

/// Parse `ss -tlnp` / `netstat -tlnp` output into (port, process) pairs of
/// every listening socket. Process is "未知进程" when the tool could not
/// report it (non-root, busybox netstat without -p, ...).
pub(crate) fn parse_occupied_ports(output: &str) -> Vec<(u16, String)> {
    let mut found: Vec<(u16, String)> = Vec::new();
    for line in output.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        // ss:   State Recv-Q Send-Q Local Peer [Process]      -> starts with LISTEN
        // netstat: Proto Recv-Q Send-Q Local Foreign State PID/Name -> col 5 == LISTEN
        let is_ss = cols.first() == Some(&"LISTEN") && cols.len() >= 4;
        let is_netstat = cols.len() >= 7 && cols[5] == "LISTEN";
        if !is_ss && !is_netstat {
            continue;
        }
        let Some(port) = cols[3].rsplit(':').next().and_then(|p| p.parse::<u16>().ok()) else {
            continue;
        };
        let process = if is_ss {
            cols[3..]
                .iter()
                .find_map(|tok| {
                    let start = tok.find("(\"")? + 2;
                    let rest = &tok[start..];
                    let end = rest.find('"')?;
                    Some(rest[..end].to_string())
                })
                .unwrap_or_else(|| "未知进程".to_string())
        } else {
            cols[6]
                .split_once('/')
                .map(|(_, name)| name.to_string())
                .unwrap_or_else(|| "未知进程".to_string())
        };
        if !found.iter().any(|(p, _)| *p == port) {
            found.push((port, process));
        }
    }
    found
}

/// First status code of a `curl -sI` header block.
fn parse_http_status(head: &str) -> Option<u16> {
    head.lines().next()?.split_whitespace().nth(1)?.parse().ok()
}

/// (version, sha256 digest of the linux asset) from the GitHub release JSON.
fn extract_release(json: &str, arch: &str) -> Result<(String, Option<String>), String> {
    let value: serde_json::Value =
        serde_json::from_str(json).map_err(|e| format!("GitHub API 响应解析失败：{e}"))?;
    let tag = value
        .get("tag_name")
        .and_then(|v| v.as_str())
        .ok_or("GitHub API 响应缺少 tag_name")?;
    let version = tag.trim_start_matches('v').to_string();
    let asset = asset_name(&version, arch);
    let digest = value.get("assets").and_then(|a| a.as_array()).and_then(|assets| {
        assets.iter().find_map(|a| {
            if a.get("name")?.as_str()? == asset {
                a.get("digest")?
                    .as_str()?
                    .strip_prefix("sha256:")
                    .map(str::to_string)
            } else {
                None
            }
        })
    });
    Ok((version, digest))
}

/// Probe the cloud vendor through its instance metadata endpoint. Aliyun runs
/// a dedicated address; AWS-style metadata lives on the link-local address.
/// Returns None outside a recognizable cloud (or when curl is missing).
async fn detect_cloud(ssh: &mut SshSession) -> Option<&'static str> {
    let endpoints: [(&str, &str); 2] = [
        ("http://100.100.100.200/latest/meta-data/instance-id", "阿里云"),
        ("http://169.254.169.254/latest/meta-data/instance-id", "AWS"),
    ];
    for (url, cloud) in endpoints {
        if let Ok((0, out, _)) = ssh
            .run_with_timeout(&format!("curl -s -m 1 '{url}' 2>/dev/null"), METADATA_TIMEOUT)
            .await
        {
            if out.trim().starts_with("i-") {
                return Some(cloud);
            }
        }
    }
    None
}

/// Query the GitHub release JSON from this machine (used when the VPS cannot
/// reach GitHub itself). None when local access also fails. Body is read as
/// text and parsed here — the crate's reqwest build has no `json` feature.
async fn fetch_release_json() -> Option<String> {
    let text = crate::util::fetch_github_release_text(RELEASE_API, Some(Duration::from_secs(30)))
        .await
        .ok()?;
    (!text.is_empty()).then_some(text)
}

/// Load-modify-save a server record in servers.json.
fn update_server_record(
    app: &AppHandle,
    server_id: &str,
    f: impl FnOnce(&mut ServerConfig),
) -> Result<(), String> {
    let mut servers = servers_store::load_servers(app);
    let Some(server) = servers.iter_mut().find(|s| s.id == server_id) else {
        return Err(format!("server not found: {server_id}"));
    };
    f(server);
    servers_store::save_server(app, server)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_server() -> ServerConfig {
        ServerConfig {
            id: "srv-1".into(),
            name: "test".into(),
            host: "203.0.113.10".into(),
            port: 22,
            username: "root".into(),
            auth_kind: crate::models::AuthKind::Password,
            frps_bind_port: 7000,
            frps_vhost_http_port: 8080,
            frps_vhost_https_port: 8443,
            frps_dashboard_port: 7500,
            subdomain_host: Some("tunnel.example.com".into()),
            frps_proxy_port_start: None,
            frps_proxy_port_end: None,
            deployed: false,
            frps_version: None,
            created_at: "2026-10-06T00:00:00+00:00".into(),
        }
    }

    #[test]
    fn frps_toml_contains_all_sections_and_optional_subdomain() {
        let toml = build_frps_toml(&sample_server(), "tok&en", "pw");
        assert!(toml.contains("bindAddr = \"0.0.0.0\""));
        assert!(toml.contains("bindPort = 7000"));
        assert!(toml.contains("vhostHTTPPort = 8080"));
        assert!(toml.contains("vhostHTTPSPort = 8443"));
        assert!(toml.contains("subdomainHost = \"tunnel.example.com\""));
        assert!(toml.contains("[auth]"));
        assert!(toml.contains("token = \"tok&en\""));
        assert!(toml.contains("[webServer]"));
        assert!(toml.contains("addr = \"127.0.0.1\""));
        assert!(toml.contains("port = 7500"));
        assert!(toml.contains("user = \"admin\""));
        assert!(toml.contains("password = \"pw\""));
    }

    #[test]
    fn frps_toml_omits_empty_subdomain_and_escapes_values() {
        let mut server = sample_server();
        server.subdomain_host = Some("  ".into());
        let toml = build_frps_toml(&server, "a\"b\\c", "d");
        assert!(!toml.contains("subdomainHost"));
        // A quote inside the value must not terminate the TOML string.
        assert!(toml.contains("token = \"a\\\"b\\\\c\""));
        assert!(toml.contains("password = \"d\""));
    }

    #[test]
    fn frps_toml_writes_allow_ports_range_only_when_set() {
        // Without a range: no allowPorts section (backwards compatible).
        let base = build_frps_toml(&sample_server(), "tok", "pw");
        assert!(!base.contains("allowPorts"));
        // With a range: the frps [[allowPorts]] table restricts client
        // remotePort claims to it.
        let mut server = sample_server();
        server.frps_proxy_port_start = Some(20000);
        server.frps_proxy_port_end = Some(21000);
        let toml = build_frps_toml(&server, "tok", "pw");
        assert!(toml.contains("[[allowPorts]]"));
        assert!(toml.contains("start = 20000"));
        assert!(toml.contains("end = 21000"));
    }

    #[test]
    fn proxy_port_range_rejects_inverted_or_zero_bounds() {
        let mut server = sample_server();
        assert_eq!(proxy_port_range(&server), None);
        server.frps_proxy_port_start = Some(21000);
        server.frps_proxy_port_end = Some(20000);
        assert_eq!(proxy_port_range(&server), None);
        server.frps_proxy_port_start = Some(0);
        server.frps_proxy_port_end = Some(21000);
        assert_eq!(proxy_port_range(&server), None);
        server.frps_proxy_port_start = Some(20000);
        server.frps_proxy_port_end = Some(20000);
        assert_eq!(proxy_port_range(&server), Some((20000, 20000)));
    }

    #[test]
    fn toml_escape_handles_specials() {
        assert_eq!(toml_escape("a\"b\\c\nd\te"), "a\\\"b\\\\c\\nd\\te");
        assert_eq!(toml_escape("plain"), "plain");
        assert_eq!(toml_escape("\u{1}"), "\\u0001");
    }

    #[test]
    fn systemd_unit_matches_contract() {
        let unit = build_systemd_unit();
        assert!(unit.contains("ExecStart=/opt/pier/frps -c /opt/pier/frps.toml"));
        assert!(unit.contains("After=network-online.target"));
        assert!(unit.contains("Restart=on-failure"));
        assert!(unit.contains("RestartSec=5"));
        assert!(unit.contains("LimitNOFILE=1048576"));
        assert!(unit.contains("WantedBy=multi-user.target"));
    }

    #[test]
    fn ss_output_parsing_finds_occupied_ports() {
        let sample = "State  Recv-Q Send-Q Local Address:Port  Peer Address:Port  Process\n\
                      LISTEN 0      128        0.0.0.0:22          0.0.0.0:*   \
                      users:((\"sshd\",pid=812,fd=3))\n\
                      LISTEN 0      128           [::]:22             [::]:*     \
                      users:((\"sshd\",pid=812,fd=4))\n\
                      LISTEN 0      511        0.0.0.0:7000       0.0.0.0:*   \
                      users:((\"frps\",pid=900,fd=3))\n\
                      LISTEN 0      4096       127.0.0.1:7500     0.0.0.0:*\n";
        let ports = parse_occupied_ports(sample);
        assert_eq!(ports.len(), 3);
        assert_eq!(ports[0], (22, "sshd".to_string()));
        assert_eq!(ports[1], (7000, "frps".to_string()));
        // Process column missing (non-root): port still detected.
        assert_eq!(ports[2], (7500, "未知进程".to_string()));
    }

    #[test]
    fn netstat_output_parsing_finds_occupied_ports() {
        let sample = "Active Internet connections (only servers)\n\
                      Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name\n\
                      tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      812/sshd\n\
                      tcp6       0      0 :::8080                 :::*                    LISTEN      900/frps\n";
        let ports = parse_occupied_ports(sample);
        assert_eq!(ports.len(), 2);
        assert_eq!(ports[0], (22, "sshd".to_string()));
        assert_eq!(ports[1], (8080, "frps".to_string()));
    }

    #[test]
    fn arch_and_asset_mapping() {
        assert_eq!(map_arch("x86_64"), Some("amd64"));
        assert_eq!(map_arch("aarch64"), Some("arm64"));
        assert_eq!(map_arch("arm64"), Some("arm64"));
        assert_eq!(map_arch("i686"), None);
        assert_eq!(asset_name("0.71.0", "amd64"), "frp_0.71.0_linux_amd64.tar.gz");
        assert_eq!(asset_name("0.71.0", "arm64"), "frp_0.71.0_linux_arm64.tar.gz");
    }

    #[test]
    fn release_json_yields_version_and_digest() {
        let json = r#"{
            "tag_name": "v0.71.0",
            "assets": [
                {"name": "frp_0.71.0_linux_arm64.tar.gz", "digest": "sha256:aaaa"},
                {"name": "frp_0.71.0_linux_amd64.tar.gz", "digest": "sha256:84f27e39f111"}
            ]
        }"#;
        let (version, digest) = extract_release(json, "amd64").unwrap();
        assert_eq!(version, "0.71.0");
        assert_eq!(digest.as_deref(), Some("84f27e39f111"));
        // Older API responses without the digest field degrade to None.
        let (_, digest) = extract_release(r#"{"tag_name": "v0.1.0", "assets": []}"#, "amd64").unwrap();
        assert_eq!(digest, None);
    }

    #[test]
    fn tokens_are_unique_and_sized() {
        let a = generate_token();
        let b = generate_token();
        assert_eq!(a.len(), 64); // 32 bytes as hex
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
        let pw = generate_dashboard_password();
        assert_eq!(pw.len(), 32);
        assert_ne!(pw, generate_dashboard_password());
    }

    #[test]
    fn http_status_parsing() {
        assert_eq!(parse_http_status("HTTP/1.1 401 Unauthorized\r\nServer: x"), Some(401));
        assert_eq!(parse_http_status("HTTP/2 200"), Some(200));
        assert_eq!(parse_http_status("curl: (7) Failed to connect"), None);
        assert_eq!(parse_http_status(""), None);
    }

    #[test]
    fn distinct_ports_dedupes() {
        let mut server = sample_server();
        server.frps_vhost_http_port = 7000; // collide with bind port
        assert_eq!(distinct_ports(&server), vec![7000, 8443, 7500]);
    }

    #[test]
    fn cloud_hint_lists_all_ports() {
        let hint = cloud_security_group_hint(&sample_server(), "AWS");
        assert!(hint.contains("AWS"));
        assert!(hint.contains("TCP 7000,8080,8443,7500"));
    }
}
