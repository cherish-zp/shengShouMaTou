// 跨模块共用的小工具：原子写 JSON、TOML 字符串转义、共享 HTTP 客户端、
// 流式下载与 GitHub release 查询。均来自 binman / cloudflare / frp_deploy /
// store 中原本逐字重复的实现，行为保持等价。

use std::path::Path;
use std::sync::OnceLock;
use std::time::Duration;

use futures_util::StreamExt;
use tokio::io::AsyncWriteExt;

/// 统一 User-Agent（GitHub API 缺失 UA 会直接 401）。
const HTTP_USER_AGENT: &str = concat!("ShengShouMaTou/", env!("CARGO_PKG_VERSION"));
/// 仅约束 TCP/TLS 握手；整体超时由调用点按需设置（大文件下载不设整体上限）。
const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// 全局共享的 reqwest 客户端：连接池与 TLS 初始化只付一次。
/// 构建失败只可能源于 TLS 后端初始化异常（native-tls 下实际不会发生），
/// 与 `reqwest::Client::new()` 的失败语义一致，此处 panic 即可。
pub fn http_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .user_agent(HTTP_USER_AGENT)
            .connect_timeout(HTTP_CONNECT_TIMEOUT)
            .build()
            .expect("failed to build the shared HTTP client")
    })
}

/// `timeout`：整体请求超时（含响应体）。`None` 表示不设整体上限，
/// 仅保留 30s 连接超时 —— 供引擎安装等大文件下载路径沿用原语义。
async fn get_with_optional_timeout(
    url: &str,
    timeout: Option<Duration>,
) -> Result<reqwest::Response, String> {
    let mut req = http_client().get(url);
    if let Some(t) = timeout {
        req = req.timeout(t);
    }
    req.send()
        .await
        .map_err(|e| format!("下载请求 {url} 失败：{e}"))
}

/// 流式下载 `url` 到 `dest`：分块直写磁盘，整个响应体不驻留内存。
/// 任何失败（含空文件）都会清理半成品。`timeout` 语义同上。
pub async fn download_to_file(
    url: &str,
    dest: &Path,
    timeout: Option<Duration>,
) -> Result<(), String> {
    let resp = get_with_optional_timeout(url, timeout).await?;
    if !resp.status().is_success() {
        return Err(format!("下载 {url} 失败：HTTP {}", resp.status()));
    }
    let mut file = tokio::fs::File::create(dest)
        .await
        .map_err(|e| format!("创建本地文件 {} 失败：{e}", dest.display()))?;
    let mut stream = resp.bytes_stream();
    let mut received: u64 = 0;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| {
            let _ = std::fs::remove_file(dest);
            format!("下载 {url} 中断（已接收 {received} 字节）：{e}")
        })?;
        file.write_all(&chunk).await.map_err(|e| {
            let _ = std::fs::remove_file(dest);
            format!("写入本地文件 {} 失败：{e}", dest.display())
        })?;
        received += chunk.len() as u64;
    }
    file.flush()
        .await
        .map_err(|e| format!("写入本地文件 {} 失败：{e}", dest.display()))?;
    if received == 0 {
        let _ = std::fs::remove_file(dest);
        return Err(format!("下载 {url} 得到空文件"));
    }
    Ok(())
}

/// 拉取 GitHub「最新 release」JSON 文本（带 `Accept: application/vnd.github+json`，
/// 响应体按文本返回，由调用点自行解析所需字段）。`timeout` 语义同上。
pub async fn fetch_github_release_text(
    api_url: &str,
    timeout: Option<Duration>,
) -> Result<String, String> {
    let mut req = http_client()
        .get(api_url)
        .header("Accept", "application/vnd.github+json");
    if let Some(t) = timeout {
        req = req.timeout(t);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| format!("request to {api_url} failed: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(format!("GitHub API returned HTTP {status} for {api_url}"));
    }
    resp.text()
        .await
        .map_err(|e| format!("reading the response from {api_url} failed: {e}"))
}

/// 原子写文件：先写 `<path>.tmp` 再 rename 覆盖，崩溃不会留下半截文件。
/// `fs::rename` 在 Windows 上无法覆盖已存在目标，故先删除。
pub fn write_json_atomic(path: &Path, text: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("failed to create data dir: {e}"))?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, text).map_err(|e| format!("failed to write temp file: {e}"))?;
    #[cfg(windows)]
    if path.exists() {
        let _ = std::fs::remove_file(path);
    }
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("failed to replace {}: {e}", path.display())
    })
}

/// Escape a string for inclusion as a TOML basic string (double-quoted).
pub fn toml_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04X}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toml_escape_handles_quotes_backslashes_and_control_chars() {
        assert_eq!(toml_escape("plain"), "plain");
        assert_eq!(toml_escape("a\"b\\c"), "a\\\"b\\\\c");
        assert_eq!(toml_escape("l1\nl2\t\r"), "l1\\nl2\\t\\r");
        assert_eq!(toml_escape("\u{1}"), "\\u0001");
        // 转义结果嵌入键值对后必须是合法 TOML basic string。
        let doc = format!("v = \"{}\"", toml_escape("a\"b\\c\nd"));
        let value: toml::Value = toml::from_str(&doc).expect("valid toml");
        assert_eq!(value["v"].as_str(), Some("a\"b\\c\nd"));
    }

    #[test]
    fn write_json_atomic_roundtrip_and_leaves_no_tmp() {
        let dir = std::env::temp_dir().join(format!("pier-util-test-{}", uuid::Uuid::new_v4()));
        let path = dir.join("data.json");
        write_json_atomic(&path, "[{\"id\":\"a\"}]").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "[{\"id\":\"a\"}]");
        // 二次写入走覆盖路径（非 Windows 也顺带覆盖验证 rename 成功）。
        write_json_atomic(&path, "[]").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "[]");
        assert!(!path.with_extension("json.tmp").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
