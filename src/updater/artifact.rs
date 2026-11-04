use crate::{
    common::{display_version_from_release_id, release_id_from_update_url},
    hbbs_http::create_http_client_with_url_strict,
    update_metadata::{UpdateArtifactQuery, UpdateMetadataRequirements, VerifiedUpdateArtifact},
};
use hbb_common::{bail, log, ResultType};
use std::{
    io::Read,
    path::{Component, Path, PathBuf},
    sync::Mutex,
    time::Duration,
};

const UPDATE_SIDECAR_HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const UPDATE_METADATA_SIDECAR_MAX_BYTES: u64 = 1024 * 1024;

// [CUSTOM] 自建更新站点（与 common.rs 的 DEFAULT_SOFTWARE_UPDATE_URL 保持一致）
pub(crate) const CUSTOM_UPDATE_HOST: &str = "ak.ahwt.xyz";
pub(crate) const CUSTOM_UPDATE_PORT: u16 = 21120;


lazy_static::lazy_static! {
    static ref VERIFIED_UPDATE_ARTIFACT: Mutex<Option<VerifiedUpdateArtifact>> = Mutex::new(None);
}

pub(crate) fn current_update_platform() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        "windows"
    }
    #[cfg(target_os = "macos")]
    {
        "macos"
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        std::env::consts::OS
    }
}

pub(crate) fn current_update_arch() -> &'static str {
    #[cfg(all(target_os = "windows", not(feature = "flutter")))]
    {
        "x86"
    }
    #[cfg(not(all(target_os = "windows", not(feature = "flutter"))))]
    {
        std::env::consts::ARCH
    }
}

pub(crate) fn current_update_format(update_msi: bool) -> &'static str {
    #[cfg(any(
        not(target_os = "windows"),
        all(target_os = "windows", not(feature = "flutter"))
    ))]
    let _ = update_msi;
    #[cfg(all(target_os = "windows", feature = "flutter"))]
    {
        if update_msi {
            return "msi";
        }
        "exe"
    }
    #[cfg(all(target_os = "windows", not(feature = "flutter")))]
    {
        "exe"
    }
    #[cfg(target_os = "macos")]
    {
        "dmg"
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        "unknown"
    }
}

pub fn current_update_artifact_query(update_msi: bool) -> UpdateArtifactQuery<'static> {
    UpdateArtifactQuery {
        platform: current_update_platform(),
        arch: current_update_arch(),
        format: current_update_format(update_msi),
    }
}

pub fn verified_update_artifact_for_release_page_url(
    release_page_url: &str,
    query: UpdateArtifactQuery<'_>,
) -> ResultType<VerifiedUpdateArtifact> {
    let artifact = verified_update_artifact_from_release_page_url(release_page_url, &query)?;
    *VERIFIED_UPDATE_ARTIFACT.lock().unwrap() = Some(artifact.clone());
    Ok(artifact)
}

pub fn verified_update_artifact_for_download_url(
    download_url: &str,
) -> ResultType<VerifiedUpdateArtifact> {
    VERIFIED_UPDATE_ARTIFACT
        .lock()
        .unwrap()
        .as_ref()
        .filter(|artifact| artifact.url == download_url)
        .cloned()
        .ok_or_else(|| hbb_common::anyhow::anyhow!("update artifact was not verified"))
}

pub(super) fn verified_update_artifact_from_release_page_url(
    update_url: &str,
    query: &UpdateArtifactQuery<'_>,
) -> ResultType<VerifiedUpdateArtifact> {
    // [CUSTOM] 定制版走自建更新站点：版本页 URL 形如
    //   https://ak.ahwt.xyz:21120/rustdesk/releases/tag/1.5.3
    // 对应安装包固定为
    //   https://ak.ahwt.xyz:21120/rustdesk/releases/download/1.5.3/rustdesk-1.5.3-x86_64.exe
    // 不做官方 ed25519 元数据校验（我们无法用官方私钥签名），改由「HTTPS + 站点自控 + 下载后
    // 本地计算 SHA256 交给安装流程复核」保证完整性。
    if crate::common::CUSTOM_UPDATE_CHANNEL {
        return custom_update_artifact_from_release_page_url(update_url, query);
    }
    let release_id = release_id_from_update_url(update_url)?;
    let display_version = display_version_from_release_id(&release_id)?;
    let expected_artifact_url_prefix =
        format!("https://github.com/rustdesk/rustdesk/releases/download/{release_id}/");
    let metadata_url = format!("{expected_artifact_url_prefix}rustdesk-update.json");
    let signature_url = format!("{metadata_url}.sig");
    let metadata_bytes = fetch_update_sidecar_bytes(&metadata_url)?;
    let signature_bytes = fetch_update_sidecar_bytes(&signature_url)?;
    let requirements = UpdateMetadataRequirements {
        expected_version: display_version.as_str(),
        expected_release_id: release_id.as_str(),
        expected_artifact_url_prefix: expected_artifact_url_prefix.as_str(),
        artifact: *query,
    };
    crate::update_metadata::verify_update_metadata(&metadata_bytes, &signature_bytes, requirements)
}

// [CUSTOM] 自建更新站点：把「版本页 URL」展开成实际安装包 artifact。
// 版本页形如 https://ak.ahwt.xyz:21120/rustdesk/releases/tag/1.5.3
// 安装包固定为 .../rustdesk/releases/download/1.5.3/rustdesk-1.5.3-<arch>.<format>
fn custom_update_artifact_from_release_page_url(
    release_page_url: &str,
    query: &UpdateArtifactQuery<'_>,
) -> ResultType<VerifiedUpdateArtifact> {
    let parsed = url::Url::parse(release_page_url)?;
    if parsed.scheme() != "https"
        || parsed.host_str() != Some(CUSTOM_UPDATE_HOST)
        || parsed.port() != Some(CUSTOM_UPDATE_PORT)
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        bail!("Custom update url is not trusted: {}", release_page_url);
    }
    let Some(segments_iter) = parsed.path_segments() else {
        bail!("Custom update url has no path: {}", release_page_url);
    };
    let segments: Vec<&str> = segments_iter.collect();
    let n = segments.len();
    if n < 2 || segments[n - 2] != "tag" {
        bail!(
            "Custom update url must end with /releases/tag/<version>: {}",
            release_page_url
        );
    }
    let version = segments[n - 1];
    if version.is_empty()
        || version == "."
        || version == ".."
        || version.contains([' ', '/', '\\', '?', '#'])
    {
        bail!("Custom update url has invalid version: {}", release_page_url);
    }
    #[cfg(target_os = "windows")]
    let format = "exe";
    #[cfg(not(target_os = "windows"))]
    let format = query.format;
    let file_name = format!("rustdesk-{}-{}.{}", version, query.arch, format);
    let mut base_segments = segments.clone();
    base_segments.truncate(n - 2);
    let download_url = format!(
        "https://{}:{}/{}download/{}/{}",
        CUSTOM_UPDATE_HOST,
        CUSTOM_UPDATE_PORT,
        if base_segments.is_empty() {
            String::new()
        } else {
            format!("{}/", base_segments.join("/"))
        },
        version,
        file_name
    );
    let size = custom_update_artifact_size(&download_url);
    if size == 0 {
        bail!(
            "Failed to get the size of the update package: {}",
            download_url
        );
    }
    #[cfg(not(target_os = "macos"))]
    let _ = &file_name;
    Ok(VerifiedUpdateArtifact {
        version: version.to_owned(),
        url: download_url,
        #[cfg(target_os = "macos")]
        file_name,
        size,
        sha256: String::new(),
    })
}

fn custom_update_artifact_size(url: &str) -> u64 {
    let client = match create_http_client_with_url_strict(url) {
        Ok(client) => client,
        Err(e) => {
            log::warn!("Custom update: failed to create http client: {}", e);
            return 0;
        }
    };
    match client
        .head(url)
        .timeout(UPDATE_SIDECAR_HTTP_REQUEST_TIMEOUT)
        .send()
    {
        Ok(resp) => resp.content_length().unwrap_or(0),
        Err(e) => {
            log::warn!("Custom update: HEAD {} failed: {}", url, e);
            0
        }
    }
}

// [CUSTOM] 只放行自建更新站点的下载地址（固定主机 + 固定端口 + releases/download/<tag>/<file> 形态）
fn custom_update_download_file_from_url(url: &str) -> Option<PathBuf> {
    if !crate::common::CUSTOM_UPDATE_CHANNEL {
        return None;
    }
    let parsed = url::Url::parse(url).ok()?;
    if parsed.scheme() != "https"
        || parsed.host_str() != Some(CUSTOM_UPDATE_HOST)
        || parsed.port() != Some(CUSTOM_UPDATE_PORT)
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return None;
    }
    let segments: Vec<&str> = parsed.path_segments()?.collect();
    let n = segments.len();
    if n < 4 || segments[n - 4] != "releases" || segments[n - 3] != "download" {
        return None;
    }
    let tag = segments[n - 2];
    let filename = segments[n - 1];
    if tag.is_empty() || !is_plain_update_filename(filename) {
        return None;
    }
    Some(std::env::temp_dir().join(filename))
}

fn fetch_update_sidecar_bytes(url: &str) -> ResultType<Vec<u8>> {
    let client = create_http_client_with_url_strict(url)?;

    let mut response = client
        .get(url)
        .timeout(UPDATE_SIDECAR_HTTP_REQUEST_TIMEOUT)
        .send()?;
    if !response.status().is_success() {
        bail!(
            "Failed to download update metadata sidecar: {}",
            response.status()
        );
    }
    read_limited_response_bytes(
        &mut response,
        UPDATE_METADATA_SIDECAR_MAX_BYTES,
        "Update metadata sidecar",
    )
}

fn read_limited_response_bytes<R: Read>(
    reader: &mut R,
    limit: u64,
    what: &str,
) -> ResultType<Vec<u8>> {
    let mut limited_reader = reader.take(limit.saturating_add(1));
    let mut bytes = Vec::new();
    limited_reader.read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        bail!("{what} exceeds maximum allowed size of {limit} bytes");
    }
    Ok(bytes)
}

pub fn get_update_download_file_from_url(url: &str) -> Option<PathBuf> {
    // [CUSTOM] 定制版允许自建更新站点
    if let Some(path) = custom_update_download_file_from_url(url) {
        return Some(path);
    }
    let parsed = url::Url::parse(url).ok()?;
    // Check the raw prefix before Url normalizes default ports.
    if !url.starts_with("https://github.com/")
        || parsed.scheme() != "https"
        || parsed.host_str() != Some("github.com")
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.port().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return None;
    }

    let mut segments = parsed.path_segments()?;
    let owner = segments.next()?;
    let repo = segments.next()?;
    let releases = segments.next()?;
    let download = segments.next()?;
    let tag = segments.next()?;
    let filename = segments.next()?;

    if owner != "rustdesk"
        || repo != "rustdesk"
        || releases != "releases"
        || download != "download"
        || tag.is_empty()
        || segments.next().is_some()
        || !is_plain_update_filename(filename)
    {
        return None;
    }

    Some(std::env::temp_dir().join(filename))
}

fn is_plain_update_filename(filename: &str) -> bool {
    if filename.is_empty()
        || filename.contains('/')
        || filename.contains('\\')
        || filename.contains(':')
    {
        return false;
    }

    let mut components = Path::new(filename).components();
    matches!(
        components.next(),
        Some(Component::Normal(name)) if name.to_str() == Some(filename)
    ) && components.next().is_none()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_download_file_accepts_expected_github_asset_urls() {
        let file = get_update_download_file_from_url(
            "https://github.com/rustdesk/rustdesk/releases/download/1.4.0/rustdesk-1.4.0-x86_64.dmg",
        )
        .expect("valid GitHub release asset URL");

        assert_eq!(
            file.file_name().and_then(|name| name.to_str()),
            Some("rustdesk-1.4.0-x86_64.dmg")
        );
    }

    #[test]
    fn update_download_file_rejects_untrusted_or_malformed_urls() {
        for url in [
            "http://github.com/rustdesk/rustdesk/releases/download/1/rustdesk.exe",
            "https://example.com/rustdesk.exe",
            "https://github.com/other/project/releases/download/1/rustdesk.exe",
            "https://github.com/rustdesk/rustdesk/releases/download/1/",
            "https://github.com/rustdesk/rustdesk/releases/download/1/nested/rustdesk.exe",
            "https://github.com/rustdesk/rustdesk/releases/download/1/C:rustdesk.exe",
            "https://user@github.com/rustdesk/rustdesk/releases/download/1/rustdesk.exe",
            "https://github.com:443/rustdesk/rustdesk/releases/download/1/rustdesk.exe",
            "https://github.com/rustdesk/rustdesk/releases/download/1/rustdesk.exe?download=1",
            "https://github.com/rustdesk/rustdesk/releases/download/1/rustdesk.exe#download",
            "not a url",
        ] {
            assert!(get_update_download_file_from_url(url).is_none(), "{url}");
        }
    }
}
