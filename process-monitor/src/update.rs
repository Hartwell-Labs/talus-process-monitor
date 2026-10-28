//! Opt-in self-updater (GitHub Releases).
//!
//! Nothing here runs unless the user types `talus-monitor update`. The monitor
//! itself never contacts GitHub, so a root-owned eBPF agent makes no network
//! calls it was not asked to make.
//!
//! * `update`            - check only: report the latest release, change nothing.
//! * `update --install`  - download the release asset, verify its SHA-256
//!   against the release's `checksums-sha256.txt`, then
//!   atomically replace the running binary (the previous
//!   binary is kept next to it as `<name>.prev`).
//!
//! The checksum file is published in the same release as the binary, so it
//! detects corruption and truncated downloads but NOT a compromised release.
//! Releases are also signed with cosign; verify with the command shown in the
//! release notes if that matters for your threat model.

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// Default GitHub source (`owner/name`). Override with `--repo`.
pub const DEFAULT_REPO: &str = "Hartwell-Labs/talus-process-monitor";
/// Default release asset to install. Override with `--asset`.
pub const DEFAULT_ASSET: &str = "talus-tui";
const CHECKSUMS_ASSET: &str = "checksums-sha256.txt";
const MAX_DOWNLOAD_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug, Deserialize)]
struct Release {
    tag_name: String,
    html_url: String,
    #[serde(default)]
    assets: Vec<Asset>,
}

#[derive(Debug, Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
}

/// Entry point for `talus-monitor update`.
pub fn run(repo: &str, install: bool, assume_yes: bool, asset: &str) -> Result<()> {
    validate_repo(repo)?;
    let current = env!("CARGO_PKG_VERSION");
    eprintln!("[talus] current version: {current}");
    eprintln!("[talus] checking https://github.com/{repo} ...");

    let client = http_client()?;
    let release = fetch_latest(&client, repo)?;
    let latest = release.tag_name.trim_start_matches('v');

    let (Some(cur_v), Some(new_v)) = (parse_version(current), parse_version(latest)) else {
        bail!("could not compare versions ('{current}' vs '{}')", release.tag_name);
    };
    if new_v <= cur_v {
        eprintln!("[talus] ✓ up to date (latest release: {})", release.tag_name);
        return Ok(());
    }
    eprintln!("[talus] update available: {current} -> {}", release.tag_name);
    eprintln!("[talus] release notes: {}", release.html_url);

    if !install {
        eprintln!("[talus] run `talus-monitor update --install` to download and install it.");
        return Ok(());
    }

    if !assume_yes && !confirm(&format!("Install {} now?", release.tag_name))? {
        eprintln!("[talus] cancelled, nothing changed.");
        return Ok(());
    }

    let bin = find_asset(&release, repo, asset)?;
    let sums = find_asset(&release, repo, CHECKSUMS_ASSET)
        .context("release has no checksums-sha256.txt; refusing to install an unverified binary")?;

    eprintln!("[talus] downloading {} ...", bin.name);
    let data = download(&client, &bin.browser_download_url)?;
    let sums_text = String::from_utf8(download(&client, &sums.browser_download_url)?)
        .context("checksums file is not valid UTF-8")?;

    let expected = expected_checksum(&sums_text, &bin.name)
        .with_context(|| format!("no checksum for '{}' in {CHECKSUMS_ASSET}", bin.name))?;
    let actual = hex::encode(Sha256::digest(&data));
    if !actual.eq_ignore_ascii_case(&expected) {
        bail!("checksum mismatch for {} (expected {expected}, got {actual}); nothing installed", bin.name);
    }
    eprintln!("[talus] ✓ sha256 verified: {actual}");

    replace_running_binary(&data)?;
    eprintln!("[talus] ✓ updated to {}. Restart talus to use it.", release.tag_name);
    eprintln!("[talus]   to verify the signature: see the release notes for the cosign command.");
    Ok(())
}

fn http_client() -> Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .user_agent(concat!("talus-monitor/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(60))
        .build()
        .context("failed to build HTTP client")
}

fn fetch_latest(client: &reqwest::blocking::Client, repo: &str) -> Result<Release> {
    let url = format!("https://api.github.com/repos/{repo}/releases/latest");
    client
        .get(&url)
        .header("Accept", "application/vnd.github+json")
        .send()
        .with_context(|| format!("could not reach {url}"))?
        .error_for_status()
        .context("GitHub returned an error (is the repository public and does it have a release?)")?
        .json::<Release>()
        .context("unexpected response from GitHub")
}

/// Only accept assets served from this repository's own release downloads.
fn find_asset<'a>(release: &'a Release, repo: &str, name: &str) -> Result<&'a Asset> {
    let prefix = format!("https://github.com/{repo}/releases/download/");
    let asset = release
        .assets
        .iter()
        .find(|a| a.name == name)
        .with_context(|| format!("release {} has no asset named '{name}'", release.tag_name))?;
    if !asset.browser_download_url.starts_with(&prefix) {
        bail!("asset URL {} is outside {prefix}; refusing", asset.browser_download_url);
    }
    Ok(asset)
}

fn download(client: &reqwest::blocking::Client, url: &str) -> Result<Vec<u8>> {
    let resp = client.get(url).send()?.error_for_status()?;
    if resp.content_length().is_some_and(|n| n > MAX_DOWNLOAD_BYTES) {
        bail!("download is larger than {} MiB; refusing", MAX_DOWNLOAD_BYTES / 1024 / 1024);
    }
    let bytes = resp.bytes()?;
    if bytes.len() as u64 > MAX_DOWNLOAD_BYTES {
        bail!("download is larger than {} MiB; refusing", MAX_DOWNLOAD_BYTES / 1024 / 1024);
    }
    Ok(bytes.to_vec())
}

/// Write next to the running binary, keep the old one as `.prev`, then
/// rename over it (atomic on the same filesystem; safe while running on Linux).
fn replace_running_binary(data: &[u8]) -> Result<()> {
    let exe = std::env::current_exe().context("cannot locate the running binary")?;
    let dir = exe.parent().context("running binary has no parent directory")?;
    let tmp = dir.join(".talus-update.tmp");

    let write = || -> io::Result<()> {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o755))
    };
    if let Err(e) = write() {
        let _ = fs::remove_file(&tmp);
        bail!(
            "cannot write to {} ({e}); re-run with sudo if the binary is in a system directory",
            dir.display()
        );
    }

    let prev = exe.with_extension("prev");
    let _ = fs::copy(&exe, &prev);
    if let Err(e) = fs::rename(&tmp, &exe) {
        let _ = fs::remove_file(&tmp);
        bail!("could not replace {}: {e}", exe.display());
    }
    Ok(())
}

fn confirm(question: &str) -> Result<bool> {
    eprint!("[talus] {question} [y/N] ");
    io::stderr().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes"))
}

// ── Pure helpers (unit-tested) ────────────────────────────────────────────

/// `owner/name`, GitHub-legal characters only: keeps user input out of the URL path.
fn validate_repo(repo: &str) -> Result<()> {
    let ok = repo.split('/').count() == 2
        && repo.split('/').all(|p| {
            !p.is_empty()
                && p != "."
                && p != ".."
                && p.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        });
    if !ok {
        bail!("invalid repository '{repo}' (expected owner/name)");
    }
    Ok(())
}

/// `v1.2.3`, `1.2.3-rc1` -> (1, 2, 3). Pre-release suffixes are ignored.
fn parse_version(v: &str) -> Option<(u64, u64, u64)> {
    let core = v.trim().trim_start_matches('v');
    let core = core.split(['-', '+']).next()?;
    let mut it = core.split('.');
    let major = it.next()?.parse().ok()?;
    let minor = it.next()?.parse().ok()?;
    let patch = it.next()?.parse().ok()?;
    if it.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

/// Parse `sha256sum` output (`<hex>  <name>` or `<hex> *<name>`).
fn expected_checksum(text: &str, name: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let (hash, file) = line.split_once(char::is_whitespace)?;
        let file = file.trim().trim_start_matches('*');
        (file == name && hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit()))
            .then(|| hash.to_ascii_lowercase())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_parse_and_compare() {
        assert_eq!(parse_version("v0.8.2"), Some((0, 8, 2)));
        assert_eq!(parse_version("1.2.3-rc1"), Some((1, 2, 3)));
        assert_eq!(parse_version("1.2"), None);
        assert_eq!(parse_version("1.2.3.4"), None);
        assert!(parse_version("0.9.0") > parse_version("0.8.12"));
        assert!(parse_version("0.8.2") <= parse_version("0.8.2"));
    }

    #[test]
    fn repo_validation() {
        assert!(validate_repo("Hartwell-Labs/talus-process-monitor").is_ok());
        assert!(validate_repo("a/b/c").is_err());
        assert!(validate_repo("../etc").is_err());
        assert!(validate_repo("owner/na me").is_err());
        assert!(validate_repo("owner").is_err());
    }

    #[test]
    fn checksum_lookup() {
        let h = "a".repeat(64);
        let text = format!("{h}  talus-tui\n{}  talus-web\n", "b".repeat(64));
        assert_eq!(expected_checksum(&text, "talus-tui"), Some(h.clone()));
        assert_eq!(expected_checksum(&format!("{h} *talus-tui"), "talus-tui"), Some(h));
        assert_eq!(expected_checksum(&text, "missing"), None);
        assert_eq!(expected_checksum("short  talus-tui", "talus-tui"), None);
    }

    #[test]
    fn asset_urls_must_belong_to_the_repo() {
        let repo = "o/r";
        let mk = |url: &str| Release {
            tag_name: "v1.0.0".into(),
            html_url: String::new(),
            assets: vec![Asset { name: "talus-tui".into(), browser_download_url: url.into() }],
        };
        assert!(find_asset(&mk("https://github.com/o/r/releases/download/v1/talus-tui"), repo, "talus-tui").is_ok());
        assert!(find_asset(&mk("https://evil.example/talus-tui"), repo, "talus-tui").is_err());
    }
}
