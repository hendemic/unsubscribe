//! `update` command: self-update the binary from the latest GitHub release.

use anyhow::{bail, Context, Result};

use crate::terminal::{BOLD, CYAN, DIM, GREEN, RESET};

pub fn cmd_update(pre: bool) -> Result<()> {
    let current = env!("CARGO_PKG_VERSION");

    eprintln!("{BOLD}Checking for updates...{RESET}");

    let client = reqwest::blocking::Client::new();

    let release: serde_json::Value = if pre {
        let resp = client
            .get("https://api.github.com/repos/hendemic/unsubscribe/releases")
            .header("User-Agent", "unsubscribe")
            .send()
            .context("Failed to check for updates")?;

        let releases: Vec<serde_json::Value> =
            resp.json().context("Failed to parse releases list")?;

        releases
            .into_iter()
            .next()
            .context("No releases found. Check https://github.com/hendemic/unsubscribe/releases")?
    } else {
        let resp = client
            .get("https://api.github.com/repos/hendemic/unsubscribe/releases/latest")
            .header("User-Agent", "unsubscribe")
            .send()
            .context("Failed to check for updates")?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            bail!("No releases found. Check https://github.com/hendemic/unsubscribe/releases");
        }

        resp.json().context("Failed to parse release info")?
    };
    let latest_tag = release["tag_name"]
        .as_str()
        .context("No tag_name in release")?;
    let latest_version = latest_tag.trim_start_matches('v');

    let current_semver =
        semver::Version::parse(current).context("Failed to parse current version")?;
    let latest_semver =
        semver::Version::parse(latest_version).context("Failed to parse release version")?;

    if latest_semver <= current_semver {
        eprintln!("{GREEN}Already up to date (v{current}).{RESET}");
        return Ok(());
    }

    eprintln!(
        "Update available: {DIM}v{current}{RESET} → {BOLD}{latest_tag}{RESET}"
    );

    // Determine the right binary for this platform
    let target = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => "linux-x86_64",
        ("macos", "x86_64") => "macos-x86_64",
        ("macos", "aarch64") => "macos-aarch64",
        (os, arch) => bail!(
            "Automatic updates are not supported on {os}-{arch}. \
             Download the latest release manually from https://github.com/hendemic/unsubscribe/releases"
        ),
    };

    let asset_name = format!("unsubscribe-{target}");
    let checksum_name = format!("{asset_name}.sha256");
    let assets = release["assets"]
        .as_array()
        .context("No assets in release")?;

    let asset = assets
        .iter()
        .find(|a| a["name"].as_str() == Some(&asset_name))
        .with_context(|| format!("No binary for {target} in this release"))?;
    let download_url = asset["browser_download_url"]
        .as_str()
        .context("No download URL for asset")?;

    // Require a checksum file — releases without one are not trusted.
    let checksum_asset = assets
        .iter()
        .find(|a| a["name"].as_str() == Some(&checksum_name))
        .with_context(|| {
            format!(
                "No checksum file ({checksum_name}) found for this release. \
                 Cannot verify download integrity. Aborting update."
            )
        })?;
    let checksum_url = checksum_asset["browser_download_url"]
        .as_str()
        .context("No download URL for checksum asset")?;

    eprintln!("Downloading {CYAN}{asset_name}{RESET}...");
    let bytes = client
        .get(download_url)
        .header("User-Agent", "unsubscribe")
        .send()
        .context("Failed to download update")?
        .bytes()
        .context("Failed to read update binary")?;

    // Fetch and verify SHA256 checksum before touching the filesystem.
    let checksum_raw = client
        .get(checksum_url)
        .header("User-Agent", "unsubscribe")
        .send()
        .context("Failed to download checksum file")?
        .text()
        .context("Failed to read checksum file")?;

    // sha256sum output format: "<hex>  <filename>"
    let expected_hex = checksum_raw
        .split_whitespace()
        .next()
        .context("Checksum file is empty or malformed")?;

    use sha2::{Digest, Sha256};
    let actual_hex = format!("{:x}", Sha256::digest(&bytes));

    if actual_hex != expected_hex {
        bail!(
            "Checksum verification failed.\n  expected: {expected_hex}\n  actual:   {actual_hex}\n\
             The downloaded binary may be corrupted or tampered with. Aborting update."
        );
    }

    eprintln!("{GREEN}Checksum verified.{RESET}");

    // Replace current binary only after integrity is confirmed.
    let current_exe = std::env::current_exe().context("Cannot determine current binary path")?;
    let tmp = current_exe.with_extension("tmp");
    std::fs::write(&tmp, &bytes).context("Failed to write update")?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
    }

    std::fs::rename(&tmp, &current_exe).context("Failed to replace binary")?;

    eprintln!("{GREEN}Updated to {latest_tag}!{RESET}");
    Ok(())
}
