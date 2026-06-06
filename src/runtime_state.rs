use std::{
    fs,
    io::{ErrorKind, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::warn;

const RUNTIME_STATE_FILE: &str = "runtime-state.json";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuntimeStateSnapshot {
    pub proxy_addr: String,
    pub ui_addr: String,
    #[serde(default)]
    pub proxy_online: bool,
    #[serde(default = "default_updated_at")]
    pub updated_at: DateTime<Utc>,
    #[serde(default = "default_app_version")]
    pub app_version: String,
}

fn default_updated_at() -> DateTime<Utc> {
    Utc::now()
}

fn default_app_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

impl RuntimeStateSnapshot {
    pub fn new(proxy_addr: SocketAddr, ui_addr: SocketAddr) -> Self {
        let ui_addr = advertise_local_api_addr(ui_addr);
        Self {
            proxy_addr: proxy_addr.to_string(),
            ui_addr: ui_addr.to_string(),
            proxy_online: true,
            updated_at: Utc::now(),
            app_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    pub fn with_proxy_status(
        proxy_addr: SocketAddr,
        ui_addr: SocketAddr,
        proxy_online: bool,
    ) -> Self {
        let ui_addr = advertise_local_api_addr(ui_addr);
        Self {
            proxy_addr: proxy_addr.to_string(),
            ui_addr: ui_addr.to_string(),
            proxy_online,
            updated_at: Utc::now(),
            app_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    pub fn api_base_url(&self) -> String {
        format!("http://{}", self.ui_addr)
    }
}

pub fn advertise_local_api_addr(addr: SocketAddr) -> SocketAddr {
    match addr.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), addr.port())
        }
        IpAddr::V6(ip) if ip.is_unspecified() => {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), addr.port())
        }
        _ => addr,
    }
}

pub fn runtime_state_path(data_dir: &Path) -> PathBuf {
    data_dir.join(RUNTIME_STATE_FILE)
}

pub fn load_runtime_state(data_dir: &Path) -> Result<Option<RuntimeStateSnapshot>> {
    let path = runtime_state_path(data_dir);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) if path.exists() => {
            warn!(
                ?error,
                path = %path.display(),
                "discarding unreadable runtime state"
            );
            move_invalid_runtime_state_aside(data_dir, &path);
            return Ok(None);
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to read runtime state at {}", path.display()));
        }
    };
    let mut snapshot = match serde_json::from_slice(&bytes) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            warn!(
                ?error,
                path = %path.display(),
                "discarding corrupt runtime state"
            );
            move_invalid_runtime_state_aside(data_dir, &path);
            return Ok(None);
        }
    };
    if let Err(error) = sanitize_loaded_runtime_state(&mut snapshot) {
        warn!(
            ?error,
            path = %path.display(),
            "discarding invalid runtime state"
        );
        move_invalid_runtime_state_aside(data_dir, &path);
        return Ok(None);
    }
    Ok(Some(snapshot))
}

fn sanitize_loaded_runtime_state(snapshot: &mut RuntimeStateSnapshot) -> Result<()> {
    let proxy_addr: SocketAddr = snapshot
        .proxy_addr
        .parse()
        .context("runtime-state proxy_addr is not a socket address")?;
    let ui_addr: SocketAddr = snapshot
        .ui_addr
        .parse()
        .context("runtime-state ui_addr is not a socket address")?;
    let advertised_ui_addr = advertise_local_api_addr(ui_addr);
    if !advertised_ui_addr.ip().is_loopback() {
        bail!("runtime-state ui_addr must be loopback");
    }
    snapshot.proxy_addr = proxy_addr.to_string();
    snapshot.ui_addr = advertised_ui_addr.to_string();
    Ok(())
}

fn move_invalid_runtime_state_aside(data_dir: &Path, path: &Path) {
    let corrupt_path = data_dir.join(format!(
        ".runtime-state.corrupt-{}.json",
        uuid::Uuid::new_v4()
    ));
    if let Err(rename_error) = fs::rename(path, &corrupt_path) {
        warn!(
            ?rename_error,
            path = %path.display(),
            "failed to move invalid runtime state aside"
        );
        let _ = fs::remove_file(path);
    }
}

pub fn persist_runtime_state(data_dir: &Path, snapshot: &RuntimeStateSnapshot) -> Result<()> {
    fs::create_dir_all(data_dir)
        .with_context(|| format!("failed to create data dir {}", data_dir.display()))?;
    let path = runtime_state_path(data_dir);
    let tmp_path = data_dir.join(format!(".runtime-state.{}.tmp", uuid::Uuid::new_v4()));
    let json = serde_json::to_vec_pretty(snapshot).context("failed to encode runtime state")?;
    {
        let mut file = fs::File::create(&tmp_path)
            .with_context(|| format!("failed to write runtime state to {}", tmp_path.display()))?;
        file.write_all(&json)
            .with_context(|| format!("failed to write runtime state to {}", tmp_path.display()))?;
        file.sync_all()
            .with_context(|| format!("failed to sync runtime state {}", tmp_path.display()))?;
    }
    if path.is_dir() {
        warn!(
            path = %path.display(),
            "moving directory runtime state aside before replace"
        );
        move_invalid_runtime_state_aside(data_dir, &path);
    }
    fs::rename(&tmp_path, &path)
        .with_context(|| format!("failed to replace runtime state at {}", path.display()))?;
    sync_directory(data_dir, "runtime state directory")?;
    Ok(())
}

pub fn remove_runtime_state(data_dir: &Path) -> Result<()> {
    let path = runtime_state_path(data_dir);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect runtime state {}", path.display()));
        }
    };
    if metadata.is_dir() {
        warn!(
            path = %path.display(),
            "moving directory runtime state aside before remove"
        );
        move_invalid_runtime_state_aside(data_dir, &path);
        return sync_directory(data_dir, "runtime state directory");
    }
    match fs::remove_file(&path) {
        Ok(()) => sync_directory(data_dir, "runtime state directory"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("failed to remove runtime state {}", path.display()))
        }
    }
}

pub fn remove_runtime_state_if_matches(
    data_dir: &Path,
    expected: &RuntimeStateSnapshot,
) -> Result<bool> {
    let Some(current) = load_runtime_state(data_dir)? else {
        return Ok(false);
    };
    if !runtime_state_matches(&current, expected) {
        return Ok(false);
    }
    remove_runtime_state(data_dir)?;
    Ok(true)
}

pub fn remove_runtime_state_if_same_ui_addr(
    data_dir: &Path,
    expected_ui_addr: SocketAddr,
) -> Result<bool> {
    let Some(current) = load_runtime_state(data_dir)? else {
        return Ok(false);
    };
    let expected_ui_addr = advertise_local_api_addr(expected_ui_addr).to_string();
    if current.ui_addr != expected_ui_addr {
        return Ok(false);
    }
    remove_runtime_state(data_dir)?;
    Ok(true)
}

fn runtime_state_matches(left: &RuntimeStateSnapshot, right: &RuntimeStateSnapshot) -> bool {
    left.proxy_addr == right.proxy_addr
        && left.ui_addr == right.ui_addr
        && left.proxy_online == right.proxy_online
        && left.updated_at == right.updated_at
        && left.app_version == right.app_version
}

fn sync_directory(path: &Path, label: &str) -> Result<()> {
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .with_context(|| format!("failed to sync {label} {}", path.display()))
}

#[cfg(test)]
mod tests {
    use std::{fs, net::SocketAddr};

    use super::{
        advertise_local_api_addr, load_runtime_state, persist_runtime_state, remove_runtime_state,
        remove_runtime_state_if_same_ui_addr, runtime_state_path, RuntimeStateSnapshot,
    };

    #[test]
    fn runtime_state_round_trip() {
        let temp_dir =
            std::env::temp_dir().join(format!("sniper-runtime-state-{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let snapshot = RuntimeStateSnapshot::new(
            "127.0.0.1:18080".parse::<SocketAddr>().unwrap(),
            "127.0.0.1:13000".parse::<SocketAddr>().unwrap(),
        );
        persist_runtime_state(&temp_dir, &snapshot).unwrap();
        let loaded = load_runtime_state(&temp_dir).unwrap().unwrap();

        assert_eq!(loaded.proxy_addr, snapshot.proxy_addr);
        assert_eq!(loaded.ui_addr, snapshot.ui_addr);
        assert!(loaded.proxy_online);
        assert!(runtime_state_path(&temp_dir).exists());

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn runtime_state_advertises_loopback_for_wildcard_ui_binds() {
        assert_eq!(
            advertise_local_api_addr("0.0.0.0:23001".parse().unwrap()).to_string(),
            "127.0.0.1:23001"
        );
        assert_eq!(
            advertise_local_api_addr("[::]:23001".parse().unwrap()).to_string(),
            "[::1]:23001"
        );

        let snapshot = RuntimeStateSnapshot::with_proxy_status(
            "127.0.0.1:8080".parse().unwrap(),
            "0.0.0.0:23001".parse().unwrap(),
            true,
        );
        assert_eq!(snapshot.api_base_url(), "http://127.0.0.1:23001");
    }

    #[test]
    fn runtime_state_remove_deletes_file_and_accepts_missing_file() {
        let temp_dir = std::env::temp_dir().join(format!(
            "sniper-runtime-state-remove-{}",
            uuid::Uuid::new_v4()
        ));
        let snapshot = RuntimeStateSnapshot::new(
            "127.0.0.1:8080".parse::<SocketAddr>().unwrap(),
            "127.0.0.1:9000".parse::<SocketAddr>().unwrap(),
        );
        persist_runtime_state(&temp_dir, &snapshot).unwrap();
        assert!(runtime_state_path(&temp_dir).exists());

        remove_runtime_state(&temp_dir).unwrap();
        assert!(!runtime_state_path(&temp_dir).exists());
        remove_runtime_state(&temp_dir).unwrap();

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn runtime_state_remove_if_matches_preserves_replaced_snapshot() {
        let temp_dir = std::env::temp_dir().join(format!(
            "sniper-runtime-state-remove-match-{}",
            uuid::Uuid::new_v4()
        ));
        let expected = RuntimeStateSnapshot::new(
            "127.0.0.1:8080".parse::<SocketAddr>().unwrap(),
            "127.0.0.1:9000".parse::<SocketAddr>().unwrap(),
        );
        let replacement = RuntimeStateSnapshot::new(
            "127.0.0.1:8081".parse::<SocketAddr>().unwrap(),
            "127.0.0.1:9001".parse::<SocketAddr>().unwrap(),
        );
        persist_runtime_state(&temp_dir, &expected).unwrap();
        persist_runtime_state(&temp_dir, &replacement).unwrap();

        assert!(!super::remove_runtime_state_if_matches(&temp_dir, &expected).unwrap());
        assert!(runtime_state_path(&temp_dir).exists());
        let loaded = load_runtime_state(&temp_dir).unwrap().unwrap();
        assert_eq!(loaded.ui_addr, replacement.ui_addr);

        assert!(super::remove_runtime_state_if_matches(&temp_dir, &replacement).unwrap());
        assert!(!runtime_state_path(&temp_dir).exists());

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn runtime_state_remove_if_same_ui_addr_deletes_matching_owner() {
        let temp_dir = std::env::temp_dir().join(format!(
            "sniper-runtime-state-remove-ui-match-{}",
            uuid::Uuid::new_v4()
        ));
        let snapshot = RuntimeStateSnapshot::with_proxy_status(
            "127.0.0.1:8080".parse::<SocketAddr>().unwrap(),
            "0.0.0.0:9000".parse::<SocketAddr>().unwrap(),
            false,
        );
        persist_runtime_state(&temp_dir, &snapshot).unwrap();

        assert!(
            remove_runtime_state_if_same_ui_addr(&temp_dir, "127.0.0.1:9000".parse().unwrap())
                .unwrap()
        );
        assert!(!runtime_state_path(&temp_dir).exists());

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn runtime_state_remove_if_same_ui_addr_preserves_other_owner() {
        let temp_dir = std::env::temp_dir().join(format!(
            "sniper-runtime-state-remove-ui-mismatch-{}",
            uuid::Uuid::new_v4()
        ));
        let snapshot = RuntimeStateSnapshot::new(
            "127.0.0.1:8080".parse::<SocketAddr>().unwrap(),
            "127.0.0.1:9001".parse::<SocketAddr>().unwrap(),
        );
        persist_runtime_state(&temp_dir, &snapshot).unwrap();

        assert!(!remove_runtime_state_if_same_ui_addr(
            &temp_dir,
            "127.0.0.1:9000".parse().unwrap()
        )
        .unwrap());
        assert!(runtime_state_path(&temp_dir).exists());
        let loaded = load_runtime_state(&temp_dir).unwrap().unwrap();
        assert_eq!(loaded.ui_addr, snapshot.ui_addr);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn runtime_state_load_accepts_missing_file() {
        let temp_dir = std::env::temp_dir().join(format!(
            "sniper-runtime-state-missing-{}",
            uuid::Uuid::new_v4()
        ));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let loaded = load_runtime_state(&temp_dir).unwrap();

        assert!(loaded.is_none());
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn runtime_state_accepts_legacy_missing_metadata() {
        let temp_dir = std::env::temp_dir().join(format!(
            "sniper-runtime-state-legacy-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        fs::write(
            runtime_state_path(&temp_dir),
            br#"{"proxy_addr":"127.0.0.1:18080","ui_addr":"127.0.0.1:23001"}"#,
        )
        .unwrap();

        let loaded = load_runtime_state(&temp_dir).unwrap().unwrap();

        assert_eq!(loaded.proxy_addr, "127.0.0.1:18080");
        assert_eq!(loaded.ui_addr, "127.0.0.1:23001");
        assert!(!loaded.proxy_online);
        assert_eq!(loaded.app_version, env!("CARGO_PKG_VERSION"));

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn runtime_state_load_normalizes_wildcard_ui_addr() {
        let temp_dir = std::env::temp_dir().join(format!(
            "sniper-runtime-state-wildcard-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        fs::write(
            runtime_state_path(&temp_dir),
            br#"{"proxy_addr":"127.0.0.1:18080","ui_addr":"0.0.0.0:23001"}"#,
        )
        .unwrap();

        let loaded = load_runtime_state(&temp_dir).unwrap().unwrap();

        assert_eq!(loaded.proxy_addr, "127.0.0.1:18080");
        assert_eq!(loaded.ui_addr, "127.0.0.1:23001");

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn runtime_state_ignores_and_moves_invalid_socket_addr() {
        let temp_dir = std::env::temp_dir().join(format!(
            "sniper-runtime-state-invalid-{}",
            uuid::Uuid::new_v4()
        ));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();
        fs::write(
            runtime_state_path(&temp_dir),
            br#"{"proxy_addr":"127.0.0.1:18080","ui_addr":"not-an-addr"}"#,
        )
        .unwrap();

        let loaded = load_runtime_state(&temp_dir).unwrap();

        assert!(loaded.is_none());
        assert!(!runtime_state_path(&temp_dir).exists());
        assert!(fs::read_dir(&temp_dir).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".runtime-state.corrupt-")
        }));

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn runtime_state_ignores_and_moves_directory_path() {
        let temp_dir = std::env::temp_dir().join(format!(
            "sniper-runtime-state-directory-{}",
            uuid::Uuid::new_v4()
        ));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(runtime_state_path(&temp_dir)).unwrap();

        let loaded = load_runtime_state(&temp_dir).unwrap();

        assert!(loaded.is_none());
        assert!(!runtime_state_path(&temp_dir).exists());
        assert!(fs::read_dir(&temp_dir).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".runtime-state.corrupt-")
        }));

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn runtime_state_persist_replaces_directory_path() {
        let temp_dir = std::env::temp_dir().join(format!(
            "sniper-runtime-state-persist-directory-{}",
            uuid::Uuid::new_v4()
        ));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(runtime_state_path(&temp_dir)).unwrap();
        let snapshot = RuntimeStateSnapshot::new(
            "127.0.0.1:18080".parse::<SocketAddr>().unwrap(),
            "127.0.0.1:23001".parse::<SocketAddr>().unwrap(),
        );

        persist_runtime_state(&temp_dir, &snapshot).unwrap();
        let loaded = load_runtime_state(&temp_dir).unwrap().unwrap();

        assert_eq!(loaded.ui_addr, "127.0.0.1:23001");
        assert!(runtime_state_path(&temp_dir).is_file());
        assert!(fs::read_dir(&temp_dir).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".runtime-state.corrupt-")
        }));

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn runtime_state_remove_moves_directory_path() {
        let temp_dir = std::env::temp_dir().join(format!(
            "sniper-runtime-state-remove-directory-{}",
            uuid::Uuid::new_v4()
        ));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(runtime_state_path(&temp_dir)).unwrap();

        remove_runtime_state(&temp_dir).unwrap();

        assert!(!runtime_state_path(&temp_dir).exists());
        assert!(fs::read_dir(&temp_dir).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".runtime-state.corrupt-")
        }));

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn runtime_state_ignores_and_moves_corrupt_json() {
        let temp_dir = std::env::temp_dir().join(format!(
            "sniper-runtime-state-corrupt-{}",
            uuid::Uuid::new_v4()
        ));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();
        fs::write(runtime_state_path(&temp_dir), b"{not json").unwrap();

        let loaded = load_runtime_state(&temp_dir).unwrap();

        assert!(loaded.is_none());
        assert!(!runtime_state_path(&temp_dir).exists());
        assert!(fs::read_dir(&temp_dir).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".runtime-state.corrupt-")
        }));

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
