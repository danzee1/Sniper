use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::warn;
use uuid::Uuid;

const UI_SETTINGS_FILE: &str = "ui-settings.json";
const DISPLAY_THEME_OPTIONS: &[&str] = &[
    "charcoal", "black", "graphite", "midnight", "slate", "obsidian", "dusk", "white", "paper",
    "snow", "ivory", "frost",
];
const DISPLAY_UI_FONT_OPTIONS: &[&str] = &[
    "plex",
    "system",
    "pretendard",
    "notokr",
    "applekr",
    "nanumgothic",
];
const DISPLAY_MONO_FONT_OPTIONS: &[&str] = &[
    "jetbrains",
    "sfmono",
    "plexmono",
    "d2coding",
    "nanumgothiccoding",
    "notomonokr",
];

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct DisplaySettingsSnapshot {
    pub size_px: u16,
    pub theme: String,
    pub ui_font: String,
    pub mono_font: String,
}

impl Default for DisplaySettingsSnapshot {
    fn default() -> Self {
        Self {
            size_px: 12,
            theme: "charcoal".to_string(),
            ui_font: "plex".to_string(),
            mono_font: "jetbrains".to_string(),
        }
    }
}

impl DisplaySettingsSnapshot {
    fn sanitized(self) -> Self {
        Self {
            size_px: self.size_px.clamp(8, 20),
            theme: sanitize_option(self.theme, "charcoal", DISPLAY_THEME_OPTIONS),
            ui_font: sanitize_option(self.ui_font, "plex", DISPLAY_UI_FONT_OPTIONS),
            mono_font: sanitize_option(self.mono_font, "jetbrains", DISPLAY_MONO_FONT_OPTIONS),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct AppUiSettingsSnapshot {
    pub display_settings: DisplaySettingsSnapshot,
    pub history_column_widths: BTreeMap<String, u16>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub ws_column_widths: BTreeMap<String, u16>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub history_column_order: Vec<String>,
    pub workbench_height: Option<u16>,
}

impl Default for AppUiSettingsSnapshot {
    fn default() -> Self {
        Self {
            display_settings: DisplaySettingsSnapshot::default(),
            history_column_widths: default_history_column_widths(),
            ws_column_widths: default_ws_column_widths(),
            history_column_order: Vec::new(),
            workbench_height: None,
        }
    }
}

impl AppUiSettingsSnapshot {
    fn sanitized(self) -> Self {
        let mut sanitized = Self::default();

        sanitized.display_settings = self.display_settings.sanitized();
        sanitized.workbench_height = self
            .workbench_height
            .filter(|height| *height > 0)
            .map(|height| height.min(4_096));

        for (key, value) in self.history_column_widths {
            if !key.trim().is_empty() {
                sanitized.history_column_widths.insert(key, value.max(1));
            }
        }

        for (key, value) in self.ws_column_widths {
            if !key.trim().is_empty() {
                sanitized.ws_column_widths.insert(key, value.max(1));
            }
        }

        sanitized.history_column_order = self
            .history_column_order
            .into_iter()
            .filter(|key| !key.trim().is_empty())
            .collect();

        sanitized
    }
}

pub struct AppUiSettingsStore {
    path: PathBuf,
    inner: RwLock<AppUiSettingsSnapshot>,
}

impl AppUiSettingsStore {
    pub fn load_or_create(data_dir: &Path) -> Result<Self> {
        let snapshot = load_ui_settings_snapshot(data_dir)?;
        Ok(Self {
            path: ui_settings_path(data_dir),
            inner: RwLock::new(snapshot),
        })
    }

    pub async fn snapshot(&self) -> AppUiSettingsSnapshot {
        self.inner.read().await.clone()
    }

    pub async fn replace_snapshot(
        &self,
        snapshot: AppUiSettingsSnapshot,
    ) -> Result<AppUiSettingsSnapshot> {
        let next = snapshot.sanitized();
        let mut current = self.inner.write().await;
        persist_ui_settings(&self.path, &next)?;
        *current = next.clone();
        Ok(next)
    }
}

fn ui_settings_path(data_dir: &Path) -> PathBuf {
    data_dir.join(UI_SETTINGS_FILE)
}

fn load_ui_settings_snapshot(data_dir: &Path) -> Result<AppUiSettingsSnapshot> {
    fs::create_dir_all(data_dir).with_context(|| {
        format!(
            "failed to create ui settings directory {}",
            data_dir.display()
        )
    })?;
    let path = ui_settings_path(data_dir);

    match fs::read(&path) {
        Ok(bytes) => serde_json::from_slice::<AppUiSettingsSnapshot>(&bytes)
            .map(AppUiSettingsSnapshot::sanitized)
            .or_else(|error| {
                warn!(
                    ?error,
                    path = %path.display(),
                    "discarding corrupt ui settings"
                );
                move_corrupt_ui_settings_aside(data_dir, &path);
                let snapshot = AppUiSettingsSnapshot::default();
                persist_ui_settings(&path, &snapshot)?;
                Ok(snapshot)
            }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let snapshot = AppUiSettingsSnapshot::default();
            persist_ui_settings(&path, &snapshot)?;
            Ok(snapshot)
        }
        Err(error) => {
            Err(error).with_context(|| format!("failed to read ui settings {}", path.display()))
        }
    }
}

fn persist_ui_settings(path: &Path, snapshot: &AppUiSettingsSnapshot) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create ui settings directory {}",
                parent.display()
            )
        })?;
    }

    let data = serde_json::to_vec_pretty(snapshot).context("failed to serialize ui settings")?;
    let tmp_path = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
    {
        let mut file = fs::File::create(&tmp_path)
            .with_context(|| format!("failed to write ui settings {}", tmp_path.display()))?;
        file.write_all(&data)
            .with_context(|| format!("failed to write ui settings {}", tmp_path.display()))?;
        file.sync_all()
            .with_context(|| format!("failed to sync ui settings {}", tmp_path.display()))?;
    }
    fs::rename(&tmp_path, path).with_context(|| {
        format!(
            "failed to rename ui settings {} to {}",
            tmp_path.display(),
            path.display()
        )
    })?;
    if let Some(parent) = path.parent() {
        sync_directory(parent, "ui settings directory")?;
    }
    Ok(())
}

fn move_corrupt_ui_settings_aside(data_dir: &Path, path: &Path) {
    let corrupt_path = data_dir.join(format!(".ui-settings.corrupt-{}.json", Uuid::new_v4()));
    if let Err(rename_error) = fs::rename(path, &corrupt_path) {
        warn!(
            ?rename_error,
            path = %path.display(),
            "failed to move corrupt ui settings aside"
        );
        let _ = fs::remove_file(path);
    }
}

fn sync_directory(path: &Path, label: &str) -> Result<()> {
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .with_context(|| format!("failed to sync {label} {}", path.display()))
}

fn sanitize_string(value: String, fallback: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        fallback.to_string()
    } else {
        trimmed.to_string()
    }
}

fn sanitize_option(value: String, fallback: &str, allowed: &[&str]) -> String {
    let trimmed = sanitize_string(value, fallback);
    if allowed.contains(&trimmed.as_str()) {
        trimmed
    } else {
        fallback.to_string()
    }
}

fn default_history_column_widths() -> BTreeMap<String, u16> {
    BTreeMap::from([
        ("host".to_string(), 320),
        ("index".to_string(), 48),
        ("length".to_string(), 104),
        ("method".to_string(), 110),
        ("mime".to_string(), 128),
        ("notes".to_string(), 90),
        ("path".to_string(), 420),
        ("started_at".to_string(), 176),
        ("status".to_string(), 110),
        ("tls".to_string(), 92),
    ])
}

fn default_ws_column_widths() -> BTreeMap<String, u16> {
    BTreeMap::from([
        ("duration_ms".to_string(), 90),
        ("frame_count".to_string(), 72),
        ("host".to_string(), 260),
        ("index".to_string(), 48),
        ("started_at".to_string(), 150),
        ("status".to_string(), 62),
    ])
}

#[cfg(test)]
mod tests {
    use super::{AppUiSettingsSnapshot, AppUiSettingsStore};

    #[tokio::test]
    async fn ui_settings_store_persists_snapshot() {
        let data_dir =
            std::env::temp_dir().join(format!("sniper-ui-settings-{}", uuid::Uuid::new_v4()));
        let store = AppUiSettingsStore::load_or_create(&data_dir).expect("store should load");

        let mut snapshot = AppUiSettingsSnapshot::default();
        snapshot.display_settings.theme = "white".to_string();
        snapshot.display_settings.size_px = 15;
        snapshot
            .history_column_widths
            .insert("host".to_string(), 444);
        snapshot
            .ws_column_widths
            .insert("frame_count".to_string(), 123);
        snapshot.workbench_height = Some(333);

        store
            .replace_snapshot(snapshot.clone())
            .await
            .expect("snapshot should persist");

        let reloaded = AppUiSettingsStore::load_or_create(&data_dir).expect("store should reload");
        let persisted = reloaded.snapshot().await;

        assert_eq!(persisted.display_settings.theme, "white");
        assert_eq!(persisted.display_settings.size_px, 15);
        assert_eq!(persisted.history_column_widths.get("host"), Some(&444));
        assert_eq!(persisted.ws_column_widths.get("frame_count"), Some(&123));
        assert_eq!(persisted.workbench_height, Some(333));

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[tokio::test]
    async fn ui_settings_store_sanitizes_unknown_display_options() {
        let data_dir =
            std::env::temp_dir().join(format!("sniper-ui-settings-{}", uuid::Uuid::new_v4()));
        let store = AppUiSettingsStore::load_or_create(&data_dir).expect("store should load");

        let mut snapshot = AppUiSettingsSnapshot::default();
        snapshot.display_settings.theme = "neon".to_string();
        snapshot.display_settings.ui_font = "comic".to_string();
        snapshot.display_settings.mono_font = "fantasy".to_string();

        store
            .replace_snapshot(snapshot)
            .await
            .expect("snapshot should persist");

        let reloaded = AppUiSettingsStore::load_or_create(&data_dir).expect("store should reload");
        let persisted = reloaded.snapshot().await;

        assert_eq!(persisted.display_settings.theme, "charcoal");
        assert_eq!(persisted.display_settings.ui_font, "plex");
        assert_eq!(persisted.display_settings.mono_font, "jetbrains");

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[tokio::test]
    async fn ui_settings_store_accepts_legacy_partial_snapshot() {
        let data_dir =
            std::env::temp_dir().join(format!("sniper-ui-settings-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&data_dir).expect("temp data dir should be created");
        std::fs::write(
            data_dir.join(super::UI_SETTINGS_FILE),
            br#"{"display_settings":{"theme":"  "},"history_column_order":["host",""]}"#,
        )
        .expect("legacy ui settings should be written");

        let store = AppUiSettingsStore::load_or_create(&data_dir)
            .expect("legacy partial ui settings should load");
        let snapshot = store.snapshot().await;

        assert_eq!(snapshot.display_settings.theme, "charcoal");
        assert_eq!(snapshot.display_settings.size_px, 12);
        assert_eq!(snapshot.display_settings.ui_font, "plex");
        assert_eq!(snapshot.display_settings.mono_font, "jetbrains");
        assert_eq!(snapshot.history_column_widths.get("host"), Some(&320));
        assert_eq!(snapshot.ws_column_widths.get("host"), Some(&260));
        assert_eq!(snapshot.history_column_order, vec!["host".to_string()]);
        assert_eq!(snapshot.workbench_height, None);

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[tokio::test]
    async fn ui_settings_store_recovers_from_corrupt_json() {
        let data_dir =
            std::env::temp_dir().join(format!("sniper-ui-settings-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&data_dir).expect("temp data dir should be created");
        std::fs::write(data_dir.join(super::UI_SETTINGS_FILE), b"{not json")
            .expect("corrupt ui settings should be written");

        let store = AppUiSettingsStore::load_or_create(&data_dir)
            .expect("corrupt ui settings should recover with defaults");
        let snapshot = store.snapshot().await;

        assert_eq!(snapshot.display_settings.theme, "charcoal");
        assert!(data_dir.join(super::UI_SETTINGS_FILE).exists());
        let has_corrupt_backup = std::fs::read_dir(&data_dir)
            .unwrap()
            .filter_map(Result::ok)
            .any(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".ui-settings.corrupt-")
            });
        assert!(has_corrupt_backup);

        let _ = std::fs::remove_dir_all(&data_dir);
    }
}
