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
const ACTIVE_TOOL_OPTIONS: &[&str] = &[
    "dashboard",
    "target",
    "proxy",
    "fuzzer",
    "sequence",
    "replay",
    "tools",
    "logger",
];
const ACTIVE_PROXY_TAB_OPTIONS: &[&str] = &[
    "intercept",
    "http-history",
    "websockets-history",
    "replace",
    "findings",
    "oast",
    "proxy-settings",
];
const WEBSOCKET_SORT_KEY_OPTIONS: &[&str] = &[
    "index",
    "host",
    "path",
    "status",
    "frame_count",
    "duration_ms",
    "started_at",
];
const WEBSOCKET_QUERY_MAX_CHARS: usize = 512;

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

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct WorkbenchPaneWidthsSnapshot {
    pub request_percent: Option<u16>,
    pub response_percent: Option<u16>,
    pub inspector_width: Option<u16>,
}

impl WorkbenchPaneWidthsSnapshot {
    fn sanitized(self) -> Self {
        Self {
            request_percent: self
                .request_percent
                .filter(|width| *width > 0)
                .map(|width| width.clamp(18, 72)),
            response_percent: self
                .response_percent
                .filter(|width| *width > 0)
                .map(|width| width.clamp(18, 72)),
            inspector_width: self
                .inspector_width
                .filter(|width| *width > 0)
                .map(|width| width.clamp(300, 4_096)),
        }
    }

    fn is_empty(&self) -> bool {
        self.request_percent.is_none()
            && self.response_percent.is_none()
            && self.inspector_width.is_none()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct AppUiSettingsSnapshot {
    pub display_settings: DisplaySettingsSnapshot,
    pub active_tool: String,
    pub active_proxy_tab: String,
    pub history_column_widths: BTreeMap<String, u16>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub ws_column_widths: BTreeMap<String, u16>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub history_column_order: Vec<String>,
    pub workbench_height: Option<u16>,
    #[serde(default, skip_serializing_if = "WorkbenchPaneWidthsSnapshot::is_empty")]
    pub workbench_pane_widths: WorkbenchPaneWidthsSnapshot,
    pub websocket_pane_width: Option<u16>,
    pub websocket_query: String,
    pub websocket_sort_key: String,
    pub websocket_sort_direction: String,
    pub websocket_in_scope_only: bool,
    pub websocket_live_only: bool,
    pub websocket_stack_height: Option<u16>,
    pub ws_replay_left_width: Option<u16>,
    pub ws_replay_frame_detail_height: Option<u16>,
}

impl Default for AppUiSettingsSnapshot {
    fn default() -> Self {
        Self {
            display_settings: DisplaySettingsSnapshot::default(),
            active_tool: "proxy".to_string(),
            active_proxy_tab: "http-history".to_string(),
            history_column_widths: default_history_column_widths(),
            ws_column_widths: default_ws_column_widths(),
            history_column_order: Vec::new(),
            workbench_height: None,
            workbench_pane_widths: WorkbenchPaneWidthsSnapshot::default(),
            websocket_pane_width: None,
            websocket_query: String::new(),
            websocket_sort_key: "started_at".to_string(),
            websocket_sort_direction: "desc".to_string(),
            websocket_in_scope_only: false,
            websocket_live_only: false,
            websocket_stack_height: None,
            ws_replay_left_width: None,
            ws_replay_frame_detail_height: None,
        }
    }
}

impl AppUiSettingsSnapshot {
    fn sanitized(self) -> Self {
        let mut sanitized = Self::default();

        sanitized.display_settings = self.display_settings.sanitized();
        sanitized.active_tool = sanitize_option(self.active_tool, "proxy", ACTIVE_TOOL_OPTIONS);
        sanitized.active_proxy_tab = sanitize_option(
            self.active_proxy_tab,
            "http-history",
            ACTIVE_PROXY_TAB_OPTIONS,
        );
        sanitized.workbench_height = self
            .workbench_height
            .filter(|height| *height > 0)
            .map(|height| height.min(4_096));
        sanitized.workbench_pane_widths = self.workbench_pane_widths.sanitized();
        sanitized.websocket_pane_width = self
            .websocket_pane_width
            .filter(|width| *width > 0)
            .map(|width| width.clamp(300, 4_096));
        sanitized.websocket_query =
            trim_to_char_limit(self.websocket_query.trim(), WEBSOCKET_QUERY_MAX_CHARS);
        sanitized.websocket_sort_key = sanitize_option(
            self.websocket_sort_key,
            "started_at",
            WEBSOCKET_SORT_KEY_OPTIONS,
        );
        sanitized.websocket_sort_direction =
            sanitize_option(self.websocket_sort_direction, "desc", &["asc", "desc"]);
        sanitized.websocket_in_scope_only = self.websocket_in_scope_only;
        sanitized.websocket_live_only = self.websocket_live_only;
        sanitized.websocket_stack_height = self
            .websocket_stack_height
            .filter(|height| *height > 0)
            .map(|height| height.clamp(160, 4_096));
        sanitized.ws_replay_left_width = self
            .ws_replay_left_width
            .filter(|width| *width > 0)
            .map(|width| width.clamp(280, 4_096));
        sanitized.ws_replay_frame_detail_height = self
            .ws_replay_frame_detail_height
            .filter(|height| *height > 0)
            .map(|height| height.clamp(120, 4_096));

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
        Err(error) if path.exists() => {
            warn!(
                ?error,
                path = %path.display(),
                "discarding unreadable ui settings"
            );
            move_corrupt_ui_settings_aside(data_dir, &path);
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
    if path.is_dir() {
        warn!(
            path = %path.display(),
            "moving directory ui settings aside before replace"
        );
        if let Some(parent) = path.parent() {
            move_corrupt_ui_settings_aside(parent, path);
        }
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

fn trim_to_char_limit(value: &str, limit: usize) -> String {
    value.chars().take(limit).collect()
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
        snapshot.active_tool = "replay".to_string();
        snapshot.active_proxy_tab = "websockets-history".to_string();
        snapshot
            .history_column_widths
            .insert("host".to_string(), 444);
        snapshot
            .ws_column_widths
            .insert("frame_count".to_string(), 123);
        snapshot.workbench_height = Some(333);
        snapshot.workbench_pane_widths.request_percent = Some(34);
        snapshot.workbench_pane_widths.response_percent = Some(41);
        snapshot.workbench_pane_widths.inspector_width = Some(390);
        snapshot.websocket_pane_width = Some(444);
        snapshot.websocket_query = "chat.example".to_string();
        snapshot.websocket_sort_key = "host".to_string();
        snapshot.websocket_sort_direction = "asc".to_string();
        snapshot.websocket_in_scope_only = true;
        snapshot.websocket_live_only = true;
        snapshot.websocket_stack_height = Some(345);
        snapshot.ws_replay_left_width = Some(555);
        snapshot.ws_replay_frame_detail_height = Some(222);

        store
            .replace_snapshot(snapshot.clone())
            .await
            .expect("snapshot should persist");

        let reloaded = AppUiSettingsStore::load_or_create(&data_dir).expect("store should reload");
        let persisted = reloaded.snapshot().await;

        assert_eq!(persisted.display_settings.theme, "white");
        assert_eq!(persisted.display_settings.size_px, 15);
        assert_eq!(persisted.active_tool, "replay");
        assert_eq!(persisted.active_proxy_tab, "websockets-history");
        assert_eq!(persisted.history_column_widths.get("host"), Some(&444));
        assert_eq!(persisted.ws_column_widths.get("frame_count"), Some(&123));
        assert_eq!(persisted.workbench_height, Some(333));
        assert_eq!(persisted.workbench_pane_widths.request_percent, Some(34));
        assert_eq!(persisted.workbench_pane_widths.response_percent, Some(41));
        assert_eq!(persisted.workbench_pane_widths.inspector_width, Some(390));
        assert_eq!(persisted.websocket_pane_width, Some(444));
        assert_eq!(persisted.websocket_query, "chat.example");
        assert_eq!(persisted.websocket_sort_key, "host");
        assert_eq!(persisted.websocket_sort_direction, "asc");
        assert!(persisted.websocket_in_scope_only);
        assert!(persisted.websocket_live_only);
        assert_eq!(persisted.websocket_stack_height, Some(345));
        assert_eq!(persisted.ws_replay_left_width, Some(555));
        assert_eq!(persisted.ws_replay_frame_detail_height, Some(222));

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
        snapshot.active_tool = "missing-tool".to_string();
        snapshot.active_proxy_tab = "missing-tab".to_string();
        snapshot.websocket_query =
            format!("  {}  ", "x".repeat(super::WEBSOCKET_QUERY_MAX_CHARS + 8));
        snapshot.websocket_sort_key = "missing-sort".to_string();
        snapshot.websocket_sort_direction = "sideways".to_string();

        store
            .replace_snapshot(snapshot)
            .await
            .expect("snapshot should persist");

        let reloaded = AppUiSettingsStore::load_or_create(&data_dir).expect("store should reload");
        let persisted = reloaded.snapshot().await;

        assert_eq!(persisted.display_settings.theme, "charcoal");
        assert_eq!(persisted.display_settings.ui_font, "plex");
        assert_eq!(persisted.display_settings.mono_font, "jetbrains");
        assert_eq!(persisted.active_tool, "proxy");
        assert_eq!(persisted.active_proxy_tab, "http-history");
        assert_eq!(
            persisted.websocket_query.chars().count(),
            super::WEBSOCKET_QUERY_MAX_CHARS
        );
        assert_eq!(persisted.websocket_sort_key, "started_at");
        assert_eq!(persisted.websocket_sort_direction, "desc");

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

    #[tokio::test]
    async fn ui_settings_store_recovers_from_directory_path() {
        let data_dir =
            std::env::temp_dir().join(format!("sniper-ui-settings-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(data_dir.join(super::UI_SETTINGS_FILE))
            .expect("ui settings directory should be created");

        let store = AppUiSettingsStore::load_or_create(&data_dir)
            .expect("directory ui settings should recover with defaults");
        let snapshot = store.snapshot().await;

        assert_eq!(snapshot.display_settings.theme, "charcoal");
        assert!(data_dir.join(super::UI_SETTINGS_FILE).is_file());

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[tokio::test]
    async fn ui_settings_store_replace_recovers_from_directory_path() {
        let data_dir =
            std::env::temp_dir().join(format!("sniper-ui-settings-{}", uuid::Uuid::new_v4()));
        let store = AppUiSettingsStore::load_or_create(&data_dir)
            .expect("ui settings store should be created");
        std::fs::remove_file(data_dir.join(super::UI_SETTINGS_FILE))
            .expect("initial ui settings file should be removed");
        std::fs::create_dir_all(data_dir.join(super::UI_SETTINGS_FILE))
            .expect("ui settings directory should be created");

        let mut snapshot = store.snapshot().await;
        snapshot.active_tool = "replay".to_string();
        let saved = store
            .replace_snapshot(snapshot)
            .await
            .expect("directory ui settings should be replaced");

        assert_eq!(saved.active_tool, "replay");
        assert!(data_dir.join(super::UI_SETTINGS_FILE).is_file());
        assert!(std::fs::read_dir(&data_dir).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".ui-settings.corrupt-")
        }));

        let _ = std::fs::remove_dir_all(&data_dir);
    }
}
