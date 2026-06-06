use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

pub const OAST_TOKEN_REDACTION: &str = "********";
pub const MIN_OAST_POLLING_INTERVAL_SECS: u64 = 1;
pub const MAX_OAST_POLLING_INTERVAL_SECS: u64 = 300;
const MAX_RUNTIME_PATTERN_ENTRIES: usize = 500;
const MAX_RUNTIME_PATTERN_BYTES: usize = 512;
const MAX_RUNTIME_TEXT_FIELD_BYTES: usize = 8 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuntimeSettingsSnapshot {
    #[serde(default)]
    pub intercept_enabled: bool,
    #[serde(default = "default_true")]
    pub websocket_capture_enabled: bool,
    #[serde(default)]
    pub scope_patterns: Vec<String>,
    #[serde(default)]
    pub passthrough_hosts: Vec<String>,
    #[serde(default = "default_upstream_insecure")]
    pub upstream_insecure: bool,
    #[serde(default = "default_true")]
    pub intercept_scope_only: bool,
    #[serde(default)]
    pub oast_enabled: bool,
    #[serde(default)]
    pub oast_server_url: String,
    #[serde(default)]
    pub oast_token: String,
    #[serde(default = "default_oast_interval")]
    pub oast_polling_interval_secs: u64,
    #[serde(default)]
    pub oast_provider: crate::oast::OastProvider,
}

fn default_oast_interval() -> u64 {
    5
}

fn default_true() -> bool {
    true
}

fn default_upstream_insecure() -> bool {
    true
}

impl Default for RuntimeSettingsSnapshot {
    fn default() -> Self {
        Self {
            intercept_enabled: false,
            websocket_capture_enabled: true,
            scope_patterns: Vec::new(),
            passthrough_hosts: Vec::new(),
            upstream_insecure: true,
            intercept_scope_only: true,
            oast_enabled: false,
            oast_server_url: String::new(),
            oast_token: String::new(),
            oast_polling_interval_secs: 5,
            oast_provider: crate::oast::OastProvider::default(),
        }
    }
}

impl RuntimeSettingsSnapshot {
    pub fn redacted_for_read(mut self) -> Self {
        if !self.oast_token.is_empty() {
            self.oast_token = OAST_TOKEN_REDACTION.to_string();
        }
        self
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct RuntimeSettingsUpdate {
    pub session_id: Option<uuid::Uuid>,
    pub intercept_enabled: Option<bool>,
    pub websocket_capture_enabled: Option<bool>,
    pub scope_patterns: Option<Vec<String>>,
    pub passthrough_hosts: Option<Vec<String>>,
    pub upstream_insecure: Option<bool>,
    pub intercept_scope_only: Option<bool>,
    pub oast_enabled: Option<bool>,
    pub oast_server_url: Option<String>,
    pub oast_token: Option<String>,
    pub oast_polling_interval_secs: Option<u64>,
    pub oast_provider: Option<crate::oast::OastProvider>,
}

pub struct RuntimeSettings {
    inner: RwLock<RuntimeSettingsSnapshot>,
}

impl RuntimeSettings {
    pub fn new() -> Self {
        Self::from_snapshot(RuntimeSettingsSnapshot::default())
    }

    pub fn from_snapshot(snapshot: RuntimeSettingsSnapshot) -> Self {
        Self {
            inner: RwLock::new(snapshot),
        }
    }

    pub async fn snapshot(&self) -> RuntimeSettingsSnapshot {
        self.inner.read().await.clone()
    }

    pub async fn update(&self, update: RuntimeSettingsUpdate) -> Result<RuntimeSettingsSnapshot> {
        if let Some(oast_polling_interval_secs) = update.oast_polling_interval_secs {
            if !(MIN_OAST_POLLING_INTERVAL_SECS..=MAX_OAST_POLLING_INTERVAL_SECS)
                .contains(&oast_polling_interval_secs)
            {
                bail!(
                    "OAST polling interval must be between {} and {} seconds",
                    MIN_OAST_POLLING_INTERVAL_SECS,
                    MAX_OAST_POLLING_INTERVAL_SECS
                );
            }
        }
        let mut current = self.inner.write().await;

        if let Some(intercept_enabled) = update.intercept_enabled {
            current.intercept_enabled = intercept_enabled;
        }

        if let Some(websocket_capture_enabled) = update.websocket_capture_enabled {
            current.websocket_capture_enabled = websocket_capture_enabled;
        }

        if let Some(scope_patterns) = update.scope_patterns {
            current.scope_patterns =
                normalize_bounded_scope_patterns("scope pattern", scope_patterns)?;
        }

        if let Some(passthrough_hosts) = update.passthrough_hosts {
            current.passthrough_hosts =
                normalize_bounded_scope_patterns("passthrough host", passthrough_hosts)?;
        }

        if let Some(upstream_insecure) = update.upstream_insecure {
            current.upstream_insecure = upstream_insecure;
        }

        if let Some(intercept_scope_only) = update.intercept_scope_only {
            current.intercept_scope_only = intercept_scope_only;
        }

        if let Some(oast_enabled) = update.oast_enabled {
            current.oast_enabled = oast_enabled;
        }
        if let Some(oast_server_url) = update.oast_server_url {
            validate_runtime_text_field("OAST server URL", &oast_server_url)?;
            current.oast_server_url = oast_server_url;
        }
        if let Some(oast_token) = update.oast_token {
            if oast_token != OAST_TOKEN_REDACTION {
                validate_runtime_text_field("OAST token", &oast_token)?;
                current.oast_token = oast_token;
            }
        }
        if let Some(oast_polling_interval_secs) = update.oast_polling_interval_secs {
            current.oast_polling_interval_secs = oast_polling_interval_secs;
        }
        if let Some(oast_provider) = update.oast_provider {
            current.oast_provider = oast_provider;
        }

        Ok(current.clone())
    }

    pub async fn replace_snapshot(
        &self,
        snapshot: RuntimeSettingsSnapshot,
    ) -> RuntimeSettingsSnapshot {
        let mut current = self.inner.write().await;
        *current = snapshot;
        current.clone()
    }

    pub async fn intercept_enabled(&self) -> bool {
        self.inner.read().await.intercept_enabled
    }

    pub async fn websocket_capture_enabled(&self) -> bool {
        self.inner.read().await.websocket_capture_enabled
    }

    pub async fn upstream_insecure(&self) -> bool {
        self.inner.read().await.upstream_insecure
    }

    pub async fn intercept_scope_only(&self) -> bool {
        self.inner.read().await.intercept_scope_only
    }

    pub async fn is_in_scope(&self, host: &str) -> bool {
        let current = self.inner.read().await;
        matches_scope(host, &current.scope_patterns)
    }

    pub async fn is_passthrough(&self, host: &str) -> bool {
        let current = self.inner.read().await;
        matches_passthrough(host, &current.passthrough_hosts)
    }
}

impl Default for RuntimeSettings {
    fn default() -> Self {
        Self::new()
    }
}

fn normalize_scope_patterns(patterns: Vec<String>) -> Vec<String> {
    patterns
        .into_iter()
        .map(|pattern| pattern.trim().to_ascii_lowercase())
        .filter(|pattern| !pattern.is_empty())
        .collect()
}

fn normalize_bounded_scope_patterns(label: &str, patterns: Vec<String>) -> Result<Vec<String>> {
    let normalized = normalize_scope_patterns(patterns);
    if normalized.len() > MAX_RUNTIME_PATTERN_ENTRIES {
        bail!("{label} list cannot exceed {MAX_RUNTIME_PATTERN_ENTRIES} entries");
    }
    for pattern in &normalized {
        if pattern.len() > MAX_RUNTIME_PATTERN_BYTES {
            bail!("{label} cannot exceed {MAX_RUNTIME_PATTERN_BYTES} bytes");
        }
    }
    Ok(normalized)
}

fn validate_runtime_text_field(label: &str, value: &str) -> Result<()> {
    if value.len() > MAX_RUNTIME_TEXT_FIELD_BYTES {
        bail!("{label} cannot exceed {MAX_RUNTIME_TEXT_FIELD_BYTES} bytes");
    }
    Ok(())
}

fn matches_scope(host: &str, patterns: &[String]) -> bool {
    if patterns.is_empty() {
        return true;
    }

    host_matches_any(host, patterns)
}

fn matches_passthrough(host: &str, patterns: &[String]) -> bool {
    if patterns.is_empty() {
        return false;
    }

    host_matches_any(host, patterns)
}

fn host_matches_any(host: &str, patterns: &[String]) -> bool {
    let hostname = normalize_host_for_matching(host);

    patterns.iter().any(|pattern| {
        let normalized = normalize_host_for_matching(pattern);
        if let Some(suffix) = normalized.strip_prefix("*.") {
            hostname == suffix || hostname.ends_with(&format!(".{suffix}"))
        } else {
            hostname == normalized
        }
    })
}

fn normalize_host_for_matching(host: &str) -> String {
    host_without_port(host).to_ascii_lowercase()
}

fn host_without_port(host: &str) -> &str {
    let trimmed = host.trim();
    if let Some(rest) = trimmed.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            return &rest[..end];
        }
    }
    if trimmed.matches(':').count() == 1 {
        return trimmed
            .split_once(':')
            .map(|(value, _)| value)
            .unwrap_or(trimmed);
    }
    trimmed
}

#[cfg(test)]
mod tests {
    use super::{
        RuntimeSettings, RuntimeSettingsSnapshot, RuntimeSettingsUpdate, OAST_TOKEN_REDACTION,
    };

    #[test]
    fn runtime_settings_accepts_legacy_partial_snapshot() {
        let snapshot: RuntimeSettingsSnapshot =
            serde_json::from_value(serde_json::json!({ "intercept_enabled": true }))
                .expect("legacy runtime settings should deserialize");

        assert!(snapshot.intercept_enabled);
        assert!(snapshot.websocket_capture_enabled);
        assert!(snapshot.scope_patterns.is_empty());
        assert!(snapshot.passthrough_hosts.is_empty());
        assert!(snapshot.upstream_insecure);
        assert!(snapshot.intercept_scope_only);
    }

    #[test]
    fn runtime_settings_read_view_redacts_oast_token() {
        let snapshot = RuntimeSettingsSnapshot {
            oast_token: "secret-token".to_string(),
            ..RuntimeSettingsSnapshot::default()
        };

        let redacted = snapshot.clone().redacted_for_read();

        assert_eq!(snapshot.oast_token, "secret-token");
        assert_eq!(redacted.oast_token, OAST_TOKEN_REDACTION);
    }

    #[tokio::test]
    async fn runtime_settings_rejects_out_of_range_oast_polling_interval() {
        let settings = RuntimeSettings::new();
        let error = settings
            .update(RuntimeSettingsUpdate {
                oast_polling_interval_secs: Some(0),
                ..RuntimeSettingsUpdate::default()
            })
            .await
            .unwrap_err();

        assert!(error.to_string().contains("OAST polling interval"));
        assert_eq!(settings.snapshot().await.oast_polling_interval_secs, 5);

        let error = settings
            .update(RuntimeSettingsUpdate {
                oast_polling_interval_secs: Some(u64::MAX),
                ..RuntimeSettingsUpdate::default()
            })
            .await
            .unwrap_err();
        assert!(error.to_string().contains("OAST polling interval"));
        assert_eq!(settings.snapshot().await.oast_polling_interval_secs, 5);
    }

    #[tokio::test]
    async fn runtime_settings_rejects_oversized_durable_fields() {
        let settings = RuntimeSettings::new();
        let error = settings
            .update(RuntimeSettingsUpdate {
                scope_patterns: Some(vec!["x".repeat(super::MAX_RUNTIME_PATTERN_BYTES + 1)]),
                ..RuntimeSettingsUpdate::default()
            })
            .await
            .unwrap_err();
        assert!(error.to_string().contains("scope pattern"));

        let error = settings
            .update(RuntimeSettingsUpdate {
                passthrough_hosts: Some(vec![
                    "example.test".to_string();
                    super::MAX_RUNTIME_PATTERN_ENTRIES + 1
                ]),
                ..RuntimeSettingsUpdate::default()
            })
            .await
            .unwrap_err();
        assert!(error.to_string().contains("passthrough host list"));

        let error = settings
            .update(RuntimeSettingsUpdate {
                oast_server_url: Some("x".repeat(super::MAX_RUNTIME_TEXT_FIELD_BYTES + 1)),
                ..RuntimeSettingsUpdate::default()
            })
            .await
            .unwrap_err();
        assert!(error.to_string().contains("OAST server URL"));
    }

    #[tokio::test]
    async fn runtime_settings_keeps_oast_token_on_redaction_sentinel() {
        let settings = RuntimeSettings::new();
        settings
            .update(RuntimeSettingsUpdate {
                oast_token: Some("real-secret".to_string()),
                ..RuntimeSettingsUpdate::default()
            })
            .await
            .unwrap();
        let snapshot = settings
            .update(RuntimeSettingsUpdate {
                oast_token: Some(OAST_TOKEN_REDACTION.to_string()),
                ..RuntimeSettingsUpdate::default()
            })
            .await
            .unwrap();

        assert_eq!(snapshot.oast_token, "real-secret");
    }
}
