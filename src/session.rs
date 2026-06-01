use std::{
    collections::{HashMap, HashSet},
    fs,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::warn;
use uuid::Uuid;

use crate::{
    event_log::{EventLogEntry, EventLogStore},
    fuzzer::{FuzzerAttackRecord, FuzzerStore},
    intercept::{InterceptQueue, ResponseInterceptQueue},
    match_replace::{MatchReplaceRule, MatchReplaceStore},
    model::{TransactionRecord, WebSocketSessionRecord},
    runtime::{RuntimeSettings, RuntimeSettingsSnapshot},
    scanner::{ScannerFinding, ScannerStore},
    sequence::{SequenceDefinition, SequenceRunRecord, SequenceStore},
    store::{
        transaction_journal_checkpoint_path, NullableStringPatch, TransactionJournalEntry,
        TransactionStore,
    },
    websocket::WebSocketStore,
    workspace::{WorkspaceStateSnapshot, WorkspaceStateStore},
};

const SESSIONS_DIR: &str = "sessions";
const REGISTRY_FILE: &str = "registry.json";
const SNAPSHOT_FILE: &str = "snapshot.json";
const TRANSACTION_JOURNAL_FILE: &str = "transactions.journal";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionMetadata {
    pub id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_opened_at: DateTime<Utc>,
    pub request_count: usize,
    pub websocket_count: usize,
    pub event_count: usize,
    #[serde(default, alias = "intruder_count")]
    pub fuzzer_count: usize,
    #[serde(default)]
    pub rule_count: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionSummary {
    pub id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_opened_at: DateTime<Utc>,
    pub request_count: usize,
    pub websocket_count: usize,
    pub event_count: usize,
    #[serde(default, alias = "intruder_count")]
    pub fuzzer_count: usize,
    #[serde(default)]
    pub rule_count: usize,
    pub storage_path: String,
    pub active: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SessionRegistrySnapshot {
    active_session_id: Uuid,
    sessions: Vec<SessionMetadata>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
struct StoredSessionSnapshot {
    runtime: RuntimeSettingsSnapshot,
    transactions: Vec<TransactionRecord>,
    websockets: Vec<WebSocketSessionRecord>,
    event_log: Vec<EventLogEntry>,
    match_replace_rules: Vec<MatchReplaceRule>,
    #[serde(alias = "intruder_attacks")]
    fuzzer_attacks: Vec<FuzzerAttackRecord>,
    #[serde(default)]
    scanner_findings: Vec<ScannerFinding>,
    #[serde(default)]
    intercept_rules: Vec<crate::intercept::InterceptRule>,
    #[serde(default)]
    sequence_definitions: Vec<SequenceDefinition>,
    #[serde(default)]
    sequence_runs: Vec<SequenceRunRecord>,
    #[serde(default)]
    oast_callbacks: Option<Vec<crate::oast::OastCallback>>,
    workspace: WorkspaceStateSnapshot,
}

pub struct SessionContext {
    id: Uuid,
    storage_dir: PathBuf,
    max_entries: usize,
    pub store: Arc<TransactionStore>,
    pub runtime: Arc<RuntimeSettings>,
    pub intercepts: Arc<InterceptQueue>,
    pub response_intercepts: Arc<ResponseInterceptQueue>,
    pub intercept_rules: Arc<crate::intercept::InterceptRuleStore>,
    pub websockets: Arc<WebSocketStore>,
    pub event_log: Arc<EventLogStore>,
    pub match_replace: Arc<MatchReplaceStore>,
    pub fuzzer: Arc<FuzzerStore>,
    pub scanner: Arc<ScannerStore>,
    pub sequence: Arc<SequenceStore>,
    pub oast: Arc<crate::oast::OastStore>,
    pub workspace: Arc<WorkspaceStateStore>,
    metadata: RwLock<SessionMetadata>,
}

impl SessionContext {
    fn from_snapshot(
        metadata: SessionMetadata,
        storage_dir: PathBuf,
        max_entries: usize,
        max_frames_per_session: usize,
        snapshot: StoredSessionSnapshot,
    ) -> Self {
        let journal_path = transaction_journal_path(&storage_dir);
        Self {
            id: metadata.id,
            storage_dir,
            max_entries,
            store: Arc::new(TransactionStore::from_records_with_journal(
                snapshot.transactions,
                journal_path,
                Some(max_entries),
            )),
            runtime: Arc::new(RuntimeSettings::from_snapshot(snapshot.runtime)),
            intercepts: Arc::new(InterceptQueue::new()),
            response_intercepts: Arc::new(ResponseInterceptQueue::new()),
            intercept_rules: Arc::new(crate::intercept::InterceptRuleStore::from_rules(
                snapshot.intercept_rules,
            )),
            websockets: Arc::new(WebSocketStore::from_sessions(
                max_entries,
                max_frames_per_session,
                snapshot.websockets,
            )),
            event_log: Arc::new(EventLogStore::from_entries(max_entries, snapshot.event_log)),
            match_replace: Arc::new(MatchReplaceStore::from_rules(snapshot.match_replace_rules)),
            fuzzer: Arc::new(FuzzerStore::from_attacks(
                max_entries,
                snapshot.fuzzer_attacks,
            )),
            scanner: Arc::new(ScannerStore::from_findings(
                max_entries,
                snapshot.scanner_findings,
            )),
            sequence: Arc::new(SequenceStore::from_data(
                max_entries,
                snapshot.sequence_definitions,
                snapshot.sequence_runs,
            )),
            oast: {
                let store = Arc::new(crate::oast::OastStore::new(max_entries));
                if let Some(callbacks) = snapshot.oast_callbacks {
                    // Restore synchronously — VecDeque assignment doesn't need async
                    let entries: std::collections::VecDeque<_> = callbacks.into();
                    *store.entries_mut_blocking() = entries;
                }
                store
            },
            workspace: Arc::new(WorkspaceStateStore::from_snapshot(snapshot.workspace)),
            metadata: RwLock::new(metadata),
        }
    }

    pub fn id(&self) -> Uuid {
        self.id
    }

    pub fn storage_dir(&self) -> &Path {
        &self.storage_dir
    }

    pub fn summary(&self, active: bool) -> SessionSummary {
        let metadata = self
            .metadata
            .read()
            .expect("session metadata lock poisoned")
            .clone();
        session_summary(&metadata, &self.storage_dir, active)
    }

    pub async fn persist(&self) -> Result<SessionMetadata> {
        let snapshot = StoredSessionSnapshot {
            runtime: self.runtime.snapshot().await,
            transactions: self
                .store
                .snapshot_for_persistence(Some(self.max_entries))
                .await
                .with_context(|| {
                    format!(
                        "failed to rotate transaction journal for {}",
                        self.storage_dir.display()
                    )
                })?,
            websockets: self.websockets.snapshot(Some(self.max_entries)).await,
            event_log: self.event_log.snapshot(Some(self.max_entries)).await,
            match_replace_rules: self.match_replace.snapshot().await,
            fuzzer_attacks: self.fuzzer.snapshot(Some(self.max_entries)).await,
            scanner_findings: self.scanner.snapshot(Some(self.max_entries)).await,
            intercept_rules: self.intercept_rules.snapshot().await,
            sequence_definitions: self.sequence.snapshot_definitions().await,
            sequence_runs: self.sequence.snapshot_runs(Some(self.max_entries)).await,
            oast_callbacks: Some(self.oast.snapshot().await),
            workspace: self.workspace.snapshot().await,
        };

        let mut metadata = self
            .metadata
            .read()
            .expect("session metadata lock poisoned")
            .clone();
        metadata.updated_at = Utc::now();
        metadata.request_count = snapshot.transactions.len();
        metadata.websocket_count = snapshot.websockets.len();
        metadata.event_count = snapshot.event_log.len();
        metadata.fuzzer_count = snapshot.fuzzer_attacks.len();
        metadata.rule_count = snapshot.match_replace_rules.len();

        fs::create_dir_all(&self.storage_dir).with_context(|| {
            format!(
                "failed to create session directory {}",
                self.storage_dir.display()
            )
        })?;
        write_json(&snapshot_path(&self.storage_dir), &snapshot)?;
        discard_transaction_journal_checkpoint(&self.storage_dir)?;

        *self
            .metadata
            .write()
            .expect("session metadata lock poisoned") = metadata.clone();

        Ok(metadata)
    }
}

pub struct SessionRegistry {
    root_dir: PathBuf,
    registry_path: PathBuf,
    max_entries: usize,
    max_frames_per_session: usize,
    inner: RwLock<SessionRegistrySnapshot>,
}

impl SessionRegistry {
    pub fn load_or_create(
        data_dir: &Path,
        max_entries: usize,
        max_frames_per_session: usize,
    ) -> Result<(Self, Arc<SessionContext>)> {
        let root_dir = data_dir.join(SESSIONS_DIR);
        fs::create_dir_all(&root_dir).with_context(|| {
            format!("failed to create sessions directory {}", root_dir.display())
        })?;
        let registry_path = root_dir.join(REGISTRY_FILE);

        let mut registry = match fs::read(&registry_path) {
            Ok(bytes) => {
                serde_json::from_slice::<SessionRegistrySnapshot>(&bytes).with_context(|| {
                    format!(
                        "failed to parse session registry {}",
                        registry_path.display()
                    )
                })?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let default = default_session_metadata("Default session");
                let snapshot = SessionRegistrySnapshot {
                    active_session_id: default.id,
                    sessions: vec![default.clone()],
                };
                persist_session_snapshot(&root_dir, &default, &StoredSessionSnapshot::default())?;
                write_json(&registry_path, &snapshot)?;
                snapshot
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to read session registry {}",
                        registry_path.display()
                    )
                })
            }
        };

        if registry.sessions.is_empty() {
            let default = default_session_metadata("Default session");
            registry.active_session_id = default.id;
            registry.sessions.push(default.clone());
            persist_session_snapshot(&root_dir, &default, &StoredSessionSnapshot::default())?;
            write_json(&registry_path, &registry)?;
        }

        if !registry
            .sessions
            .iter()
            .any(|session| session.id == registry.active_session_id)
        {
            registry.active_session_id = registry.sessions[0].id;
            write_json(&registry_path, &registry)?;
        }

        let this = Self {
            root_dir,
            registry_path,
            max_entries,
            max_frames_per_session,
            inner: RwLock::new(registry.clone()),
        };
        let active_metadata = this.touch_active_session(registry.active_session_id)?;
        let active_context = this.load_context(active_metadata.id)?;
        Ok((this, active_context))
    }

    pub fn summaries(&self) -> Vec<SessionSummary> {
        let registry = self.inner.read().expect("session registry lock poisoned");
        let active_id = registry.active_session_id;
        let mut sessions = registry
            .sessions
            .iter()
            .map(|metadata| {
                session_summary(
                    metadata,
                    &session_dir(&self.root_dir, metadata.id),
                    metadata.id == active_id,
                )
            })
            .collect::<Vec<_>>();
        sessions.sort_by(|left, right| right.last_opened_at.cmp(&left.last_opened_at));
        sessions
    }

    pub fn active_session_id(&self) -> Uuid {
        self.inner
            .read()
            .expect("session registry lock poisoned")
            .active_session_id
    }

    pub fn create_session(&self, name: Option<String>) -> Result<SessionMetadata> {
        let now = Utc::now();
        let metadata = SessionMetadata {
            id: Uuid::new_v4(),
            name: normalize_session_name(name.as_deref(), now),
            created_at: now,
            updated_at: now,
            last_opened_at: now,
            request_count: 0,
            websocket_count: 0,
            event_count: 0,
            fuzzer_count: 0,
            rule_count: 0,
        };

        {
            let mut registry = self.inner.write().expect("session registry lock poisoned");
            registry.sessions.push(metadata.clone());
            write_json(&self.registry_path, &*registry)?;
        }

        persist_session_snapshot(&self.root_dir, &metadata, &StoredSessionSnapshot::default())?;
        Ok(metadata)
    }

    pub fn activate_session(&self, id: Uuid) -> Result<SessionMetadata> {
        self.touch_active_session(id)
    }

    pub fn update_metadata(&self, metadata: SessionMetadata) -> Result<()> {
        let mut registry = self.inner.write().expect("session registry lock poisoned");
        let Some(existing) = registry
            .sessions
            .iter_mut()
            .find(|session| session.id == metadata.id)
        else {
            return Err(anyhow!("session {} was not found", metadata.id));
        };
        *existing = metadata;
        write_json(&self.registry_path, &*registry)
    }

    pub fn delete_session(&self, id: Uuid) -> Result<()> {
        let mut registry = self.inner.write().expect("session registry lock poisoned");
        if registry.active_session_id == id {
            return Err(anyhow!("cannot delete the active session"));
        }
        let index = registry
            .sessions
            .iter()
            .position(|session| session.id == id)
            .ok_or_else(|| anyhow!("session {id} was not found"))?;
        registry.sessions.remove(index);
        write_json(&self.registry_path, &*registry)?;

        let storage_dir = session_dir(&self.root_dir, id);
        if storage_dir.exists() {
            let _ = fs::remove_dir_all(&storage_dir);
        }
        Ok(())
    }

    pub fn session_storage_path(&self, id: Uuid) -> Result<PathBuf> {
        let registry = self.inner.read().expect("session registry lock poisoned");
        if !registry.sessions.iter().any(|s| s.id == id) {
            return Err(anyhow!("session {id} was not found"));
        }
        Ok(session_dir(&self.root_dir, id))
    }

    pub fn load_context(&self, id: Uuid) -> Result<Arc<SessionContext>> {
        let metadata = self
            .inner
            .read()
            .expect("session registry lock poisoned")
            .sessions
            .iter()
            .find(|session| session.id == id)
            .cloned()
            .ok_or_else(|| anyhow!("session {id} was not found"))?;
        let storage_dir = session_dir(&self.root_dir, id);
        let snapshot = load_session_snapshot(&storage_dir, self.max_entries)?;
        Ok(Arc::new(SessionContext::from_snapshot(
            metadata,
            storage_dir,
            self.max_entries,
            self.max_frames_per_session,
            snapshot,
        )))
    }

    fn touch_active_session(&self, id: Uuid) -> Result<SessionMetadata> {
        let mut registry = self.inner.write().expect("session registry lock poisoned");
        let Some(index) = registry
            .sessions
            .iter()
            .position(|session| session.id == id)
        else {
            return Err(anyhow!("session {id} was not found"));
        };

        registry.sessions[index].last_opened_at = Utc::now();
        registry.active_session_id = id;
        let metadata = registry.sessions[index].clone();
        write_json(&self.registry_path, &*registry)?;
        Ok(metadata)
    }
}

fn default_session_metadata(name: &str) -> SessionMetadata {
    let now = Utc::now();
    SessionMetadata {
        id: Uuid::new_v4(),
        name: name.to_string(),
        created_at: now,
        updated_at: now,
        last_opened_at: now,
        request_count: 0,
        websocket_count: 0,
        event_count: 0,
        fuzzer_count: 0,
        rule_count: 0,
    }
}

fn normalize_session_name(name: Option<&str>, now: DateTime<Utc>) -> String {
    name.map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| format!("Session {}", now.format("%Y-%m-%d %H:%M")))
}

fn session_summary(metadata: &SessionMetadata, storage_dir: &Path, active: bool) -> SessionSummary {
    SessionSummary {
        id: metadata.id,
        name: metadata.name.clone(),
        created_at: metadata.created_at,
        updated_at: metadata.updated_at,
        last_opened_at: metadata.last_opened_at,
        request_count: metadata.request_count,
        websocket_count: metadata.websocket_count,
        event_count: metadata.event_count,
        fuzzer_count: metadata.fuzzer_count,
        rule_count: metadata.rule_count,
        storage_path: storage_dir.display().to_string(),
        active,
    }
}

fn session_dir(root_dir: &Path, id: Uuid) -> PathBuf {
    root_dir.join(id.to_string())
}

fn snapshot_path(storage_dir: &Path) -> PathBuf {
    storage_dir.join(SNAPSHOT_FILE)
}

fn transaction_journal_path(storage_dir: &Path) -> PathBuf {
    storage_dir.join(TRANSACTION_JOURNAL_FILE)
}

fn load_session_snapshot(storage_dir: &Path, max_entries: usize) -> Result<StoredSessionSnapshot> {
    fs::create_dir_all(storage_dir).with_context(|| {
        format!(
            "failed to create session directory {}",
            storage_dir.display()
        )
    })?;
    let path = snapshot_path(storage_dir);
    let mut snapshot = match fs::read(&path) {
        Ok(bytes) => serde_json::from_slice::<StoredSessionSnapshot>(&bytes)
            .with_context(|| format!("failed to parse session snapshot {}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(StoredSessionSnapshot::default())
        }
        Err(error) => Err(error)
            .with_context(|| format!("failed to read session snapshot {}", path.display())),
    }?;
    replay_transaction_journal(storage_dir, max_entries, &mut snapshot)?;
    Ok(snapshot)
}

fn replay_transaction_journal(
    storage_dir: &Path,
    max_entries: usize,
    snapshot: &mut StoredSessionSnapshot,
) -> Result<()> {
    let journal_path = transaction_journal_path(storage_dir);
    let checkpoint_path = transaction_journal_checkpoint_path(&journal_path);

    let mut order = Vec::with_capacity(snapshot.transactions.len());
    let mut records = HashMap::with_capacity(snapshot.transactions.len());
    let mut seen = HashSet::with_capacity(snapshot.transactions.len());
    for record in snapshot.transactions.drain(..) {
        if seen.insert(record.id) {
            order.push(record.id);
            records.insert(record.id, record);
        }
    }
    let replay_insert_after_sequence = (!records.is_empty()).then(|| {
        records
            .values()
            .map(|record| record.sequence)
            .max()
            .unwrap_or(0)
    });

    replay_transaction_journal_file(
        &checkpoint_path,
        replay_insert_after_sequence,
        &mut order,
        &mut records,
        &mut seen,
    )?;
    replay_transaction_journal_file(
        &journal_path,
        replay_insert_after_sequence,
        &mut order,
        &mut records,
        &mut seen,
    )?;

    snapshot.transactions = order
        .into_iter()
        .filter_map(|id| records.remove(&id))
        .take(max_entries)
        .collect();
    Ok(())
}

fn replay_transaction_journal_file(
    journal_path: &Path,
    insert_after_sequence: Option<u64>,
    order: &mut Vec<Uuid>,
    records: &mut HashMap<Uuid, TransactionRecord>,
    seen: &mut HashSet<Uuid>,
) -> Result<()> {
    let file = match fs::File::open(journal_path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to read transaction journal {}",
                    journal_path.display()
                )
            })
        }
    };

    let mut reader = BufReader::new(file);
    let mut inserted_order = Vec::new();
    let mut line = String::new();
    let mut line_number = 0usize;
    loop {
        line.clear();
        let bytes = reader.read_line(&mut line).with_context(|| {
            format!(
                "failed to read transaction journal {}",
                journal_path.display()
            )
        })?;
        if bytes == 0 {
            break;
        }
        line_number += 1;
        let line_has_newline = line.ends_with('\n');
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let entry: TransactionJournalEntry = match serde_json::from_str(trimmed) {
            Ok(entry) => entry,
            Err(error) if !line_has_newline => {
                warn!(
                    ?error,
                    path = %journal_path.display(),
                    line = line_number,
                    "ignoring trailing partial transaction journal line"
                );
                break;
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to parse transaction journal {} line {}",
                        journal_path.display(),
                        line_number
                    )
                })
            }
        };
        match entry {
            TransactionJournalEntry::Insert { record } => {
                if insert_after_sequence.is_some_and(|sequence| record.sequence <= sequence) {
                    continue;
                }
                if seen.insert(record.id) {
                    inserted_order.push(record.id);
                    records.insert(record.id, record);
                }
            }
            TransactionJournalEntry::Annotation {
                id,
                color_tag,
                user_note,
            } => {
                if let Some(record) = records.get_mut(&id) {
                    apply_nullable_string_patch(&mut record.color_tag, color_tag);
                    apply_nullable_string_patch(&mut record.user_note, user_note);
                }
            }
        }
    }
    if !inserted_order.is_empty() {
        let mut replayed_order = Vec::with_capacity(inserted_order.len() + order.len());
        replayed_order.extend(inserted_order.into_iter().rev());
        replayed_order.append(order);
        *order = replayed_order;
    }
    Ok(())
}

fn apply_nullable_string_patch(target: &mut Option<String>, patch: Option<NullableStringPatch>) {
    match patch {
        Some(NullableStringPatch::Set(value)) => *target = Some(value),
        Some(NullableStringPatch::Clear) => *target = None,
        None => {}
    }
}

fn discard_transaction_journal_checkpoint(storage_dir: &Path) -> Result<()> {
    let checkpoint_path =
        transaction_journal_checkpoint_path(&transaction_journal_path(storage_dir));
    match fs::remove_file(&checkpoint_path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| {
            format!(
                "failed to remove transaction journal checkpoint {}",
                checkpoint_path.display()
            )
        }),
    }
}

fn persist_session_snapshot(
    root_dir: &Path,
    metadata: &SessionMetadata,
    snapshot: &StoredSessionSnapshot,
) -> Result<()> {
    let storage_dir = session_dir(root_dir, metadata.id);
    fs::create_dir_all(&storage_dir).with_context(|| {
        format!(
            "failed to create session directory {}",
            storage_dir.display()
        )
    })?;
    write_json(&snapshot_path(&storage_dir), snapshot)
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create parent directory {}", parent.display()))?;
    }
    let data = serde_json::to_vec_pretty(value).context("failed to serialize JSON file")?;
    let tmp_path = path.with_extension("tmp");
    fs::write(&tmp_path, &data)
        .with_context(|| format!("failed to write {}", tmp_path.display()))?;
    fs::rename(&tmp_path, path).with_context(|| {
        format!(
            "failed to rename {} to {}",
            tmp_path.display(),
            path.display()
        )
    })
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::SessionRegistry;
    use crate::{
        model::{BodyEncoding, EditableRequest, HeaderRecord, MessageRecord, TransactionRecord},
        store::{
            transaction_journal_checkpoint_path, NullableStringPatch, TransactionJournalEntry,
        },
        workspace::{
            FuzzerWorkspaceState, ReplayHistoryEntryState, ReplayTabState, ReplayWorkspaceState,
            WorkspaceStateSnapshot,
        },
    };

    #[tokio::test]
    async fn registry_persists_created_session_and_active_context() {
        let data_dir =
            std::env::temp_dir().join(format!("sniper-session-test-{}", uuid::Uuid::new_v4()));
        let (registry, _active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();

        let created = registry.create_session(Some("Review".to_string())).unwrap();
        let active = registry.activate_session(created.id).unwrap();
        let loaded = registry.load_context(active.id).unwrap();

        assert_eq!(loaded.summary(true).name, "Review");
        assert!(registry
            .summaries()
            .iter()
            .any(|session| session.id == created.id));
    }

    #[tokio::test]
    async fn registry_persists_workspace_state() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-workspace-test-{}",
            uuid::Uuid::new_v4()
        ));
        let (registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();

        let request = EditableRequest {
            scheme: "https".to_string(),
            host: "example.com".to_string(),
            method: "POST".to_string(),
            path: "/login".to_string(),
            headers: vec![],
            body: "{\"name\":\"demo\"}".to_string(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        };

        active
            .workspace
            .replace_snapshot(WorkspaceStateSnapshot {
                replay: ReplayWorkspaceState {
                    tabs: vec![ReplayTabState {
                        id: "tab-1".to_string(),
                        sequence: 1,
                        custom_label: "Login replay".to_string(),
                        base_request: Some(request.clone()),
                        source_transaction_id: None,
                        notice: "Saved".to_string(),
                        request_text: "POST /login HTTP/1.1".to_string(),
                        response_record: None,
                        target_scheme: "https".to_string(),
                        target_host: "example.com".to_string(),
                        target_port: "443".to_string(),
                        history_entries: vec![ReplayHistoryEntryState {
                            request: request.clone(),
                            request_text: "POST /login HTTP/1.1".to_string(),
                            response_record: None,
                            notice: "Saved".to_string(),
                            target_scheme: "https".to_string(),
                            target_host: "example.com".to_string(),
                            target_port: "443".to_string(),
                        }],
                        history_index: Some(0),
                        ..Default::default()
                    }],
                    active_tab_id: Some("tab-1".to_string()),
                    tab_sequence: 1,
                },
                fuzzer: FuzzerWorkspaceState {
                    base_request: Some(request.clone()),
                    source_transaction_id: None,
                    notice: "Ready".to_string(),
                    request_text: "POST /login HTTP/1.1".to_string(),
                    payloads_text: "admin\nuser".to_string(),
                    attack_record: None,
                },
            })
            .await;

        active.persist().await.unwrap();

        let loaded = registry.load_context(active.id()).unwrap();
        let workspace = loaded.workspace.snapshot().await;
        assert_eq!(workspace.replay.tabs.len(), 1);
        assert_eq!(workspace.replay.active_tab_id.as_deref(), Some("tab-1"));
        assert_eq!(
            workspace
                .replay
                .tabs
                .first()
                .map(|tab| tab.custom_label.as_str()),
            Some("Login replay")
        );
        assert_eq!(workspace.fuzzer.notice, "Ready");
        assert_eq!(workspace.fuzzer.payloads_text, "admin\nuser");
        assert_eq!(
            workspace
                .replay
                .tabs
                .first()
                .and_then(|tab| tab.history_index),
            Some(0)
        );
        assert_eq!(
            workspace
                .replay
                .tabs
                .first()
                .and_then(|tab| tab.base_request.as_ref())
                .map(|value| value.host.as_str()),
            Some("example.com")
        );
        assert_eq!(
            workspace
                .replay
                .tabs
                .first()
                .and_then(|tab| tab.history_entries.first())
                .map(|entry| entry.target_port.as_str()),
            Some("443")
        );
    }

    #[tokio::test]
    async fn registry_persists_http_history_transactions() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-transactions-test-{}",
            uuid::Uuid::new_v4()
        ));
        let (registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();

        let request = MessageRecord {
            headers: vec![HeaderRecord {
                name: "host".to_string(),
                value: "example.com".to_string(),
            }],
            body_preview: "{\"hello\":\"world\"}".to_string(),
            body_encoding: BodyEncoding::Utf8,
            body_size: 17,
            preview_truncated: false,
            content_type: Some("application/json".to_string()),
            content_decoded: false,
        };
        let response = MessageRecord {
            headers: vec![HeaderRecord {
                name: "content-type".to_string(),
                value: "application/json".to_string(),
            }],
            body_preview: "{\"ok\":true}".to_string(),
            body_encoding: BodyEncoding::Utf8,
            body_size: 11,
            preview_truncated: false,
            content_type: Some("application/json".to_string()),
            content_decoded: false,
        };

        active
            .store
            .insert(TransactionRecord::http(
                Utc::now(),
                "POST".to_string(),
                "https".to_string(),
                "example.com:443".to_string(),
                "/api/login".to_string(),
                Some(201),
                42,
                request,
                Some(response),
                vec!["persisted".to_string()],
                None,
                None,
            ))
            .await;

        let metadata = active.persist().await.unwrap();
        registry.update_metadata(metadata).unwrap();

        let loaded = registry.load_context(active.id()).unwrap();
        let restored = loaded.store.snapshot(Some(10)).await;

        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].method, "POST");
        assert_eq!(restored[0].scheme, "https");
        assert_eq!(restored[0].host, "example.com:443");
        assert_eq!(restored[0].path, "/api/login");
        assert_eq!(restored[0].status, Some(201));
        assert_eq!(restored[0].duration_ms, 42);
        assert_eq!(
            restored[0].request.header_value("host"),
            Some("example.com")
        );
        assert_eq!(
            restored[0]
                .response
                .as_ref()
                .and_then(|message| message.header_value("content-type")),
            Some("application/json")
        );
    }

    #[tokio::test]
    async fn registry_replays_transaction_journal_entries_after_snapshot() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-journal-test-{}",
            uuid::Uuid::new_v4()
        ));
        let (registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();

        let request = MessageRecord {
            headers: vec![HeaderRecord {
                name: "host".to_string(),
                value: "journal.example".to_string(),
            }],
            body_preview: String::new(),
            body_encoding: BodyEncoding::Utf8,
            body_size: 0,
            preview_truncated: false,
            content_type: None,
            content_decoded: false,
        };
        let record = TransactionRecord::http(
            Utc::now(),
            "GET".to_string(),
            "https".to_string(),
            "journal.example:443".to_string(),
            "/from-journal".to_string(),
            Some(200),
            7,
            request,
            None,
            vec!["journaled".to_string()],
            None,
            None,
        );
        let record_id = record.id;

        let storage_dir = registry.session_storage_path(active.id()).unwrap();
        let journal_path = super::transaction_journal_path(&storage_dir);
        let mut lines = Vec::new();
        serde_json::to_writer(&mut lines, &TransactionJournalEntry::Insert { record }).unwrap();
        lines.push(b'\n');
        serde_json::to_writer(
            &mut lines,
            &TransactionJournalEntry::Annotation {
                id: record_id,
                color_tag: Some(NullableStringPatch::Set("red".to_string())),
                user_note: Some(NullableStringPatch::Set("remember me".to_string())),
            },
        )
        .unwrap();
        lines.push(b'\n');
        std::fs::write(journal_path, lines).unwrap();

        let loaded = registry.load_context(active.id()).unwrap();
        let restored = loaded.store.snapshot(Some(10)).await;

        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].method, "GET");
        assert_eq!(restored[0].host, "journal.example:443");
        assert_eq!(restored[0].path, "/from-journal");
        assert_eq!(restored[0].notes, vec!["journaled".to_string()]);
        assert_eq!(restored[0].color_tag.as_deref(), Some("red"));
        assert_eq!(restored[0].user_note.as_deref(), Some("remember me"));
    }

    #[tokio::test]
    async fn registry_ignores_trailing_partial_transaction_journal_line() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-journal-partial-test-{}",
            uuid::Uuid::new_v4()
        ));
        let (registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();

        let request = MessageRecord {
            headers: vec![HeaderRecord {
                name: "host".to_string(),
                value: "partial.example".to_string(),
            }],
            body_preview: String::new(),
            body_encoding: BodyEncoding::Utf8,
            body_size: 0,
            preview_truncated: false,
            content_type: None,
            content_decoded: false,
        };
        let record = TransactionRecord::http(
            Utc::now(),
            "GET".to_string(),
            "https".to_string(),
            "partial.example:443".to_string(),
            "/before-partial".to_string(),
            Some(200),
            5,
            request,
            None,
            vec![],
            None,
            None,
        );

        let storage_dir = registry.session_storage_path(active.id()).unwrap();
        let journal_path = super::transaction_journal_path(&storage_dir);
        let mut lines = Vec::new();
        serde_json::to_writer(&mut lines, &TransactionJournalEntry::Insert { record }).unwrap();
        lines.push(b'\n');
        lines.extend_from_slice(br#"{"type":"insert""#);
        std::fs::write(journal_path, lines).unwrap();

        let loaded = registry.load_context(active.id()).unwrap();
        let restored = loaded.store.snapshot(Some(10)).await;

        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].host, "partial.example:443");
        assert_eq!(restored[0].path, "/before-partial");
    }

    #[tokio::test]
    async fn registry_replays_transaction_journal_checkpoint_before_active_journal() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-journal-checkpoint-test-{}",
            uuid::Uuid::new_v4()
        ));
        let (registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();

        let old_record = TransactionRecord::http(
            Utc::now(),
            "GET".to_string(),
            "https".to_string(),
            "checkpoint.example:443".to_string(),
            "/checkpoint".to_string(),
            Some(200),
            1,
            MessageRecord {
                headers: vec![],
                body_preview: String::new(),
                body_encoding: BodyEncoding::Utf8,
                body_size: 0,
                preview_truncated: false,
                content_type: None,
                content_decoded: false,
            },
            None,
            vec![],
            None,
            None,
        );
        let new_record = TransactionRecord::http(
            Utc::now(),
            "GET".to_string(),
            "https".to_string(),
            "active.example:443".to_string(),
            "/active".to_string(),
            Some(200),
            1,
            MessageRecord {
                headers: vec![],
                body_preview: String::new(),
                body_encoding: BodyEncoding::Utf8,
                body_size: 0,
                preview_truncated: false,
                content_type: None,
                content_decoded: false,
            },
            None,
            vec![],
            None,
            None,
        );

        let storage_dir = registry.session_storage_path(active.id()).unwrap();
        let journal_path = super::transaction_journal_path(&storage_dir);
        let checkpoint_path = transaction_journal_checkpoint_path(&journal_path);

        let mut checkpoint = Vec::new();
        serde_json::to_writer(
            &mut checkpoint,
            &TransactionJournalEntry::Insert { record: old_record },
        )
        .unwrap();
        checkpoint.push(b'\n');
        std::fs::write(checkpoint_path, checkpoint).unwrap();

        let mut active_journal = Vec::new();
        serde_json::to_writer(
            &mut active_journal,
            &TransactionJournalEntry::Insert { record: new_record },
        )
        .unwrap();
        active_journal.push(b'\n');
        std::fs::write(journal_path, active_journal).unwrap();

        let loaded = registry.load_context(active.id()).unwrap();
        let restored = loaded.store.snapshot(Some(10)).await;

        assert_eq!(restored.len(), 2);
        assert_eq!(restored[0].host, "active.example:443");
        assert_eq!(restored[1].host, "checkpoint.example:443");
    }

    #[tokio::test]
    async fn registry_ignores_old_journal_entries_already_trimmed_from_snapshot() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-journal-trim-test-{}",
            uuid::Uuid::new_v4()
        ));
        let (registry, active) = SessionRegistry::load_or_create(&data_dir, 2, 32).unwrap();

        let mut records = Vec::new();
        for sequence in 1..=4 {
            let mut record = TransactionRecord::http(
                Utc::now(),
                "GET".to_string(),
                "https".to_string(),
                format!("{sequence}.example:443"),
                format!("/{sequence}"),
                Some(200),
                1,
                MessageRecord {
                    headers: vec![],
                    body_preview: String::new(),
                    body_encoding: BodyEncoding::Utf8,
                    body_size: 0,
                    preview_truncated: false,
                    content_type: None,
                    content_decoded: false,
                },
                None,
                vec![],
                None,
                None,
            );
            record.sequence = sequence;
            records.push(record);
        }

        let storage_dir = registry.session_storage_path(active.id()).unwrap();
        let snapshot = super::StoredSessionSnapshot {
            transactions: vec![records[3].clone(), records[2].clone()],
            ..Default::default()
        };
        super::write_json(&super::snapshot_path(&storage_dir), &snapshot).unwrap();

        let journal_path = super::transaction_journal_path(&storage_dir);
        let mut journal = Vec::new();
        for record in records {
            serde_json::to_writer(&mut journal, &TransactionJournalEntry::Insert { record })
                .unwrap();
            journal.push(b'\n');
        }
        std::fs::write(journal_path, journal).unwrap();

        let loaded = registry.load_context(active.id()).unwrap();
        let restored = loaded.store.snapshot(Some(10)).await;

        assert_eq!(restored.len(), 2);
        assert_eq!(restored[0].host, "4.example:443");
        assert_eq!(restored[1].host, "3.example:443");
    }

    #[tokio::test]
    async fn registry_persist_compacts_transaction_journal_after_snapshot() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-session-journal-compact-test-{}",
            uuid::Uuid::new_v4()
        ));
        let (registry, active) = SessionRegistry::load_or_create(&data_dir, 32, 32).unwrap();

        active
            .store
            .insert(TransactionRecord::http(
                Utc::now(),
                "GET".to_string(),
                "https".to_string(),
                "compact.example:443".to_string(),
                "/compact".to_string(),
                Some(200),
                1,
                MessageRecord {
                    headers: vec![],
                    body_preview: String::new(),
                    body_encoding: BodyEncoding::Utf8,
                    body_size: 0,
                    preview_truncated: false,
                    content_type: None,
                    content_decoded: false,
                },
                None,
                vec![],
                None,
                None,
            ))
            .await;

        active.persist().await.unwrap();

        let storage_dir = registry.session_storage_path(active.id()).unwrap();
        let journal_path = super::transaction_journal_path(&storage_dir);
        let checkpoint_path = transaction_journal_checkpoint_path(&journal_path);
        let journal_len = std::fs::metadata(&journal_path)
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        assert_eq!(journal_len, 0);
        assert!(!checkpoint_path.exists());

        let loaded = registry.load_context(active.id()).unwrap();
        let restored = loaded.store.snapshot(Some(10)).await;
        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].host, "compact.example:443");
    }
}
