use std::{
    collections::{HashMap, VecDeque},
    error::Error as StdError,
    fmt,
    sync::Arc,
};

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::{
    event_log::{EventLevel, EventLogEntry},
    model::{EditableRequest, RequestTargetOverride},
    proxy,
    session::SessionContext,
    state::AppState,
};

#[derive(Debug)]
pub struct SequencePersistenceError {
    source: anyhow::Error,
}

impl SequencePersistenceError {
    pub(crate) fn new(source: anyhow::Error) -> Self {
        Self { source }
    }
}

impl fmt::Display for SequencePersistenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "failed to persist sequence run")
    }
}

impl StdError for SequencePersistenceError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(self.source.as_ref())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtractionSource {
    ResponseBody,
    ResponseHeader,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtractionRule {
    pub variable_name: String,
    pub source: ExtractionSource,
    pub pattern: String,
    #[serde(default = "default_group")]
    pub group: usize,
}

fn default_group() -> usize {
    1
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SequenceStep {
    pub id: Uuid,
    pub label: String,
    pub request: EditableRequest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_transaction_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<RequestTargetOverride>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_parse_error: Option<String>,
    #[serde(default)]
    pub extractions: Vec<ExtractionRule>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SequenceDefinition {
    pub id: Uuid,
    pub name: String,
    #[serde(default)]
    pub steps: Vec<SequenceStep>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SequenceRunStatus {
    Completed,
    Failed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StepResult {
    pub step_id: Uuid,
    pub label: String,
    pub transaction_id: Option<Uuid>,
    pub status: Option<u16>,
    pub duration_ms: Option<u64>,
    #[serde(default)]
    pub extracted: HashMap<String, String>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SequenceRunRecord {
    pub id: Uuid,
    pub sequence_id: Uuid,
    pub sequence_name: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub status: SequenceRunStatus,
    #[serde(default)]
    pub step_results: Vec<StepResult>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SequenceRunSummary {
    pub id: Uuid,
    pub sequence_id: Uuid,
    pub sequence_name: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub status: SequenceRunStatus,
    pub step_count: usize,
}

impl SequenceRunRecord {
    pub fn summary(&self) -> SequenceRunSummary {
        SequenceRunSummary {
            id: self.id,
            sequence_id: self.sequence_id,
            sequence_name: self.sequence_name.clone(),
            started_at: self.started_at,
            completed_at: self.completed_at,
            status: self.status.clone(),
            step_count: self.step_results.len(),
        }
    }
}

pub struct SequenceStore {
    max_entries: usize,
    definitions: RwLock<Vec<SequenceDefinition>>,
    runs: RwLock<VecDeque<SequenceRunRecord>>,
}

impl SequenceStore {
    pub fn new(max_entries: usize) -> Self {
        Self {
            max_entries,
            definitions: RwLock::new(Vec::new()),
            runs: RwLock::new(VecDeque::new()),
        }
    }

    pub fn from_data(
        max_entries: usize,
        definitions: Vec<SequenceDefinition>,
        runs: Vec<SequenceRunRecord>,
    ) -> Self {
        let mut run_deque = VecDeque::with_capacity(runs.len().min(max_entries));
        run_deque.extend(runs.into_iter().take(max_entries));
        Self {
            max_entries,
            definitions: RwLock::new(definitions),
            runs: RwLock::new(run_deque),
        }
    }

    pub async fn list_definitions(&self) -> Vec<SequenceDefinition> {
        self.definitions.read().await.clone()
    }

    pub async fn get_definition(&self, id: Uuid) -> Option<SequenceDefinition> {
        self.definitions
            .read()
            .await
            .iter()
            .find(|d| d.id == id)
            .cloned()
    }

    pub async fn upsert_definition(&self, def: SequenceDefinition) {
        let mut defs = self.definitions.write().await;
        if let Some(existing) = defs.iter_mut().find(|d| d.id == def.id) {
            *existing = def;
        } else {
            defs.push(def);
        }
    }

    pub async fn replace_definitions(&self, definitions: Vec<SequenceDefinition>) {
        *self.definitions.write().await = definitions;
    }

    pub async fn delete_definition(&self, id: Uuid) -> bool {
        let mut defs = self.definitions.write().await;
        let before = defs.len();
        defs.retain(|d| d.id != id);
        defs.len() < before
    }

    pub async fn insert_run(&self, record: SequenceRunRecord) -> Vec<SequenceRunRecord> {
        let mut runs = self.runs.write().await;
        runs.push_front(record);
        let mut evicted = Vec::new();
        while runs.len() > self.max_entries {
            if let Some(record) = runs.pop_back() {
                evicted.push(record);
            }
        }
        evicted
    }

    pub async fn replace_runs(&self, runs: Vec<SequenceRunRecord>) {
        let mut current = self.runs.write().await;
        current.clear();
        current.extend(runs.into_iter().take(self.max_entries));
    }

    pub async fn remove_run_and_restore(&self, id: Uuid, restore: Vec<SequenceRunRecord>) -> bool {
        let mut runs = self.runs.write().await;
        let before = runs.len();
        runs.retain(|run| run.id != id);
        let removed = runs.len() < before;
        if removed {
            for record in restore {
                if runs.len() >= self.max_entries {
                    break;
                }
                runs.push_back(record);
            }
        }
        removed
    }

    pub async fn list_runs(&self, limit: Option<usize>) -> Vec<SequenceRunSummary> {
        self.runs
            .read()
            .await
            .iter()
            .take(limit.unwrap_or(self.max_entries).min(self.max_entries))
            .map(SequenceRunRecord::summary)
            .collect()
    }

    pub async fn get_run(&self, id: Uuid) -> Option<SequenceRunRecord> {
        self.runs.read().await.iter().find(|r| r.id == id).cloned()
    }

    pub async fn snapshot_definitions(&self) -> Vec<SequenceDefinition> {
        self.definitions.read().await.clone()
    }

    pub async fn snapshot_runs(&self, limit: Option<usize>) -> Vec<SequenceRunRecord> {
        self.runs
            .read()
            .await
            .iter()
            .take(limit.unwrap_or(self.max_entries).min(self.max_entries))
            .cloned()
            .collect()
    }
}

fn substitute_variables(text: &str, variables: &HashMap<String, String>) -> String {
    let mut result = text.to_string();
    for (name, value) in variables {
        result = result.replace(&format!("{{{{{name}}}}}"), value);
    }
    result
}

fn apply_variables_to_request(
    request: &EditableRequest,
    variables: &HashMap<String, String>,
) -> EditableRequest {
    let mut applied = EditableRequest {
        scheme: request.scheme.clone(),
        host: substitute_variables(&request.host, variables),
        method: request.method.clone(),
        path: substitute_variables(&request.path, variables),
        headers: request
            .headers
            .iter()
            .map(|h| crate::model::HeaderRecord {
                name: h.name.clone(),
                value: substitute_variables(&h.value, variables),
            })
            .collect(),
        body: substitute_variables(&request.body, variables),
        body_encoding: request.body_encoding.clone(),
        preview_truncated: request.preview_truncated,
    };
    if let Some(host) = applied
        .headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("host"))
        .map(|header| header.value.clone())
    {
        applied.host = host;
    }
    applied
}

fn extract_from_response(
    rules: &[ExtractionRule],
    response_body: &str,
    response_headers: &[crate::model::HeaderRecord],
    response_preview_truncated: bool,
) -> Result<HashMap<String, String>> {
    let mut extracted = HashMap::new();
    for rule in rules {
        if matches!(rule.source, ExtractionSource::ResponseBody) && response_preview_truncated {
            return Err(anyhow!(
                "Extraction {} cannot read response body because the captured response preview is truncated",
                rule.variable_name
            ));
        }
        let source_text = match rule.source {
            ExtractionSource::ResponseBody => response_body.to_string(),
            ExtractionSource::ResponseHeader => response_headers
                .iter()
                .find(|h| h.name.eq_ignore_ascii_case(&rule.pattern))
                .map(|h| h.value.clone())
                .ok_or_else(|| {
                    anyhow!(
                        "Extraction {} could not find response header {}",
                        rule.variable_name,
                        rule.pattern
                    )
                })?,
        };

        let value = match rule.source {
            ExtractionSource::ResponseHeader => source_text,
            ExtractionSource::ResponseBody => {
                let regex = Regex::new(&rule.pattern).map_err(|error| {
                    anyhow!(
                        "Extraction {} has invalid regex {}: {}",
                        rule.variable_name,
                        rule.pattern,
                        error
                    )
                })?;
                regex
                    .captures(&source_text)
                    .and_then(|caps| caps.get(rule.group).map(|m| m.as_str().to_string()))
                    .ok_or_else(|| {
                        anyhow!(
                            "Extraction {} did not match response body",
                            rule.variable_name
                        )
                    })?
            }
        };

        if value.is_empty() {
            return Err(anyhow!(
                "Extraction {} produced an empty value",
                rule.variable_name
            ));
        }
        extracted.insert(rule.variable_name.clone(), value);
    }
    Ok(extracted)
}

pub async fn run_sequence(
    state: Arc<AppState>,
    session: Arc<SessionContext>,
    definition: SequenceDefinition,
) -> Result<SequenceRunRecord> {
    if definition.steps.is_empty() {
        return Err(anyhow!("Sequence has no steps"));
    }
    ensure_sequence_requests_are_runnable(&definition)?;

    let started_at = Utc::now();
    let mut variables: HashMap<String, String> = HashMap::new();
    let mut step_results = Vec::with_capacity(definition.steps.len());
    let mut failed = false;

    let (started_event, started_evicted_events) = session
        .event_log
        .push_with_evicted(
            EventLevel::Info,
            "sequence",
            "Sequence started",
            format!(
                "Running \"{}\" with {} step(s)",
                definition.name,
                definition.steps.len()
            ),
        )
        .await;

    for step in &definition.steps {
        let request = apply_variables_to_request(&step.request, &variables);

        match proxy::try_send_replay_request_for_session(
            state.clone(),
            session.clone(),
            request,
            step.target.clone(),
            step.source_transaction_id,
            step.http_version.clone(),
        )
        .await
        {
            Ok(record) => {
                let response_body = record
                    .response
                    .as_ref()
                    .map(|r| {
                        if r.body_encoding == crate::model::BodyEncoding::Utf8 {
                            r.body_preview.clone()
                        } else {
                            String::new()
                        }
                    })
                    .unwrap_or_default();
                let response_headers = record
                    .response
                    .as_ref()
                    .map(|r| r.headers.clone())
                    .unwrap_or_default();
                let response_preview_truncated = record
                    .response
                    .as_ref()
                    .is_some_and(|r| r.preview_truncated);
                match extract_from_response(
                    &step.extractions,
                    &response_body,
                    &response_headers,
                    response_preview_truncated,
                ) {
                    Ok(extracted) => {
                        variables.extend(extracted.clone());

                        step_results.push(StepResult {
                            step_id: step.id,
                            label: step.label.clone(),
                            transaction_id: Some(record.id),
                            status: record.status,
                            duration_ms: Some(record.duration_ms),
                            extracted,
                            error: None,
                        });
                    }
                    Err(error) => {
                        step_results.push(StepResult {
                            step_id: step.id,
                            label: step.label.clone(),
                            transaction_id: Some(record.id),
                            status: record.status,
                            duration_ms: Some(record.duration_ms),
                            extracted: HashMap::new(),
                            error: Some(error.to_string()),
                        });
                        failed = true;
                        break;
                    }
                }
            }
            Err(error) => {
                let record = error.record();
                step_results.push(StepResult {
                    step_id: step.id,
                    label: step.label.clone(),
                    transaction_id: record.map(|record| record.id),
                    status: record.and_then(|record| record.status),
                    duration_ms: record.map(|record| record.duration_ms),
                    extracted: HashMap::new(),
                    error: Some(error.to_string()),
                });
                failed = true;
                break;
            }
        }
    }

    let completed_at = Utc::now();
    let status = if failed {
        SequenceRunStatus::Failed
    } else {
        SequenceRunStatus::Completed
    };

    let record = SequenceRunRecord {
        id: Uuid::new_v4(),
        sequence_id: definition.id,
        sequence_name: definition.name.clone(),
        started_at,
        completed_at,
        status,
        step_results,
    };

    let _mutation_guard = session.mutation_guard().await;
    let (completed_event, evicted_events) = session
        .event_log
        .push_with_evicted(
            EventLevel::Info,
            "sequence",
            "Sequence completed",
            format!(
                "\"{}\" finished with status {:?} ({}/{} steps)",
                definition.name,
                record.status,
                record.step_results.len(),
                definition.steps.len()
            ),
        )
        .await;
    let evicted_runs = session.sequence.insert_run(record.clone()).await;
    if let Err(error) = state
        .persist_session_context_mutation_locked(&session)
        .await
    {
        rollback_failed_sequence_persist(
            &session,
            record.id,
            evicted_runs,
            completed_event.id,
            evicted_events,
            started_event.id,
            started_evicted_events,
        )
        .await;
        if let Err(rollback_error) = state
            .persist_session_context_mutation_locked(&session)
            .await
        {
            tracing::warn!(
                ?rollback_error,
                session_id = %session.id(),
                "failed to persist rolled back sequence state after run persist failure"
            );
        }
        return Err(SequencePersistenceError::new(error).into());
    }

    Ok(record)
}

async fn rollback_failed_sequence_persist(
    session: &Arc<SessionContext>,
    run_id: Uuid,
    evicted_runs: Vec<SequenceRunRecord>,
    completed_event_id: Uuid,
    evicted_events: Vec<EventLogEntry>,
    started_event_id: Uuid,
    started_evicted_events: Vec<EventLogEntry>,
) {
    session
        .sequence
        .remove_run_and_restore(run_id, evicted_runs)
        .await;
    session
        .event_log
        .remove_and_restore(completed_event_id, evicted_events)
        .await;
    session
        .event_log
        .remove_and_restore(started_event_id, started_evicted_events)
        .await;
}

fn ensure_sequence_requests_are_runnable(definition: &SequenceDefinition) -> Result<()> {
    for step in &definition.steps {
        if let Some(error) = step
            .request_parse_error
            .as_deref()
            .map(str::trim)
            .filter(|error| !error.is_empty())
        {
            return Err(anyhow!(
                "Sequence step {} has an invalid request draft: {error}",
                step.label
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::AppConfig,
        model::{BodyEncoding, HeaderRecord},
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    #[test]
    fn sequence_definition_accepts_legacy_missing_steps() {
        let definition: SequenceDefinition = serde_json::from_value(serde_json::json!({
            "id": "00000000-0000-0000-0000-000000000101",
            "name": "Legacy sequence"
        }))
        .expect("legacy sequence definition should deserialize");

        assert!(definition.steps.is_empty());
    }

    #[test]
    fn sequence_step_preserves_raw_request_draft_fields() {
        let definition: SequenceDefinition = serde_json::from_value(serde_json::json!({
            "id": "00000000-0000-0000-0000-000000000111",
            "name": "Draft sequence",
            "steps": [{
                "id": "00000000-0000-0000-0000-000000000112",
                "label": "draft",
                "request": {
                    "scheme": "https",
                    "host": "example.test",
                    "method": "GET",
                    "path": "/",
                    "headers": [],
                    "body": "",
                    "body_encoding": "utf8",
                    "preview_truncated": false
                },
                "request_text": "GET http://example.test/raw HTTP/2\nHost: example.test\nX-Bad-Header",
                "request_parse_error": "Invalid header line: X-Bad-Header"
            }]
        }))
        .expect("sequence draft fields should deserialize");

        let step = &definition.steps[0];
        assert_eq!(
            step.request_text.as_deref(),
            Some("GET http://example.test/raw HTTP/2\nHost: example.test\nX-Bad-Header")
        );
        assert_eq!(
            step.request_parse_error.as_deref(),
            Some("Invalid header line: X-Bad-Header")
        );

        let serialized = serde_json::to_value(&definition).unwrap();
        assert_eq!(
            serialized["steps"][0]["request_text"],
            "GET http://example.test/raw HTTP/2\nHost: example.test\nX-Bad-Header"
        );
    }

    #[test]
    fn runnable_sequence_rejects_invalid_request_draft() {
        let definition: SequenceDefinition = serde_json::from_value(serde_json::json!({
            "id": "00000000-0000-0000-0000-000000000121",
            "name": "Draft sequence",
            "steps": [{
                "id": "00000000-0000-0000-0000-000000000122",
                "label": "draft",
                "request": {
                    "scheme": "https",
                    "host": "example.test",
                    "method": "GET",
                    "path": "/previous",
                    "headers": [],
                    "body": "",
                    "body_encoding": "utf8",
                    "preview_truncated": false
                },
                "request_text": "GET /new HTTP/1.1\nHost: example.test\nX-Bad-Header",
                "request_parse_error": "Invalid header line: X-Bad-Header"
            }]
        }))
        .expect("sequence should deserialize");

        let error = ensure_sequence_requests_are_runnable(&definition).unwrap_err();
        assert!(error.to_string().contains("invalid request draft"));
    }

    #[test]
    fn sequence_variable_host_header_updates_request_authority() {
        let request = EditableRequest {
            scheme: "https".to_string(),
            host: "old.example".to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            headers: vec![HeaderRecord {
                name: "Host".to_string(),
                value: "{{host}}".to_string(),
            }],
            body: String::new(),
            body_encoding: crate::model::BodyEncoding::Utf8,
            preview_truncated: false,
        };
        let variables = HashMap::from([("host".to_string(), "new.example".to_string())]);

        let applied = apply_variables_to_request(&request, &variables);

        assert_eq!(applied.host, "new.example");
        assert_eq!(
            applied.headers.first().map(|header| header.value.as_str()),
            Some("new.example")
        );
    }

    #[test]
    fn sequence_run_record_accepts_legacy_missing_step_results() {
        let run: SequenceRunRecord = serde_json::from_value(serde_json::json!({
            "id": "00000000-0000-0000-0000-000000000201",
            "sequence_id": "00000000-0000-0000-0000-000000000202",
            "sequence_name": "Legacy sequence",
            "started_at": "2026-01-01T00:00:00Z",
            "completed_at": "2026-01-01T00:00:01Z",
            "status": "completed"
        }))
        .expect("legacy sequence run should deserialize");

        assert!(run.step_results.is_empty());
        assert_eq!(run.summary().step_count, 0);
    }

    #[tokio::test]
    async fn from_data_does_not_preallocate_full_retention_for_empty_restore() {
        let store = SequenceStore::from_data(500_000, Vec::new(), Vec::new());

        assert_eq!(store.runs.read().await.capacity(), 0);
    }

    #[test]
    fn step_result_accepts_legacy_missing_extracted_map() {
        let result: StepResult = serde_json::from_value(serde_json::json!({
            "step_id": "00000000-0000-0000-0000-000000000301",
            "label": "Login",
            "status": 200
        }))
        .expect("legacy step result should deserialize");

        assert!(result.extracted.is_empty());
        assert_eq!(result.status, Some(200));
    }

    #[test]
    fn response_body_extraction_requires_a_match() {
        let rules = vec![ExtractionRule {
            variable_name: "token".to_string(),
            source: ExtractionSource::ResponseBody,
            pattern: "csrf=([a-z]+)".to_string(),
            group: 1,
        }];

        let extracted = extract_from_response(&rules, "csrf=abc", &[], false).unwrap();
        assert_eq!(extracted.get("token").map(String::as_str), Some("abc"));

        let error = extract_from_response(&rules, "no token here", &[], false).unwrap_err();
        assert!(error.to_string().contains("did not match response body"));
    }

    #[test]
    fn response_body_extraction_fails_on_truncated_preview() {
        let rules = vec![ExtractionRule {
            variable_name: "token".to_string(),
            source: ExtractionSource::ResponseBody,
            pattern: "csrf=([a-z]+)".to_string(),
            group: 1,
        }];

        let error = extract_from_response(&rules, "csrf=abc", &[], true).unwrap_err();

        assert!(error.to_string().contains("response preview is truncated"));
    }

    #[test]
    fn response_header_extraction_requires_header() {
        let rules = vec![ExtractionRule {
            variable_name: "session".to_string(),
            source: ExtractionSource::ResponseHeader,
            pattern: "x-session".to_string(),
            group: 1,
        }];
        let headers = vec![HeaderRecord {
            name: "X-Session".to_string(),
            value: "abc".to_string(),
        }];

        let extracted = extract_from_response(&rules, "", &headers, false).unwrap();
        assert_eq!(extracted.get("session").map(String::as_str), Some("abc"));

        let error = extract_from_response(&rules, "", &[], false).unwrap_err();
        assert!(error.to_string().contains("could not find response header"));
    }

    #[tokio::test]
    async fn forced_http2_failure_step_keeps_history_transaction_id() {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_handle = tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.unwrap();
            let mut buffer = [0u8; 1024];
            let _ = stream.read(&mut buffer).await.unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                .await
                .unwrap();
        });

        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 32,
            body_preview_bytes: 4096,
            data_dir: std::env::temp_dir()
                .join(format!("sniper-sequence-http2-failure-{}", Uuid::new_v4())),
        };
        let data_dir = config.data_dir.clone();
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let request = EditableRequest {
            scheme: "http".to_string(),
            host: upstream_addr.to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            headers: Vec::new(),
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        };
        let definition = SequenceDefinition {
            id: Uuid::new_v4(),
            name: "HTTP2 mismatch".to_string(),
            steps: vec![SequenceStep {
                id: Uuid::new_v4(),
                label: "forced h2".to_string(),
                request,
                source_transaction_id: None,
                http_version: Some("HTTP/2".to_string()),
                target: None,
                request_text: None,
                request_parse_error: None,
                extractions: Vec::new(),
            }],
        };

        let run = run_sequence(state, session.clone(), definition)
            .await
            .unwrap();
        assert_eq!(run.status, SequenceRunStatus::Failed);
        let step = run.step_results.first().unwrap();
        let transaction_id = step
            .transaction_id
            .expect("failed replay step should keep transaction id");
        assert_eq!(step.status, Some(502));
        assert!(step.error.as_deref().unwrap_or_default().contains("HTTP/2"));

        let records = session.store.snapshot(Some(10)).await;
        assert!(records.iter().any(|record| record.id == transaction_id));

        upstream_handle.abort();
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn upstream_connection_failure_marks_sequence_step_failed_with_transaction_record() {
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 32,
            body_preview_bytes: 4096,
            data_dir: std::env::temp_dir().join(format!(
                "sniper-sequence-upstream-failure-{}",
                Uuid::new_v4()
            )),
        };
        let data_dir = config.data_dir.clone();
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let request = EditableRequest {
            scheme: "http".to_string(),
            host: "127.0.0.1:1".to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            headers: Vec::new(),
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        };
        let definition = SequenceDefinition {
            id: Uuid::new_v4(),
            name: "Upstream failure".to_string(),
            steps: vec![SequenceStep {
                id: Uuid::new_v4(),
                label: "connection refused".to_string(),
                request,
                source_transaction_id: None,
                http_version: None,
                target: None,
                request_text: None,
                request_parse_error: None,
                extractions: Vec::new(),
            }],
        };

        let run = run_sequence(state, session.clone(), definition)
            .await
            .unwrap();

        assert_eq!(run.status, SequenceRunStatus::Failed);
        let step = run.step_results.first().unwrap();
        let transaction_id = step
            .transaction_id
            .expect("failed replay step should keep transaction id");
        assert_eq!(step.status, Some(502));
        assert!(step
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("Upstream request failed"));

        let records = session.store.snapshot(Some(10)).await;
        assert!(records.iter().any(|record| record.id == transaction_id));

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn registry_metadata_failure_persists_rolled_back_sequence_snapshot() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-sequence-registry-rollback-{}",
            Uuid::new_v4()
        ));
        let state = Arc::new(
            AppState::new(AppConfig {
                proxy_addr: "127.0.0.1:0".parse().unwrap(),
                ui_addr: "127.0.0.1:0".parse().unwrap(),
                max_entries: 32,
                body_preview_bytes: 4096,
                data_dir: data_dir.clone(),
            })
            .unwrap(),
        );
        let session = state.session().await;
        let request = EditableRequest {
            scheme: "http".to_string(),
            host: "127.0.0.1:1".to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            headers: Vec::new(),
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        };
        let definition = SequenceDefinition {
            id: Uuid::new_v4(),
            name: "Registry rollback".to_string(),
            steps: vec![SequenceStep {
                id: Uuid::new_v4(),
                label: "connection refused".to_string(),
                request,
                source_transaction_id: None,
                http_version: None,
                target: None,
                request_text: None,
                request_parse_error: None,
                extractions: Vec::new(),
            }],
        };
        let registry_path = session
            .storage_dir()
            .parent()
            .expect("session dir should have registry parent")
            .join("registry.json");
        std::fs::remove_file(&registry_path).unwrap();
        std::fs::create_dir(&registry_path).unwrap();

        let error = run_sequence(state.clone(), session.clone(), definition)
            .await
            .unwrap_err();

        assert!(error.to_string().contains("failed to persist sequence run"));
        assert!(session.sequence.snapshot_runs(None).await.is_empty());
        assert!(session
            .event_log
            .snapshot(None)
            .await
            .iter()
            .all(|entry| entry.source != "sequence"));

        let reloaded = state.sessions.load_context(session.id()).unwrap();
        assert!(reloaded.sequence.snapshot_runs(None).await.is_empty());
        assert!(reloaded
            .event_log
            .snapshot(None)
            .await
            .iter()
            .all(|entry| entry.source != "sequence"));

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn sequence_store_remove_and_restore_recovers_evicted_run() {
        fn run(id: &str) -> SequenceRunRecord {
            SequenceRunRecord {
                id: Uuid::parse_str(id).unwrap(),
                sequence_id: Uuid::parse_str("00000000-0000-0000-0000-000000000401").unwrap(),
                sequence_name: "Smoke".to_string(),
                started_at: Utc::now(),
                completed_at: Utc::now(),
                status: SequenceRunStatus::Completed,
                step_results: Vec::new(),
            }
        }

        let store = SequenceStore::new(1);
        let old = run("00000000-0000-0000-0000-000000000411");
        let new = run("00000000-0000-0000-0000-000000000412");

        assert!(store.insert_run(old.clone()).await.is_empty());
        let evicted = store.insert_run(new.clone()).await;
        assert_eq!(
            evicted.iter().map(|run| run.id).collect::<Vec<_>>(),
            vec![old.id]
        );

        assert!(store.remove_run_and_restore(new.id, evicted).await);
        assert_eq!(store.get_run(old.id).await.map(|run| run.id), Some(old.id));
        assert!(store.get_run(new.id).await.is_none());
    }
}
