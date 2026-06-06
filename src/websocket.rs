use std::{
    cmp::Ordering,
    collections::{HashMap, VecDeque},
};

use chrono::{DateTime, Utc};
use tokio::sync::{broadcast, RwLock};
use uuid::Uuid;

use crate::model::{
    MessageRecord, WebSocketFrameRecord, WebSocketSessionRecord, WebSocketSessionSummary,
};

const MAX_WEBSOCKET_BROADCAST_CAPACITY: usize = 4096;

pub struct WebSocketStore {
    max_entries: usize,
    max_frames_per_session: usize,
    inner: RwLock<WebSocketStoreInner>,
    events: broadcast::Sender<WebSocketSessionSummary>,
}

struct WebSocketStoreInner {
    order: VecDeque<Uuid>,
    sessions: HashMap<Uuid, WebSocketSessionEntry>,
}

impl WebSocketStoreInner {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            order: VecDeque::with_capacity(capacity),
            sessions: HashMap::with_capacity(capacity),
        }
    }
}

#[derive(Clone)]
struct WebSocketSessionEntry {
    id: Uuid,
    started_at: DateTime<Utc>,
    closed_at: Option<DateTime<Utc>>,
    duration_ms: Option<u64>,
    scheme: String,
    host: String,
    path: String,
    status: Option<u16>,
    request: MessageRecord,
    response: Option<MessageRecord>,
    frames: VecDeque<WebSocketFrameRecord>,
    notes: Vec<String>,
}

impl From<WebSocketSessionRecord> for WebSocketSessionEntry {
    fn from(record: WebSocketSessionRecord) -> Self {
        Self {
            id: record.id,
            started_at: record.started_at,
            closed_at: record.closed_at,
            duration_ms: record.duration_ms,
            scheme: record.scheme,
            host: record.host,
            path: record.path,
            status: record.status,
            request: record.request,
            response: record.response,
            frames: VecDeque::from(record.frames),
            notes: record.notes,
        }
    }
}

impl WebSocketSessionEntry {
    fn summary(&self) -> WebSocketSessionSummary {
        WebSocketSessionSummary {
            id: self.id,
            started_at: self.started_at,
            closed_at: self.closed_at,
            duration_ms: self.duration_ms,
            scheme: self.scheme.clone(),
            host: self.host.clone(),
            path: self.path.clone(),
            status: self.status,
            frame_count: self.frames.len(),
            last_frame_index: self.frames.back().map(|frame| frame.index),
            note_count: self.notes.len(),
        }
    }

    fn to_record(&self) -> WebSocketSessionRecord {
        self.to_record_with_frame_window(None)
    }

    fn to_record_with_frame_window(&self, frame_limit: Option<usize>) -> WebSocketSessionRecord {
        let frames = frame_window(&self.frames, frame_limit);

        WebSocketSessionRecord {
            id: self.id,
            started_at: self.started_at,
            closed_at: self.closed_at,
            duration_ms: self.duration_ms,
            scheme: self.scheme.clone(),
            host: self.host.clone(),
            path: self.path.clone(),
            status: self.status,
            request: self.request.clone(),
            response: self.response.clone(),
            frames,
            notes: self.notes.clone(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct WebSocketListPage {
    pub items: Vec<WebSocketSessionSummary>,
    pub total: usize,
    pub filtered_total: Option<usize>,
    pub offset: usize,
    pub limit: usize,
    pub has_more: bool,
}

#[derive(Clone, Debug, Default)]
pub struct WebSocketListFilters {
    pub query: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    pub sort_key: Option<String>,
    pub sort_direction: Option<String>,
    pub scope_patterns: Vec<String>,
    pub in_scope_only: bool,
    pub live_only: bool,
}

impl WebSocketStore {
    pub fn new(max_entries: usize, max_frames_per_session: usize) -> Self {
        Self::from_sessions(max_entries, max_frames_per_session, Vec::new())
    }

    pub fn from_sessions(
        max_entries: usize,
        max_frames_per_session: usize,
        records: Vec<WebSocketSessionRecord>,
    ) -> Self {
        let (events, _) =
            broadcast::channel(max_entries.clamp(32, MAX_WEBSOCKET_BROADCAST_CAPACITY));
        let records = sessions_with_live_preserved(records, max_entries, max_frames_per_session);
        let inner = inner_from_records(records, max_entries);
        Self {
            max_entries,
            max_frames_per_session,
            inner: RwLock::new(inner),
            events,
        }
    }

    pub async fn open(&self, mut session: WebSocketSessionRecord) {
        trim_frame_overflow(&mut session.frames, self.max_frames_per_session);
        let summary = session.summary();
        let mut inner = self.inner.write().await;
        remove_ordered_session(&mut inner, session.id);
        let id = session.id;
        inner.order.push_front(id);
        inner
            .sessions
            .insert(id, WebSocketSessionEntry::from(session));
        trim_overflow(&mut inner, self.max_entries);
        let _ = self.events.send(summary);
    }

    pub async fn append_frame(&self, id: Uuid, frame: WebSocketFrameRecord) -> bool {
        let mut inner = self.inner.write().await;
        if let Some(session) = inner.sessions.get_mut(&id) {
            session.frames.push_back(frame);
            trim_frame_deque_overflow(&mut session.frames, self.max_frames_per_session);
            let _ = self.events.send(session.summary());
            true
        } else {
            false
        }
    }

    pub async fn close(
        &self,
        id: Uuid,
        closed_at: DateTime<Utc>,
        duration_ms: u64,
        note: Option<String>,
    ) -> bool {
        let mut inner = self.inner.write().await;
        if let Some(session) = inner.sessions.get_mut(&id) {
            session.closed_at = Some(closed_at);
            session.duration_ms = Some(duration_ms);
            if let Some(note) = note {
                session.notes.push(note);
            }
            let summary = session.summary();
            let _ = self.events.send(summary);
            trim_overflow(&mut inner, self.max_entries);
            true
        } else {
            false
        }
    }

    pub async fn list(&self, limit: Option<usize>) -> Vec<WebSocketSessionSummary> {
        self.list_page(limit, None).await.items
    }

    pub async fn list_page(
        &self,
        limit: Option<usize>,
        offset: Option<usize>,
    ) -> WebSocketListPage {
        self.list_page_filtered(&WebSocketListFilters {
            limit,
            offset,
            ..WebSocketListFilters::default()
        })
        .await
    }

    pub async fn list_page_filtered(&self, filters: &WebSocketListFilters) -> WebSocketListPage {
        let inner = self.inner.read().await;
        let total = inner.order.len();
        let limit = filters
            .limit
            .unwrap_or(self.max_entries)
            .min(self.max_entries);
        let normalized_query = filters
            .query
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_ascii_lowercase);
        let mut matched: Vec<(usize, WebSocketSessionSummary)> = inner
            .order
            .iter()
            .enumerate()
            .filter_map(|(index, id)| {
                inner
                    .sessions
                    .get(id)
                    .map(WebSocketSessionEntry::summary)
                    .map(|summary| (index, summary))
            })
            .filter(|(_, summary)| {
                websocket_summary_matches_filters(summary, filters, normalized_query.as_deref())
            })
            .collect();
        sort_websocket_summaries(
            &mut matched,
            filters.sort_key.as_deref(),
            filters.sort_direction.as_deref(),
        );
        let filtered_total = matched.len();
        let offset = filters.offset.unwrap_or(0).min(filtered_total);
        let items = matched
            .into_iter()
            .skip(offset)
            .take(limit)
            .map(|(_, summary)| summary)
            .collect::<Vec<_>>();
        WebSocketListPage {
            items,
            total,
            filtered_total: Some(filtered_total),
            offset,
            limit,
            has_more: limit != 0 && offset.saturating_add(limit) < filtered_total,
        }
    }

    pub async fn get(&self, id: Uuid) -> Option<WebSocketSessionRecord> {
        self.inner
            .read()
            .await
            .sessions
            .get(&id)
            .map(WebSocketSessionEntry::to_record)
    }

    pub async fn get_windowed(
        &self,
        id: Uuid,
        frame_limit: Option<usize>,
    ) -> Option<WebSocketSessionRecord> {
        self.inner
            .read()
            .await
            .sessions
            .get(&id)
            .map(|session| session.to_record_with_frame_window(frame_limit))
    }

    pub async fn snapshot(&self, limit: Option<usize>) -> Vec<WebSocketSessionRecord> {
        let inner = self.inner.read().await;
        let limit = limit.unwrap_or(self.max_entries).min(self.max_entries);
        let mut live_remaining = limit;
        let mut closed_remaining = limit.saturating_sub(
            inner
                .order
                .iter()
                .filter_map(|id| inner.sessions.get(id))
                .filter(|session| session.closed_at.is_none())
                .count(),
        );
        inner
            .order
            .iter()
            .filter_map(|id| inner.sessions.get(id))
            .filter(|session| {
                if session.closed_at.is_none() {
                    if live_remaining == 0 {
                        return false;
                    }
                    live_remaining -= 1;
                    return true;
                }
                if closed_remaining == 0 {
                    return false;
                }
                closed_remaining -= 1;
                true
            })
            .map(WebSocketSessionEntry::to_record)
            .collect()
    }

    pub async fn replace_all(&self, records: Vec<WebSocketSessionRecord>) {
        let mut inner = self.inner.write().await;
        *inner = inner_from_records(
            sessions_with_live_preserved(records, self.max_entries, self.max_frames_per_session),
            self.max_entries,
        );
    }

    pub fn subscribe(&self) -> broadcast::Receiver<WebSocketSessionSummary> {
        self.events.subscribe()
    }
}

fn sessions_with_live_preserved(
    records: Vec<WebSocketSessionRecord>,
    max_entries: usize,
    max_frames_per_session: usize,
) -> Vec<WebSocketSessionRecord> {
    let live_count = records
        .iter()
        .filter(|session| session.closed_at.is_none())
        .count();
    let mut closed_remaining = max_entries.saturating_sub(live_count);
    let mut live_remaining = max_entries;
    records
        .into_iter()
        .filter_map(|mut session| {
            trim_frame_overflow(&mut session.frames, max_frames_per_session);
            if session.closed_at.is_none() {
                if live_remaining == 0 {
                    return None;
                }
                live_remaining -= 1;
                return Some(session);
            }
            if closed_remaining == 0 {
                return None;
            }
            closed_remaining -= 1;
            Some(session)
        })
        .collect()
}

fn inner_from_records(
    records: Vec<WebSocketSessionRecord>,
    max_entries: usize,
) -> WebSocketStoreInner {
    let mut inner = WebSocketStoreInner::with_capacity(records.len().min(max_entries));
    for record in records {
        remove_ordered_session(&mut inner, record.id);
        let id = record.id;
        inner.order.push_back(id);
        inner
            .sessions
            .insert(id, WebSocketSessionEntry::from(record));
    }
    inner
}

fn frame_window(
    frames: &VecDeque<WebSocketFrameRecord>,
    frame_limit: Option<usize>,
) -> Vec<WebSocketFrameRecord> {
    match frame_limit {
        Some(0) => Vec::new(),
        Some(limit) if frames.len() > limit => {
            frames.iter().skip(frames.len() - limit).cloned().collect()
        }
        _ => frames.iter().cloned().collect(),
    }
}

fn trim_frame_overflow(frames: &mut Vec<WebSocketFrameRecord>, max_frames_per_session: usize) {
    if frames.len() > max_frames_per_session {
        let overflow = frames.len() - max_frames_per_session;
        frames.drain(..overflow);
    }
}

fn trim_frame_deque_overflow(
    frames: &mut VecDeque<WebSocketFrameRecord>,
    max_frames_per_session: usize,
) {
    while frames.len() > max_frames_per_session {
        frames.pop_front();
    }
}

fn remove_ordered_session(inner: &mut WebSocketStoreInner, id: Uuid) {
    inner.sessions.remove(&id);
    if let Some(index) = inner.order.iter().position(|candidate| *candidate == id) {
        inner.order.remove(index);
    }
}

fn websocket_summary_matches_filters(
    summary: &WebSocketSessionSummary,
    filters: &WebSocketListFilters,
    normalized_query: Option<&str>,
) -> bool {
    if filters.in_scope_only && !summary_matches_scope(&summary.host, &filters.scope_patterns) {
        return false;
    }
    if filters.live_only && summary.duration_ms.is_some() {
        return false;
    }
    if let Some(query) = normalized_query {
        if !websocket_summary_search_haystack(summary).contains(query) {
            return false;
        }
    }
    true
}

fn websocket_summary_search_haystack(summary: &WebSocketSessionSummary) -> String {
    [
        summary.scheme.clone(),
        summary.host.clone(),
        summary.path.clone(),
        summary
            .status
            .map(|value| value.to_string())
            .unwrap_or_default(),
        summary.frame_count.to_string(),
        summary
            .duration_ms
            .map(|value| format!("{value} ms"))
            .unwrap_or_else(|| "live".to_string()),
        summary.started_at.to_rfc3339(),
    ]
    .join("\n")
    .to_ascii_lowercase()
}

fn sort_websocket_summaries(
    entries: &mut [(usize, WebSocketSessionSummary)],
    sort_key: Option<&str>,
    sort_direction: Option<&str>,
) {
    let Some(sort_key) = sort_key.filter(|key| !key.trim().is_empty()) else {
        return;
    };
    let descending = !matches!(sort_direction, Some("asc"));
    entries.sort_by(|left, right| {
        let ordering = compare_websocket_summary(sort_key, left, right);
        let ordering = if descending {
            ordering.reverse()
        } else {
            ordering
        };
        ordering.then_with(|| left.0.cmp(&right.0))
    });
}

fn compare_websocket_summary(
    sort_key: &str,
    left: &(usize, WebSocketSessionSummary),
    right: &(usize, WebSocketSessionSummary),
) -> Ordering {
    match sort_key {
        "index" => left.0.cmp(&right.0),
        "host" => left
            .1
            .host
            .to_ascii_lowercase()
            .cmp(&right.1.host.to_ascii_lowercase()),
        "path" => left
            .1
            .path
            .to_ascii_lowercase()
            .cmp(&right.1.path.to_ascii_lowercase()),
        "status" => left.1.status.cmp(&right.1.status),
        "frame_count" => left.1.frame_count.cmp(&right.1.frame_count),
        "duration_ms" => left
            .1
            .duration_ms
            .unwrap_or(u64::MAX)
            .cmp(&right.1.duration_ms.unwrap_or(u64::MAX)),
        "started_at" => left.1.started_at.cmp(&right.1.started_at),
        _ => left.0.cmp(&right.0),
    }
}

fn summary_matches_scope(host: &str, patterns: &[String]) -> bool {
    if patterns.is_empty() {
        return true;
    }

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
    let mut value = host.trim().to_ascii_lowercase();
    if let Some((_, rest)) = value.split_once("://") {
        value = rest.to_string();
    } else if let Some(rest) = value.strip_prefix("//") {
        value = rest.to_string();
    }
    let host = value.split(['/', '?', '#']).next().unwrap_or("").trim();
    host_without_port(host).to_string()
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

fn trim_closed_overflow(inner: &mut WebSocketStoreInner, max_entries: usize) {
    while inner.order.len() > max_entries {
        let Some(index) = inner.order.iter().rposition(|id| {
            inner
                .sessions
                .get(id)
                .is_some_and(|session| session.closed_at.is_some())
        }) else {
            break;
        };
        if let Some(id) = inner.order.remove(index) {
            inner.sessions.remove(&id);
        }
    }
}

fn trim_overflow(inner: &mut WebSocketStoreInner, max_entries: usize) {
    trim_closed_overflow(inner, max_entries);
    while inner.order.len() > max_entries {
        if let Some(id) = inner.order.pop_back() {
            inner.sessions.remove(&id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{BodyEncoding, MessageRecord, WebSocketFrameDirection, WebSocketFrameKind};
    use http::HeaderMap;

    fn frame(index: usize) -> WebSocketFrameRecord {
        WebSocketFrameRecord {
            index,
            captured_at: Utc::now(),
            direction: WebSocketFrameDirection::ClientToServer,
            kind: WebSocketFrameKind::Text,
            body_preview: format!("frame-{index}"),
            body_encoding: BodyEncoding::Utf8,
            body_size: 0,
            preview_truncated: false,
        }
    }

    fn session(frames: Vec<WebSocketFrameRecord>) -> WebSocketSessionRecord {
        WebSocketSessionRecord {
            id: Uuid::new_v4(),
            started_at: Utc::now(),
            closed_at: None,
            duration_ms: None,
            scheme: "wss".to_string(),
            host: "example.com".to_string(),
            path: "/ws".to_string(),
            status: Some(101),
            request: MessageRecord::from_headers_and_body(&HeaderMap::new(), &[], 1024),
            response: None,
            frames,
            notes: Vec::new(),
        }
    }

    fn closed_session(frames: Vec<WebSocketFrameRecord>) -> WebSocketSessionRecord {
        let mut record = session(frames);
        record.closed_at = Some(Utc::now());
        record.duration_ms = Some(25);
        record
    }

    #[tokio::test]
    async fn list_page_filtered_searches_sorts_and_offsets_after_filtering() {
        let mut live = session(vec![frame(1)]);
        live.host = "zeta.example.test".to_string();
        live.path = "/chat".to_string();
        live.started_at = Utc::now();

        let mut closed = closed_session(vec![frame(1), frame(2)]);
        closed.host = "api.example.test".to_string();
        closed.path = "/socket".to_string();
        closed.status = Some(500);
        closed.duration_ms = Some(12);
        closed.started_at = Utc::now();

        let store = WebSocketStore::from_sessions(10, 10, vec![live, closed]);

        let page = store
            .list_page_filtered(&WebSocketListFilters {
                query: Some("500".to_string()),
                limit: Some(10),
                sort_key: Some("host".to_string()),
                sort_direction: Some("asc".to_string()),
                ..WebSocketListFilters::default()
            })
            .await;

        assert_eq!(page.total, 2);
        assert_eq!(page.filtered_total, Some(1));
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].host, "api.example.test");

        let sorted_page = store
            .list_page_filtered(&WebSocketListFilters {
                limit: Some(1),
                offset: Some(1),
                sort_key: Some("host".to_string()),
                sort_direction: Some("asc".to_string()),
                ..WebSocketListFilters::default()
            })
            .await;

        assert_eq!(sorted_page.filtered_total, Some(2));
        assert_eq!(sorted_page.items.len(), 1);
        assert_eq!(sorted_page.items[0].host, "zeta.example.test");
        assert!(!sorted_page.has_more);
    }

    #[tokio::test]
    async fn list_page_filtered_supports_live_only_and_scope_filters() {
        let mut live = session(vec![frame(1)]);
        live.host = "chat.example.test".to_string();

        let mut closed = closed_session(vec![frame(1)]);
        closed.host = "out.example.test".to_string();

        let store = WebSocketStore::from_sessions(10, 10, vec![live, closed]);

        let live_page = store
            .list_page_filtered(&WebSocketListFilters {
                live_only: true,
                ..WebSocketListFilters::default()
            })
            .await;

        assert_eq!(live_page.filtered_total, Some(1));
        assert_eq!(live_page.items[0].host, "chat.example.test");

        let scope_page = store
            .list_page_filtered(&WebSocketListFilters {
                in_scope_only: true,
                scope_patterns: vec!["chat.example.test".to_string()],
                ..WebSocketListFilters::default()
            })
            .await;

        assert_eq!(scope_page.filtered_total, Some(1));
        assert_eq!(scope_page.items[0].host, "chat.example.test");
    }

    #[tokio::test]
    async fn from_sessions_trims_restored_frames_to_cap() {
        let store =
            WebSocketStore::from_sessions(10, 2, vec![session(vec![frame(1), frame(2), frame(3)])]);

        let restored = store.snapshot(None).await;

        assert_eq!(restored[0].frames.len(), 2);
        assert_eq!(restored[0].frames[0].index, 2);
        assert_eq!(restored[0].frames[1].index, 3);
    }

    #[tokio::test]
    async fn open_trims_initial_frames_to_cap() {
        let store = WebSocketStore::new(10, 2);

        store
            .open(session(vec![frame(1), frame(2), frame(3)]))
            .await;

        let restored = store.snapshot(None).await;
        assert_eq!(
            restored[0]
                .frames
                .iter()
                .map(|frame| frame.index)
                .collect::<Vec<_>>(),
            vec![2, 3]
        );
        let page = store.list_page(Some(10), None).await;
        assert_eq!(page.items[0].frame_count, 2);
        assert_eq!(page.items[0].last_frame_index, Some(3));
    }

    #[tokio::test]
    async fn get_windowed_returns_only_requested_tail_frames() {
        let record = session(vec![frame(1), frame(2), frame(3), frame(4)]);
        let record_id = record.id;
        let store = WebSocketStore::from_sessions(10, 10, vec![record]);

        let detail = store.get_windowed(record_id, Some(2)).await.unwrap();

        assert_eq!(
            detail
                .frames
                .iter()
                .map(|frame| frame.index)
                .collect::<Vec<_>>(),
            vec![3, 4]
        );
    }

    #[tokio::test]
    async fn summary_tracks_last_retained_frame_index_after_frame_cap() {
        let record = session(vec![frame(1), frame(2)]);
        let record_id = record.id;
        let store = WebSocketStore::from_sessions(10, 2, vec![record]);

        assert!(store.append_frame(record_id, frame(3)).await);

        let page = store.list_page(Some(10), None).await;
        let summary = &page.items[0];
        assert_eq!(summary.frame_count, 2);
        assert_eq!(summary.last_frame_index, Some(3));
    }

    #[tokio::test]
    async fn append_frame_caps_with_tail_order_after_many_overflow_frames() {
        let record = session(Vec::new());
        let record_id = record.id;
        let store = WebSocketStore::from_sessions(10, 3, vec![record]);

        for index in 1..=10 {
            assert!(store.append_frame(record_id, frame(index)).await);
        }

        let stored = store.get(record_id).await.unwrap();
        assert_eq!(
            stored
                .frames
                .iter()
                .map(|frame| frame.index)
                .collect::<Vec<_>>(),
            vec![8, 9, 10]
        );
        let summary = &store.list_page(Some(10), None).await.items[0];
        assert_eq!(summary.frame_count, 3);
        assert_eq!(summary.last_frame_index, Some(10));
    }

    #[tokio::test]
    async fn snapshot_materializes_vec_frames_in_wire_order() {
        let store = WebSocketStore::new(10, 3);
        store
            .open(session(vec![frame(1), frame(2), frame(3)]))
            .await;

        let snapshot = store.snapshot(None).await;
        let raw = serde_json::to_string(&snapshot).unwrap();
        assert!(raw.contains("\"frames\""));
        assert!(!raw.contains("\"order\""));
        assert!(!raw.contains("\"sessions\""));

        let value = serde_json::to_value(&snapshot[0]).unwrap();
        assert!(value["frames"].is_array());

        let round_trip: WebSocketSessionRecord = serde_json::from_value(value).unwrap();
        assert_eq!(
            round_trip
                .frames
                .iter()
                .map(|frame| frame.index)
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
    }

    #[tokio::test]
    async fn reopening_same_session_id_replaces_ordered_entry() {
        let first = session(vec![frame(1)]);
        let first_id = first.id;
        let mut replacement = session(vec![frame(2)]);
        replacement.id = first_id;
        replacement.host = "replacement.example".to_string();
        let store = WebSocketStore::new(10, 10);

        store.open(first).await;
        store.open(replacement).await;

        let page = store.list_page(Some(10), None).await;
        assert_eq!(page.total, 1);
        assert_eq!(page.items[0].host, "replacement.example");
        let stored = store.get(first_id).await.unwrap();
        assert_eq!(stored.frames[0].index, 2);
    }

    #[tokio::test]
    async fn list_page_returns_offset_window_without_resending_prefix() {
        let store = WebSocketStore::new(10, 10);
        let first = session(Vec::new());
        let second = session(Vec::new());
        let second_id = second.id;
        let third = session(Vec::new());

        store.open(first).await;
        store.open(second).await;
        store.open(third).await;

        let page = store.list_page(Some(1), Some(1)).await;

        assert_eq!(page.total, 3);
        assert_eq!(page.offset, 1);
        assert_eq!(page.limit, 1);
        assert!(page.has_more);
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].id, second_id);
    }

    #[tokio::test]
    async fn open_evicts_oldest_live_session_when_all_entries_are_live() {
        let store = WebSocketStore::new(1, 10);
        let first = session(Vec::new());
        let first_id = first.id;
        store.open(first).await;

        let second = session(Vec::new());
        store.open(second).await;

        assert!(store.get(first_id).await.is_none());
        assert!(!store.append_frame(first_id, frame(1)).await);
        assert!(
            !store
                .close(first_id, Utc::now(), 10, Some("closed".to_string()))
                .await
        );

        let snapshot = store.snapshot(Some(10)).await;
        assert_eq!(snapshot.len(), 1);
        assert_ne!(snapshot[0].id, first_id);
        assert_eq!(store.list_page(Some(10), None).await.total, 1);
    }

    #[tokio::test]
    async fn from_sessions_does_not_preallocate_full_retention_for_empty_restore() {
        let store = WebSocketStore::from_sessions(500_000, 10, Vec::new());

        assert_eq!(store.inner.read().await.order.capacity(), 0);
    }

    #[tokio::test]
    async fn snapshot_caps_live_sessions_at_limit() {
        let store = WebSocketStore::new(1, 10);
        let first = session(vec![frame(1)]);
        let first_id = first.id;
        let second = session(Vec::new());
        let second_id = second.id;
        store.open(first).await;
        store.open(second).await;

        let snapshot = store.snapshot(Some(1)).await;

        assert_eq!(snapshot.len(), 1);
        assert!(!snapshot.iter().any(|session| session.id == first_id));
        assert!(snapshot.iter().any(|session| session.id == second_id));
    }

    #[tokio::test]
    async fn replace_all_caps_live_sessions_at_limit() {
        let first = session(vec![frame(1)]);
        let first_id = first.id;
        let second = session(Vec::new());
        let second_id = second.id;
        let store = WebSocketStore::from_sessions(1, 10, vec![second, first]);

        let snapshot = store.snapshot(Some(1)).await;

        assert_eq!(snapshot.len(), 1);
        assert!(!snapshot.iter().any(|session| session.id == first_id));
        assert!(snapshot.iter().any(|session| session.id == second_id));
    }

    #[tokio::test]
    async fn open_evicts_oldest_closed_session_first() {
        let store = WebSocketStore::new(2, 10);
        let closed = closed_session(Vec::new());
        let closed_id = closed.id;
        store.open(closed).await;

        let live = session(Vec::new());
        let live_id = live.id;
        store.open(live).await;
        store.open(session(Vec::new())).await;

        let snapshot = store.snapshot(None).await;
        assert_eq!(snapshot.len(), 2);
        assert!(!snapshot.iter().any(|session| session.id == closed_id));
        assert!(snapshot.iter().any(|session| session.id == live_id));
    }
}
