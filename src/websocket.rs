use std::collections::{HashMap, VecDeque};

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
    pub limit: usize,
    pub has_more: bool,
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
        self.list_page(limit).await.items
    }

    pub async fn list_page(&self, limit: Option<usize>) -> WebSocketListPage {
        let inner = self.inner.read().await;
        let total = inner.order.len();
        let limit = limit.unwrap_or(self.max_entries).min(self.max_entries);
        let items = inner
            .order
            .iter()
            .take(limit)
            .filter_map(|id| inner.sessions.get(id).map(WebSocketSessionEntry::summary))
            .collect();
        WebSocketListPage {
            items,
            total,
            limit,
            has_more: limit < total,
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
        record
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
        let page = store.list_page(Some(10)).await;
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

        let page = store.list_page(Some(10)).await;
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
        let summary = &store.list_page(Some(10)).await.items[0];
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

        let page = store.list_page(Some(10)).await;
        assert_eq!(page.total, 1);
        assert_eq!(page.items[0].host, "replacement.example");
        let stored = store.get(first_id).await.unwrap();
        assert_eq!(stored.frames[0].index, 2);
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
        assert_eq!(store.list_page(Some(10)).await.total, 1);
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
