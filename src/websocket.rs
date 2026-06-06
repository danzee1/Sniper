use std::collections::VecDeque;

use chrono::{DateTime, Utc};
use tokio::sync::{broadcast, RwLock};
use uuid::Uuid;

use crate::model::{WebSocketFrameRecord, WebSocketSessionRecord, WebSocketSessionSummary};

const MAX_WEBSOCKET_BROADCAST_CAPACITY: usize = 4096;

pub struct WebSocketStore {
    max_entries: usize,
    max_frames_per_session: usize,
    sessions: RwLock<VecDeque<WebSocketSessionRecord>>,
    events: broadcast::Sender<WebSocketSessionSummary>,
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
        let mut sessions = VecDeque::with_capacity(records.len().min(max_entries));
        sessions.extend(sessions_with_live_preserved(
            records,
            max_entries,
            max_frames_per_session,
        ));
        Self {
            max_entries,
            max_frames_per_session,
            sessions: RwLock::new(sessions),
            events,
        }
    }

    pub async fn open(&self, mut session: WebSocketSessionRecord) {
        trim_frame_overflow(&mut session.frames, self.max_frames_per_session);
        let summary = session.summary();
        let mut sessions = self.sessions.write().await;
        sessions.push_front(session);
        trim_overflow(&mut sessions, self.max_entries);
        let _ = self.events.send(summary);
    }

    pub async fn append_frame(&self, id: Uuid, frame: WebSocketFrameRecord) -> bool {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.iter_mut().find(|session| session.id == id) {
            session.frames.push(frame);
            trim_frame_overflow(&mut session.frames, self.max_frames_per_session);
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
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.iter_mut().find(|session| session.id == id) {
            session.closed_at = Some(closed_at);
            session.duration_ms = Some(duration_ms);
            if let Some(note) = note {
                session.notes.push(note);
            }
            let summary = session.summary();
            let _ = self.events.send(summary);
            trim_overflow(&mut sessions, self.max_entries);
            true
        } else {
            false
        }
    }

    pub async fn list(&self, limit: Option<usize>) -> Vec<WebSocketSessionSummary> {
        self.list_page(limit).await.items
    }

    pub async fn list_page(&self, limit: Option<usize>) -> WebSocketListPage {
        let sessions = self.sessions.read().await;
        let total = sessions.len();
        let limit = limit.unwrap_or(self.max_entries).min(self.max_entries);
        let items = sessions
            .iter()
            .take(limit)
            .map(WebSocketSessionRecord::summary)
            .collect();
        WebSocketListPage {
            items,
            total,
            limit,
            has_more: limit < total,
        }
    }

    pub async fn get(&self, id: Uuid) -> Option<WebSocketSessionRecord> {
        self.sessions
            .read()
            .await
            .iter()
            .find(|session| session.id == id)
            .cloned()
    }

    pub async fn get_windowed(
        &self,
        id: Uuid,
        frame_limit: Option<usize>,
    ) -> Option<WebSocketSessionRecord> {
        self.sessions
            .read()
            .await
            .iter()
            .find(|session| session.id == id)
            .map(|session| clone_session_with_frame_window(session, frame_limit))
    }

    pub async fn snapshot(&self, limit: Option<usize>) -> Vec<WebSocketSessionRecord> {
        let sessions = self.sessions.read().await;
        let limit = limit.unwrap_or(self.max_entries).min(self.max_entries);
        let mut live_remaining = limit;
        let mut closed_remaining = limit.saturating_sub(
            sessions
                .iter()
                .filter(|session| session.closed_at.is_none())
                .count(),
        );
        sessions
            .iter()
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
            .cloned()
            .collect()
    }

    pub async fn replace_all(&self, records: Vec<WebSocketSessionRecord>) {
        let mut sessions = self.sessions.write().await;
        sessions.clear();
        sessions.extend(sessions_with_live_preserved(
            records,
            self.max_entries,
            self.max_frames_per_session,
        ));
    }

    pub fn subscribe(&self) -> broadcast::Receiver<WebSocketSessionSummary> {
        self.events.subscribe()
    }
}

fn clone_session_with_frame_window(
    session: &WebSocketSessionRecord,
    frame_limit: Option<usize>,
) -> WebSocketSessionRecord {
    let frames = match frame_limit {
        Some(0) => Vec::new(),
        Some(limit) if session.frames.len() > limit => {
            session.frames[session.frames.len() - limit..].to_vec()
        }
        _ => session.frames.clone(),
    };

    WebSocketSessionRecord {
        id: session.id,
        started_at: session.started_at,
        closed_at: session.closed_at,
        duration_ms: session.duration_ms,
        scheme: session.scheme.clone(),
        host: session.host.clone(),
        path: session.path.clone(),
        status: session.status,
        request: session.request.clone(),
        response: session.response.clone(),
        frames,
        notes: session.notes.clone(),
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

fn trim_frame_overflow(frames: &mut Vec<WebSocketFrameRecord>, max_frames_per_session: usize) {
    if frames.len() > max_frames_per_session {
        let overflow = frames.len() - max_frames_per_session;
        frames.drain(..overflow);
    }
}

fn trim_closed_overflow(sessions: &mut VecDeque<WebSocketSessionRecord>, max_entries: usize) {
    while sessions.len() > max_entries {
        let Some(index) = sessions
            .iter()
            .rposition(|session| session.closed_at.is_some())
        else {
            break;
        };
        sessions.remove(index);
    }
}

fn trim_overflow(sessions: &mut VecDeque<WebSocketSessionRecord>, max_entries: usize) {
    trim_closed_overflow(sessions, max_entries);
    while sessions.len() > max_entries {
        sessions.pop_back();
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

        assert_eq!(store.sessions.read().await.capacity(), 0);
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
