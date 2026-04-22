use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::{broadcast, RwLock};
use uuid::Uuid;

use crate::model::{TransactionRecord, TransactionSummary};

#[derive(Clone, Debug, Default)]
pub struct ListFilters {
    pub query: Option<String>,
    pub method: Option<String>,
    pub limit: Option<usize>,
    pub host: Option<String>,
    pub status: Option<u16>,
    pub status_range: Option<String>,
    pub since: Option<String>,
    pub mime: Option<String>,
}

pub struct TransactionStore {
    entries: RwLock<VecDeque<TransactionRecord>>,
    events: broadcast::Sender<TransactionSummary>,
    next_sequence: AtomicU64,
}

impl TransactionStore {
    pub fn new() -> Self {
        Self::from_records(Vec::new())
    }

    pub fn from_records(records: Vec<TransactionRecord>) -> Self {
        let (events, _) = broadcast::channel(256);
        let entries = VecDeque::from(records);
        // Resume sequence from the highest existing number.
        let max_seq = entries.iter().map(|r| r.sequence).max().unwrap_or(0);
        Self {
            entries: RwLock::new(entries),
            events,
            next_sequence: AtomicU64::new(max_seq + 1),
        }
    }

    pub async fn insert(&self, mut record: TransactionRecord) {
        record.sequence = self.next_sequence.fetch_add(1, Ordering::Relaxed);
        let summary = record.summary();
        let mut entries = self.entries.write().await;
        entries.push_front(record);
        let _ = self.events.send(summary);
    }

    pub async fn list(&self, filters: &ListFilters) -> Vec<TransactionSummary> {
        let query = filters
            .query
            .as_ref()
            .map(|value| value.to_ascii_lowercase());
        let method = filters
            .method
            .as_ref()
            .map(|value| value.to_ascii_uppercase());
        let host = filters
            .host
            .as_ref()
            .map(|value| value.to_ascii_lowercase());
        let since_dt = filters.since.as_deref().and_then(parse_since);
        let status_pred = filters
            .status
            .map(StatusPredicate::Exact)
            .or_else(|| filters.status_range.as_deref().and_then(parse_status_range));
        let mime = filters
            .mime
            .as_ref()
            .map(|value| value.to_ascii_lowercase());
        let limit = filters.limit.unwrap_or(5000);
        let entries = self.entries.read().await;

        let filtered = entries.iter().filter(|record| {
            matches_filters(
                record,
                query.as_deref(),
                method.as_deref(),
                host.as_deref(),
                status_pred.as_ref(),
                since_dt.as_ref(),
                mime.as_deref(),
            )
        });

        if limit == 0 {
            // limit=0 means unlimited
            filtered.map(TransactionRecord::summary).collect()
        } else {
            filtered.take(limit).map(TransactionRecord::summary).collect()
        }
    }

    pub async fn get(&self, id: Uuid) -> Option<TransactionRecord> {
        let entries = self.entries.read().await;
        entries.iter().find(|record| record.id == id).cloned()
    }

    pub async fn snapshot(&self, limit: Option<usize>) -> Vec<TransactionRecord> {
        let entries = self.entries.read().await;
        match limit {
            Some(n) => entries.iter().take(n).cloned().collect(),
            None => entries.iter().cloned().collect(),
        }
    }

    pub async fn update_annotations(
        &self,
        id: Uuid,
        color_tag: Option<Option<String>>,
        user_note: Option<Option<String>>,
    ) -> Option<TransactionSummary> {
        let mut entries = self.entries.write().await;
        let record = entries.iter_mut().find(|r| r.id == id)?;
        if let Some(tag) = color_tag {
            record.color_tag = tag;
        }
        if let Some(note) = user_note {
            record.user_note = note;
        }
        Some(record.summary())
    }

    pub async fn replace_all(&self, records: Vec<TransactionRecord>) {
        let mut entries = self.entries.write().await;
        entries.clear();
        entries.extend(records);
        let max_seq = entries.iter().map(|r| r.sequence).max().unwrap_or(0);
        self.next_sequence.store(max_seq + 1, Ordering::Relaxed);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<TransactionSummary> {
        self.events.subscribe()
    }
}

#[derive(Clone, Debug)]
enum StatusPredicate {
    Exact(u16),
    Range(u16, u16),
    Class(u16), // e.g. 4 means 4xx (400-499)
}

impl StatusPredicate {
    fn matches(&self, status: Option<u16>) -> bool {
        let Some(s) = status else { return false };
        match self {
            StatusPredicate::Exact(v) => s == *v,
            StatusPredicate::Range(lo, hi) => s >= *lo && s <= *hi,
            StatusPredicate::Class(c) => s / 100 == *c,
        }
    }
}

fn parse_status_range(input: &str) -> Option<StatusPredicate> {
    let trimmed = input.trim();
    // "4xx", "5xx", etc.
    if trimmed.len() == 3 && trimmed.ends_with("xx") {
        let class = trimmed[..1].parse::<u16>().ok()?;
        if (1..=5).contains(&class) {
            return Some(StatusPredicate::Class(class));
        }
    }
    // "200-299"
    if let Some((lo_str, hi_str)) = trimmed.split_once('-') {
        let lo = lo_str.trim().parse::<u16>().ok()?;
        let hi = hi_str.trim().parse::<u16>().ok()?;
        if lo <= hi {
            return Some(StatusPredicate::Range(lo, hi));
        }
    }
    None
}

fn parse_since(input: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    let trimmed = input.trim();
    // Relative: "1h", "30m", "2d", "7d"
    if let Some(rest) = trimmed.strip_suffix('h') {
        let hours: i64 = rest.parse().ok()?;
        return Some(chrono::Utc::now() - chrono::Duration::hours(hours));
    }
    if let Some(rest) = trimmed.strip_suffix('m') {
        let minutes: i64 = rest.parse().ok()?;
        return Some(chrono::Utc::now() - chrono::Duration::minutes(minutes));
    }
    if let Some(rest) = trimmed.strip_suffix('d') {
        let days: i64 = rest.parse().ok()?;
        return Some(chrono::Utc::now() - chrono::Duration::days(days));
    }
    if let Some(rest) = trimmed.strip_suffix('s') {
        let secs: i64 = rest.parse().ok()?;
        return Some(chrono::Utc::now() - chrono::Duration::seconds(secs));
    }
    // Absolute: "2024-01-01" or "2024-01-01T12:00:00Z"
    if let Ok(dt) = chrono::NaiveDate::parse_from_str(trimmed, "%Y-%m-%d") {
        let datetime = dt.and_hms_opt(0, 0, 0)?;
        return Some(chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(
            datetime,
            chrono::Utc,
        ));
    }
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(trimmed) {
        return Some(dt.with_timezone(&chrono::Utc));
    }
    None
}

fn matches_filters(
    record: &TransactionRecord,
    query: Option<&str>,
    method: Option<&str>,
    host: Option<&str>,
    status_pred: Option<&StatusPredicate>,
    since: Option<&chrono::DateTime<chrono::Utc>>,
    mime: Option<&str>,
) -> bool {
    if let Some(m) = method {
        if !record.method.eq_ignore_ascii_case(m) {
            return false;
        }
    }

    if let Some(h) = host {
        if !record.host.to_ascii_lowercase().contains(h) {
            return false;
        }
    }

    if let Some(pred) = status_pred {
        if !pred.matches(record.status) {
            return false;
        }
    }

    if let Some(since_dt) = since {
        if record.started_at < *since_dt {
            return false;
        }
    }

    if let Some(mime_filter) = mime {
        let content_type = record
            .response
            .as_ref()
            .and_then(|r| r.content_type.as_deref())
            .unwrap_or("");
        let ct_lower = content_type.to_ascii_lowercase();
        if !ct_lower.contains(mime_filter) {
            return false;
        }
    }

    let Some(value) = query else { return true };
    let haystack = format!(
        "{} {} {} {}",
        record.id, record.method, record.host, record.path
    )
    .to_ascii_lowercase();
    haystack.contains(value)
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;
    use crate::model::{MessageRecord, TransactionRecord};

    #[tokio::test]
    async fn store_respects_capacity_and_filters() {
        let store = TransactionStore::new();
        let empty_message = MessageRecord {
            headers: Vec::new(),
            body_preview: String::new(),
            body_encoding: crate::model::BodyEncoding::Utf8,
            body_size: 0,
            preview_truncated: false,
            content_type: None,
        };

        store
            .insert(TransactionRecord::http(
                Utc::now(),
                "GET".into(),
                "http".into(),
                "one.local".into(),
                "/".into(),
                Some(200),
                1,
                empty_message.clone(),
                Some(empty_message.clone()),
                Vec::new(),
                None,
                None,
            ))
            .await;

        store
            .insert(TransactionRecord::http(
                Utc::now(),
                "POST".into(),
                "http".into(),
                "two.local".into(),
                "/submit".into(),
                Some(201),
                2,
                empty_message.clone(),
                Some(empty_message.clone()),
                Vec::new(),
                None,
                None,
            ))
            .await;

        store
            .insert(TransactionRecord::http(
                Utc::now(),
                "DELETE".into(),
                "http".into(),
                "three.local".into(),
                "/resource".into(),
                Some(204),
                3,
                empty_message.clone(),
                Some(empty_message),
                Vec::new(),
                None,
                None,
            ))
            .await;

        let all = store.list(&ListFilters::default()).await;
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].method, "DELETE");

        let filtered = store
            .list(&ListFilters {
                query: Some("two.local".into()),
                method: Some("POST".into()),
                limit: Some(10),
                ..Default::default()
            })
            .await;
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].host, "two.local");
    }
}
