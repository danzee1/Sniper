use std::collections::VecDeque;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, RwLock};
use uuid::Uuid;

const MAX_EVENT_LOG_BROADCAST_CAPACITY: usize = 4096;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventLevel {
    Info,
    Warn,
    Error,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EventLogEntry {
    pub id: Uuid,
    pub captured_at: DateTime<Utc>,
    pub level: EventLevel,
    pub source: String,
    pub title: String,
    pub message: String,
}

pub struct EventLogStore {
    max_entries: usize,
    entries: RwLock<VecDeque<EventLogEntry>>,
    events: broadcast::Sender<EventLogEntry>,
}

impl EventLogStore {
    pub fn new(max_entries: usize) -> Self {
        Self::from_entries(max_entries, Vec::new())
    }

    pub fn from_entries(max_entries: usize, records: Vec<EventLogEntry>) -> Self {
        let (events, _) =
            broadcast::channel(max_entries.clamp(64, MAX_EVENT_LOG_BROADCAST_CAPACITY));
        let mut entries = VecDeque::with_capacity(records.len().min(max_entries));
        entries.extend(records.into_iter().take(max_entries));
        Self {
            max_entries,
            entries: RwLock::new(entries),
            events,
        }
    }

    pub async fn push(
        &self,
        level: EventLevel,
        source: impl Into<String>,
        title: impl Into<String>,
        message: impl Into<String>,
    ) -> EventLogEntry {
        self.push_with_evicted(level, source, title, message)
            .await
            .0
    }

    pub async fn push_with_evicted(
        &self,
        level: EventLevel,
        source: impl Into<String>,
        title: impl Into<String>,
        message: impl Into<String>,
    ) -> (EventLogEntry, Vec<EventLogEntry>) {
        let entry = EventLogEntry {
            id: Uuid::new_v4(),
            captured_at: Utc::now(),
            level,
            source: source.into(),
            title: title.into(),
            message: message.into(),
        };

        let mut entries = self.entries.write().await;
        entries.push_front(entry.clone());
        let mut evicted = Vec::new();
        while entries.len() > self.max_entries {
            if let Some(record) = entries.pop_back() {
                evicted.push(record);
            }
        }
        let _ = self.events.send(entry.clone());
        (entry, evicted)
    }

    pub async fn remove_and_restore(&self, id: Uuid, restore: Vec<EventLogEntry>) -> bool {
        let mut entries = self.entries.write().await;
        let before = entries.len();
        entries.retain(|entry| entry.id != id);
        let removed = entries.len() < before;
        if removed {
            for record in restore {
                if entries.len() >= self.max_entries {
                    break;
                }
                entries.push_back(record);
            }
        }
        removed
    }

    pub async fn list(&self, limit: Option<usize>) -> Vec<EventLogEntry> {
        let entries = self.entries.read().await;
        entries
            .iter()
            .take(limit.unwrap_or(self.max_entries).min(self.max_entries))
            .cloned()
            .collect()
    }

    pub async fn snapshot(&self, limit: Option<usize>) -> Vec<EventLogEntry> {
        self.list(limit).await
    }

    pub async fn replace_all(&self, records: Vec<EventLogEntry>) {
        let mut entries = self.entries.write().await;
        entries.clear();
        entries.extend(records.into_iter().take(self.max_entries));
    }

    pub async fn clear(&self) {
        self.entries.write().await.clear();
    }

    pub fn subscribe(&self) -> broadcast::Receiver<EventLogEntry> {
        self.events.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn remove_and_restore_recovers_evicted_entry_after_failed_insert() {
        let store = EventLogStore::new(1);
        let old = store.push(EventLevel::Info, "test", "old", "old").await;
        let (new, evicted) = store
            .push_with_evicted(EventLevel::Info, "test", "new", "new")
            .await;

        assert_eq!(
            evicted.iter().map(|entry| entry.id).collect::<Vec<_>>(),
            vec![old.id]
        );

        assert!(store.remove_and_restore(new.id, evicted).await);
        let entries = store.snapshot(None).await;
        assert_eq!(
            entries.iter().map(|entry| entry.id).collect::<Vec<_>>(),
            vec![old.id]
        );
    }

    #[tokio::test]
    async fn from_entries_does_not_preallocate_full_retention_for_empty_restore() {
        let store = EventLogStore::from_entries(500_000, Vec::new());

        assert_eq!(store.entries.read().await.capacity(), 0);
    }
}
