use std::{
    collections::HashMap,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    thread,
};

use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, oneshot, RwLock};
use tracing::warn;
use uuid::Uuid;

use regex::{Regex, RegexBuilder};

use crate::model::{TrafficKind, TransactionRecord, TransactionSummary};

#[derive(Clone, Debug, Default)]
pub struct ListFilters {
    pub query: Option<String>,
    pub method: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    pub before_sequence: Option<u64>,
    pub sort_key: Option<String>,
    pub sort_direction: Option<String>,
    pub scope_patterns: Vec<String>,
    pub in_scope_only: bool,
    pub hide_connect: bool,
    pub hide_without_responses: bool,
    pub only_parameterized: bool,
    pub only_notes: bool,
    pub status_classes: Option<Vec<String>>,
    pub mime_types: Option<Vec<String>>,
    pub hidden_extensions: Vec<String>,
    pub host: Option<String>,
    pub status: Option<u16>,
    pub status_range: Option<String>,
    pub since: Option<String>,
    pub mime: Option<String>,
    pub port: Option<String>,
    pub color_tags: Vec<String>,
    pub advanced_search: Option<String>,
    pub advanced_regex: bool,
    pub advanced_case_sensitive: bool,
    pub advanced_negative: bool,
}

#[derive(Clone, Debug)]
pub struct TransactionListPage {
    pub items: Vec<TransactionSummary>,
    pub total: usize,
    pub filtered_total: Option<usize>,
    pub offset: usize,
    pub limit: usize,
    pub has_more: bool,
}

pub struct TransactionStore {
    inner: RwLock<StoreInner>,
    events: broadcast::Sender<TransactionSummary>,
    journal_tx: Option<mpsc::Sender<TransactionJournalCommand>>,
    max_entries: Option<usize>,
    next_sequence: AtomicU64,
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum TransactionJournalEntry {
    Insert {
        record: TransactionRecord,
    },
    Annotation {
        id: Uuid,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        color_tag: Option<NullableStringPatch>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        user_note: Option<NullableStringPatch>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum NullableStringPatch {
    Set(String),
    Clear,
}

#[derive(Serialize)]
struct TransactionJournalInsert<'a> {
    #[serde(rename = "type")]
    entry_type: &'static str,
    record: &'a TransactionRecord,
}

enum TransactionJournalCommand {
    Append {
        line: Vec<u8>,
        ack: Option<oneshot::Sender<io::Result<()>>>,
    },
    Rotate {
        ack: mpsc::Sender<io::Result<()>>,
    },
}

#[derive(Default)]
struct StoreInner {
    /// Oldest to newest. New captures append, queries iterate in reverse.
    entries: Vec<TransactionRecord>,
    summaries: Vec<CachedSummary>,
    by_id: HashMap<Uuid, usize>,
}

#[derive(Clone, Debug)]
struct CachedSummary {
    summary: TransactionSummary,
    method_upper: String,
    host_lower: String,
    content_type_lower: String,
    path_lower: String,
    path_extension: Option<String>,
    port: Option<String>,
    mime: &'static str,
    total_bytes: usize,
    is_tls: bool,
    quick_haystack: String,
    advanced_haystack: String,
    advanced_haystack_lower: String,
}

impl CachedSummary {
    fn new(summary: TransactionSummary) -> Self {
        let method_upper = summary.method.to_ascii_uppercase();
        let host_lower = summary.host.to_ascii_lowercase();
        let content_type_lower = summary
            .content_type
            .as_deref()
            .unwrap_or("")
            .to_ascii_lowercase();
        let path_extension = extract_path_extension(&summary.path);
        let path_lower = summary.path.to_ascii_lowercase();
        let port = extract_host_port(&summary.host).map(str::to_string);
        let mime = infer_summary_mime(&summary);
        let total_bytes = summary_total_bytes(&summary);
        let is_tls = is_tls_summary(&summary);
        let quick_haystack = format!(
            "{} {} {} {} {} {} {} {} {} {} {} {}",
            summary.id,
            summary.sequence,
            summary.method,
            summary.host,
            summary.path,
            summary
                .status
                .map(|status| status.to_string())
                .unwrap_or_default(),
            summary.content_type.as_deref().unwrap_or(""),
            mime,
            total_bytes,
            format_size(total_bytes),
            summary.started_at.to_rfc3339(),
            summary.started_at.format("%b %d, %H:%M:%S"),
        )
        .to_ascii_lowercase();
        let advanced_haystack = format!(
            "{} {} {} {}",
            summary.host,
            summary.method,
            summary.path,
            summary.content_type.as_deref().unwrap_or("")
        );
        let advanced_haystack_lower = advanced_haystack.to_ascii_lowercase();

        Self {
            summary,
            method_upper,
            host_lower,
            content_type_lower,
            path_lower,
            path_extension,
            port,
            mime,
            total_bytes,
            is_tls,
            quick_haystack,
            advanced_haystack,
            advanced_haystack_lower,
        }
    }
}

impl StoreInner {
    fn from_newest_first(records: Vec<TransactionRecord>) -> Self {
        Self::from_oldest_first(records.into_iter().rev().collect())
    }

    fn from_oldest_first(mut entries: Vec<TransactionRecord>) -> Self {
        normalize_storage_sequences(&mut entries);
        let mut summaries = Vec::with_capacity(entries.len());
        let mut by_id = HashMap::with_capacity(entries.len());
        for (index, record) in entries.iter().enumerate() {
            summaries.push(CachedSummary::new(record.summary()));
            by_id.insert(record.id, index);
        }
        Self {
            entries,
            summaries,
            by_id,
        }
    }

    fn push(&mut self, record: TransactionRecord, summary: TransactionSummary) {
        let index = self.entries.len();
        self.by_id.insert(record.id, index);
        self.entries.push(record);
        self.summaries.push(CachedSummary::new(summary));
    }

    fn trim_to_max_entries(&mut self, max_entries: usize) {
        if max_entries == 0 {
            self.entries.clear();
            self.summaries.clear();
            self.by_id.clear();
            return;
        }

        let slack = if max_entries < 4096 { 0 } else { 1024 };
        if self.entries.len() <= max_entries.saturating_add(slack) {
            return;
        }

        let remove_count = self.entries.len().saturating_sub(max_entries);
        for record in self.entries.drain(0..remove_count) {
            self.by_id.remove(&record.id);
        }
        self.summaries.drain(0..remove_count);
        for index in self.by_id.values_mut() {
            *index = index.saturating_sub(remove_count);
        }
    }
}

impl TransactionStore {
    pub fn new() -> Self {
        Self::from_records(Vec::new())
    }

    pub fn from_records(records: Vec<TransactionRecord>) -> Self {
        Self::from_records_with_max_entries(records, None)
    }

    pub fn from_records_with_max_entries(
        records: Vec<TransactionRecord>,
        max_entries: Option<usize>,
    ) -> Self {
        let (events, _) = broadcast::channel(256);
        let mut inner = StoreInner::from_newest_first(records);
        if let Some(max_entries) = max_entries {
            inner.trim_to_max_entries(max_entries);
        }
        // Resume sequence from the highest existing number.
        let max_seq = inner.entries.iter().map(|r| r.sequence).max().unwrap_or(0);
        Self {
            inner: RwLock::new(inner),
            events,
            journal_tx: None,
            max_entries,
            next_sequence: AtomicU64::new(max_seq + 1),
        }
    }

    pub fn from_records_with_journal(
        records: Vec<TransactionRecord>,
        journal_path: PathBuf,
        max_entries: Option<usize>,
    ) -> Self {
        let mut store = Self::from_records_with_max_entries(records, max_entries);
        store.journal_tx = start_transaction_journal_writer(journal_path);
        store
    }

    pub async fn insert(&self, mut record: TransactionRecord) {
        let mut inner = self.inner.write().await;
        record.sequence = self.next_sequence.fetch_add(1, Ordering::Relaxed);
        let journal_line = self
            .journal_tx
            .as_ref()
            .and_then(|_| encode_transaction_insert_journal_line(&record));
        if let (Some(tx), Some(line)) = (&self.journal_tx, journal_line) {
            if let Err(error) = append_transaction_journal(tx, line).await {
                warn!(
                    ?error,
                    "failed to append transaction insert journal entry before storing"
                );
            }
        }
        let summary = record.summary();
        inner.push(record, summary.clone());
        if let Some(max_entries) = self.max_entries {
            inner.trim_to_max_entries(max_entries);
        }
        drop(inner);
        let _ = self.events.send(summary);
    }

    pub async fn list(&self, filters: &ListFilters) -> Vec<TransactionSummary> {
        self.list_page(filters).await.items
    }

    pub async fn list_page(&self, filters: &ListFilters) -> TransactionListPage {
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
        let offset = filters.offset.unwrap_or(0);
        let before_sequence = filters.before_sequence;
        let advanced_matcher = AdvancedSearchMatcher::new(filters);

        if can_stream_in_storage_order(filters) {
            let inner = self.inner.read().await;
            let total = inner.summaries.len();
            let scan_end = newest_scan_end(&inner.summaries, before_sequence);
            let mut matched_count = 0usize;
            let mut exhausted = true;
            let mut items = if limit == 0 {
                Vec::new()
            } else {
                Vec::with_capacity(limit.min(total.saturating_sub(offset)))
            };
            let stop_after = if limit == 0 {
                None
            } else {
                Some(offset.saturating_add(limit).saturating_add(1))
            };

            for cached in inner.summaries[..scan_end].iter().rev() {
                if !matches_filters(
                    cached,
                    query.as_deref(),
                    method.as_deref(),
                    host.as_deref(),
                    status_pred.as_ref(),
                    since_dt.as_ref(),
                    mime.as_deref(),
                    None,
                    filters,
                    advanced_matcher.as_ref(),
                ) {
                    continue;
                }

                let matched_index = matched_count;
                matched_count += 1;
                if matched_index >= offset && (limit == 0 || items.len() < limit) {
                    items.push(cached.summary.clone());
                }
                if stop_after.is_some_and(|threshold| matched_count >= threshold) {
                    exhausted = false;
                    break;
                }
            }
            let has_more = limit != 0 && matched_count > offset.saturating_add(items.len());

            return TransactionListPage {
                has_more,
                items,
                total,
                filtered_total: (exhausted && before_sequence.is_none()).then_some(matched_count),
                offset,
                limit,
            };
        }

        let inner = self.inner.read().await;
        let total = inner.summaries.len();

        let mut filtered: Vec<_> = inner
            .summaries
            .iter()
            .rev()
            .filter(|cached| {
                matches_filters(
                    cached,
                    query.as_deref(),
                    method.as_deref(),
                    host.as_deref(),
                    status_pred.as_ref(),
                    since_dt.as_ref(),
                    mime.as_deref(),
                    before_sequence,
                    filters,
                    advanced_matcher.as_ref(),
                )
            })
            .collect();
        let filtered_total = filtered.len();

        sort_filtered_records(&mut filtered, filters);

        let items: Vec<TransactionSummary> = if limit == 0 {
            // limit=0 means unlimited
            filtered
                .into_iter()
                .skip(offset)
                .map(|cached| cached.summary.clone())
                .collect()
        } else {
            filtered
                .into_iter()
                .skip(offset)
                .take(limit)
                .map(|cached| cached.summary.clone())
                .collect()
        };

        TransactionListPage {
            has_more: limit != 0 && offset.saturating_add(items.len()) < filtered_total,
            items,
            total,
            filtered_total: before_sequence.is_none().then_some(filtered_total),
            offset,
            limit,
        }
    }

    pub async fn get(&self, id: Uuid) -> Option<TransactionRecord> {
        let inner = self.inner.read().await;
        let index = *inner.by_id.get(&id)?;
        inner.entries.get(index).cloned()
    }

    pub async fn snapshot(&self, limit: Option<usize>) -> Vec<TransactionRecord> {
        let inner = self.inner.read().await;
        snapshot_entries(&inner, limit)
    }

    pub async fn snapshot_for_persistence(
        &self,
        limit: Option<usize>,
    ) -> io::Result<Vec<TransactionRecord>> {
        let inner = self.inner.write().await;
        if let Some(tx) = &self.journal_tx {
            rotate_transaction_journal(tx)?;
        }
        Ok(snapshot_entries(&inner, limit))
    }

    pub async fn update_annotations(
        &self,
        id: Uuid,
        color_tag: Option<Option<String>>,
        user_note: Option<Option<String>>,
    ) -> Option<TransactionSummary> {
        let color_patch = nullable_string_patch(color_tag.as_ref());
        let note_patch = nullable_string_patch(user_note.as_ref());
        let mut inner = self.inner.write().await;
        let index = *inner.by_id.get(&id)?;
        if color_patch.is_some() || note_patch.is_some() {
            if let Some(tx) = &self.journal_tx {
                if let Some(line) =
                    encode_transaction_journal_line(&TransactionJournalEntry::Annotation {
                        id,
                        color_tag: color_patch,
                        user_note: note_patch,
                    })
                {
                    if let Err(error) = append_transaction_journal(tx, line).await {
                        warn!(
                            ?error,
                            "failed to append transaction annotation journal entry before storing"
                        );
                    }
                }
            }
        }
        let record = inner.entries.get_mut(index)?;
        if let Some(tag) = color_tag {
            record.color_tag = tag;
        }
        if let Some(note) = user_note {
            record.user_note = note;
        }
        let summary = record.summary();
        inner.summaries[index] = CachedSummary::new(summary.clone());
        Some(summary)
    }

    pub async fn replace_all(&self, records: Vec<TransactionRecord>) {
        let mut inner = StoreInner::from_newest_first(records);
        if let Some(max_entries) = self.max_entries {
            inner.trim_to_max_entries(max_entries);
        }
        let max_seq = inner.entries.iter().map(|r| r.sequence).max().unwrap_or(0);
        *self.inner.write().await = inner;
        self.next_sequence.store(max_seq + 1, Ordering::Relaxed);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<TransactionSummary> {
        self.events.subscribe()
    }

    pub fn latest_sequence(&self) -> u64 {
        self.next_sequence.load(Ordering::Relaxed).saturating_sub(1)
    }
}

impl Default for TransactionStore {
    fn default() -> Self {
        Self::new()
    }
}

fn normalize_storage_sequences(entries: &mut [TransactionRecord]) {
    let needs_repair = entries
        .iter()
        .try_fold(0u64, |previous, record| {
            (record.sequence > previous).then_some(record.sequence)
        })
        .is_none();
    if !needs_repair {
        return;
    }

    for (index, record) in entries.iter_mut().enumerate() {
        record.sequence = (index as u64).saturating_add(1);
    }
}

fn can_stream_in_storage_order(filters: &ListFilters) -> bool {
    let key = filters.sort_key.as_deref().unwrap_or("index");
    let direction = filters.sort_direction.as_deref().unwrap_or("desc");
    direction == "desc" && key == "index"
}

fn newest_scan_end(summaries: &[CachedSummary], before_sequence: Option<u64>) -> usize {
    before_sequence
        .map(|before| summaries.partition_point(|cached| cached.summary.sequence < before))
        .unwrap_or(summaries.len())
}

fn snapshot_entries(inner: &StoreInner, limit: Option<usize>) -> Vec<TransactionRecord> {
    match limit {
        Some(n) => inner.entries.iter().rev().take(n).cloned().collect(),
        None => inner.entries.iter().rev().cloned().collect(),
    }
}

fn start_transaction_journal_writer(
    journal_path: PathBuf,
) -> Option<mpsc::Sender<TransactionJournalCommand>> {
    let (tx, rx) = mpsc::channel::<TransactionJournalCommand>();
    let spawn_result = thread::Builder::new()
        .name("sniper-transaction-journal".to_string())
        .spawn(move || {
            if let Some(parent) = journal_path.parent() {
                if let Err(error) = fs::create_dir_all(parent) {
                    warn!(?error, path = %parent.display(), "failed to create transaction journal directory");
                    return;
                }
            }

            let mut file = match OpenOptions::new()
                .create(true)
                .append(true)
                .open(&journal_path)
            {
                Ok(file) => file,
                Err(error) => {
                    warn!(?error, path = %journal_path.display(), "failed to open transaction journal");
                    return;
                }
            };

            while let Ok(command) = rx.recv() {
                match command {
                    TransactionJournalCommand::Append { line, ack } => {
                        let result = file.write_all(&line);
                        let failed = result.is_err();
                        if let Err(error) = &result {
                            warn!(?error, path = %journal_path.display(), "failed to append transaction journal entry");
                        }
                        if let Some(ack) = ack {
                            let _ = ack.send(result);
                        }
                        if failed {
                            return;
                        }
                    }
                    TransactionJournalCommand::Rotate { ack } => {
                        let result = rotate_transaction_journal_file(&mut file, &journal_path);
                        if let Err(error) = &result {
                            warn!(?error, path = %journal_path.display(), "failed to rotate transaction journal");
                        }
                        let failed = result.is_err();
                        let _ = ack.send(result);
                        if failed {
                            return;
                        }
                    }
                }
            }
        });

    match spawn_result {
        Ok(_) => Some(tx),
        Err(error) => {
            warn!(?error, "failed to spawn transaction journal writer");
            None
        }
    }
}

fn rotate_transaction_journal(tx: &mpsc::Sender<TransactionJournalCommand>) -> io::Result<()> {
    let (ack, rx) = mpsc::channel();
    tx.send(TransactionJournalCommand::Rotate { ack })
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "transaction journal writer stopped",
            )
        })?;
    rx.recv().map_err(|_| {
        io::Error::new(
            io::ErrorKind::BrokenPipe,
            "transaction journal writer stopped",
        )
    })?
}

async fn append_transaction_journal(
    tx: &mpsc::Sender<TransactionJournalCommand>,
    line: Vec<u8>,
) -> io::Result<()> {
    let (ack, rx) = oneshot::channel();
    tx.send(TransactionJournalCommand::Append {
        line,
        ack: Some(ack),
    })
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::BrokenPipe,
            "transaction journal writer stopped",
        )
    })?;
    rx.await.map_err(|_| {
        io::Error::new(
            io::ErrorKind::BrokenPipe,
            "transaction journal writer stopped",
        )
    })?
}

fn rotate_transaction_journal_file(file: &mut fs::File, journal_path: &Path) -> io::Result<()> {
    file.flush()?;
    let active = match fs::read(journal_path) {
        Ok(active) => active,
        Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(error) => return Err(error),
    };

    if !active.is_empty() {
        let checkpoint_path = transaction_journal_checkpoint_path(journal_path);
        if let Some(parent) = checkpoint_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut checkpoint = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&checkpoint_path)?;
        checkpoint.write_all(&active)?;
        checkpoint.flush()?;
    }

    file.set_len(0)?;
    file.flush()
}

pub(crate) fn transaction_journal_checkpoint_path(journal_path: &Path) -> PathBuf {
    let file_name = journal_path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("transactions.journal");
    journal_path.with_file_name(format!("{file_name}.checkpoint"))
}

fn encode_transaction_insert_journal_line(record: &TransactionRecord) -> Option<Vec<u8>> {
    let entry = TransactionJournalInsert {
        entry_type: "insert",
        record,
    };
    encode_transaction_journal_line(&entry)
}

fn encode_transaction_journal_line(entry: &impl Serialize) -> Option<Vec<u8>> {
    match serde_json::to_vec(entry) {
        Ok(mut line) => {
            line.push(b'\n');
            Some(line)
        }
        Err(error) => {
            warn!(?error, "failed to encode transaction journal entry");
            None
        }
    }
}

fn nullable_string_patch(value: Option<&Option<String>>) -> Option<NullableStringPatch> {
    value.map(|patch| match patch {
        Some(value) => NullableStringPatch::Set(value.clone()),
        None => NullableStringPatch::Clear,
    })
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
    cached: &CachedSummary,
    query: Option<&str>,
    method: Option<&str>,
    host: Option<&str>,
    status_pred: Option<&StatusPredicate>,
    since: Option<&chrono::DateTime<chrono::Utc>>,
    mime: Option<&str>,
    before_sequence: Option<u64>,
    filters: &ListFilters,
    advanced_matcher: Option<&AdvancedSearchMatcher>,
) -> bool {
    let summary = &cached.summary;

    if let Some(before) = before_sequence {
        if summary.sequence >= before {
            return false;
        }
    }

    if let Some(m) = method {
        if cached.method_upper != m {
            return false;
        }
    }

    if let Some(h) = host {
        if !cached.host_lower.contains(h) {
            return false;
        }
    }

    if let Some(pred) = status_pred {
        if !pred.matches(summary.status) {
            return false;
        }
    }

    if let Some(since_dt) = since {
        if summary.started_at < *since_dt {
            return false;
        }
    }

    if let Some(mime_filter) = mime {
        if !cached.content_type_lower.contains(mime_filter) {
            return false;
        }
    }

    if filters.in_scope_only && !summary_matches_scope(&summary.host, &filters.scope_patterns) {
        return false;
    }

    if filters.hide_connect && summary.method == "CONNECT" {
        return false;
    }

    if filters.hide_without_responses && !summary.has_response {
        return false;
    }

    if filters.only_parameterized && !summary.path.contains('?') {
        return false;
    }

    if filters.only_notes && summary.note_count == 0 {
        return false;
    }

    if !matches_status_classes(summary.status, filters.status_classes.as_deref()) {
        return false;
    }

    if !matches_mime_types(cached.mime, filters.mime_types.as_deref()) {
        return false;
    }

    if !matches_hidden_extensions(cached.path_extension.as_deref(), &filters.hidden_extensions) {
        return false;
    }

    if !matches_port_filter(cached.port.as_deref(), filters.port.as_deref()) {
        return false;
    }

    if !matches_color_tags(summary.color_tag.as_deref(), &filters.color_tags) {
        return false;
    }

    if let Some(matcher) = advanced_matcher {
        if !matcher.matches(cached) {
            return false;
        }
    }

    let Some(value) = query else { return true };
    cached.quick_haystack.contains(value)
}

fn sort_filtered_records(records: &mut [&CachedSummary], filters: &ListFilters) {
    let key = filters.sort_key.as_deref().unwrap_or("index");
    let direction = filters.sort_direction.as_deref().unwrap_or("desc");
    let ascending = direction == "asc";

    match key {
        "index" => records.sort_by(|left, right| compare_sequence(left, right)),
        "host" => records.sort_by(|left, right| {
            left.host_lower
                .cmp(&right.host_lower)
                .then_with(|| compare_sequence(left, right))
        }),
        "method" => records.sort_by(|left, right| {
            left.method_upper
                .cmp(&right.method_upper)
                .then_with(|| compare_sequence(left, right))
        }),
        "path" => records.sort_by(|left, right| {
            left.path_lower
                .cmp(&right.path_lower)
                .then_with(|| compare_sequence(left, right))
        }),
        "status" => records.sort_by(|left, right| {
            left.summary
                .status
                .unwrap_or(0)
                .cmp(&right.summary.status.unwrap_or(0))
                .then_with(|| compare_sequence(left, right))
        }),
        "length" => records.sort_by(|left, right| {
            left.total_bytes
                .cmp(&right.total_bytes)
                .then_with(|| compare_sequence(left, right))
        }),
        "mime" => records.sort_by(|left, right| {
            left.mime
                .cmp(right.mime)
                .then_with(|| compare_sequence(left, right))
        }),
        "notes" => records.sort_by(|left, right| {
            left.summary
                .note_count
                .cmp(&right.summary.note_count)
                .then_with(|| compare_sequence(left, right))
        }),
        "tls" => records.sort_by(|left, right| {
            left.is_tls
                .cmp(&right.is_tls)
                .then_with(|| compare_sequence(left, right))
        }),
        "started_at" => records.sort_by(|left, right| compare_started_at(left, right)),
        _ => records.sort_by(|left, right| compare_started_at(left, right)),
    }

    if !ascending {
        records.reverse();
    }
}

fn compare_sequence(left: &CachedSummary, right: &CachedSummary) -> std::cmp::Ordering {
    left.summary.sequence.cmp(&right.summary.sequence)
}

fn compare_started_at(left: &CachedSummary, right: &CachedSummary) -> std::cmp::Ordering {
    left.summary
        .started_at
        .cmp(&right.summary.started_at)
        .then_with(|| compare_sequence(left, right))
}

fn infer_summary_mime(summary: &TransactionSummary) -> &'static str {
    let content_type = summary
        .content_type
        .as_deref()
        .unwrap_or("")
        .to_ascii_lowercase();
    if content_type.contains("html") {
        return "html";
    }
    if content_type.contains("javascript") {
        return "script";
    }
    if content_type.contains("css") {
        return "css";
    }
    if content_type.contains("json") || content_type.contains("text") {
        return "json";
    }
    if content_type.contains("image") {
        return "image";
    }
    let path = summary.path.to_ascii_lowercase();
    if path.ends_with(".js") {
        return "script";
    }
    if path.ends_with(".css") {
        return "css";
    }
    if path.ends_with(".json") {
        return "json";
    }
    if path.ends_with(".html") {
        return "html";
    }
    if [".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico"]
        .iter()
        .any(|extension| path.ends_with(extension))
    {
        return "image";
    }
    if summary.is_websocket {
        return "websocket";
    }
    "other"
}

fn summary_total_bytes(summary: &TransactionSummary) -> usize {
    summary.request_bytes + summary.response_bytes
}

fn is_tls_summary(summary: &TransactionSummary) -> bool {
    matches!(summary.kind, TrafficKind::Tunnel) || summary.scheme == "https"
}

fn matches_status_classes(status: Option<u16>, classes: Option<&[String]>) -> bool {
    let Some(classes) = classes else {
        return true;
    };

    let class = match status {
        Some(value) if (200..300).contains(&value) => "success",
        Some(value) if (300..400).contains(&value) => "redirect",
        Some(value) if (400..500).contains(&value) => "client_error",
        Some(value) if (500..600).contains(&value) => "server_error",
        _ => "other",
    };
    classes.iter().any(|value| value == class)
}

fn matches_mime_types(mime: &str, mime_types: Option<&[String]>) -> bool {
    let Some(mime_types) = mime_types else {
        return true;
    };
    mime_types.iter().any(|value| value == mime)
}

fn matches_hidden_extensions(extension: Option<&str>, hidden_extensions: &[String]) -> bool {
    if hidden_extensions.is_empty() {
        return true;
    }
    let Some(extension) = extension else {
        return true;
    };
    !hidden_extensions
        .iter()
        .any(|value| value.as_str() == extension)
}

fn matches_port_filter(actual: Option<&str>, port: Option<&str>) -> bool {
    let Some(expected) = port.filter(|value| !value.is_empty()) else {
        return true;
    };
    actual.unwrap_or("") == expected
}

fn matches_color_tags(color_tag: Option<&str>, color_tags: &[String]) -> bool {
    if color_tags.is_empty() {
        return true;
    }
    color_tag
        .map(|tag| color_tags.iter().any(|value| value == tag))
        .unwrap_or(false)
}

fn extract_path_extension(path: &str) -> Option<String> {
    let clean = path.split('?').next().unwrap_or(path);
    let (_, extension) = clean.rsplit_once('.')?;
    if extension.is_empty() || !extension.chars().all(|ch| ch.is_ascii_alphanumeric()) {
        return None;
    }
    Some(extension.to_ascii_lowercase())
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

fn extract_host_port(host: &str) -> Option<&str> {
    let trimmed = host.trim();
    if let Some(rest) = trimmed.strip_prefix('[') {
        let end = rest.find(']')?;
        return rest[end + 1..]
            .strip_prefix(':')
            .filter(|port| !port.is_empty());
    }
    if trimmed.matches(':').count() == 1 {
        return trimmed
            .split_once(':')
            .map(|(_, port)| port)
            .filter(|port| !port.is_empty());
    }
    None
}

fn format_size(bytes: usize) -> String {
    if bytes == 0 {
        return "0 B".to_string();
    }

    let units = ["B", "KB", "MB", "GB"];
    let mut size = bytes as f64;
    let mut index = 0;
    while size >= 1024.0 && index < units.len() - 1 {
        size /= 1024.0;
        index += 1;
    }
    let precision = if size >= 10.0 || index == 0 { 0 } else { 1 };
    format!("{size:.precision$} {}", units[index])
}

enum AdvancedSearchMatcher {
    Plain {
        needle: String,
        case_sensitive: bool,
        negative: bool,
    },
    Regex {
        regex: Regex,
        negative: bool,
    },
    Always(bool),
}

impl AdvancedSearchMatcher {
    fn new(filters: &ListFilters) -> Option<Self> {
        let term = filters.advanced_search.as_deref()?.trim();
        if term.is_empty() {
            return None;
        }

        if filters.advanced_regex {
            return Some(
                RegexBuilder::new(term)
                    .case_insensitive(!filters.advanced_case_sensitive)
                    .build()
                    .map(|regex| Self::Regex {
                        regex,
                        negative: filters.advanced_negative,
                    })
                    .unwrap_or(Self::Always(!filters.advanced_negative)),
            );
        }

        Some(Self::Plain {
            needle: if filters.advanced_case_sensitive {
                term.to_string()
            } else {
                term.to_ascii_lowercase()
            },
            case_sensitive: filters.advanced_case_sensitive,
            negative: filters.advanced_negative,
        })
    }

    fn matches(&self, cached: &CachedSummary) -> bool {
        match self {
            Self::Plain {
                needle,
                case_sensitive,
                negative,
            } => {
                let matched = if *case_sensitive {
                    cached.advanced_haystack.contains(needle)
                } else {
                    cached.advanced_haystack_lower.contains(needle)
                };
                if *negative {
                    !matched
                } else {
                    matched
                }
            }
            Self::Regex { regex, negative } => {
                let matched = regex.is_match(&cached.advanced_haystack);
                if *negative {
                    !matched
                } else {
                    matched
                }
            }
            Self::Always(value) => *value,
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};

    use super::*;
    use crate::model::{BodyEncoding, MessageRecord, TransactionRecord};

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
            content_decoded: false,
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

        let older_than_second = store
            .list(&ListFilters {
                limit: Some(10),
                before_sequence: Some(all[1].sequence),
                ..Default::default()
            })
            .await;
        assert_eq!(older_than_second.len(), 1);
        assert_eq!(older_than_second[0].host, "one.local");

        let page = store
            .list_page(&ListFilters {
                limit: Some(1),
                offset: Some(1),
                sort_key: Some("index".into()),
                sort_direction: Some("desc".into()),
                ..Default::default()
            })
            .await;
        assert_eq!(page.total, 3);
        assert_eq!(page.filtered_total, None);
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].host, "two.local");
        assert!(page.has_more);

        let searched = store
            .list_page(&ListFilters {
                query: Some("resource".into()),
                limit: Some(10),
                ..Default::default()
            })
            .await;
        assert_eq!(searched.filtered_total, Some(1));
        assert_eq!(searched.items[0].host, "three.local");
    }

    #[tokio::test]
    async fn store_applies_live_retention_limit() {
        let store = TransactionStore::from_records_with_max_entries(Vec::new(), Some(2));
        let empty_message = MessageRecord {
            headers: Vec::new(),
            body_preview: String::new(),
            body_encoding: BodyEncoding::Utf8,
            body_size: 0,
            preview_truncated: false,
            content_type: None,
            content_decoded: false,
        };

        for index in 0..5 {
            store
                .insert(TransactionRecord::http(
                    Utc::now(),
                    "GET".into(),
                    "https".into(),
                    format!("{}.local", index),
                    format!("/{index}"),
                    Some(200),
                    index,
                    empty_message.clone(),
                    None,
                    Vec::new(),
                    None,
                    None,
                ))
                .await;
        }

        let all = store.snapshot(None).await;
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].host, "4.local");
        assert_eq!(all[1].host, "3.local");
        assert!(store.get(all[0].id).await.is_some());
    }

    #[tokio::test]
    async fn storage_order_paging_uses_sequence_cursor_without_duplicates() {
        let store = TransactionStore::new();
        let empty_message = MessageRecord {
            headers: Vec::new(),
            body_preview: String::new(),
            body_encoding: BodyEncoding::Utf8,
            body_size: 0,
            preview_truncated: false,
            content_type: None,
            content_decoded: false,
        };

        for index in 0..8 {
            store
                .insert(TransactionRecord::http(
                    Utc::now(),
                    "GET".into(),
                    "https".into(),
                    format!("{index}.local"),
                    format!("/{index}"),
                    Some(200),
                    index,
                    empty_message.clone(),
                    None,
                    Vec::new(),
                    None,
                    None,
                ))
                .await;
        }

        let first_page = store
            .list_page(&ListFilters {
                limit: Some(3),
                sort_key: Some("index".into()),
                sort_direction: Some("desc".into()),
                ..Default::default()
            })
            .await;
        assert_eq!(
            first_page
                .items
                .iter()
                .map(|item| item.host.as_str())
                .collect::<Vec<_>>(),
            vec!["7.local", "6.local", "5.local"]
        );
        assert!(first_page.has_more);

        let second_page = store
            .list_page(&ListFilters {
                limit: Some(3),
                before_sequence: first_page.items.last().map(|item| item.sequence),
                sort_key: Some("index".into()),
                sort_direction: Some("desc".into()),
                ..Default::default()
            })
            .await;
        assert_eq!(
            second_page
                .items
                .iter()
                .map(|item| item.host.as_str())
                .collect::<Vec<_>>(),
            vec!["4.local", "3.local", "2.local"]
        );
        assert!(second_page.has_more);

        let final_page = store
            .list_page(&ListFilters {
                limit: Some(3),
                before_sequence: second_page.items.last().map(|item| item.sequence),
                sort_key: Some("index".into()),
                sort_direction: Some("desc".into()),
                ..Default::default()
            })
            .await;
        assert_eq!(
            final_page
                .items
                .iter()
                .map(|item| item.host.as_str())
                .collect::<Vec<_>>(),
            vec!["1.local", "0.local"]
        );
        assert!(!final_page.has_more);
    }

    #[tokio::test]
    async fn storage_order_paging_repairs_legacy_zero_sequences() {
        let empty_message = MessageRecord {
            headers: Vec::new(),
            body_preview: String::new(),
            body_encoding: BodyEncoding::Utf8,
            body_size: 0,
            preview_truncated: false,
            content_type: None,
            content_decoded: false,
        };
        let mut records = Vec::new();
        for index in 0..8 {
            records.push(TransactionRecord::http(
                Utc::now(),
                "GET".into(),
                "https".into(),
                format!("{index}.legacy"),
                format!("/{index}"),
                Some(200),
                index,
                empty_message.clone(),
                None,
                Vec::new(),
                None,
                None,
            ));
        }

        let store = TransactionStore::from_records(records.into_iter().rev().collect());
        let first_page = store
            .list_page(&ListFilters {
                limit: Some(3),
                sort_key: Some("index".into()),
                sort_direction: Some("desc".into()),
                ..Default::default()
            })
            .await;
        let second_page = store
            .list_page(&ListFilters {
                limit: Some(3),
                before_sequence: first_page.items.last().map(|item| item.sequence),
                sort_key: Some("index".into()),
                sort_direction: Some("desc".into()),
                ..Default::default()
            })
            .await;

        assert_eq!(
            first_page
                .items
                .iter()
                .map(|item| item.host.as_str())
                .collect::<Vec<_>>(),
            vec!["7.legacy", "6.legacy", "5.legacy"]
        );
        assert_eq!(
            second_page
                .items
                .iter()
                .map(|item| item.host.as_str())
                .collect::<Vec<_>>(),
            vec!["4.legacy", "3.legacy", "2.legacy"]
        );
        assert!(first_page.items.iter().all(|item| item.sequence > 0));
    }

    #[tokio::test]
    async fn started_at_sort_uses_timestamp_not_insert_sequence() {
        let store = TransactionStore::new();
        let empty_message = MessageRecord {
            headers: Vec::new(),
            body_preview: String::new(),
            body_encoding: BodyEncoding::Utf8,
            body_size: 0,
            preview_truncated: false,
            content_type: None,
            content_decoded: false,
        };
        let base = Utc::now();

        store
            .insert(TransactionRecord::http(
                base + Duration::seconds(1),
                "GET".into(),
                "https".into(),
                "newer-start.local".into(),
                "/newer".into(),
                Some(200),
                1,
                empty_message.clone(),
                None,
                Vec::new(),
                None,
                None,
            ))
            .await;
        store
            .insert(TransactionRecord::http(
                base,
                "GET".into(),
                "https".into(),
                "older-start.local".into(),
                "/older".into(),
                Some(200),
                1,
                empty_message,
                None,
                Vec::new(),
                None,
                None,
            ))
            .await;

        let page = store
            .list_page(&ListFilters {
                sort_key: Some("started_at".into()),
                sort_direction: Some("desc".into()),
                limit: Some(10),
                ..Default::default()
            })
            .await;

        assert_eq!(page.items[0].host, "newer-start.local");
        assert_eq!(page.items[1].host, "older-start.local");
    }

    #[tokio::test]
    async fn css_mime_filter_matches_text_css_before_generic_text() {
        let store = TransactionStore::new();
        let request = MessageRecord {
            headers: Vec::new(),
            body_preview: String::new(),
            body_encoding: BodyEncoding::Utf8,
            body_size: 0,
            preview_truncated: false,
            content_type: None,
            content_decoded: false,
        };
        let response = MessageRecord {
            content_type: Some("text/css; charset=utf-8".into()),
            ..request.clone()
        };

        store
            .insert(TransactionRecord::http(
                Utc::now(),
                "GET".into(),
                "https".into(),
                "assets.local:443".into(),
                "/style".into(),
                Some(200),
                1,
                request,
                Some(response),
                Vec::new(),
                None,
                None,
            ))
            .await;

        let css = store
            .list(&ListFilters {
                mime_types: Some(vec!["css".into()]),
                ..Default::default()
            })
            .await;
        let json = store
            .list(&ListFilters {
                mime_types: Some(vec!["json".into()]),
                ..Default::default()
            })
            .await;

        assert_eq!(css.len(), 1);
        assert!(json.is_empty());
    }

    #[tokio::test]
    async fn port_and_scope_filters_handle_bracketed_ipv6_hosts() {
        let store = TransactionStore::new();
        let empty_message = MessageRecord {
            headers: Vec::new(),
            body_preview: String::new(),
            body_encoding: BodyEncoding::Utf8,
            body_size: 0,
            preview_truncated: false,
            content_type: None,
            content_decoded: false,
        };

        store
            .insert(TransactionRecord::http(
                Utc::now(),
                "GET".into(),
                "https".into(),
                "[::1]:9443".into(),
                "/ipv6".into(),
                Some(200),
                1,
                empty_message,
                None,
                Vec::new(),
                None,
                None,
            ))
            .await;

        let filtered = store
            .list(&ListFilters {
                port: Some("9443".into()),
                in_scope_only: true,
                scope_patterns: vec!["::1".into()],
                ..Default::default()
            })
            .await;

        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].host, "[::1]:9443");
    }
}
