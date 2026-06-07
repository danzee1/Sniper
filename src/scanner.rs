use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::atomic::{AtomicU64, Ordering},
};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, RwLock};
use uuid::Uuid;

use crate::model::{BodyEncoding, MessageRecord, TransactionRecord};

const MAX_SCANNER_BROADCAST_CAPACITY: usize = 4096;

// ── Scanner config ──

/// Built-in rule identifiers.
pub const BUILTIN_RULES: &[(&str, &str)] = &[
    ("jwt", "JWT Analysis"),
    ("header", "Security Headers"),
    ("cookie", "Cookie Flags"),
    ("disclosure", "Sensitive Data Exposure"),
    ("cors", "CORS Misconfiguration"),
    ("server", "Server Disclosure"),
    ("error", "Error Messages"),
    ("misconfig", "Security Misconfiguration"),
    ("info", "Information Disclosure"),
    ("auth", "Authentication Issues"),
];

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CustomRule {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    /// Where to search: "response_body", "response_header", "request_header"
    pub target: String,
    /// For header targets, the header name to check.
    #[serde(default)]
    pub header_name: String,
    pub pattern: String,
    pub severity: Severity,
    pub category: String,
    pub description: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScannerConfig {
    #[serde(default = "default_scanner_enabled")]
    pub enabled: bool,
    /// Per-rule toggle. Key = rule id (e.g. "jwt", "header"), value = enabled.
    #[serde(default = "default_rule_toggles")]
    pub rules: HashMap<String, bool>,
    #[serde(default)]
    pub custom_rules: Vec<CustomRule>,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            rules: default_rule_toggles(),
            custom_rules: Vec::new(),
        }
    }
}

fn default_scanner_enabled() -> bool {
    true
}

fn default_rule_toggles() -> HashMap<String, bool> {
    let mut rules = HashMap::new();
    for &(id, _) in BUILTIN_RULES {
        rules.insert(id.to_string(), true);
    }
    rules
}

impl ScannerConfig {
    pub fn is_rule_enabled(&self, rule_id: &str) -> bool {
        self.enabled && *self.rules.get(rule_id).unwrap_or(&true)
    }
}

// ── Finding model ──

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScannerFinding {
    pub id: Uuid,
    pub record_id: Uuid,
    pub found_at: DateTime<Utc>,
    pub severity: Severity,
    pub category: String,
    pub title: String,
    pub detail: String,
    pub evidence: String,
    pub host: String,
    pub path: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FindingSummary {
    pub id: Uuid,
    pub record_id: Uuid,
    pub found_at: DateTime<Utc>,
    pub severity: Severity,
    pub category: String,
    pub title: String,
    pub host: String,
    pub path: String,
}

impl ScannerFinding {
    pub fn summary(&self) -> FindingSummary {
        FindingSummary {
            id: self.id,
            record_id: self.record_id,
            found_at: self.found_at,
            severity: self.severity.clone(),
            category: self.category.clone(),
            title: self.title.clone(),
            host: self.host.clone(),
            path: self.path.clone(),
        }
    }
}

// ── Finding store ──

pub struct ScannerStore {
    max_entries: usize,
    entries: RwLock<VecDeque<ScannerFinding>>,
    events: broadcast::Sender<FindingSummary>,
    config: RwLock<ScannerConfig>,
    seen: RwLock<HashSet<FindingDedupKey>>,
    clear_generation: AtomicU64,
}

impl ScannerStore {
    pub fn new(max_entries: usize) -> Self {
        let (events, _) = broadcast::channel(max_entries.clamp(64, MAX_SCANNER_BROADCAST_CAPACITY));
        Self {
            max_entries,
            entries: RwLock::new(VecDeque::new()),
            events,
            config: RwLock::new(ScannerConfig::default()),
            seen: RwLock::new(HashSet::new()),
            clear_generation: AtomicU64::new(0),
        }
    }

    /// Push a finding, deduplicating by transaction+host+path+category+title.
    pub async fn push(&self, finding: ScannerFinding) -> bool {
        self.push_inner(finding, None).await
    }

    pub fn clear_generation(&self) -> u64 {
        self.clear_generation.load(Ordering::Acquire)
    }

    pub fn restore_clear_generation(&self, generation: u64) {
        self.clear_generation.store(generation, Ordering::Release);
    }

    pub async fn push_if_generation(&self, finding: ScannerFinding, generation: u64) -> bool {
        self.push_inner(finding, Some(generation)).await
    }

    async fn push_inner(&self, finding: ScannerFinding, generation: Option<u64>) -> bool {
        let dedup_key = finding_dedup_key(&finding);
        let summary = finding.summary();
        let mut entries = self.entries.write().await;
        let mut seen = self.seen.write().await;
        if generation.is_some_and(|expected| self.clear_generation() != expected) {
            return false;
        }
        if !seen.insert(dedup_key) {
            return false; // duplicate — skip
        }
        entries.push_front(finding);
        while entries.len() > self.max_entries {
            if let Some(evicted) = entries.pop_back() {
                seen.remove(&finding_dedup_key(&evicted));
            }
        }
        let _ = self.events.send(summary);
        true
    }

    pub async fn list(&self, limit: Option<usize>) -> Vec<FindingSummary> {
        let entries = self.entries.read().await;
        entries
            .iter()
            .take(limit.unwrap_or(self.max_entries).min(self.max_entries))
            .map(ScannerFinding::summary)
            .collect()
    }

    pub async fn get(&self, id: Uuid) -> Option<ScannerFinding> {
        let entries = self.entries.read().await;
        entries.iter().find(|f| f.id == id).cloned()
    }

    pub async fn clear(&self) {
        self.clear_generation.fetch_add(1, Ordering::AcqRel);
        self.entries.write().await.clear();
        self.seen.write().await.clear();
    }

    pub async fn replace_all(&self, findings: Vec<ScannerFinding>) {
        let mut entries = self.entries.write().await;
        let mut seen = self.seen.write().await;
        entries.clear();
        seen.clear();
        for finding in findings.into_iter().take(self.max_entries) {
            seen.insert(finding_dedup_key(&finding));
            entries.push_back(finding);
        }
    }

    pub async fn count(&self) -> usize {
        self.entries.read().await.len()
    }

    pub fn subscribe(&self) -> broadcast::Receiver<FindingSummary> {
        self.events.subscribe()
    }

    pub async fn get_config(&self) -> ScannerConfig {
        self.config.read().await.clone()
    }

    pub async fn update_config(&self, new_config: ScannerConfig) {
        *self.config.write().await = new_config;
    }

    /// Create a store pre-populated with persisted findings.
    pub fn from_findings(max_entries: usize, findings: Vec<ScannerFinding>) -> Self {
        Self::from_findings_with_config(max_entries, findings, ScannerConfig::default())
    }

    pub fn from_findings_with_config(
        max_entries: usize,
        findings: Vec<ScannerFinding>,
        config: ScannerConfig,
    ) -> Self {
        let (events, _) = broadcast::channel(max_entries.clamp(64, MAX_SCANNER_BROADCAST_CAPACITY));
        let findings: Vec<_> = findings.into_iter().take(max_entries).collect();
        let seen = findings.iter().map(finding_dedup_key).collect();
        Self {
            max_entries,
            entries: RwLock::new(VecDeque::from(findings)),
            events,
            config: RwLock::new(config),
            seen: RwLock::new(seen),
            clear_generation: AtomicU64::new(0),
        }
    }

    /// Take a snapshot of all findings for persistence.
    pub async fn snapshot(&self, limit: Option<usize>) -> Vec<ScannerFinding> {
        let entries = self.entries.read().await;
        entries
            .iter()
            .take(limit.unwrap_or(self.max_entries).min(self.max_entries))
            .cloned()
            .collect()
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct FindingDedupKey {
    record_id: Uuid,
    host: String,
    path: String,
    category: String,
    title: String,
}

fn finding_dedup_key(finding: &ScannerFinding) -> FindingDedupKey {
    FindingDedupKey {
        record_id: finding.record_id,
        host: finding.host.clone(),
        path: finding.path.clone(),
        category: finding.category.clone(),
        title: finding.title.clone(),
    }
}

// ── Scanner engine ──

/// Returns true when the message body is binary (base64-encoded).
/// Binary bodies (images, fonts, wasm, etc.) should be skipped by pattern-matching
/// rules because regex hits on raw base64 are almost always false positives.
fn is_binary_body(msg: &MessageRecord) -> bool {
    msg.body_encoding == BodyEncoding::Base64
}

/// Returns true if the regex match appears to be embedded inside a larger base64
/// string (e.g., base64-encoded ad payloads in JSON responses). Such matches are
/// almost always false positives — the token pattern coincidentally appears within
/// base64-encoded binary data.
fn is_embedded_in_base64(body: &str, m: &regex::Match) -> bool {
    let bytes = body.as_bytes();
    let start = m.start();
    let end = m.end();

    // Count continuous base64 chars before the match
    let pre = (0..start)
        .rev()
        .take_while(|&i| is_base64_char(bytes[i]))
        .count();

    // Count continuous base64 chars after the match
    let post = (end..bytes.len())
        .take_while(|&i| is_base64_char(bytes[i]))
        .count();

    // If 20+ base64 chars on each side, the match is embedded in base64 data
    pre >= 20 && post >= 20
}

#[inline]
fn is_base64_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'='
}

/// Run all passive scan rules against a transaction record, respecting config.
pub fn scan_transaction(record: &TransactionRecord, config: &ScannerConfig) -> Vec<ScannerFinding> {
    if !config.enabled {
        return Vec::new();
    }

    let mut findings = Vec::new();

    if config.is_rule_enabled("jwt") {
        check_jwt(record, &mut findings);
    }
    if config.is_rule_enabled("header") {
        check_security_headers(record, &mut findings);
    }
    if config.is_rule_enabled("cookie") {
        check_cookie_flags(record, &mut findings);
    }
    if config.is_rule_enabled("disclosure") {
        check_sensitive_data(record, &mut findings);
    }
    if config.is_rule_enabled("cors") {
        check_cors(record, &mut findings);
    }
    if config.is_rule_enabled("server") {
        check_server_disclosure(record, &mut findings);
    }
    if config.is_rule_enabled("error") {
        check_error_messages(record, &mut findings);
    }
    if config.is_rule_enabled("misconfig") {
        check_security_misconfig(record, &mut findings);
    }
    if config.is_rule_enabled("info") {
        check_info_disclosure(record, &mut findings);
    }
    if config.is_rule_enabled("auth") {
        check_auth_issues(record, &mut findings);
    }

    // Run enabled custom rules
    for rule in &config.custom_rules {
        if rule.enabled {
            check_custom_rule(record, rule, &mut findings);
        }
    }

    findings
}

/// Execute a single custom regex rule against the transaction.
fn check_custom_rule(
    record: &TransactionRecord,
    rule: &CustomRule,
    findings: &mut Vec<ScannerFinding>,
) {
    let re = match Regex::new(&rule.pattern) {
        Ok(re) => re,
        Err(_) => return, // invalid pattern — skip silently
    };

    let targets: Vec<(&str, String)> = match rule.target.as_str() {
        "response_body" => {
            if let Some(response) = &record.response {
                if is_binary_body(response) {
                    vec![]
                } else {
                    vec![("response body", response.body_preview.clone())]
                }
            } else {
                vec![]
            }
        }
        "response_header" => {
            if let Some(response) = &record.response {
                response
                    .headers
                    .iter()
                    .filter(|h| {
                        rule.header_name.is_empty()
                            || h.name.eq_ignore_ascii_case(&rule.header_name)
                    })
                    .map(|h| (h.name.as_str(), h.value.clone()))
                    .collect::<Vec<_>>()
                    .into_iter()
                    .map(|(n, v)| {
                        // Need to own the name for the tuple
                        (n as &str, v)
                    })
                    .collect::<Vec<_>>()
            } else {
                vec![]
            }
        }
        "request_header" => record
            .request
            .headers
            .iter()
            .filter(|h| {
                rule.header_name.is_empty() || h.name.eq_ignore_ascii_case(&rule.header_name)
            })
            .map(|h| ("request header", h.value.clone()))
            .collect(),
        _ => vec![],
    };

    for (_source, text) in targets {
        if let Some(m) = re.find(&text) {
            findings.push(make_finding(
                record,
                rule.severity.clone(),
                &rule.category,
                &rule.name,
                &rule.description,
                truncate_evidence(m.as_str(), 120),
            ));
            break; // one match per rule per request is enough
        }
    }
}

fn make_finding(
    record: &TransactionRecord,
    severity: Severity,
    category: &str,
    title: impl Into<String>,
    detail: impl Into<String>,
    evidence: impl Into<String>,
) -> ScannerFinding {
    ScannerFinding {
        id: Uuid::new_v4(),
        record_id: record.id,
        found_at: Utc::now(),
        severity,
        category: category.to_string(),
        title: title.into(),
        detail: detail.into(),
        evidence: evidence.into(),
        host: record.host.clone(),
        path: record.path.clone(),
    }
}

// ── Rule 1: JWT Analysis ──

fn check_jwt(record: &TransactionRecord, findings: &mut Vec<ScannerFinding>) {
    let mut jwt_sources: Vec<(&str, String)> = Vec::new();

    // Check Authorization header in request
    if let Some(auth) = record.request.header_value("authorization") {
        if let Some(token) = authorization_bearer_token(auth) {
            let token = normalize_jwt_token_candidate(token);
            if looks_like_jwt(&token) {
                jwt_sources.push(("Authorization header", token));
            }
        }
    }

    // Check cookies for JWTs
    for header in &record.request.headers {
        if header.name.eq_ignore_ascii_case("cookie") {
            for part in header.value.split(';') {
                let part = part.trim();
                if let Some((_name, value)) = part.split_once('=') {
                    let token = normalize_jwt_token_candidate(value);
                    if looks_like_jwt(&token) {
                        jwt_sources.push(("Cookie", token));
                    }
                }
            }
        }
    }

    // Check response Set-Cookie for JWTs
    if let Some(response) = &record.response {
        for header in &response.headers {
            if header.name.eq_ignore_ascii_case("set-cookie") {
                if let Some(value) = header.value.split(';').next() {
                    if let Some((_name, val)) = value.split_once('=') {
                        let token = normalize_jwt_token_candidate(val);
                        if looks_like_jwt(&token) {
                            jwt_sources.push(("Set-Cookie", token));
                        }
                    }
                }
            }
        }
    }

    // Check response body for JWTs (skip binary bodies)
    if let Some(response) = &record.response {
        if !is_binary_body(response) {
            let body = &response.body_preview;
            for token in extract_jwt_from_text(body) {
                jwt_sources.push(("Response body", token));
            }
        }
    }

    for (source, token) in jwt_sources {
        analyze_jwt(record, findings, source, &token);
    }
}

fn looks_like_jwt(value: &str) -> bool {
    let parts: Vec<&str> = value.split('.').collect();
    if parts.len() != 3 {
        return false;
    }
    // Each part should be valid base64url
    parts[0..2].iter().all(|part| is_non_empty_base64url(part))
        && parts[2]
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '=')
}

fn normalize_jwt_token_candidate(value: &str) -> String {
    let trimmed = value.trim().trim_matches(|ch| ch == '"' || ch == '\'');
    percent_decode(trimmed)
        .trim()
        .trim_matches(|ch| ch == '"' || ch == '\'')
        .to_string()
}

fn authorization_bearer_token(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    let (scheme, token) = trimmed.split_once(char::is_whitespace)?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then_some(token.trim())
        .filter(|token| !token.is_empty())
}

fn is_non_empty_base64url(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '=')
}

fn extract_jwt_from_text(text: &str) -> Vec<String> {
    // Simple pattern: JWT-looking base64url segments with a JSON-looking header.
    let re = Regex::new(r"eyJ[A-Za-z0-9_-]*(?:\.|%2[eE])[A-Za-z0-9_-]+(?:\.|%2[eE])[A-Za-z0-9_-]*")
        .unwrap();
    re.find_iter(text)
        .map(|m| normalize_jwt_token_candidate(m.as_str()))
        .filter(|token| looks_like_jwt(token))
        .collect()
}

fn decode_jwt_part(part: &str) -> Option<String> {
    // JWT uses base64url encoding (no padding)
    let padded = match part.len() % 4 {
        2 => format!("{part}=="),
        3 => format!("{part}="),
        _ => part.to_string(),
    };
    let decoded = STANDARD
        .decode(padded.replace('-', "+").replace('_', "/"))
        .ok()?;
    String::from_utf8(decoded).ok()
}

fn analyze_jwt(
    record: &TransactionRecord,
    findings: &mut Vec<ScannerFinding>,
    source: &str,
    token: &str,
) {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return;
    }

    let header_json = match decode_jwt_part(parts[0]) {
        Some(json) => json,
        None => return,
    };
    let payload_json = decode_jwt_part(parts[1]).unwrap_or_default();

    let jwt_alg = jwt_alg_from_header(&header_json);

    // Check alg:none
    if jwt_alg.as_deref() == Some("none") {
        findings.push(make_finding(
            record,
            Severity::High,
            "jwt",
            "JWT with alg:none",
            format!("JWT token in {source} uses algorithm \"none\", which means no signature verification. This is a critical vulnerability if the server accepts this token."),
            truncate_evidence(token, 120),
        ));
    }

    // Check weak algorithms
    for weak_alg in &["hs256", "hs384", "hs512"] {
        if jwt_alg.as_deref() == Some(*weak_alg) {
            findings.push(make_finding(
                record,
                Severity::Low,
                "jwt",
                format!("JWT uses symmetric algorithm ({})", weak_alg.to_uppercase()),
                format!("JWT token in {source} uses symmetric signing ({0}). If the secret is weak or shared, tokens can be forged.", weak_alg.to_uppercase()),
                truncate_evidence(token, 120),
            ));
        }
    }

    // Check expiration
    if payload_json.contains("\"exp\"") {
        // Try to extract exp value
        if let Some(exp) = extract_json_number(&payload_json, "exp") {
            let now = Utc::now().timestamp();
            if exp < now {
                findings.push(make_finding(
                    record,
                    Severity::Info,
                    "jwt",
                    "Expired JWT token",
                    format!("JWT token in {source} has expired (exp: {exp}, now: {now})."),
                    truncate_evidence(token, 120),
                ));
            }
        }
    } else {
        findings.push(make_finding(
            record,
            Severity::Medium,
            "jwt",
            "JWT without expiration",
            format!("JWT token in {source} has no 'exp' claim. Tokens without expiration never expire and can be reused indefinitely if stolen."),
            truncate_evidence(token, 120),
        ));
    }

    // Always report JWT detection as info (so user knows JWTs are in use)
    findings.push(make_finding(
        record,
        Severity::Info,
        "jwt",
        format!("JWT detected in {source}"),
        format!("JWT token found in {source}. Header: {header_json}"),
        truncate_evidence(token, 120),
    ));
}

fn jwt_alg_from_header(header_json: &str) -> Option<String> {
    let header = serde_json::from_str::<serde_json::Value>(header_json).ok()?;
    header
        .get("alg")?
        .as_str()
        .map(|alg| alg.to_ascii_lowercase())
}

// ── Rule 2: Security Headers ──

fn check_security_headers(record: &TransactionRecord, findings: &mut Vec<ScannerFinding>) {
    let response = match &record.response {
        Some(r) => r,
        None => return,
    };

    // Only check HTML page responses.
    if !is_html_page_response(response) {
        return;
    }

    let header_value = |name: &str| -> Option<&str> {
        response
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.as_str())
    };

    if header_value("content-security-policy").is_none_or(|value| value.trim().is_empty()) {
        findings.push(make_finding(
            record,
            Severity::Low,
            "header",
            "Missing Content-Security-Policy",
            "No CSP header found. CSP helps prevent XSS and data injection attacks.",
            "",
        ));
    }

    if !header_value("strict-transport-security").is_some_and(valid_hsts_header_value)
        && record.scheme == "https"
    {
        findings.push(make_finding(
            record,
            Severity::Low,
            "header",
            "Missing Strict-Transport-Security",
            "HTTPS response lacks HSTS header. Browsers may allow HTTP downgrade attacks.",
            "",
        ));
    }

    if !header_value("x-content-type-options")
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("nosniff"))
    {
        findings.push(make_finding(
            record,
            Severity::Info,
            "header",
            "Missing X-Content-Type-Options",
            "No X-Content-Type-Options: nosniff header. Browsers may MIME-sniff the response.",
            "",
        ));
    }

    if !header_value("x-frame-options").is_some_and(valid_x_frame_options_value)
        && !has_csp_frame_ancestors(response)
    {
        findings.push(make_finding(
            record,
            Severity::Low,
            "header",
            "Missing X-Frame-Options",
            "No X-Frame-Options or CSP frame-ancestors. Page may be framed for clickjacking.",
            "",
        ));
    }
}

fn valid_hsts_header_value(value: &str) -> bool {
    value.split(';').any(|directive| {
        let Some((name, value)) = directive.trim().split_once('=') else {
            return false;
        };
        name.trim().eq_ignore_ascii_case("max-age")
            && value.trim().parse::<u64>().is_ok_and(|max_age| max_age > 0)
    })
}

fn valid_x_frame_options_value(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "deny" | "sameorigin"
    )
}

fn has_csp_frame_ancestors(response: &crate::model::MessageRecord) -> bool {
    response.headers.iter().any(|h| {
        if !h.name.eq_ignore_ascii_case("content-security-policy") {
            return false;
        }
        h.value.split(';').any(|directive| {
            let mut tokens = directive.split_whitespace();
            matches!(tokens.next(), Some(name) if name.eq_ignore_ascii_case("frame-ancestors"))
                && tokens.next().is_some()
        })
    })
}

fn is_html_page_response(response: &crate::model::MessageRecord) -> bool {
    if let Some(content_type) = response.content_type.as_deref() {
        let ct = content_type.trim();
        if !ct.is_empty() {
            return ct.to_ascii_lowercase().contains("text/html");
        }
    }

    if !matches!(response.body_encoding, BodyEncoding::Utf8) {
        return false;
    }

    let body = response.body_preview.trim_start().to_ascii_lowercase();
    body.starts_with("<!doctype html")
        || body.starts_with("<html")
        || body.contains("<head")
        || body.contains("<body")
}

// ── Rule 3: Cookie Flags ──

fn check_cookie_flags(record: &TransactionRecord, findings: &mut Vec<ScannerFinding>) {
    let response = match &record.response {
        Some(r) => r,
        None => return,
    };

    for header in &response.headers {
        if !header.name.eq_ignore_ascii_case("set-cookie") {
            continue;
        }

        let cookie_name = header.value.split('=').next().unwrap_or("unknown").trim();
        let attributes = cookie_attribute_names(&header.value);

        if !attributes.contains("httponly") {
            findings.push(make_finding(
                record,
                Severity::Medium,
                "cookie",
                format!("Cookie '{cookie_name}' missing HttpOnly flag"),
                "Cookie accessible via JavaScript. If XSS exists, attacker can steal this cookie.",
                &header.value,
            ));
        }

        if !attributes.contains("secure") && record.scheme == "https" {
            findings.push(make_finding(
                record,
                Severity::Medium,
                "cookie",
                format!("Cookie '{cookie_name}' missing Secure flag"),
                "Cookie may be sent over unencrypted HTTP connections, exposing it to interception.",
                &header.value,
            ));
        }

        if !attributes.contains("samesite") {
            findings.push(make_finding(
                record,
                Severity::Low,
                "cookie",
                format!("Cookie '{cookie_name}' missing SameSite attribute"),
                "No SameSite attribute. Cookie may be sent in cross-site requests (CSRF risk).",
                &header.value,
            ));
        }
    }
}

fn cookie_attribute_names(value: &str) -> HashSet<String> {
    value
        .split(';')
        .skip(1)
        .filter_map(|attribute| attribute.trim().split('=').next())
        .map(|name| name.trim().to_ascii_lowercase())
        .filter(|name| !name.is_empty())
        .collect()
}

// ── Rule 4: Sensitive Data Exposure ──

fn check_sensitive_data(record: &TransactionRecord, findings: &mut Vec<ScannerFinding>) {
    let response = match &record.response {
        Some(r) => r,
        None => return,
    };

    // Skip binary bodies — regex hits on base64-encoded images/fonts are false positives
    if is_binary_body(response) {
        return;
    }

    let body = &response.body_preview;
    if body.is_empty() {
        return;
    }

    static PATTERNS: &[(&str, &str, Severity)] = &[
        // ── Cloud provider keys ──
        (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID", Severity::High),
        (
            r#"(?i)\b(aws_secret_access_key|aws_secret)\b["']?\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}"#,
            "AWS Secret Access Key",
            Severity::High,
        ),
        (r"AIza[0-9A-Za-z_-]{35}", "Google API Key", Severity::High),
        (
            r"(?i)\b[0-9]+-[a-z0-9_]+\.apps\.googleusercontent\.com\b",
            "Google OAuth Client ID",
            Severity::Medium,
        ),
        // ── AI / ML tokens ──
        (
            r"sk-proj-[A-Za-z0-9_-]{74,}",
            "OpenAI Project API Key",
            Severity::Critical,
        ),
        (
            r"sk-svcacct-[A-Za-z0-9_-]{74,}",
            "OpenAI Service Account Key",
            Severity::Critical,
        ),
        (
            r"sk-ant-api03-[a-zA-Z0-9_\-]{93}",
            "Anthropic API Key",
            Severity::Critical,
        ),
        (
            r"sk-ant-admin01-[a-zA-Z0-9_\-]{80,}",
            "Anthropic Admin Key",
            Severity::Critical,
        ),
        (
            r"\bhf_[a-zA-Z0-9]{34}\b",
            "HuggingFace Token",
            Severity::High,
        ),
        (r"gsk_[a-zA-Z0-9]{48}", "Groq API Key", Severity::Critical),
        (
            r"pplx-[a-zA-Z0-9]{48}",
            "Perplexity API Key",
            Severity::Critical,
        ),
        (
            r"xai-[a-zA-Z0-9]{20,}",
            "xAI (Grok) API Key",
            Severity::Critical,
        ),
        (r"r8_[a-zA-Z0-9]{38}", "Replicate API Token", Severity::High),
        // ── VCS / DevOps tokens ──
        (
            r"ghp_[A-Za-z0-9]{36}",
            "GitHub Personal Access Token",
            Severity::High,
        ),
        (r"gho_[A-Za-z0-9]{36}", "GitHub OAuth Token", Severity::High),
        (r"ghs_[A-Za-z0-9]{36}", "GitHub App Token", Severity::High),
        (
            r"ghr_[A-Za-z0-9]{36}",
            "GitHub Refresh Token",
            Severity::High,
        ),
        (
            r"github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}",
            "GitHub Fine-Grained PAT",
            Severity::High,
        ),
        (
            r"glpat-[A-Za-z0-9\-]{20,}",
            "GitLab Personal Access Token",
            Severity::High,
        ),
        (
            r"\b(?:glrt|glrtr|gloas|gldt|glcbt|glptt|glft|glimt|glagent|glwt|glsoat|glffct)-[A-Za-z0-9_\-]{20,}",
            "GitLab Token",
            Severity::High,
        ),
        (
            r"ATATT3[A-Za-z0-9_\-=]{100,}",
            "Atlassian/Jira API Token",
            Severity::High,
        ),
        (r"dop_v1_[a-f0-9]{64}", "DigitalOcean PAT", Severity::High),
        (r"dapi[a-f0-9]{32}", "Databricks API Token", Severity::High),
        (
            r"LTAI[a-z0-9]{20}",
            "Alibaba Cloud Access Key",
            Severity::High,
        ),
        (
            r"dckr_pat_[a-zA-Z0-9_-]{20,}",
            "Docker Hub PAT",
            Severity::High,
        ),
        (
            r"pscale_tkn_[a-zA-Z0-9_=-]{32,}",
            "PlanetScale Token",
            Severity::High,
        ),
        (r"sbp_[a-f0-9]{40,}", "Supabase PAT", Severity::High),
        (
            r"dt0c01\.[a-z0-9]{24}\.[a-z0-9]{64}",
            "Dynatrace API Token",
            Severity::High,
        ),
        (r"pul-[a-f0-9]{40}", "Pulumi API Token", Severity::High),
        (
            r"AKCp[A-Za-z0-9]{69}",
            "JFrog Artifactory Token",
            Severity::High,
        ),
        (r"ntn_[a-zA-Z0-9]{40,}", "Notion API Token", Severity::High),
        (r"figd_[a-zA-Z0-9_-]{40,}", "Figma PAT", Severity::High),
        (
            r"EAA[MC][a-zA-Z0-9]{100,}",
            "Facebook Page Access Token",
            Severity::High,
        ),
        // ── Chat / SaaS tokens ──
        (
            r"xox[bpras]-[A-Za-z0-9\-]{10,}",
            "Slack Token",
            Severity::High,
        ),
        (
            r"https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+",
            "Slack Webhook URL",
            Severity::High,
        ),
        // ── Generic secrets ──
        (
            r#"(?i)\b(api[_-]?key|apikey|api[_-]?secret)\b["']?\s*[:=]\s*["']?[A-Za-z0-9_\-]{20,}"#,
            "API Key/Secret pattern",
            Severity::Medium,
        ),
        (
            r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
            "Private Key",
            Severity::High,
        ),
        (
            r#"(?i)(?:\b|[_-])(?:password|passwd|pwd)\b\s*["']?\s*[:=]\s*(?:"([^"]{4,})"|'([^']{4,})'|([^\s"'<>{}]{4,}))"#,
            "Password in response",
            Severity::High,
        ),
        (
            r#"(?i)\b(secret[_-]?key|client[_-]?secret|auth[_-]?token|access[_-]?token)\b["']?\s*[:=]\s*["']?[A-Za-z0-9_\-/+=]{16,}"#,
            "Secret/Token pattern",
            Severity::Medium,
        ),
        // ── Payment / SaaS tokens ──
        (
            r"sk_live_[0-9a-zA-Z]{24,}",
            "Stripe Secret Key",
            Severity::Critical,
        ),
        (
            r"pk_live_[0-9a-zA-Z]{24,}",
            "Stripe Publishable Key",
            Severity::Low,
        ),
        (
            r"rk_live_[0-9a-zA-Z]{24,}",
            "Stripe Restricted Key",
            Severity::High,
        ),
        (
            r"sq0[a-z]{3}-[0-9A-Za-z\-_]{22,}",
            "Square Access Token",
            Severity::High,
        ),
        (
            r"shpat_[a-fA-F0-9]{32}",
            "Shopify Admin Token",
            Severity::High,
        ),
        (
            r"shpss_[a-fA-F0-9]{32}",
            "Shopify Shared Secret",
            Severity::High,
        ),
        // ── Communication / Messaging tokens ──
        (r"SK[0-9a-fA-F]{32}", "Twilio API Key", Severity::High),
        (
            r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
            "SendGrid API Key",
            Severity::High,
        ),
        (r"key-[0-9a-zA-Z]{32}", "Mailgun API Key", Severity::High),
        (
            r"[0-9]+:AA[A-Za-z0-9_-]{33}",
            "Telegram Bot Token",
            Severity::High,
        ),
        (
            r"[MN][A-Za-z0-9]{23}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27}",
            "Discord Bot Token",
            Severity::High,
        ),
        (
            r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+",
            "Discord Webhook URL",
            Severity::High,
        ),
        // ── Infrastructure / DevOps secrets ──
        (
            r"hvs\.[a-zA-Z0-9_-]{90,}",
            "Hashicorp Vault Token",
            Severity::High,
        ),
        (r"dp\.pt\.[a-z0-9]{43}", "Doppler API Token", Severity::High),
        (r"lin_api_[a-zA-Z0-9]{40}", "Linear API Key", Severity::High),
        // ── Monitoring / Observability ──
        (
            r"NRAK-[A-Z0-9]{27}",
            "New Relic User API Key",
            Severity::High,
        ),
        (
            r"NRII-[a-zA-Z0-9]{32}",
            "New Relic Insert Key",
            Severity::High,
        ),
        (
            r"glc_[A-Za-z0-9+/]{32,}",
            "Grafana Cloud Token",
            Severity::High,
        ),
        (
            r"glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}",
            "Grafana Service Account Token",
            Severity::High,
        ),
        (
            r"https://[a-zA-Z0-9]+@[a-z]+\.ingest\.sentry\.io/\d+",
            "Sentry DSN",
            Severity::Medium,
        ),
        // ── Database connection strings ──
        (
            r#"mongodb(?:\+srv)?://[^\s'"]{10,}"#,
            "MongoDB connection string",
            Severity::High,
        ),
        (
            r#"postgres(?:ql)?://[^\s'"]{10,}"#,
            "PostgreSQL connection string",
            Severity::High,
        ),
        (
            r#"mysql://[^\s'"]{10,}"#,
            "MySQL connection string",
            Severity::High,
        ),
        (
            r#"redis://[^\s'"]{10,}"#,
            "Redis connection string",
            Severity::High,
        ),
        // ── Package registry tokens ──
        (r"npm_[A-Za-z0-9]{36}", "npm Access Token", Severity::High),
        (r"pypi-[A-Za-z0-9_-]{50,}", "PyPI API Token", Severity::High),
        // ── Cloud / Infrastructure ──
        (
            r"(?i)heroku[a-z0-9_ .\-,]{0,25}[=:]\s*[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            "Heroku API Key",
            Severity::High,
        ),
        (
            r"(?i)(?:AccountKey|SharedAccessKey)\s*=\s*[A-Za-z0-9+/=]{40,}",
            "Azure Storage/SAS Key",
            Severity::High,
        ),
        // ── Firebase ──
        (
            r"(?i)[a-z0-9-]+\.firebaseio\.com",
            "Firebase database URL",
            Severity::Low,
        ),
        (
            r"(?i)[a-z0-9-]+\.firebaseapp\.com",
            "Firebase app URL",
            Severity::Info,
        ),
        // ── Network / Infrastructure ──
        (
            r"\b(?:10\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d)|172\.(?:1[6-9]|2\d|3[01])\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d)|192\.168\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d))\b",
            "Internal IP address",
            Severity::Low,
        ),
        // ── Sensitive file paths ──
        (
            r"(?i)/\.(?:env|git|svn|htpasswd|htaccess|DS_Store|aws/credentials|npmrc|dockerenv)\b",
            "Sensitive file path exposed",
            Severity::Medium,
        ),
        // ── Credit card patterns (basic) ──
        (
            r"\b4[0-9]{3}[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b",
            "Possible Visa card number",
            Severity::High,
        ),
        (
            r"\b5[1-5][0-9]{2}[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b",
            "Possible Mastercard number",
            Severity::High,
        ),
    ];

    for &(pattern, label, ref severity) in PATTERNS {
        if let Ok(re) = Regex::new(pattern) {
            for captures in re.captures_iter(body) {
                let Some(m) = captures.get(0) else {
                    continue;
                };
                if label == "Password in response"
                    && !password_candidate_looks_like_secret(&captures)
                {
                    continue;
                }
                if is_card_number_label(label) && !luhn_valid(m.as_str()) {
                    continue;
                }
                // Skip matches embedded inside base64 strings (false positives from
                // base64-encoded ad payloads, tracking pixels, etc. in JSON responses)
                if is_embedded_in_base64(body, &m) {
                    continue;
                }
                findings.push(make_finding(
                    record,
                    severity.clone(),
                    "disclosure",
                    format!("{label} detected in response"),
                    format!("{label} found in response body. This may expose sensitive information to clients."),
                    truncate_evidence(m.as_str(), 80),
                ));
                break;
            }
        }
    }
}

fn password_candidate_looks_like_secret(captures: &regex::Captures<'_>) -> bool {
    let Some(value) = captures
        .iter()
        .skip(1)
        .flatten()
        .map(|capture| capture.as_str().trim())
        .find(|value| !value.is_empty())
    else {
        return false;
    };
    if value.len() < 8 {
        return false;
    }

    let normalized = value
        .trim_matches(|ch: char| ch.is_ascii_punctuation())
        .trim()
        .to_ascii_lowercase();
    if normalized == "password" || normalized == "passwd" {
        return false;
    }

    let collapsed = normalized.split_whitespace().collect::<Vec<_>>().join(" ");
    let validation_phrases = [
        "password is ",
        "password must ",
        "password cannot ",
        "password should ",
        "password do ",
        "password does ",
        "please ",
        "enter ",
        "confirm ",
        "must ",
        "cannot ",
        "should ",
        "do not ",
        "don't ",
        "don’t ",
        "match ",
        "matches ",
    ];
    if validation_phrases
        .iter()
        .any(|phrase| collapsed.starts_with(phrase))
    {
        return false;
    }
    !matches!(
        collapsed.as_str(),
        "password required" | "confirm password" | "password confirmation"
    )
}

fn is_card_number_label(label: &str) -> bool {
    matches!(
        label,
        "Possible Visa card number" | "Possible Mastercard number"
    )
}

fn luhn_valid(candidate: &str) -> bool {
    let digits: Vec<u32> = candidate
        .chars()
        .filter(|ch| ch.is_ascii_digit())
        .filter_map(|ch| ch.to_digit(10))
        .collect();
    if digits.len() < 12 {
        return false;
    }

    let mut sum = 0u32;
    let mut double = false;
    for digit in digits.iter().rev() {
        let mut value = *digit;
        if double {
            value *= 2;
            if value > 9 {
                value -= 9;
            }
        }
        sum += value;
        double = !double;
    }
    sum.is_multiple_of(10)
}

// ── Rule 5: CORS ──

fn check_cors(record: &TransactionRecord, findings: &mut Vec<ScannerFinding>) {
    let response = match &record.response {
        Some(r) => r,
        None => return,
    };

    let acao = response
        .header_value("access-control-allow-origin")
        .map(str::trim);
    let acac = response
        .header_value("access-control-allow-credentials")
        .map(str::trim);

    if let Some(origin) = acao {
        if origin == "*" {
            if acac.is_some_and(|v| v.eq_ignore_ascii_case("true")) {
                findings.push(make_finding(
                    record,
                    Severity::High,
                    "cors",
                    "CORS: wildcard origin with credentials",
                    "Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true. Browsers block this, but the misconfiguration indicates sloppy CORS policy.",
                    "ACAO: * + ACAC: true",
                ));
            } else {
                findings.push(make_finding(
                    record,
                    Severity::Low,
                    "cors",
                    "CORS: wildcard origin",
                    "Access-Control-Allow-Origin: *. Any site can read responses from this endpoint.",
                    "ACAO: *",
                ));
            }
        } else if origin.eq_ignore_ascii_case("null")
            && acac.is_some_and(|v| v.eq_ignore_ascii_case("true"))
        {
            findings.push(make_finding(
                record,
                Severity::Medium,
                "cors",
                "CORS: null origin with credentials",
                "Access-Control-Allow-Origin: null with Access-Control-Allow-Credentials: true can expose credentialed responses to sandboxed or file-origin contexts.",
                "ACAO: null, ACAC: true",
            ));
        } else if acac.is_some_and(|v| v.eq_ignore_ascii_case("true")) {
            // Reflect origin with credentials — potentially dangerous
            let req_origin = record.request.header_value("origin").unwrap_or("").trim();
            if !req_origin.is_empty() && origin == req_origin {
                findings.push(make_finding(
                    record,
                    Severity::Medium,
                    "cors",
                    "CORS: reflected origin with credentials",
                    format!("Server reflects the request Origin ({origin}) with credentials allowed. If there is no whitelist, any site can read authenticated responses."),
                    format!("ACAO: {origin}, ACAC: true"),
                ));
            }
        }
    }
}

// ── Rule 6: Server / Version Disclosure ──

fn check_server_disclosure(record: &TransactionRecord, findings: &mut Vec<ScannerFinding>) {
    let response = match &record.response {
        Some(r) => r,
        None => return,
    };

    for (header_name, label) in &[
        ("server", "Server"),
        ("x-powered-by", "X-Powered-By"),
        ("x-aspnet-version", "X-AspNet-Version"),
    ] {
        if let Some(value) = response.header_value(header_name) {
            // Only flag if it contains version-like info
            let has_version = value.chars().any(|c| c.is_ascii_digit())
                || value.to_ascii_lowercase().contains("php")
                || value.to_ascii_lowercase().contains("asp");
            if has_version {
                findings.push(make_finding(
                    record,
                    Severity::Info,
                    "server",
                    format!("{label} version disclosure"),
                    format!("{label} header reveals server technology/version. This helps attackers fingerprint the stack."),
                    format!("{header_name}: {value}"),
                ));
            }
        }
    }

    // Debug / infrastructure headers that should not be in production
    for (header_name, label, severity) in &[
        (
            "x-backend-server",
            "X-Backend-Server header",
            Severity::Medium,
        ),
        (
            "x-chromelogger-data",
            "ChromeLogger debug data",
            Severity::Medium,
        ),
        ("x-chromephp-data", "ChromePHP debug data", Severity::Medium),
        (
            "x-debug-token-link",
            "Symfony debug profiler link",
            Severity::Medium,
        ),
    ] {
        if let Some(value) = response.header_value(header_name) {
            findings.push(make_finding(
                record,
                severity.clone(),
                "server",
                format!("{label} exposed"),
                format!("{label} found in response. This debug/infrastructure header should not be present in production."),
                format!("{header_name}: {}", truncate_evidence(value, 80)),
            ));
        }
    }
}

// ── Rule 7: Error Messages ──

fn check_error_messages(record: &TransactionRecord, findings: &mut Vec<ScannerFinding>) {
    let response = match &record.response {
        Some(r) => r,
        None => return,
    };

    if is_binary_body(response) {
        return;
    }

    // Only check 4xx/5xx responses
    let status = record.status.unwrap_or(0);
    if status < 400 {
        return;
    }

    let body = &response.body_preview;
    if body.is_empty() {
        return;
    }

    let body_lower = body.to_ascii_lowercase();

    static ERROR_PATTERNS: &[(&str, &str, Severity)] = &[
        // ── SQL / Database ──
        ("sql syntax", "SQL error message", Severity::Medium),
        ("mysql", "MySQL error disclosure", Severity::Medium),
        (
            "postgresql",
            "PostgreSQL error disclosure",
            Severity::Medium,
        ),
        ("ora-", "Oracle DB error disclosure", Severity::Medium),
        ("sqlite", "SQLite error disclosure", Severity::Medium),
        ("mongodb", "MongoDB error disclosure", Severity::Medium),
        ("mongoose", "Mongoose (MongoDB) error", Severity::Medium),
        ("redis", "Redis error disclosure", Severity::Low),
        ("mariadb", "MariaDB error disclosure", Severity::Medium),
        (
            "microsoft sql server",
            "MSSQL error disclosure",
            Severity::Medium,
        ),
        (
            "unclosed quotation mark",
            "SQL injection indicator",
            Severity::High,
        ),
        (
            "unterminated string",
            "SQL injection indicator",
            Severity::High,
        ),
        (
            "column count doesn't match",
            "SQL column mismatch error",
            Severity::Medium,
        ),
        (
            "incorrect column name",
            "SQL column error",
            Severity::Medium,
        ),
        ("unknown table", "SQL unknown table error", Severity::Medium),
        // ── DB2 / Informix / Access / JDBC (ZAP) ──
        ("db2 driver", "DB2 error disclosure", Severity::Medium),
        ("db2 error", "DB2 error disclosure", Severity::Medium),
        ("odbc db2", "DB2 ODBC error", Severity::Medium),
        ("[cli driver][db2", "DB2 CLI error", Severity::Medium),
        ("[informix]", "Informix DB error", Severity::Medium),
        (
            "odbc microsoft access",
            "MS Access ODBC error",
            Severity::Medium,
        ),
        ("jdbc driver", "JDBC driver error", Severity::Medium),
        ("jdbc error", "JDBC error disclosure", Severity::Medium),
        ("ole db provider", "OLE DB error", Severity::Medium),
        // ── Generic errors ──
        ("syntax error", "Syntax error in response", Severity::Low),
        ("stack trace", "Stack trace disclosure", Severity::Medium),
        (
            "internal server error",
            "Internal server error detail",
            Severity::Low,
        ),
        // ── Language-specific stack traces ──
        (
            "traceback (most recent",
            "Python traceback",
            Severity::Medium,
        ),
        ("at java.", "Java stack trace", Severity::Medium),
        ("at system.", ".NET stack trace", Severity::Medium),
        ("exception in thread", "Java exception", Severity::Medium),
        ("runtime error", "Runtime error disclosure", Severity::Low),
        ("fatal error", "Fatal error disclosure", Severity::Medium),
        // ── PHP ──
        ("parse error:", "PHP parse error", Severity::Medium),
        ("fatal error:", "PHP fatal error", Severity::Medium),
        ("warning:</b>", "PHP warning (HTML)", Severity::Medium),
        ("notice:</b>", "PHP notice (HTML)", Severity::Low),
        (
            "warning: mysql_query()",
            "PHP MySQL warning",
            Severity::Medium,
        ),
        (
            "warning: pg_connect()",
            "PHP PostgreSQL warning",
            Severity::Medium,
        ),
        (
            "warning: cannot modify header information",
            "PHP header warning",
            Severity::Low,
        ),
        // ── Node.js / JavaScript ──
        ("syntaxerror:", "JavaScript SyntaxError", Severity::Medium),
        (
            "referenceerror:",
            "JavaScript ReferenceError",
            Severity::Medium,
        ),
        ("typeerror:", "JavaScript TypeError", Severity::Low),
        ("node_modules/", "Node.js path disclosure", Severity::Low),
        // ── ASP / VBScript / ColdFusion ──
        ("microsoft vbscript", "VBScript error", Severity::Medium),
        (
            "active server pages error",
            "Classic ASP error",
            Severity::Medium,
        ),
        ("adodb.field error", "ASP ADODB error", Severity::Medium),
        (
            "server error in '/' application",
            "ASP.NET application error",
            Severity::Medium,
        ),
        (
            "error occurred while processing request",
            "ColdFusion error",
            Severity::Medium,
        ),
        ("jrun servlet error", "JRun servlet error", Severity::Medium),
        ("disallowed parent path", "IIS path error", Severity::Medium),
        // ── Framework debug ──
        ("debug mode", "Debug mode enabled", Severity::Medium),
        ("django.core", "Django debug info", Severity::Medium),
        ("laravel", "Laravel framework error", Severity::Medium),
        ("spring boot", "Spring Boot error page", Severity::Low),
        (
            "whitelabel error page",
            "Spring Boot default error page",
            Severity::Low,
        ),
        (
            "werkzeug debugger",
            "Flask/Werkzeug debugger exposed",
            Severity::High,
        ),
        ("x-debug-token", "Symfony debug token", Severity::Medium),
    ];

    for &(pattern, label, ref severity) in ERROR_PATTERNS {
        if body_lower.contains(pattern) {
            let evidence_start = body_lower.find(pattern).unwrap_or(0);
            let evidence = evidence_window(body, evidence_start, pattern.len(), 20, 60);
            findings.push(make_finding(
                record,
                severity.clone(),
                "error",
                format!("{label} in error response"),
                format!("HTTP {status} response contains {label}. Detailed error messages help attackers understand the backend stack."),
                truncate_evidence(evidence, 120),
            ));
            break; // One finding per response is enough
        }
    }
}

// ── Rule 8: Security Misconfiguration ──

fn check_security_misconfig(record: &TransactionRecord, findings: &mut Vec<ScannerFinding>) {
    let response = match &record.response {
        Some(r) => r,
        None => return,
    };

    let has_header = |name: &str| -> bool {
        response
            .headers
            .iter()
            .any(|h| h.name.eq_ignore_ascii_case(name))
    };

    let header_value = |name: &str| -> Option<String> {
        response
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.clone())
    };

    // Referrer-Policy missing (HTML responses)
    if is_html_page_response(response) && !has_header("referrer-policy") {
        findings.push(make_finding(
            record,
            Severity::Info,
            "misconfig",
            "Missing Referrer-Policy header",
            "No Referrer-Policy header. The browser may send full URL as referer to external sites, potentially leaking sensitive path/query info.",
            "",
        ));
    }

    // Permissions-Policy / Feature-Policy missing (HTML responses)
    if is_html_page_response(response)
        && !has_header("permissions-policy")
        && !has_header("feature-policy")
    {
        findings.push(make_finding(
            record,
            Severity::Info,
            "misconfig",
            "Missing Permissions-Policy header",
            "No Permissions-Policy (or Feature-Policy) header. Browser features like camera, microphone, geolocation are not restricted.",
            "",
        ));
    }

    // CSP with unsafe-inline or unsafe-eval
    if let Some(csp) = header_value("content-security-policy") {
        if csp_script_sources_contain(&csp, "'unsafe-inline'") {
            findings.push(make_finding(
                record,
                Severity::Medium,
                "misconfig",
                "CSP allows unsafe-inline",
                "Content-Security-Policy contains 'unsafe-inline', which undermines XSS protection by allowing inline scripts.",
                truncate_evidence(&csp, 120),
            ));
        }
        if csp_script_sources_contain(&csp, "'unsafe-eval'") {
            findings.push(make_finding(
                record,
                Severity::Medium,
                "misconfig",
                "CSP allows unsafe-eval",
                "Content-Security-Policy contains 'unsafe-eval', which allows eval() and similar dynamic code execution.",
                truncate_evidence(&csp, 120),
            ));
        }
    }

    // X-XSS-Protection set (deprecated — can cause issues in modern browsers)
    if let Some(xxp) = header_value("x-xss-protection") {
        if xxp.contains("1") {
            findings.push(make_finding(
                record,
                Severity::Info,
                "misconfig",
                "Deprecated X-XSS-Protection header",
                "X-XSS-Protection is deprecated and can introduce XSS vulnerabilities in older browsers. Use CSP instead.",
                format!("X-XSS-Protection: {xxp}"),
            ));
        }
    }

    // Cache-Control missing on authenticated responses
    let has_auth = has_authenticated_cache_context(record, response);
    if has_auth && !has_header("cache-control") {
        findings.push(make_finding(
            record,
            Severity::Low,
            "misconfig",
            "Missing Cache-Control on authenticated response",
            "Response to an authenticated request lacks Cache-Control header. Sensitive data may be cached by browsers or proxies.",
            "",
        ));
    }

    // Sensitive data in Cache-Control: public
    if has_auth {
        if let Some(cc) = header_value("cache-control") {
            let cc_lower = cc.to_ascii_lowercase();
            if cc_lower.contains("public") && !cc_lower.contains("no-store") {
                findings.push(make_finding(
                    record,
                    Severity::Medium,
                    "misconfig",
                    "Cache-Control: public on authenticated response",
                    "Authenticated response has Cache-Control: public, allowing caching of potentially sensitive data.",
                    format!("Cache-Control: {cc}"),
                ));
            }
        }
    }

    // Access-Control-Allow-Methods with dangerous methods
    if let Some(methods) = header_value("access-control-allow-methods") {
        for dangerous in &["put", "delete", "patch"] {
            if cors_allows_method(&methods, dangerous) {
                findings.push(make_finding(
                    record,
                    Severity::Info,
                    "misconfig",
                    format!("CORS allows {}", dangerous.to_uppercase()),
                    format!("Access-Control-Allow-Methods includes {}. Verify these methods are intentionally exposed.", dangerous.to_uppercase()),
                    format!("ACAM: {methods}"),
                ));
                break;
            }
        }
    }
}

fn csp_script_sources_contain(csp: &str, token: &str) -> bool {
    let token = token.to_ascii_lowercase();
    let mut default_sources: Option<Vec<String>> = None;
    let mut has_script_directive = false;
    let mut matched_script_directive = false;

    for directive in csp.split(';') {
        let mut parts = directive.split_whitespace();
        let Some(name) = parts.next() else {
            continue;
        };
        let name = name.to_ascii_lowercase();
        let sources = parts.map(str::to_ascii_lowercase).collect::<Vec<String>>();
        if name == "default-src" {
            default_sources = Some(sources);
            continue;
        }
        if matches!(
            name.as_str(),
            "script-src" | "script-src-elem" | "script-src-attr"
        ) {
            has_script_directive = true;
            matched_script_directive |= sources.iter().any(|source| source == &token);
        }
    }

    if has_script_directive {
        matched_script_directive
    } else {
        default_sources
            .as_deref()
            .is_some_and(|sources| sources.iter().any(|source| source == &token))
    }
}

fn cors_allows_method(methods: &str, method: &str) -> bool {
    methods
        .split(',')
        .map(str::trim)
        .any(|candidate| candidate.eq_ignore_ascii_case(method))
}

fn has_authenticated_cache_context(
    record: &TransactionRecord,
    response: &crate::model::MessageRecord,
) -> bool {
    record.request.headers.iter().any(|header| {
        header.name.eq_ignore_ascii_case("authorization") && !header.value.trim().is_empty()
    }) || request_has_auth_cookie(record)
        || response_sets_auth_cookie(response)
}

fn request_has_auth_cookie(record: &TransactionRecord) -> bool {
    record.request.headers.iter().any(|header| {
        if !header.name.eq_ignore_ascii_case("cookie") {
            return false;
        }
        header.value.split(';').any(|part| {
            part.split_once('=')
                .is_some_and(|(name, _)| is_auth_cookie_name(name))
        })
    })
}

fn response_sets_auth_cookie(response: &crate::model::MessageRecord) -> bool {
    response.headers.iter().any(|header| {
        if !header.name.eq_ignore_ascii_case("set-cookie") {
            return false;
        }
        header
            .value
            .split(';')
            .next()
            .and_then(|pair| pair.split_once('='))
            .is_some_and(|(name, _)| is_auth_cookie_name(name))
    })
}

fn is_auth_cookie_name(name: &str) -> bool {
    let normalized = name.trim().trim_start_matches('$').to_ascii_lowercase();
    matches!(
        normalized.as_str(),
        "sid"
            | "jwt"
            | "token"
            | "access_token"
            | "refresh_token"
            | "id_token"
            | "phpsessid"
            | "jsessionid"
    ) || [
        "session", "sess", "auth", "access", "refresh", "csrf", "xsrf",
    ]
    .iter()
    .any(|needle| normalized.contains(needle))
}

// ── Rule 9: Information Disclosure ──

fn check_info_disclosure(record: &TransactionRecord, findings: &mut Vec<ScannerFinding>) {
    let response = match &record.response {
        Some(r) => r,
        None => return,
    };

    push_source_map_header_finding(record, response, findings);

    if is_binary_body(response) {
        return;
    }

    let body = &response.body_preview;
    if body.is_empty() {
        return;
    }

    let body_lower = body.to_ascii_lowercase();

    // Directory listing detection
    if (body_lower.contains("index of /") || body_lower.contains("directory listing for"))
        && (body_lower.contains("parent directory") || body_lower.contains("last modified"))
    {
        findings.push(make_finding(
            record,
            Severity::Medium,
            "info",
            "Directory listing enabled",
            "Server is exposing directory contents. This reveals file structure and may expose sensitive files.",
            truncate_evidence(evidence_prefix(body, 120), 120),
        ));
    }

    // Source map references
    let sourcemap_re = Regex::new(r"//[#@]\s*sourceMappingURL\s*=\s*(\S+\.map)").unwrap();
    if let Some(m) = sourcemap_re.find(body) {
        findings.push(make_finding(
            record,
            Severity::Low,
            "info",
            "JavaScript source map reference",
            "Source map file referenced in response. Source maps can expose original source code, making it easier for attackers to understand application logic.",
            truncate_evidence(m.as_str(), 120),
        ));
    }

    // GraphQL Introspection enabled
    if body.contains("__schema") && body.contains("queryType") {
        findings.push(make_finding(
            record,
            Severity::Medium,
            "info",
            "GraphQL introspection enabled",
            "GraphQL introspection query response detected. Introspection exposes the entire API schema to attackers.",
            "__schema { queryType { ... } }",
        ));
    }

    // HTML comments with sensitive keywords
    if let Ok(comment_re) = Regex::new(r"<!--[\s\S]{0,500}?-->") {
        for m in comment_re.find_iter(body) {
            let comment = m.as_str().to_ascii_lowercase();
            let sensitive_keywords = [
                "todo",
                "fixme",
                "hack",
                "bug",
                "password",
                "secret",
                "credential",
                "token",
                "api_key",
                "apikey",
                "admin",
                "internal",
                "debug",
                "temporary",
                "remove before",
            ];
            for keyword in &sensitive_keywords {
                if comment.contains(keyword) {
                    findings.push(make_finding(
                        record,
                        Severity::Info,
                        "info",
                        format!("HTML comment contains '{keyword}'"),
                        "HTML comments may reveal developer notes, internal paths, or sensitive information to users.",
                        truncate_evidence(m.as_str(), 120),
                    ));
                    break;
                }
            }
        }
    }

    // Email addresses in response body
    if let Ok(email_re) = Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}") {
        let ct = response.content_type.as_deref().unwrap_or("");
        let ct_lower = ct.to_ascii_lowercase();
        // Only flag in non-email contexts (HTML/JSON)
        if ct_lower.contains("html") || ct_lower.contains("json") {
            for m in email_re.find_iter(body) {
                // Skip obvious false positives
                let email = m.as_str();
                if should_ignore_disclosed_email(email) {
                    continue;
                }
                findings.push(make_finding(
                    record,
                    Severity::Info,
                    "info",
                    "Email address in response",
                    "Email addresses found in response body. These could be used for phishing or social engineering.",
                    truncate_evidence(email, 80),
                ));
                break;
            }
        }
    }

    // Version control metadata exposure
    if body.contains("\"sha\"") && body.contains("\"commit\"") && body.contains("\"author\"") {
        findings.push(make_finding(
            record,
            Severity::Low,
            "info",
            "Git commit metadata exposed",
            "Response contains git commit metadata (sha, author). This may reveal internal development details.",
            "",
        ));
    }

    // Swagger/OpenAPI exposure
    if (body_lower.contains("\"swagger\"") || body_lower.contains("\"openapi\""))
        && (body_lower.contains("\"paths\"") || body_lower.contains("\"info\""))
    {
        findings.push(make_finding(
            record,
            Severity::Low,
            "info",
            "Swagger/OpenAPI spec exposed",
            "Swagger or OpenAPI specification found in response. This reveals the full API structure to potential attackers.",
            "",
        ));
    }

    // WSDL exposure
    if body_lower.contains("<wsdl:") || body_lower.contains("xmlns:wsdl") {
        findings.push(make_finding(
            record,
            Severity::Low,
            "info",
            "WSDL service definition exposed",
            "WSDL document found in response. This reveals web service endpoints and data types.",
            "",
        ));
    }
}

fn push_source_map_header_finding(
    record: &TransactionRecord,
    response: &crate::model::MessageRecord,
    findings: &mut Vec<ScannerFinding>,
) {
    if let Some(sm) = response
        .header_value("sourcemap")
        .or_else(|| response.header_value("x-sourcemap"))
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        findings.push(make_finding(
            record,
            Severity::Low,
            "info",
            "Source map header present",
            "SourceMap HTTP header found. Source maps can expose original source code.",
            format!("SourceMap: {sm}"),
        ));
    }
}

// ── Rule 10: Authentication Issues ──

fn check_auth_issues(record: &TransactionRecord, findings: &mut Vec<ScannerFinding>) {
    // Session token in URL
    if let Some(param) = session_token_parameter_in_url(&record.path) {
        findings.push(make_finding(
                record,
                Severity::Medium,
                "auth",
            format!("Session/token parameter in URL: {param}"),
                "Session token or credentials found in URL. URLs are logged in browser history, server logs, and referer headers, exposing the token.",
                truncate_evidence(&record.path, 120),
            ));
    }

    // Basic authentication over HTTP (not HTTPS)
    if record.scheme == "http" {
        if let Some(auth) = record.request.header_value("authorization") {
            if auth.to_ascii_lowercase().starts_with("basic ") {
                findings.push(make_finding(
                    record,
                    Severity::High,
                    "auth",
                    "Basic authentication over HTTP",
                    "HTTP Basic authentication is used over unencrypted HTTP. Credentials are Base64-encoded (not encrypted) and can be intercepted.",
                    "Authorization: Basic ***",
                ));
            }
        }
    }

    // Credentials in URL (userinfo component)
    if let Ok(cred_re) = Regex::new(r"https?://[^@/\s]+:[^@/\s]+@") {
        // Check request path / referer for credentials
        if cred_re.is_match(&record.path) {
            findings.push(make_finding(
                record,
                Severity::High,
                "auth",
                "Credentials in URL",
                "URL contains user:password credentials. This exposes credentials in logs, browser history, and referer headers.",
                "https://user:pass@...",
            ));
        }
        // Also check Referer header
        for h in &record.request.headers {
            if h.name.eq_ignore_ascii_case("referer") && cred_re.is_match(&h.value) {
                findings.push(make_finding(
                    record,
                    Severity::High,
                    "auth",
                    "Credentials in Referer header",
                    "Referer header contains URL with embedded credentials, leaking authentication data to third parties.",
                    truncate_evidence(&h.value, 80),
                ));
            }
        }
    }

    // Weak authentication: no Secure flag on session cookies over HTTPS
    // (Handled in cookie rule, skip here)

    // Open redirect indicators in response headers
    if let Some(response) = &record.response {
        let status = record.status.unwrap_or(0);
        if (300..=399).contains(&status) {
            if let Some(loc) = response.header_value("location") {
                // Check if Location contains user-controlled input (common open redirect patterns)
                let path_params: Vec<&str> = record.path.split('?').collect();
                if path_params.len() > 1 {
                    let query = path_params[1];
                    let redirect_params = [
                        "redirect",
                        "url",
                        "next",
                        "return",
                        "goto",
                        "redir",
                        "redirect_uri",
                        "return_url",
                        "continue",
                        "dest",
                        "destination",
                    ];
                    let matched_param = query.split('&').find_map(|pair| {
                        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
                        let key = key.replace('+', " ");
                        let decoded_key = percent_decode(&key).to_ascii_lowercase();
                        if !redirect_params.contains(&decoded_key.as_str()) {
                            return None;
                        }
                        let value = value.replace('+', " ");
                        let decoded_value = percent_decode(&value);
                        redirect_parameter_controls_location(
                            &decoded_value,
                            loc,
                            &record.scheme,
                            &record.host,
                        )
                        .then_some(decoded_key)
                    });
                    if let Some(param) = matched_param {
                        // Check if Location points to an external origin.
                        if is_external_redirect_location(loc, &record.scheme, &record.host) {
                            findings.push(make_finding(
                                record,
                                Severity::Medium,
                                "auth",
                                "Possible open redirect",
                                format!("Redirect to external URL based on user-controlled parameter. Query contains '{param}' and Location points to a different host."),
                                format!("Location: {}", truncate_evidence(loc, 80)),
                            ));
                        }
                    }
                }
            }
        }
    }

    // WWW-Authenticate header reveals auth scheme
    if let Some(response) = &record.response {
        if let Some(www_auth) = response.header_value("www-authenticate") {
            let wa_lower = www_auth.to_ascii_lowercase();
            if wa_lower.contains("basic") && record.scheme == "http" {
                findings.push(make_finding(
                    record,
                    Severity::Medium,
                    "auth",
                    "Server requests Basic auth over HTTP",
                    "WWW-Authenticate header requests Basic authentication over unencrypted HTTP.",
                    format!("WWW-Authenticate: {www_auth}"),
                ));
            }
        }
    }
}

fn should_ignore_disclosed_email(email: &str) -> bool {
    let Some((_, domain)) = email.rsplit_once('@') else {
        return false;
    };
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    matches!(domain.as_str(), "example.com" | "example.org")
        || domain.ends_with(".example.com")
        || domain.ends_with(".example.org")
        || matches!(domain.as_str(), "schema.org" | "w3.org")
        || domain.ends_with(".schema.org")
        || domain.ends_with(".w3.org")
}

fn is_external_redirect_location(location: &str, request_scheme: &str, request_host: &str) -> bool {
    let base = match url::Url::parse(&format!("{request_scheme}://{request_host}")) {
        Ok(base) => base,
        Err(_) => return false,
    };
    let redirect = match url::Url::parse(location).or_else(|_| base.join(location)) {
        Ok(redirect) => redirect,
        Err(_) => return false,
    };
    if !matches!(redirect.scheme(), "http" | "https") {
        return false;
    }
    let Some(base_host) = base.host_str() else {
        return false;
    };
    let Some(redirect_host) = redirect.host_str() else {
        return false;
    };
    !base.scheme().eq_ignore_ascii_case(redirect.scheme())
        || !base_host.eq_ignore_ascii_case(redirect_host)
        || base.port_or_known_default() != redirect.port_or_known_default()
}

fn redirect_parameter_controls_location(
    value: &str,
    location: &str,
    request_scheme: &str,
    request_host: &str,
) -> bool {
    let value = value.trim();
    if value.is_empty() {
        return false;
    }
    let base = match url::Url::parse(&format!("{request_scheme}://{request_host}")) {
        Ok(base) => base,
        Err(_) => return false,
    };
    let parameter_url = match url::Url::parse(value).or_else(|_| base.join(value)) {
        Ok(url) => url,
        Err(_) => return false,
    };
    if !is_external_redirect_location(parameter_url.as_str(), request_scheme, request_host) {
        return false;
    }
    let location_url = match url::Url::parse(location).or_else(|_| base.join(location)) {
        Ok(url) => url,
        Err(_) => return false,
    };
    parameter_url == location_url || location.contains(value)
}

// ── Utilities ──

fn extract_json_number(json: &str, key: &str) -> Option<i64> {
    let pattern = format!("\"{key}\"");
    let idx = json.find(&pattern)?;
    let rest = &json[idx + pattern.len()..];
    // Skip whitespace and colon
    let rest = rest.trim_start().strip_prefix(':')?;
    let rest = rest.trim_start();
    // Parse number
    let num_str: String = rest
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '-')
        .collect();
    num_str.parse().ok()
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(high), Some(low)) = (hex_value(bytes[i + 1]), hex_value(bytes[i + 2])) {
                decoded.push((high << 4) | low);
                i += 3;
                continue;
            }
        }
        decoded.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

fn session_token_parameter_in_url(path: &str) -> Option<String> {
    let lower = path.to_ascii_lowercase();
    if lower.contains(";jsessionid=") || lower.contains(";phpsessid=") {
        return lower.split(';').skip(1).find_map(|segment| {
            let key = segment
                .split_once('=')
                .map(|(key, _)| key)
                .unwrap_or(segment);
            matches!(key, "jsessionid" | "phpsessid").then(|| key.to_string())
        });
    }

    let query = path.split_once('?')?.1;
    let session_param_names = [
        "jsessionid",
        "phpsessid",
        "sessionid",
        "session_id",
        "sid",
        "aspsessionid",
        "token",
        "access_token",
        "auth_token",
        "api_key",
    ];
    query.split('&').find_map(|pair| {
        let key = pair.split_once('=').map(|(key, _)| key).unwrap_or(pair);
        let key = key.replace('+', " ");
        let decoded = percent_decode(&key).to_ascii_lowercase();
        session_param_names
            .contains(&decoded.as_str())
            .then_some(decoded)
    })
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn truncate_evidence(value: &str, max: usize) -> String {
    if value.len() <= max {
        value.to_string()
    } else {
        let end = value
            .char_indices()
            .map(|(idx, _)| idx)
            .take_while(|idx| *idx <= max)
            .last()
            .unwrap_or(0);
        format!("{}...", &value[..end])
    }
}

fn evidence_window(
    value: &str,
    match_start: usize,
    match_len: usize,
    before: usize,
    after: usize,
) -> &str {
    let start = previous_char_boundary(value, match_start.saturating_sub(before));
    let end = next_char_boundary(value, (match_start + match_len + after).min(value.len()));
    &value[start..end]
}

fn evidence_prefix(value: &str, max: usize) -> &str {
    &value[..previous_char_boundary(value, value.len().min(max))]
}

fn previous_char_boundary(value: &str, mut index: usize) -> usize {
    while index > 0 && !value.is_char_boundary(index) {
        index -= 1;
    }
    index
}

fn next_char_boundary(value: &str, mut index: usize) -> usize {
    while index < value.len() && !value.is_char_boundary(index) {
        index += 1;
    }
    index
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{BodyEncoding, HeaderRecord, MessageRecord, TransactionRecord};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use chrono::Utc;

    fn make_record(
        req_headers: Vec<(&str, &str)>,
        res_headers: Vec<(&str, &str)>,
        res_body: &str,
        status: u16,
    ) -> TransactionRecord {
        TransactionRecord::http(
            Utc::now(),
            "GET".into(),
            "https".into(),
            "example.com".into(),
            "/test".into(),
            Some(status),
            10,
            MessageRecord {
                headers: req_headers
                    .into_iter()
                    .map(|(n, v)| HeaderRecord {
                        name: n.into(),
                        value: v.into(),
                    })
                    .collect(),
                body_preview: String::new(),
                body_encoding: BodyEncoding::Utf8,
                body_size: 0,
                decoded_body_size: None,
                preview_truncated: false,
                content_type: None,
                content_decoded: false,
            },
            Some(MessageRecord {
                headers: res_headers
                    .into_iter()
                    .map(|(n, v)| HeaderRecord {
                        name: n.into(),
                        value: v.into(),
                    })
                    .collect(),
                body_preview: res_body.into(),
                body_encoding: BodyEncoding::Utf8,
                body_size: res_body.len(),
                decoded_body_size: None,
                preview_truncated: false,
                content_decoded: false,
                content_type: Some("text/html".into()),
            }),
            Vec::new(),
            None,
            None,
        )
    }

    fn finding(title: &str) -> ScannerFinding {
        ScannerFinding {
            id: Uuid::new_v4(),
            record_id: Uuid::new_v4(),
            found_at: Utc::now(),
            severity: Severity::Low,
            category: "test".to_string(),
            title: title.to_string(),
            detail: String::new(),
            evidence: String::new(),
            host: "example.com".to_string(),
            path: "/".to_string(),
        }
    }

    fn jwt_token(header: serde_json::Value, payload: serde_json::Value) -> String {
        format!(
            "{}.{}.signature",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(payload.to_string())
        )
    }

    #[tokio::test]
    async fn scanner_store_from_findings_trims_to_max_entries() {
        let store = ScannerStore::from_findings(
            2,
            vec![finding("first"), finding("second"), finding("third")],
        );

        let findings = store.list(None).await;

        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].title, "first");
        assert_eq!(findings[1].title, "second");
    }

    #[tokio::test]
    async fn scanner_store_deduplicates_by_path_too() {
        let store = ScannerStore::new(10);
        let mut first = finding("Missing CSP");
        first.path = "/login".to_string();
        let mut second = finding("Missing CSP");
        second.path = "/admin".to_string();

        store.push(first).await;
        store.push(second).await;

        let findings = store.list(None).await;
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().any(|finding| finding.path == "/login"));
        assert!(findings.iter().any(|finding| finding.path == "/admin"));
    }

    #[tokio::test]
    async fn scanner_store_keeps_same_path_findings_for_distinct_records() {
        let store = ScannerStore::new(10);
        let first = finding("Missing CSP");
        let mut second = first.clone();
        second.id = Uuid::new_v4();
        second.record_id = Uuid::new_v4();

        store.push(first).await;
        store.push(second).await;

        let findings = store.list(None).await;
        assert_eq!(findings.len(), 2);
    }

    #[tokio::test]
    async fn scanner_store_removes_dedup_key_when_finding_is_evicted() {
        let store = ScannerStore::new(1);
        let first = finding("Missing CSP");
        let second = finding("Missing HSTS");

        store.push(first.clone()).await;
        store.push(second).await;
        store.push(first).await;

        let findings = store.list(None).await;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "Missing CSP");
    }

    #[tokio::test]
    async fn scanner_store_clear_resets_dedup_state() {
        let store = ScannerStore::new(10);
        let finding = finding("Missing CSP");

        store.push(finding.clone()).await;
        store.clear().await;
        store.push(finding).await;

        let findings = store.list(None).await;
        assert_eq!(findings.len(), 1);
    }

    #[tokio::test]
    async fn scanner_store_dedup_key_preserves_field_boundaries() {
        let store = ScannerStore::new(10);
        let record_id = Uuid::new_v4();
        let mut first = finding("c");
        first.record_id = record_id;
        first.category = "a:b".to_string();
        let mut second = finding("b:c");
        second.record_id = record_id;
        second.category = "a".to_string();

        assert!(store.push(first).await);
        assert!(store.push(second).await);

        let findings = store.list(None).await;
        assert_eq!(findings.len(), 2);
    }

    #[tokio::test]
    async fn scanner_store_rejects_pre_clear_generation_findings() {
        let store = ScannerStore::new(10);
        let generation = store.clear_generation();
        let finding = finding("Missing CSP");

        store.clear().await;

        assert!(!store.push_if_generation(finding, generation).await);
        assert_eq!(store.count().await, 0);
    }

    #[tokio::test]
    async fn scanner_store_can_restore_clear_generation_after_failed_clear() {
        let store = ScannerStore::new(10);
        let generation = store.clear_generation();

        store.clear().await;
        store.restore_clear_generation(generation);

        assert!(
            store
                .push_if_generation(finding("Missing CSP"), generation)
                .await
        );
        assert_eq!(store.count().await, 1);
    }

    #[test]
    fn truncate_evidence_does_not_split_utf8_codepoints() {
        assert_eq!(truncate_evidence("😀😀", 5), "😀...");
    }

    #[test]
    fn scanner_config_accepts_legacy_empty_object() {
        let config: ScannerConfig =
            serde_json::from_value(serde_json::json!({})).expect("config should deserialize");

        assert!(config.enabled);
        assert!(config.custom_rules.is_empty());
        assert_eq!(config.rules.get("jwt"), Some(&true));
        assert_eq!(config.rules.get("header"), Some(&true));
    }

    #[test]
    fn scanner_config_accepts_partial_legacy_object() {
        let config: ScannerConfig = serde_json::from_value(serde_json::json!({
            "enabled": false
        }))
        .expect("partial config should deserialize");

        assert!(!config.enabled);
        assert!(config.custom_rules.is_empty());
        assert_eq!(config.rules.get("jwt"), Some(&true));
    }

    #[test]
    fn sensitive_scanner_ignores_css_property_that_looks_like_gitlab_token() {
        let record = make_record(
            vec![],
            vec![],
            r#".icon { glyph-orientation-horizontal: 0deg; }"#,
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings
                .iter()
                .any(|finding| finding.title == "GitLab Token detected in response"),
            "CSS glyph-* properties should not be reported as GitLab tokens"
        );
    }

    #[test]
    fn sensitive_scanner_detects_documented_gitlab_token_prefixes() {
        let record = make_record(
            vec![],
            vec![],
            r#"runner_token = "glrt-ABCDEFGHIJKLMNOPQRSTUV123456";"#,
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            findings
                .iter()
                .any(|finding| finding.title == "GitLab Token detected in response"),
            "documented GitLab token prefixes should still be reported"
        );
    }

    #[test]
    fn sensitive_scanner_ignores_password_validation_copy() {
        let record = make_record(
            vec![],
            vec![],
            r#"{ "password": "Password is required", "confirmPassword": "Confirm password" }"#,
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings
                .iter()
                .any(|finding| finding.title == "Password in response detected in response"),
            "validation copy should not be reported as a password leak"
        );
    }

    #[test]
    fn sensitive_scanner_detects_likely_hardcoded_password() {
        let record = make_record(
            vec![],
            vec![],
            r#"{ "password": "CorrectHorseBattery99" }"#,
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            findings
                .iter()
                .any(|finding| finding.title == "Password in response detected in response"),
            "likely hardcoded passwords should still be reported"
        );
    }

    #[test]
    fn open_redirect_detection_compares_location_host_not_substrings() {
        let mut record = make_record(
            vec![],
            vec![("location", "HTTPS://example.com.evil/landing")],
            "",
            302,
        );
        record.path = "/login?next=https://example.com.evil/landing".to_string();
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            findings
                .iter()
                .any(|finding| finding.title == "Possible open redirect"),
            "external suffix host should be reported"
        );
    }

    #[test]
    fn open_redirect_detection_allows_same_host_default_port() {
        let mut record = make_record(
            vec![],
            vec![("location", "https://example.com:443/landing")],
            "",
            302,
        );
        record.path = "/login?next=https://example.com/landing".to_string();
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings
                .iter()
                .any(|finding| finding.title == "Possible open redirect"),
            "same host with default port should not be reported"
        );
    }

    #[test]
    fn open_redirect_detection_ignores_unrelated_external_sso_location() {
        let mut record = make_record(
            vec![],
            vec![("location", "https://idp.example/login")],
            "",
            302,
        );
        record.path = "/login?next=/dashboard".to_string();
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings
                .iter()
                .any(|finding| finding.title == "Possible open redirect"),
            "external SSO redirects should not be reported unless the redirect parameter controls the Location"
        );
    }

    #[test]
    fn open_redirect_detection_requires_exact_query_parameter_name() {
        let mut record = make_record(
            vec![],
            vec![("location", "https://evil.example/landing")],
            "",
            302,
        );
        record.path = "/login?curl=https://evil.example/landing".to_string();
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings
                .iter()
                .any(|finding| finding.title == "Possible open redirect"),
            "substring matches like curl should not be treated as url parameters"
        );
    }

    #[test]
    fn open_redirect_detection_decodes_query_parameter_names() {
        let mut record = make_record(
            vec![],
            vec![("location", "https://evil.example/landing")],
            "",
            302,
        );
        record.path = "/login?redirect%5Furi=https://evil.example/landing".to_string();
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            findings
                .iter()
                .any(|finding| finding.title == "Possible open redirect"),
            "percent-encoded redirect parameter names should still be detected"
        );
    }

    #[test]
    fn open_redirect_detection_treats_scheme_downgrade_as_external() {
        let mut record = make_record(
            vec![],
            vec![("location", "http://example.com:8443/callback")],
            "",
            302,
        );
        record.host = "example.com:8443".to_string();
        record.path = "/login?next=http%3A%2F%2Fexample.com%3A8443%2Fcallback".to_string();
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            findings
                .iter()
                .any(|finding| finding.title == "Possible open redirect"),
            "same host and port with a different scheme is still a cross-origin redirect"
        );
    }

    #[test]
    fn jwt_algorithm_checks_only_use_alg_claim() {
        let token = jwt_token(
            serde_json::json!({ "alg": "RS256", "kid": "none", "hint": "HS256" }),
            serde_json::json!({ "sub": "1234", "exp": 4_102_444_800_i64 }),
        );
        let record = make_record(
            vec![("authorization", &format!("Bearer {token}"))],
            vec![("content-type", "text/html")],
            "",
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings
                .iter()
                .any(|finding| finding.title == "JWT with alg:none"),
            "only the alg claim should trigger alg:none"
        );
        assert!(
            !findings
                .iter()
                .any(|finding| finding.title.contains("symmetric algorithm")),
            "non-alg header fields should not trigger symmetric algorithm findings"
        );
    }

    #[test]
    fn security_header_checks_treat_content_type_case_insensitively() {
        let mut record = make_record(
            vec![],
            vec![("content-type", "TEXT/HTML; Charset=UTF-8")],
            "<html></html>",
            200,
        );
        if let Some(response) = &mut record.response {
            response.content_type = Some("TEXT/HTML; Charset=UTF-8".to_string());
        }
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            findings
                .iter()
                .any(|finding| finding.title == "Missing Content-Security-Policy"),
            "HTML content-type checks should be case-insensitive"
        );
    }

    #[test]
    fn test_jwt_detection() {
        // JWT with no expiration (header: {"alg":"HS256","typ":"JWT"}, payload: {"sub":"1234"})
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.abc123";
        let record = make_record(
            vec![("authorization", &format!("Bearer {token}"))],
            vec![("content-type", "text/html")],
            "",
            200,
        );
        let config = ScannerConfig::default();
        let findings = scan_transaction(&record, &config);
        assert!(
            findings
                .iter()
                .any(|f| f.category == "jwt" && f.title.contains("without expiration")),
            "Should detect JWT without expiration"
        );
    }

    #[test]
    fn jwt_detection_accepts_uppercase_bearer_scheme_and_empty_signature() {
        let token = jwt_token(
            serde_json::json!({ "alg": "none", "typ": "JWT" }),
            serde_json::json!({ "sub": "1234", "exp": 4_102_444_800_i64 }),
        );
        let token = token.trim_end_matches("signature").to_string();
        let record = make_record(
            vec![("authorization", &format!("BEARER   {token}"))],
            vec![("content-type", "text/html")],
            "",
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            findings
                .iter()
                .any(|finding| finding.title == "JWT with alg:none"),
            "case-insensitive bearer schemes and empty signatures should be analyzed"
        );
    }

    #[test]
    fn jwt_detection_decodes_url_encoded_cookie_values() {
        let token = jwt_token(
            serde_json::json!({ "alg": "HS256", "typ": "JWT" }),
            serde_json::json!({ "sub": "1234" }),
        );
        let encoded_token = token.replace('.', "%2E");
        let record = make_record(
            vec![("cookie", &format!("session=\"{encoded_token}\""))],
            vec![("content-type", "text/html")],
            "",
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            findings
                .iter()
                .any(|finding| finding.title == "JWT without expiration"),
            "percent-encoded JWT cookie values should still be analyzed"
        );
    }

    #[test]
    fn jwt_detection_decodes_url_encoded_bearer_tokens() {
        let token = jwt_token(
            serde_json::json!({ "alg": "HS256", "typ": "JWT" }),
            serde_json::json!({ "sub": "1234" }),
        );
        let encoded_token = token.replace('.', "%2E");
        let record = make_record(
            vec![("authorization", &format!("Bearer {encoded_token}"))],
            vec![("content-type", "text/html")],
            "",
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            findings
                .iter()
                .any(|finding| finding.title == "JWT without expiration"),
            "percent-encoded bearer JWTs should still be analyzed"
        );
    }

    #[test]
    fn jwt_detection_decodes_url_encoded_body_tokens() {
        let token = jwt_token(
            serde_json::json!({ "alg": "HS256", "typ": "JWT" }),
            serde_json::json!({ "sub": "1234" }),
        );
        let encoded_token = token.replace('.', "%2E");
        let record = make_record(
            vec![],
            vec![("content-type", "application/json")],
            &format!(r#"{{"token":"{encoded_token}"}}"#),
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            findings
                .iter()
                .any(|finding| finding.title == "JWT without expiration"),
            "percent-encoded JWTs in response bodies should still be analyzed"
        );
    }

    #[test]
    fn jwt_detection_accepts_non_object_payload_prefix_in_body_tokens() {
        let token = jwt_token(
            serde_json::json!({ "alg": "none", "typ": "JWT" }),
            serde_json::json!({}),
        );
        let record = make_record(
            vec![],
            vec![("content-type", "application/json")],
            &format!(r#"{{"token":"{token}"}}"#),
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(findings
            .iter()
            .any(|finding| finding.title == "JWT with alg:none"));
    }

    #[test]
    fn test_missing_security_headers() {
        let record = make_record(
            vec![],
            vec![("content-type", "text/html")],
            "<html></html>",
            200,
        );
        let config = ScannerConfig::default();
        let findings = scan_transaction(&record, &config);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("Content-Security-Policy")),
            "Should detect missing CSP"
        );
    }

    #[test]
    fn security_header_checks_reject_invalid_hsts_values() {
        let record = make_record(
            vec![],
            vec![
                ("content-security-policy", "default-src 'self'"),
                ("strict-transport-security", "max-age=0"),
                ("x-content-type-options", "nosniff"),
                ("x-frame-options", "DENY"),
            ],
            "<html></html>",
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(findings
            .iter()
            .any(|finding| finding.title == "Missing Strict-Transport-Security"));
    }

    #[test]
    fn security_header_checks_reject_invalid_content_type_options() {
        let record = make_record(
            vec![],
            vec![
                ("content-security-policy", "default-src 'self'"),
                ("strict-transport-security", "max-age=31536000"),
                ("x-content-type-options", "sniff"),
                ("x-frame-options", "DENY"),
            ],
            "<html></html>",
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(findings
            .iter()
            .any(|finding| finding.title == "Missing X-Content-Type-Options"));
    }

    #[test]
    fn security_header_checks_reject_invalid_frame_protection() {
        let record = make_record(
            vec![],
            vec![
                ("content-security-policy", "default-src 'self'"),
                ("strict-transport-security", "max-age=31536000"),
                ("x-content-type-options", "nosniff"),
                ("x-frame-options", "ALLOWALL"),
            ],
            "<html></html>",
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(findings
            .iter()
            .any(|finding| finding.title == "Missing X-Frame-Options"));
    }

    #[test]
    fn security_header_checks_reject_empty_frame_ancestors_directive() {
        let record = make_record(
            vec![],
            vec![
                ("content-security-policy", "frame-ancestors"),
                ("strict-transport-security", "max-age=31536000"),
                ("x-content-type-options", "nosniff"),
            ],
            "<html></html>",
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(findings
            .iter()
            .any(|finding| finding.title == "Missing X-Frame-Options"));
    }

    #[test]
    fn page_header_checks_skip_binary_response_without_content_type() {
        let mut record = make_record(vec![], vec![], "", 200);
        if let Some(response) = &mut record.response {
            response.body_preview = STANDARD.encode([0x89, b'P', b'N', b'G']);
            response.body_encoding = BodyEncoding::Base64;
            response.body_size = 4;
            response.content_type = None;
        }
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings
                .iter()
                .any(|finding| finding.title == "Missing Content-Security-Policy"),
            "binary responses without content-type should not be treated as HTML pages"
        );
        assert!(
            !findings
                .iter()
                .any(|finding| finding.title == "Missing Referrer-Policy header"),
            "binary responses without content-type should not get page-only misconfig findings"
        );
    }

    #[test]
    fn session_token_detection_requires_exact_query_parameter_name() {
        let mut record = make_record(vec![], vec![("content-type", "text/html")], "", 200);
        record.path = "/search?notoken=1&xapi_key=2".to_string();
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings
                .iter()
                .any(|finding| finding.title.starts_with("Session/token parameter")),
            "token-like substrings inside unrelated parameter names should not be reported"
        );
    }

    #[test]
    fn session_token_detection_decodes_exact_query_parameter_name() {
        let mut record = make_record(vec![], vec![("content-type", "text/html")], "", 200);
        record.path = "/search?access%5Ftoken=secret".to_string();
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            findings
                .iter()
                .any(|finding| finding.title == "Session/token parameter in URL: access_token"),
            "percent-encoded token parameter names should be reported"
        );
    }

    #[test]
    fn session_token_detection_reports_actual_matrix_parameter_name() {
        let mut record = make_record(vec![], vec![("content-type", "text/html")], "", 200);
        record.path = "/app;foo=bar;jsessionid=abc".to_string();
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            findings
                .iter()
                .any(|finding| finding.title == "Session/token parameter in URL: jsessionid"),
            "matrix path scanning should report the actual session parameter"
        );
        assert!(
            !findings
                .iter()
                .any(|finding| finding.title == "Session/token parameter in URL: foo"),
            "unrelated matrix parameters should not be reported as session tokens"
        );
    }

    #[test]
    fn internal_ip_pattern_reports_full_private_ipv4_address() {
        let record = make_record(
            vec![],
            vec![("content-type", "application/json")],
            r#"{"upstream":"10.1.2.3"}"#,
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            findings.iter().any(|finding| {
                finding.title.contains("Internal IP address")
                    && finding.evidence.contains("10.1.2.3")
            }),
            "10/8 addresses should include all four octets in evidence"
        );
    }

    #[test]
    fn test_cookie_flags() {
        let record = make_record(
            vec![],
            vec![("set-cookie", "session=abc123; Path=/")],
            "",
            200,
        );
        let config = ScannerConfig::default();
        let findings = scan_transaction(&record, &config);
        assert!(
            findings.iter().any(|f| f.title.contains("HttpOnly")),
            "Should detect missing HttpOnly"
        );
    }

    #[test]
    fn cookie_flags_are_detected_from_attributes_not_cookie_name_or_value() {
        let record = make_record(
            vec![],
            vec![("set-cookie", "insecure_samesite=httponly_value; Path=/")],
            "",
            200,
        );
        let config = ScannerConfig::default();
        let findings = scan_transaction(&record, &config);

        assert!(
            findings.iter().any(|f| f.title.contains("HttpOnly")),
            "Should detect missing HttpOnly when only the value contains httponly"
        );
        assert!(
            findings.iter().any(|f| f.title.contains("Secure")),
            "Should detect missing Secure when only the name contains secure"
        );
        assert!(
            findings.iter().any(|f| f.title.contains("SameSite")),
            "Should detect missing SameSite when only the name contains samesite"
        );
    }

    #[test]
    fn cache_control_check_treats_auth_cookies_as_authenticated() {
        let record = make_record(
            vec![("cookie", "session=abc123; theme=dark")],
            vec![("content-type", "application/json")],
            r#"{"private":true}"#,
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(findings
            .iter()
            .any(|finding| finding.title == "Missing Cache-Control on authenticated response"));
    }

    #[test]
    fn cache_control_public_check_treats_auth_cookies_as_authenticated() {
        let record = make_record(
            vec![("cookie", "access_token=abc123")],
            vec![
                ("content-type", "application/json"),
                ("cache-control", "public, max-age=60"),
            ],
            r#"{"private":true}"#,
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(findings
            .iter()
            .any(|finding| finding.title == "Cache-Control: public on authenticated response"));
    }

    #[test]
    fn test_cors_wildcard() {
        let record = make_record(vec![], vec![("access-control-allow-origin", "*")], "", 200);
        let config = ScannerConfig::default();
        let findings = scan_transaction(&record, &config);
        assert!(
            findings.iter().any(|f| f.category == "cors"),
            "Should detect wildcard CORS"
        );
    }

    #[test]
    fn cors_checks_trim_header_ows_before_comparison() {
        let record = make_record(
            vec![],
            vec![
                ("access-control-allow-origin", " * "),
                ("access-control-allow-credentials", " true "),
            ],
            "",
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            findings
                .iter()
                .any(|f| f.category == "cors" && f.severity == Severity::High),
            "OWS around CORS headers should not hide wildcard-with-credentials"
        );
    }

    #[test]
    fn cors_null_origin_with_credentials_is_reported() {
        let record = make_record(
            vec![("origin", "null")],
            vec![
                ("access-control-allow-origin", "null"),
                ("access-control-allow-credentials", "true"),
            ],
            "",
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(findings
            .iter()
            .any(|finding| finding.title == "CORS: null origin with credentials"));
    }

    #[test]
    fn cors_allowed_methods_match_exact_method_tokens() {
        let record = make_record(
            vec![],
            vec![("access-control-allow-methods", "GET, OPTIONS, COMPUTE")],
            "",
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings.iter().any(|f| f.title == "CORS allows PUT"),
            "method names embedded in other tokens should not count as allowed CORS methods"
        );
    }

    #[test]
    fn cors_allowed_methods_still_report_patch_token() {
        let record = make_record(
            vec![],
            vec![("access-control-allow-methods", "GET, PATCH")],
            "",
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(findings.iter().any(|f| f.title == "CORS allows PATCH"));
    }

    #[test]
    fn test_server_disclosure() {
        let record = make_record(vec![], vec![("server", "Apache/2.4.51")], "", 200);
        let config = ScannerConfig::default();
        let findings = scan_transaction(&record, &config);
        assert!(
            findings
                .iter()
                .any(|f| f.category == "server" && f.title.contains("Server version")),
            "Should detect server version disclosure"
        );
    }

    #[test]
    fn test_sql_error() {
        let record = make_record(
            vec![],
            vec![],
            "You have an error in your SQL syntax; check the manual",
            500,
        );
        let config = ScannerConfig::default();
        let findings = scan_transaction(&record, &config);
        assert!(
            findings.iter().any(|f| f.category == "error"),
            "Should detect SQL error message"
        );
    }

    #[test]
    fn sql_error_evidence_window_does_not_split_utf8_padding() {
        let body = format!("a{}sql syntax near select", "語".repeat(7));
        let record = make_record(vec![], vec![], &body, 500);
        let config = ScannerConfig::default();
        let findings = scan_transaction(&record, &config);

        assert!(
            findings.iter().any(|f| f.category == "error"),
            "Should detect SQL error without panicking on UTF-8 evidence window"
        );
    }

    #[test]
    fn test_csp_unsafe_inline() {
        let record = make_record(
            vec![],
            vec![
                ("content-type", "text/html"),
                (
                    "content-security-policy",
                    "default-src 'self' 'unsafe-inline'",
                ),
            ],
            "<html></html>",
            200,
        );
        let config = ScannerConfig::default();
        let findings = scan_transaction(&record, &config);
        assert!(
            findings
                .iter()
                .any(|f| f.category == "misconfig" && f.title.contains("unsafe-inline")),
            "Should detect CSP unsafe-inline"
        );
    }

    #[test]
    fn csp_unsafe_inline_check_ignores_style_only_directive() {
        let record = make_record(
            vec![],
            vec![
                ("content-type", "text/html"),
                (
                    "content-security-policy",
                    "default-src 'self'; script-src 'self'; style-src 'unsafe-inline' 'unsafe-eval'",
                ),
            ],
            "<html></html>",
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            !findings.iter().any(|f| {
                f.category == "misconfig"
                    && (f.title.contains("unsafe-inline") || f.title.contains("unsafe-eval"))
            }),
            "style-only unsafe tokens should not be reported as script CSP risks"
        );
    }

    #[test]
    fn csp_unsafe_inline_uses_default_src_only_without_script_directive() {
        let record = make_record(
            vec![],
            vec![
                ("content-type", "text/html"),
                (
                    "content-security-policy",
                    "default-src 'self' 'unsafe-inline'; style-src 'self'",
                ),
            ],
            "<html></html>",
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(
            findings
                .iter()
                .any(|f| f.category == "misconfig" && f.title.contains("unsafe-inline")),
            "default-src should be checked when no script directive is present"
        );
    }

    #[test]
    fn test_directory_listing() {
        let record = make_record(
            vec![],
            vec![("content-type", "text/html")],
            "<html><body><h1>Index of /uploads</h1><a href=\"../\">Parent Directory</a><br>Last modified</body></html>",
            200,
        );
        let config = ScannerConfig::default();
        let findings = scan_transaction(&record, &config);
        assert!(
            findings
                .iter()
                .any(|f| f.category == "info" && f.title.contains("Directory listing")),
            "Should detect directory listing"
        );
    }

    #[test]
    fn directory_listing_evidence_prefix_does_not_split_utf8() {
        let body = format!(
            "a{}<html><body><h1>Index of /uploads</h1>Parent Directory Last modified</body></html>",
            "語".repeat(40)
        );
        let record = make_record(vec![], vec![("content-type", "text/html")], &body, 200);
        let config = ScannerConfig::default();
        let findings = scan_transaction(&record, &config);

        assert!(
            findings
                .iter()
                .any(|f| f.category == "info" && f.title.contains("Directory listing")),
            "Should detect directory listing without panicking on UTF-8 prefix"
        );
    }

    #[test]
    fn test_graphql_introspection() {
        let record = make_record(
            vec![],
            vec![("content-type", "application/json")],
            r#"{"data":{"__schema":{"queryType":{"name":"Query"}}}}"#,
            200,
        );
        let config = ScannerConfig::default();
        let findings = scan_transaction(&record, &config);
        assert!(
            findings
                .iter()
                .any(|f| f.category == "info" && f.title.contains("GraphQL introspection")),
            "Should detect GraphQL introspection"
        );
    }

    #[test]
    fn test_session_token_in_url() {
        let record = TransactionRecord::http(
            Utc::now(),
            "GET".into(),
            "https".into(),
            "example.com".into(),
            "/app?JSESSIONID=abc123def456".into(),
            Some(200),
            10,
            MessageRecord {
                headers: vec![],
                body_preview: String::new(),
                body_encoding: BodyEncoding::Utf8,
                body_size: 0,
                decoded_body_size: None,
                preview_truncated: false,
                content_type: None,
                content_decoded: false,
            },
            Some(MessageRecord {
                headers: vec![],
                body_preview: String::new(),
                body_encoding: BodyEncoding::Utf8,
                body_size: 0,
                decoded_body_size: None,
                preview_truncated: false,
                content_type: Some("text/html".into()),
                content_decoded: false,
            }),
            Vec::new(),
            None,
            None,
        );
        let config = ScannerConfig::default();
        let findings = scan_transaction(&record, &config);
        assert!(
            findings
                .iter()
                .any(|f| f.category == "auth" && f.title.contains("Session/token")),
            "Should detect session token in URL"
        );
    }

    #[test]
    fn test_basic_auth_over_http() {
        let record = TransactionRecord::http(
            Utc::now(),
            "GET".into(),
            "http".into(),
            "example.com".into(),
            "/admin".into(),
            Some(200),
            10,
            MessageRecord {
                headers: vec![HeaderRecord {
                    name: "Authorization".into(),
                    value: "Basic dXNlcjpwYXNz".into(),
                }],
                body_preview: String::new(),
                body_encoding: BodyEncoding::Utf8,
                body_size: 0,
                decoded_body_size: None,
                preview_truncated: false,
                content_type: None,
                content_decoded: false,
            },
            Some(MessageRecord {
                headers: vec![],
                body_preview: String::new(),
                body_encoding: BodyEncoding::Utf8,
                body_size: 0,
                decoded_body_size: None,
                preview_truncated: false,
                content_type: Some("text/html".into()),
                content_decoded: false,
            }),
            Vec::new(),
            None,
            None,
        );
        let config = ScannerConfig::default();
        let findings = scan_transaction(&record, &config);
        assert!(
            findings.iter().any(|f| f.category == "auth" && f.title.contains("Basic authentication over HTTP")),
            "Should detect Basic auth over HTTP"
        );
    }

    #[test]
    fn test_stripe_key_detection() {
        // Build test key at runtime to avoid GitHub push protection false positive
        let fake_key = format!("sk_{}_{}a", "live", "TESTKEY000000000000000000");
        let body = format!(r#"<script>var key = "{fake_key}";</script>"#);
        let record = make_record(vec![], vec![("content-type", "text/html")], &body, 200);
        let config = ScannerConfig::default();
        let findings = scan_transaction(&record, &config);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("Stripe Secret Key")),
            "Should detect Stripe secret key"
        );
    }

    #[test]
    fn sensitive_scanner_detects_json_api_key() {
        let fake_key = "A".repeat(24);
        let body = format!(r#"{{"api_key":"{fake_key}"}}"#);
        let record = make_record(
            vec![],
            vec![("content-type", "application/json")],
            &body,
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(findings
            .iter()
            .any(|f| f.title.contains("API Key/Secret pattern")));
    }

    #[test]
    fn sensitive_scanner_detects_quoted_secret_token_assignment() {
        let fake_token = "b".repeat(24);
        let body = format!(r#"const auth_token = "{fake_token}";"#);
        let record = make_record(vec![], vec![("content-type", "text/html")], &body, 200);
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(findings
            .iter()
            .any(|f| f.title.contains("Secret/Token pattern")));
    }

    #[test]
    fn sensitive_scanner_detects_json_aws_secret_access_key() {
        let fake_secret = "c".repeat(40);
        let body = format!(r#"{{"aws_secret_access_key":"{fake_secret}"}}"#);
        let record = make_record(
            vec![],
            vec![("content-type", "application/json")],
            &body,
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(findings
            .iter()
            .any(|f| f.title.contains("AWS Secret Access Key")));
    }

    #[test]
    fn sensitive_scanner_detects_huggingface_token_with_digits() {
        let body = format!("token=hf_{}", "a1".repeat(17));
        let record = make_record(vec![], vec![("content-type", "text/html")], &body, 200);
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(findings
            .iter()
            .any(|f| f.title.contains("HuggingFace Token")));
    }

    #[test]
    fn sensitive_scanner_requires_huggingface_token_boundaries() {
        let token = format!("hf_{}", "a1".repeat(17));
        let record = make_record(
            vec![],
            vec![("content-type", "text/html")],
            &format!("prefix{token} {token}suffix"),
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(!findings
            .iter()
            .any(|f| f.title.contains("HuggingFace Token")));
    }

    #[test]
    fn sensitive_scanner_rejects_invalid_luhn_card_number() {
        let invalid_card = format!("{}{}", "411111111111111", "2");
        let record = make_record(
            vec![],
            vec![("content-type", "text/html")],
            &invalid_card,
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(!findings
            .iter()
            .any(|f| f.title.contains("Possible Visa card number")));
    }

    #[test]
    fn sensitive_scanner_detects_luhn_valid_visa_card_number() {
        let valid_card = format!("{}{}", "411111111111111", "1");
        let record = make_record(
            vec![],
            vec![("content-type", "text/html")],
            &valid_card,
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(findings
            .iter()
            .any(|f| f.title.contains("Possible Visa card number")));
    }

    #[test]
    fn test_html_comment_sensitive() {
        let record = make_record(
            vec![],
            vec![("content-type", "text/html")],
            "<html><!-- TODO: remove admin password check --><body>Hello</body></html>",
            200,
        );
        let config = ScannerConfig::default();
        let findings = scan_transaction(&record, &config);
        assert!(
            findings
                .iter()
                .any(|f| f.category == "info" && f.title.contains("HTML comment")),
            "Should detect sensitive HTML comment"
        );
    }

    #[test]
    fn test_swagger_exposure() {
        let record = make_record(
            vec![],
            vec![("content-type", "application/json")],
            r#"{"swagger":"2.0","info":{"title":"API"},"paths":{"/users":{"get":{}}}}"#,
            200,
        );
        let config = ScannerConfig::default();
        let findings = scan_transaction(&record, &config);
        assert!(
            findings
                .iter()
                .any(|f| f.category == "info" && f.title.contains("Swagger")),
            "Should detect Swagger/OpenAPI spec exposure"
        );
    }

    #[test]
    fn source_map_header_is_reported_even_when_body_is_empty() {
        let record = make_record(vec![], vec![("sourcemap", "/static/app.js.map")], "", 200);
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(findings
            .iter()
            .any(|finding| finding.title == "Source map header present"));
    }

    #[test]
    fn blank_source_map_header_is_ignored() {
        let record = make_record(vec![], vec![("sourcemap", "   ")], "", 200);
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(!findings
            .iter()
            .any(|finding| finding.title == "Source map header present"));
    }

    #[test]
    fn email_disclosure_ignores_example_domains_case_insensitively() {
        let record = make_record(
            vec![],
            vec![("content-type", "text/html")],
            "<html>Contact ADMIN@EXAMPLE.COM for docs.</html>",
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(!findings
            .iter()
            .any(|f| f.title == "Email address in response"));
    }

    #[test]
    fn email_disclosure_does_not_ignore_suffix_lookalike_domains() {
        let record = make_record(
            vec![],
            vec![("content-type", "text/html")],
            "<html>Contact security@notexample.com for help.</html>",
            200,
        );
        let findings = scan_transaction(&record, &ScannerConfig::default());

        assert!(findings
            .iter()
            .any(|f| f.title == "Email address in response"));
    }
}
