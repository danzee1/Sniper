use std::{
    collections::HashSet,
    convert::Infallible,
    net::{IpAddr, Ipv6Addr},
    path::{Component, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use async_stream::stream;
use axum::{
    extract::{Path, Query, Request, State},
    http::{
        header,
        uri::{Authority, PathAndQuery},
        HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri,
    },
    middleware::{self, Next},
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Response,
    },
    routing::{delete, get, patch, post},
    Json, Router,
};
use indexmap::IndexMap;
use regex::RegexBuilder;
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};
use tokio::sync::OwnedMutexGuard;
use uuid::Uuid;

use crate::{
    config::{StartupSettingsUpdate, StartupSettingsView},
    event_log::{EventLevel, EventLogEntry},
    fuzzer::{self, FuzzerAttackPayload},
    match_replace::{MatchReplaceRule, MatchReplaceRulesPayload},
    model::{BodyEncoding, EditableRequest, EditableResponse, HeaderRecord, RequestTargetOverride},
    proxy,
    runtime::RuntimeSettingsUpdate,
    runtime_state::{self, RuntimeStateSnapshot},
    sequence::{self, SequenceDefinition},
    session::{SessionContext, SessionSummary},
    state::AppState,
    store::{ListFilters, TransactionListPage},
    target::{TargetHostNode, TargetPathNode},
    ui_settings::AppUiSettingsSnapshot,
    workspace::{
        can_replace_snapshot, validate_workspace_serialized_size, WorkspaceReplaceError,
        WorkspaceStateSnapshot, MAX_WORKSPACE_SERIALIZED_BYTES,
    },
};

const MAX_WORKSPACE_WS_FRAMES: usize = 1_000;
const MAX_WORKSPACE_WS_FRAME_BODY_BYTES: usize = 16 * 1024;
const MAX_WORKSPACE_WS_TOTAL_FRAMES: usize = 2_000;
const MAX_WORKSPACE_WS_TOTAL_FRAME_BODY_BYTES: usize = 12 * 1024 * 1024;
const MAX_WORKSPACE_REPLAY_TABS: usize = 128;
const MAX_WORKSPACE_REPLAY_HISTORY_ENTRIES_PER_TAB: usize = 500;
const MAX_WORKSPACE_TEXT_FIELD_BYTES: usize = 2 * 1024 * 1024;
const MAX_WORKSPACE_FUZZER_PAYLOAD_TEXT_BYTES: usize = 4 * 1024 * 1024;
const MAX_WORKSPACE_FUZZER_PAYLOAD_LINES: usize = 5_000;
const MAX_WORKSPACE_WS_HEADERS: usize = 200;
const MAX_WORKSPACE_WS_HEADER_BYTES: usize = 64 * 1024;
const MAX_WORKSPACE_WS_HEADERS_BYTES: usize = 256 * 1024;
const MAX_WORKSPACE_WS_SETUP_QUEUE_ITEMS: usize = 250;
const MAX_WORKSPACE_WS_SETUP_ITEM_BYTES: usize = 64 * 1024;
const MAX_WORKSPACE_EDITABLE_MESSAGE_BYTES: usize = 2 * 1024 * 1024;
const MAX_WORKSPACE_EMBEDDED_RECORD_BYTES: usize = 4 * 1024 * 1024;
const MAX_WORKSPACE_STORED_BYTES: usize = MAX_WORKSPACE_SERIALIZED_BYTES;
const MAX_WORKSPACE_CLIENT_ID_BYTES: usize = 128;
const MAX_WORKSPACE_REPLAY_TAB_ID_BYTES: usize = 128;
const MAX_WORKSPACE_REPLAY_TAB_TYPE_BYTES: usize = 32;
const MAX_WORKSPACE_REPLAY_ACTIVE_TAB_ID_BYTES: usize = 128;
const MAX_WORKSPACE_REPLAY_TARGET_FIELD_BYTES: usize = 4 * 1024;
const MAX_SEQUENCE_STEPS: usize = 250;
const MAX_SEQUENCE_EXTRACTIONS_PER_STEP: usize = 50;
const MAX_SEQUENCE_TEXT_FIELD_BYTES: usize = 64 * 1024;
const MAX_SEQUENCE_DEFINITION_BYTES: usize = 8 * 1024 * 1024;
const MAX_SCANNER_CUSTOM_RULES: usize = 250;
const MAX_SCANNER_FIELD_BYTES: usize = 64 * 1024;
const MAX_SCANNER_CONFIG_BYTES: usize = 4 * 1024 * 1024;
const MAX_MATCH_REPLACE_RULES: usize = 500;
const MAX_MATCH_REPLACE_FIELD_BYTES: usize = 256 * 1024;
const MAX_MATCH_REPLACE_RULES_BYTES: usize = 8 * 1024 * 1024;
const MAX_ANNOTATION_NOTE_BYTES: usize = 32 * 1024;
const ALLOWED_COLOR_TAGS: &[&str] = &["red", "orange", "yellow", "green", "blue", "purple"];
const DEFAULT_WEBSOCKET_DETAIL_FRAME_LIMIT: usize = 1_000;
const MAX_WEBSOCKET_DETAIL_FRAME_LIMIT: usize = 1_000;
const OPEN_PATH: &str = "/usr/bin/open";

#[derive(RustEmbed)]
#[folder = "web/decoder/"]
struct DecoderAssets;

pub async fn run_api(state: Arc<AppState>) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(state.config.ui_addr)
        .await
        .with_context(|| format!("failed to bind UI listener to {}", state.config.ui_addr))?;

    serve_api(listener, state).await
}

pub async fn serve_api(listener: tokio::net::TcpListener, state: Arc<AppState>) -> Result<()> {
    let ui_addr = listener
        .local_addr()
        .context("failed to read bound UI listener address")?;
    let advertised_ui_addr = runtime_state::advertise_local_api_addr(ui_addr);
    state.set_active_ui_addr(advertised_ui_addr).await;
    if let Err(error) = persist_bound_runtime_state(&state, advertised_ui_addr).await {
        tracing::warn!(?error, "failed to persist runtime-state.json");
    }
    let app = router(state);
    tracing::info!(ui_addr = %ui_addr, advertised_ui_addr = %advertised_ui_addr, "ui listener ready");
    axum::serve(listener, app)
        .await
        .context("ui server stopped unexpectedly")
}

async fn persist_bound_runtime_state(
    state: &Arc<AppState>,
    ui_addr: std::net::SocketAddr,
) -> Result<()> {
    runtime_state::persist_runtime_state(
        &state.config.data_dir,
        &RuntimeStateSnapshot::with_proxy_status(
            state.get_active_proxy_addr().await,
            ui_addr,
            state.is_proxy_online(),
        ),
    )
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/decoder", get(decoder_index))
        .route("/decoder/", get(decoder_index))
        .route("/decoder/*path", get(decoder_asset))
        .route("/app.js", get(app_js))
        .route("/codemirror.js", get(codemirror_js))
        .route("/styles.css", get(styles_css))
        .route("/favicon.svg", get(favicon_svg))
        .route("/logo.svg", get(logo_svg))
        .route("/fonts/Bungee-Regular.ttf", get(bungee_font))
        .route("/api/settings", get(get_settings))
        .route("/api/app-version", get(get_app_version))
        .route("/api/self-update", post(self_update))
        .route("/api/sessions", get(list_sessions).post(create_session))
        .route("/api/sessions/:id/activate", post(activate_session))
        .route("/api/sessions/:id", delete(delete_session))
        .route("/api/sessions/:id/reveal", post(reveal_session_folder))
        .route(
            "/api/runtime",
            get(get_runtime_settings).post(update_runtime_settings),
        )
        .route(
            "/api/workspace-state",
            get(get_workspace_state).post(update_workspace_state),
        )
        .route(
            "/api/startup-settings",
            get(get_startup_settings).post(update_startup_settings),
        )
        .route(
            "/api/ui-settings",
            get(get_ui_settings).post(update_ui_settings),
        )
        .route(
            "/api/event-log",
            get(list_event_log).delete(clear_event_log),
        )
        .route("/api/certificates/root.pem", get(download_root_pem))
        .route("/api/certificates/root.der", get(download_root_der))
        .route("/api/certificates/reveal", post(reveal_certificate_folder))
        .route(
            "/api/match-replace",
            get(list_match_replace_rules).post(update_match_replace_rules),
        )
        .route("/api/findings", get(list_findings))
        .route("/api/findings/count", get(count_findings))
        .route("/api/findings/:id", get(get_finding))
        .route("/api/findings/clear", post(clear_findings))
        .route(
            "/api/scanner-config",
            get(get_scanner_config).post(update_scanner_config),
        )
        .route("/api/oast/callbacks", get(list_oast_callbacks))
        .route("/api/oast/callbacks/:id", get(get_oast_callback))
        .route("/api/oast/callbacks/clear", post(clear_oast_callbacks))
        .route("/api/oast/generate", post(generate_oast_payload))
        .route("/api/oast/status", get(oast_status))
        .route("/api/target/site-map", get(get_target_site_map))
        .route("/api/transactions", get(list_transactions))
        .route("/api/transactions-page", get(list_transactions_page))
        .route("/api/transactions/:id", get(get_transaction))
        .route(
            "/api/transactions/:id/annotations",
            patch(update_transaction_annotations),
        )
        .route("/api/intercepts", get(list_intercepts))
        .route("/api/intercepts/forward-all", post(forward_all_intercepts))
        .route("/api/intercepts/:id", get(get_intercept))
        .route("/api/intercepts/:id/forward", post(forward_intercept))
        .route("/api/intercepts/:id/drop", post(drop_intercept))
        .route(
            "/api/intercept-rules",
            get(list_intercept_rules).post(upsert_intercept_rule),
        )
        .route("/api/intercept-rules/:id", delete(delete_intercept_rule))
        .route("/api/response-intercepts", get(list_response_intercepts))
        .route(
            "/api/response-intercepts/forward-all",
            post(forward_all_response_intercepts),
        )
        .route("/api/response-intercepts/:id", get(get_response_intercept))
        .route(
            "/api/response-intercepts/:id/forward",
            post(forward_response_intercept),
        )
        .route(
            "/api/response-intercepts/:id/drop",
            post(drop_response_intercept),
        )
        .route("/api/replay/send", post(send_replay))
        .route(
            "/api/fuzzer/attacks",
            get(list_fuzzer_attacks).post(run_fuzzer_attack),
        )
        .route("/api/fuzzer/attacks/:id", get(get_fuzzer_attack))
        .route("/api/sequences", get(list_sequences).post(upsert_sequence))
        .route(
            "/api/sequences/:id",
            get(get_sequence).delete(delete_sequence),
        )
        .route("/api/sequences/:id/run", post(run_sequence))
        .route("/api/sequence-runs", get(list_sequence_runs))
        .route("/api/sequence-runs/:id", get(get_sequence_run))
        .route("/api/websockets", get(list_websockets))
        .route("/api/websockets-page", get(list_websockets_page))
        .route("/api/websockets/:id", get(get_websocket))
        .route("/api/replay/ws-connect", post(ws_replay_connect))
        .route("/api/replay/ws-send", post(ws_replay_send))
        .route("/api/replay/ws-disconnect", post(ws_replay_disconnect))
        .route("/api/replay/ws-snapshot/:id", get(ws_replay_snapshot))
        .route("/api/replay/ws-frames/:id", get(ws_replay_frames))
        .route("/api/events", get(events))
        .fallback(get(index))
        .layer(middleware::from_fn(local_api_write_guard))
        .layer(axum::extract::DefaultBodyLimit::max(64 * 1024 * 1024)) // 64 MB
        .with_state(state)
}

async fn local_api_write_guard(request: Request, next: Next) -> Response {
    if request.uri().path().starts_with("/api/") {
        if !request_host_is_allowed_local_api(request.headers(), request.uri()) {
            return (
                StatusCode::FORBIDDEN,
                "requests to the local Sniper API must use a loopback Host",
            )
                .into_response();
        }
        if !matches!(
            *request.method(),
            Method::GET | Method::HEAD | Method::OPTIONS
        ) && !is_allowed_browser_write(request.headers(), request.uri())
        {
            return (
                StatusCode::FORBIDDEN,
                "cross-origin writes to the local Sniper API are blocked",
            )
                .into_response();
        }
    }
    next.run(request).await
}

fn request_host_is_allowed_local_api(headers: &HeaderMap, uri: &Uri) -> bool {
    let Some(authority) = request_authority(headers, uri) else {
        return false;
    };
    let Some(host) = host_from_request_authority(&authority) else {
        return false;
    };
    host == "localhost" || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

fn host_from_request_authority(authority: &str) -> Option<String> {
    let authority = authority.trim();
    if authority.is_empty() {
        return None;
    }
    if let Some(bracketed) = authority.strip_prefix('[') {
        let (host, rest) = bracketed.split_once(']')?;
        if host.is_empty() || rest.contains(']') {
            return None;
        }
        if !rest.is_empty() {
            let port = rest.strip_prefix(':')?;
            if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
        }
    } else if authority.matches(':').count() > 1 {
        return None;
    } else if let Some((host, port)) = authority.split_once(':') {
        if host.is_empty() || port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
    }

    let parsed = authority.parse::<Authority>().ok()?;
    let host = parsed
        .host()
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or_else(|| parsed.host())
        .to_ascii_lowercase();
    (!host.is_empty()).then_some(host)
}

fn is_allowed_browser_write(headers: &HeaderMap, uri: &Uri) -> bool {
    if request_has_cross_site_fetch_metadata(headers) {
        return false;
    }
    if let Some(origin) = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    {
        return request_origin_matches(origin, headers, uri);
    }
    if let Some(referer) = headers
        .get(header::REFERER)
        .and_then(|value| value.to_str().ok())
    {
        return request_origin_matches(referer, headers, uri);
    }
    true
}

fn request_has_cross_site_fetch_metadata(headers: &HeaderMap) -> bool {
    headers
        .get("sec-fetch-site")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("cross-site"))
}

fn request_origin_matches(origin: &str, headers: &HeaderMap, uri: &Uri) -> bool {
    let Some(request_authority) = request_authority(headers, uri) else {
        return false;
    };
    let Ok(parsed) = url::Url::parse(origin) else {
        return false;
    };
    let Some(origin_host) = parsed.host_str() else {
        return false;
    };
    let origin_scheme = parsed.scheme();
    if origin_scheme != "http" && origin_scheme != "https" {
        return false;
    }
    let origin_port = parsed
        .port()
        .unwrap_or(if origin_scheme == "https" { 443 } else { 80 });
    let origin_authority = format_authority_for_origin(origin_host, origin_port, origin_scheme);
    authorities_equivalent_for_origin(&request_authority, &origin_authority, origin_scheme)
}

fn request_authority(headers: &HeaderMap, uri: &Uri) -> Option<String> {
    uri.authority()
        .map(|authority| authority.as_str().to_string())
        .or_else(|| {
            headers
                .get(header::HOST)
                .and_then(|value| value.to_str().ok())
                .map(str::to_string)
        })
}

fn format_authority_for_origin(host: &str, port: u16, scheme: &str) -> String {
    let host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    if (scheme == "https" && port == 443) || (scheme == "http" && port == 80) {
        host
    } else {
        format!("{host}:{port}")
    }
}

fn authorities_equivalent_for_origin(left: &str, right: &str, scheme: &str) -> bool {
    let left = authority_to_origin_parts(left, scheme);
    let right = authority_to_origin_parts(right, scheme);
    left == right
}

fn authority_to_origin_parts(authority: &str, scheme: &str) -> Option<(String, u16)> {
    let parsed = url::Url::parse(&format!("{scheme}://{authority}")).ok()?;
    let host = parsed.host_str()?.to_ascii_lowercase();
    let port = parsed
        .port()
        .unwrap_or(if scheme == "https" { 443 } else { 80 });
    Some((host, port))
}

#[derive(Debug, Default, Deserialize)]
struct TransactionQuery {
    session_id: Option<Uuid>,
    q: Option<String>,
    method: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
    before_sequence: Option<u64>,
    sort_key: Option<String>,
    sort_direction: Option<String>,
    in_scope_only: Option<bool>,
    hide_without_responses: Option<bool>,
    only_parameterized: Option<bool>,
    only_notes: Option<bool>,
    status_classes: Option<String>,
    mime_types: Option<String>,
    hidden_extensions: Option<String>,
    port: Option<String>,
    color_tags: Option<String>,
    advanced_search: Option<String>,
    advanced_regex: Option<bool>,
    advanced_case_sensitive: Option<bool>,
    advanced_negative: Option<bool>,
    hide_connect: Option<bool>,
    host: Option<String>,
    status: Option<u16>,
    status_range: Option<String>,
    since: Option<String>,
    mime: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TransactionGetQuery {
    session_id: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
struct WorkspaceStateQuery {
    session_id: Option<Uuid>,
}

#[derive(Debug, Serialize, Deserialize)]
struct TransactionPageResponse {
    items: Vec<crate::model::TransactionSummary>,
    total: usize,
    filtered_total: Option<usize>,
    hidden_connect_total: Option<usize>,
    offset: usize,
    limit: usize,
    has_more: bool,
}

fn csv_param(value: Option<String>) -> Vec<String> {
    value
        .unwrap_or_default()
        .split(',')
        .map(|item| item.trim().to_ascii_lowercase())
        .filter(|item| !item.is_empty())
        .collect()
}

fn optional_csv_param(value: Option<String>) -> Option<Vec<String>> {
    value.and_then(|raw| {
        let values: Vec<String> = raw
            .split(',')
            .map(|item| item.trim().to_ascii_lowercase())
            .filter(|item| !item.is_empty())
            .collect();
        (!values.is_empty()).then_some(values)
    })
}

fn transaction_list_filters(query: TransactionQuery, scope_patterns: Vec<String>) -> ListFilters {
    ListFilters {
        query: query.q,
        method: query.method,
        limit: query.limit,
        offset: query.offset,
        before_sequence: query.before_sequence,
        sort_key: query.sort_key,
        sort_direction: query.sort_direction,
        scope_patterns,
        in_scope_only: query.in_scope_only.unwrap_or(false),
        hide_connect: query.hide_connect.unwrap_or(false),
        hide_without_responses: query.hide_without_responses.unwrap_or(false),
        only_parameterized: query.only_parameterized.unwrap_or(false),
        only_notes: query.only_notes.unwrap_or(false),
        status_classes: optional_csv_param(query.status_classes),
        mime_types: optional_csv_param(query.mime_types),
        hidden_extensions: csv_param(query.hidden_extensions),
        host: query.host,
        status: query.status,
        status_range: query.status_range,
        since: query.since,
        mime: query.mime,
        port: query.port,
        color_tags: csv_param(query.color_tags),
        advanced_search: query.advanced_search,
        advanced_regex: query.advanced_regex.unwrap_or(false),
        advanced_case_sensitive: query.advanced_case_sensitive.unwrap_or(false),
        advanced_negative: query.advanced_negative.unwrap_or(false),
    }
}

fn validate_transaction_query(query: &TransactionQuery) -> std::result::Result<(), String> {
    validate_optional_limit(query.limit)?;

    if let Some(value) = query.status_range.as_deref() {
        validate_status_range(value)
            .ok_or_else(|| format!("invalid status_range filter: {value}"))?;
    }
    if let Some(status) = query.status {
        validate_status_code(status).ok_or_else(|| format!("invalid status filter: {status}"))?;
    }

    if let Some(value) = query.since.as_deref() {
        validate_since(value).ok_or_else(|| format!("invalid since filter: {value}"))?;
    }

    if query.advanced_regex.unwrap_or(false) {
        if let Some(term) = query.advanced_search.as_deref().map(str::trim) {
            if !term.is_empty() {
                RegexBuilder::new(term)
                    .case_insensitive(!query.advanced_case_sensitive.unwrap_or(false))
                    .build()
                    .map_err(|error| format!("invalid advanced_search regex: {error}"))?;
            }
        }
    }

    Ok(())
}

fn validate_status_code(status: u16) -> Option<()> {
    (100..=599).contains(&status).then_some(())
}

fn validate_optional_limit(limit: Option<usize>) -> std::result::Result<(), String> {
    if limit == Some(0) {
        return Err("limit must be greater than zero".to_string());
    }
    Ok(())
}

fn validate_status_range(input: &str) -> Option<()> {
    let trimmed = input.trim();
    if trimmed.len() == 3 && trimmed.ends_with("xx") {
        let class = trimmed[..1].parse::<u16>().ok()?;
        return (1..=5).contains(&class).then_some(());
    }
    let (low, high) = trimmed.split_once('-')?;
    let low = low.trim().parse::<u16>().ok()?;
    let high = high.trim().parse::<u16>().ok()?;
    (low <= high && (100..=599).contains(&low) && (100..=599).contains(&high)).then_some(())
}

fn validate_since(input: &str) -> Option<()> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }
    for suffix in ['h', 'm', 'd', 's'] {
        if let Some(value) = trimmed.strip_suffix(suffix) {
            return value
                .parse::<i64>()
                .ok()
                .filter(|value| *value > 0)
                .map(|_| ());
        }
    }
    if chrono::NaiveDate::parse_from_str(trimmed, "%Y-%m-%d").is_ok() {
        return Some(());
    }
    chrono::DateTime::parse_from_rfc3339(trimmed)
        .ok()
        .map(|_| ())
}

fn validate_editable_request(request: &EditableRequest) -> std::result::Result<(), String> {
    validate_http_scheme_field(&request.scheme, "request scheme")?;
    validate_editable_request_host(&request.host)?;
    validate_editable_request_path(&request.path)?;
    validate_http_method(&request.method)?;
    for header in &request.headers {
        validate_editable_header(header)?;
    }
    validate_unique_host_header(&request.headers)?;
    let body = request
        .try_body_bytes()
        .map_err(|_| "request body is not valid base64".to_string())?;
    validate_editable_body_framing(&request.headers, body.len())
}

fn validate_http_scheme_field(scheme: &str, label: &str) -> std::result::Result<(), String> {
    let trimmed = scheme.trim();
    if trimmed != scheme {
        return Err(format!("{label} must not include surrounding whitespace"));
    }
    if !matches!(trimmed, "http" | "https") {
        return Err(format!("unsupported {label}: {scheme}"));
    }
    Ok(())
}

fn validate_editable_request_host(host: &str) -> std::result::Result<(), String> {
    let trimmed = host.trim();
    if trimmed != host {
        return Err("request host must not include surrounding whitespace".to_string());
    }
    if trimmed.is_empty() {
        return Err("request host is required".to_string());
    }
    if trimmed.chars().any(char::is_whitespace)
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.contains('@')
        || trimmed.contains('?')
        || trimmed.contains('#')
    {
        return Err(format!("invalid request host: {host}"));
    }
    if trimmed.starts_with('[') {
        let Some(end) = trimmed.find(']') else {
            return Err(format!("invalid request host: {host}"));
        };
        let inner = &trimmed[1..end];
        inner
            .parse::<IpAddr>()
            .map_err(|_| format!("invalid request host: {host}"))?;
        let suffix = &trimmed[end + 1..];
        if suffix.is_empty() {
            return Ok(());
        }
        let Some(port) = suffix.strip_prefix(':') else {
            return Err(format!("invalid request host: {host}"));
        };
        validate_port_text(port, "request host port")?;
        return Ok(());
    }
    if trimmed.contains(':') && trimmed.parse::<IpAddr>().is_ok() {
        return Err("IPv6 request hosts must be bracketed".to_string());
    }
    if trimmed.contains(':') {
        if trimmed.matches(':').count() != 1 {
            return Err("request host must not include multiple port separators".to_string());
        }
        let Some((host_part, port_part)) = trimmed.rsplit_once(':') else {
            return Err(format!("invalid request host: {host}"));
        };
        if host_part.is_empty() {
            return Err(format!("invalid request host: {host}"));
        }
        validate_port_text(port_part, "request host port")?;
    }
    Ok(())
}

fn validate_editable_request_path(path: &str) -> std::result::Result<(), String> {
    if path.is_empty() {
        return Err("request path is required".to_string());
    }
    if path.chars().any(|ch| ch.is_control() || ch.is_whitespace()) {
        return Err(format!("invalid request path: {path}"));
    }
    if path.contains('#') {
        return Err("request path must not include a fragment".to_string());
    }
    if path != "*" && !path.starts_with('/') {
        return Err("request path must start with '/'".to_string());
    }
    if path != "*" {
        path.parse::<PathAndQuery>()
            .map_err(|_| format!("invalid request path: {path}"))?;
    }
    Ok(())
}

fn validate_http_method(method: &str) -> std::result::Result<(), String> {
    let raw_method = method;
    let method = raw_method.trim();
    if method != raw_method {
        return Err("request method must not include surrounding whitespace".to_string());
    }
    if method.is_empty() {
        return Err("request method is required".to_string());
    }
    if method.eq_ignore_ascii_case("CONNECT") {
        return Err("CONNECT requests are not supported by Replay".to_string());
    }
    if !method.bytes().all(is_http_token_byte) {
        return Err(format!("invalid request method: {method}"));
    }
    Ok(())
}

fn is_http_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn validate_editable_response(response: &EditableResponse) -> std::result::Result<(), String> {
    if !(100..=599).contains(&response.status) {
        return Err(format!("invalid response status: {}", response.status));
    }
    for header in &response.headers {
        validate_editable_header(header)?;
    }
    let body = response
        .try_body_bytes()
        .map_err(|_| "response body is not valid base64".to_string())?;
    validate_editable_body_framing(&response.headers, body.len())
}

fn validate_editable_body_framing(
    headers: &[HeaderRecord],
    body_len: usize,
) -> std::result::Result<(), String> {
    if headers.iter().any(|header| {
        header.name.eq_ignore_ascii_case("transfer-encoding")
            && header
                .value
                .split(',')
                .any(|value| value.trim().eq_ignore_ascii_case("chunked"))
    }) {
        return Err(
            "Transfer-Encoding: chunked is not supported for editable messages".to_string(),
        );
    }

    let mut content_length: Option<usize> = None;
    for header in headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("content-length"))
    {
        let parsed = header
            .value
            .trim()
            .parse::<usize>()
            .map_err(|_| format!("invalid Content-Length: {}", header.value))?;
        if let Some(previous) = content_length {
            if previous != parsed {
                return Err("conflicting Content-Length headers".to_string());
            }
        }
        content_length = Some(parsed);
    }

    if let Some(expected) = content_length {
        if expected != body_len {
            return Err(format!(
                "Content-Length {expected} does not match body length {body_len}"
            ));
        }
    }
    Ok(())
}

fn validate_editable_header(header: &HeaderRecord) -> std::result::Result<(), String> {
    let raw_name = header.name.as_str();
    let name = raw_name.trim();
    if name != raw_name {
        return Err(format!(
            "request header name must not include surrounding whitespace: {}",
            header.name
        ));
    }
    if name.is_empty() {
        return Err("request header name is required".to_string());
    }
    HeaderName::from_bytes(name.as_bytes())
        .map_err(|_| format!("invalid request header name: {}", header.name))?;
    HeaderValue::from_str(&header.value)
        .map_err(|_| format!("invalid request header value for {name}"))?;
    Ok(())
}

fn validate_unique_host_header(headers: &[HeaderRecord]) -> std::result::Result<(), String> {
    let host_count = headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("host"))
        .count();
    if host_count > 1 {
        return Err("request must not include multiple Host headers".to_string());
    }
    Ok(())
}

fn validate_request_target_override(
    target: &RequestTargetOverride,
) -> std::result::Result<(), String> {
    validate_http_scheme_field(&target.scheme, "replay target scheme")?;
    validate_replay_target_host(&target.host)?;
    validate_port_text(&target.port, "replay target port")?;
    Ok(())
}

fn validate_workspace_state(snapshot: &WorkspaceStateSnapshot) -> std::result::Result<(), String> {
    validate_workspace_serialized_size(snapshot)?;
    let mut tab_ids = HashSet::new();
    let mut ws_frame_total = 0usize;
    let mut ws_frame_body_total = 0usize;
    let mut stored_bytes_total = 0usize;
    if let Some(client_id) = snapshot.client_id.as_deref() {
        validate_workspace_string_bytes(
            "workspace client id",
            client_id,
            MAX_WORKSPACE_CLIENT_ID_BYTES,
        )?;
    }
    if snapshot.replay.tabs.len() > MAX_WORKSPACE_REPLAY_TABS {
        return Err(format!(
            "workspace has too many replay tabs: {}",
            snapshot.replay.tabs.len()
        ));
    }
    if let Some(active_tab_id) = snapshot.replay.active_tab_id.as_deref() {
        validate_workspace_string_bytes(
            "active replay tab id",
            active_tab_id,
            MAX_WORKSPACE_REPLAY_ACTIVE_TAB_ID_BYTES,
        )?;
    }
    for tab in &snapshot.replay.tabs {
        if tab.id.trim().is_empty() {
            return Err("replay tab id is required".to_string());
        }
        validate_workspace_string_bytes(
            "replay tab id",
            &tab.id,
            MAX_WORKSPACE_REPLAY_TAB_ID_BYTES,
        )?;
        validate_workspace_string_bytes(
            "replay tab type",
            &tab.tab_type,
            MAX_WORKSPACE_REPLAY_TAB_TYPE_BYTES,
        )?;
        if !tab_ids.insert(tab.id.as_str()) {
            return Err(format!("duplicate replay tab id: {}", tab.id));
        }
        if tab.tab_type == "websocket" && Uuid::parse_str(&tab.id).is_err() {
            return Err(format!("websocket replay tab {} id must be a UUID", tab.id));
        }
        if tab.custom_label.chars().count() > 80 {
            return Err(format!("replay tab {} custom label is too long", tab.id));
        }
        let is_websocket_tab = tab.tab_type == "websocket";
        if !is_websocket_tab && replay_tab_has_websocket_payload(tab) {
            return Err(format!(
                "non-websocket replay tab {} must not include websocket state",
                tab.id
            ));
        }
        add_workspace_text_bytes(
            &mut stored_bytes_total,
            "replay tab request text",
            &tab.request_text,
            MAX_WORKSPACE_TEXT_FIELD_BYTES,
        )?;
        add_workspace_text_bytes(
            &mut stored_bytes_total,
            "replay tab notice",
            &tab.notice,
            MAX_WORKSPACE_TEXT_FIELD_BYTES,
        )?;
        add_workspace_text_bytes(
            &mut stored_bytes_total,
            "websocket handshake text",
            &tab.ws_handshake_text,
            MAX_WORKSPACE_TEXT_FIELD_BYTES,
        )?;
        add_workspace_text_bytes(
            &mut stored_bytes_total,
            "websocket editor text",
            &tab.ws_editor_text,
            MAX_WORKSPACE_TEXT_FIELD_BYTES,
        )?;
        add_workspace_text_bytes(
            &mut stored_bytes_total,
            "websocket setup notice",
            &tab.ws_setup_notice,
            MAX_WORKSPACE_TEXT_FIELD_BYTES,
        )?;
        if is_websocket_tab {
            if tab.ws_headers.len() > MAX_WORKSPACE_WS_HEADERS {
                return Err(format!(
                    "WebSocket replay tab has too many headers: {}",
                    tab.ws_headers.len()
                ));
            }
            let mut ws_headers_bytes_total = 0usize;
            for header in &tab.ws_headers {
                let header_bytes = add_workspace_json_bytes(
                    &mut stored_bytes_total,
                    "WebSocket header",
                    header,
                    MAX_WORKSPACE_WS_HEADER_BYTES,
                )?;
                ws_headers_bytes_total = ws_headers_bytes_total.saturating_add(header_bytes);
                if ws_headers_bytes_total > MAX_WORKSPACE_WS_HEADERS_BYTES {
                    return Err(format!(
                        "WebSocket replay headers exceed {MAX_WORKSPACE_WS_HEADERS_BYTES} stored bytes"
                    ));
                }
            }
        }
        if tab.history_entries.len() > MAX_WORKSPACE_REPLAY_HISTORY_ENTRIES_PER_TAB {
            return Err(format!(
                "replay tab {} has too many history entries: {}",
                tab.id,
                tab.history_entries.len()
            ));
        }
        if let Some(index) = tab.history_index {
            if index >= tab.history_entries.len() {
                return Err(format!("invalid replay history index for tab {}", tab.id));
            }
        }
        if tab.ws_setup_queue.len() > MAX_WORKSPACE_WS_SETUP_QUEUE_ITEMS {
            return Err(format!(
                "WebSocket setup queue has too many items: {}",
                tab.ws_setup_queue.len()
            ));
        }
        for item in &tab.ws_setup_queue {
            add_workspace_json_bytes(
                &mut stored_bytes_total,
                "WebSocket setup item",
                item,
                MAX_WORKSPACE_WS_SETUP_ITEM_BYTES,
            )?;
        }
        if is_websocket_tab {
            let ws_stats = validate_workspace_ws_tab(tab)
                .map_err(|error| format!("invalid websocket replay tab: {error}"))?;
            ws_frame_total = ws_frame_total.saturating_add(ws_stats.frames);
            ws_frame_body_total = ws_frame_body_total.saturating_add(ws_stats.body_bytes);
            if ws_frame_total > MAX_WORKSPACE_WS_TOTAL_FRAMES {
                return Err(format!(
                    "workspace has too many persisted WebSocket replay frames: {ws_frame_total}"
                ));
            }
            if ws_frame_body_total > MAX_WORKSPACE_WS_TOTAL_FRAME_BODY_BYTES {
                return Err(format!(
                    "workspace WebSocket replay frames exceed {MAX_WORKSPACE_WS_TOTAL_FRAME_BODY_BYTES} stored bytes"
                ));
            }
        }
        if let Some(request) = &tab.base_request {
            validate_workspace_draft_request(request)
                .map_err(|error| format!("invalid replay base request: {error}"))?;
            add_workspace_json_bytes(
                &mut stored_bytes_total,
                "replay base request",
                request,
                MAX_WORKSPACE_EDITABLE_MESSAGE_BYTES,
            )?;
        }
        if let Some(record) = &tab.response_record {
            add_workspace_json_bytes(
                &mut stored_bytes_total,
                "replay response record",
                record,
                MAX_WORKSPACE_EMBEDDED_RECORD_BYTES,
            )?;
        }
        validate_workspace_target_fields(&tab.target_scheme, &tab.target_host, &tab.target_port)
            .map_err(|error| format!("invalid replay target: {error}"))?;
        for entry in &tab.history_entries {
            add_workspace_text_bytes(
                &mut stored_bytes_total,
                "replay history request text",
                &entry.request_text,
                MAX_WORKSPACE_TEXT_FIELD_BYTES,
            )?;
            add_workspace_text_bytes(
                &mut stored_bytes_total,
                "replay history notice",
                &entry.notice,
                MAX_WORKSPACE_TEXT_FIELD_BYTES,
            )?;
            if let Some(request) = &entry.request {
                validate_editable_request(request)
                    .map_err(|error| format!("invalid replay history request: {error}"))?;
                add_workspace_json_bytes(
                    &mut stored_bytes_total,
                    "replay history request",
                    request,
                    MAX_WORKSPACE_EDITABLE_MESSAGE_BYTES,
                )?;
            }
            if let Some(record) = &entry.response_record {
                add_workspace_json_bytes(
                    &mut stored_bytes_total,
                    "replay history response record",
                    record,
                    MAX_WORKSPACE_EMBEDDED_RECORD_BYTES,
                )?;
            }
            validate_workspace_target_fields(
                &entry.target_scheme,
                &entry.target_host,
                &entry.target_port,
            )
            .map_err(|error| format!("invalid replay history target: {error}"))?;
        }
    }
    if let Some(active_tab_id) = snapshot.replay.active_tab_id.as_deref() {
        if !active_tab_id.is_empty() && !tab_ids.contains(active_tab_id) {
            return Err(format!("active replay tab does not exist: {active_tab_id}"));
        }
    }
    if let Some(request) = &snapshot.fuzzer.base_request {
        validate_workspace_draft_request(request)
            .map_err(|error| format!("invalid fuzzer base request: {error}"))?;
        add_workspace_json_bytes(
            &mut stored_bytes_total,
            "fuzzer base request",
            request,
            MAX_WORKSPACE_EDITABLE_MESSAGE_BYTES,
        )?;
    }
    if let Some(target) = &snapshot.fuzzer.target {
        validate_request_target_override(target)
            .map_err(|error| format!("invalid fuzzer target: {error}"))?;
    }
    add_workspace_text_bytes(
        &mut stored_bytes_total,
        "fuzzer notice",
        &snapshot.fuzzer.notice,
        MAX_WORKSPACE_TEXT_FIELD_BYTES,
    )?;
    add_workspace_text_bytes(
        &mut stored_bytes_total,
        "fuzzer request text",
        &snapshot.fuzzer.request_text,
        MAX_WORKSPACE_TEXT_FIELD_BYTES,
    )?;
    add_workspace_text_bytes(
        &mut stored_bytes_total,
        "fuzzer payload text",
        &snapshot.fuzzer.payloads_text,
        MAX_WORKSPACE_FUZZER_PAYLOAD_TEXT_BYTES,
    )?;
    if snapshot.fuzzer.payloads_text.lines().count() > MAX_WORKSPACE_FUZZER_PAYLOAD_LINES {
        return Err(format!(
            "fuzzer payload text cannot contain more than {MAX_WORKSPACE_FUZZER_PAYLOAD_LINES} lines"
        ));
    }
    Ok(())
}

fn replay_tab_has_websocket_payload(tab: &crate::workspace::ReplayTabState) -> bool {
    !tab.ws_scheme.is_empty()
        || !tab.ws_host.is_empty()
        || !tab.ws_port.is_null()
        || !tab.ws_path.is_empty()
        || !tab.ws_headers.is_empty()
        || !tab.ws_handshake_text.is_empty()
        || tab.ws_handshake_edited
        || !tab.ws_editor_text.is_empty()
        || !tab.ws_message_type.is_empty()
        || tab.ws_editor_body_encoded
        || !tab.ws_setup_notice.is_empty()
        || !tab.ws_setup_queue.is_empty()
        || !tab.ws_frames.is_empty()
        || tab.ws_selected_frame_index.is_some()
        || tab.ws_frame_window_start.is_some()
}

fn add_workspace_text_bytes(
    total: &mut usize,
    label: &str,
    value: &str,
    field_limit: usize,
) -> std::result::Result<(), String> {
    let bytes = value.len();
    if bytes > field_limit {
        return Err(format!("{label} cannot exceed {field_limit} bytes"));
    }
    add_workspace_stored_bytes(total, label, bytes)
}

fn add_workspace_json_bytes<T: Serialize>(
    total: &mut usize,
    label: &str,
    value: &T,
    field_limit: usize,
) -> std::result::Result<usize, String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("failed to measure {label}: {error}"))?
        .len();
    if bytes > field_limit {
        return Err(format!("{label} cannot exceed {field_limit} stored bytes"));
    }
    add_workspace_stored_bytes(total, label, bytes)?;
    Ok(bytes)
}

fn add_workspace_stored_bytes(
    total: &mut usize,
    label: &str,
    bytes: usize,
) -> std::result::Result<(), String> {
    *total = total.saturating_add(bytes);
    if *total > MAX_WORKSPACE_STORED_BYTES {
        return Err(format!(
            "workspace stored state exceeds {MAX_WORKSPACE_STORED_BYTES} bytes while adding {label}"
        ));
    }
    Ok(())
}

fn validate_workspace_string_bytes(
    label: &str,
    value: &str,
    limit: usize,
) -> std::result::Result<(), String> {
    if value.len() > limit {
        return Err(format!("{label} cannot exceed {limit} bytes"));
    }
    Ok(())
}

fn validate_workspace_draft_request(request: &EditableRequest) -> std::result::Result<(), String> {
    if !request.host.trim().is_empty() {
        return validate_editable_request(request);
    }
    if request.host.trim() != request.host {
        return Err("draft request host must not include whitespace".to_string());
    }
    if !request.scheme.trim().is_empty() {
        validate_http_scheme_field(&request.scheme, "request scheme")?;
    }
    if !request.path.trim().is_empty() {
        validate_editable_request_path(&request.path)?;
    }
    if !request.method.trim().is_empty() {
        validate_http_method(&request.method)?;
    }
    for header in &request.headers {
        validate_editable_header(header)?;
    }
    let body = request
        .try_body_bytes()
        .map_err(|_| "request body is not valid base64".to_string())?;
    validate_editable_body_framing(&request.headers, body.len())
}

fn validate_workspace_target_fields(
    scheme: &str,
    host: &str,
    port: &str,
) -> std::result::Result<(), String> {
    validate_workspace_string_bytes(
        "replay target scheme",
        scheme,
        MAX_WORKSPACE_REPLAY_TARGET_FIELD_BYTES,
    )?;
    validate_workspace_string_bytes(
        "replay target host",
        host,
        MAX_WORKSPACE_REPLAY_TARGET_FIELD_BYTES,
    )?;
    validate_workspace_string_bytes(
        "replay target port",
        port,
        MAX_WORKSPACE_REPLAY_TARGET_FIELD_BYTES,
    )?;
    let raw_scheme = scheme;
    let raw_host = host;
    let raw_port = port;
    let scheme = raw_scheme.trim();
    let host = raw_host.trim();
    let port = raw_port.trim();
    if scheme != raw_scheme {
        return Err("replay target scheme must not include surrounding whitespace".to_string());
    }
    if host != raw_host {
        return Err("replay target host must not include surrounding whitespace".to_string());
    }
    if port != raw_port {
        return Err("replay target port must not include surrounding whitespace".to_string());
    }
    if !scheme.is_empty() {
        validate_http_scheme_field(scheme, "replay target scheme")?;
    }
    if host.is_empty() {
        if !port.is_empty() {
            validate_port_text(port, "replay target port")?;
        }
        return Ok(());
    }
    if scheme.is_empty() || port.is_empty() {
        return Err("replay target scheme, host, and port must be saved together".to_string());
    }
    validate_replay_target_host(host)?;
    if !port.is_empty() {
        validate_port_text(port, "replay target port")?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Default)]
struct WorkspaceWsFrameStats {
    frames: usize,
    body_bytes: usize,
}

fn validate_workspace_ws_tab(
    tab: &crate::workspace::ReplayTabState,
) -> std::result::Result<WorkspaceWsFrameStats, String> {
    let scheme = tab.ws_scheme.trim();
    if scheme != tab.ws_scheme {
        return Err("WebSocket scheme must not include surrounding whitespace".to_string());
    }
    if !scheme.is_empty() {
        validate_workspace_ws_scheme(scheme)?;
    }

    let host = tab.ws_host.trim();
    if host != tab.ws_host {
        return Err("WebSocket host must not include surrounding whitespace".to_string());
    }
    let port = validate_workspace_ws_port(&tab.ws_port)?;
    if !tab.ws_path.trim().is_empty() {
        normalize_ws_replay_path(&tab.ws_path)?;
    }

    if !host.is_empty() {
        let scheme = if scheme.is_empty() { "wss" } else { scheme };
        let port = port.unwrap_or_else(|| default_ws_replay_port(scheme));
        build_ws_replay_url(scheme, host, port, &tab.ws_path)?;
    }

    let mut headers = Vec::with_capacity(tab.ws_headers.len());
    for (index, value) in tab.ws_headers.iter().enumerate() {
        let header: HeaderRecord = serde_json::from_value(value.clone())
            .map_err(|_| format!("invalid WebSocket header at index {index}"))?;
        headers.push(header);
    }
    validate_ws_replay_headers(&headers)?;

    if !tab.ws_message_type.trim().is_empty() {
        validate_ws_message_kind(&tab.ws_message_type)?;
    }
    for (index, item) in tab.ws_setup_queue.iter().enumerate() {
        validate_workspace_ws_setup_item(item, index)?;
    }
    if tab.ws_frames.len() > MAX_WORKSPACE_WS_FRAMES {
        return Err(format!(
            "WebSocket replay tab has too many frames: {}",
            tab.ws_frames.len()
        ));
    }
    let mut stats = WorkspaceWsFrameStats {
        frames: tab.ws_frames.len(),
        body_bytes: 0,
    };
    for (index, frame) in tab.ws_frames.iter().enumerate() {
        stats.body_bytes = stats
            .body_bytes
            .saturating_add(validate_workspace_ws_frame(frame, index)?);
    }

    Ok(stats)
}

fn validate_workspace_ws_frame(
    frame: &crate::ws_replay::WsReplayFrame,
    index: usize,
) -> std::result::Result<usize, String> {
    chrono::DateTime::parse_from_rfc3339(&frame.captured_at)
        .map_err(|_| format!("WebSocket frame {index} has an invalid timestamp"))?;
    let body_len = match &frame.body_encoding {
        BodyEncoding::Utf8 => frame.body.len(),
        BodyEncoding::Base64 => decode_ws_replay_payload(&frame.body)
            .map_err(|error| format!("invalid WebSocket frame {index}: {error}"))?
            .len(),
    };
    if body_len > MAX_WORKSPACE_WS_FRAME_BODY_BYTES {
        return Err(format!(
            "WebSocket frame {index} body cannot exceed {MAX_WORKSPACE_WS_FRAME_BODY_BYTES} bytes"
        ));
    }
    if frame.body_size < body_len {
        return Err(format!(
            "WebSocket frame {index} body_size is smaller than the stored body"
        ));
    }
    if !frame.preview_truncated && frame.body_size != body_len {
        return Err(format!(
            "WebSocket frame {index} body_size must match the stored body when it is not truncated"
        ));
    }
    Ok(body_len)
}

fn validate_workspace_ws_scheme(scheme: &str) -> std::result::Result<(), String> {
    match scheme.to_ascii_lowercase().as_str() {
        "ws" | "wss" => Ok(()),
        _ => Err(format!("unsupported WebSocket scheme: {scheme}")),
    }
}

fn validate_workspace_ws_port(
    value: &serde_json::Value,
) -> std::result::Result<Option<u16>, String> {
    match value {
        serde_json::Value::Null => Ok(None),
        serde_json::Value::Number(number) => {
            let Some(port) = number.as_u64() else {
                return Err("invalid WebSocket port".to_string());
            };
            let port =
                u16::try_from(port).map_err(|_| format!("invalid WebSocket port: {port}"))?;
            if port == 0 {
                return Err("WebSocket port must be greater than zero".to_string());
            }
            Ok(Some(port))
        }
        serde_json::Value::String(port) => {
            if port.trim().is_empty() {
                Ok(None)
            } else {
                parse_ws_replay_port(port).map(Some)
            }
        }
        _ => Err("invalid WebSocket port".to_string()),
    }
}

fn validate_workspace_ws_setup_item(
    item: &serde_json::Value,
    index: usize,
) -> std::result::Result<(), String> {
    let object = item
        .as_object()
        .ok_or_else(|| format!("WebSocket setup item {index} must be an object"))?;
    let kind = object
        .get("kind")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("text");
    let kind = validate_ws_message_kind(kind)?;
    let body = match object.get("body") {
        Some(value) => value
            .as_str()
            .ok_or_else(|| format!("WebSocket setup item {index} body must be a string"))?,
        None => "",
    };
    let body_encoded = object
        .get("body_encoded")
        .or_else(|| object.get("bodyEncoded"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    if body_encoded {
        match kind {
            "text" => {}
            "binary" => {
                decode_ws_replay_payload(body)
                    .map_err(|error| format!("invalid WebSocket setup item {index}: {error}"))?;
            }
            "ping" | "pong" => {
                decode_ws_replay_control_payload(body)
                    .map_err(|error| format!("invalid WebSocket setup item {index}: {error}"))?;
            }
            _ => unreachable!(),
        }
    }
    for field in ["label"] {
        if let Some(value) = object.get(field) {
            if !value.is_string() {
                return Err(format!(
                    "WebSocket setup item {index} {field} must be a string"
                ));
            }
        }
    }
    for field in ["autoSend", "sent", "body_encoded", "bodyEncoded"] {
        if let Some(value) = object.get(field) {
            if !value.is_boolean() {
                return Err(format!(
                    "WebSocket setup item {index} {field} must be a boolean"
                ));
            }
        }
    }
    Ok(())
}

fn validate_ws_message_kind(kind: &str) -> std::result::Result<&'static str, String> {
    match kind.trim().to_ascii_lowercase().as_str() {
        "text" => Ok("text"),
        "binary" => Ok("binary"),
        "ping" => Ok("ping"),
        "pong" => Ok("pong"),
        _ => Err(format!("unsupported WebSocket message type: {kind}")),
    }
}

fn validate_replay_target_host(host: &str) -> std::result::Result<(), String> {
    let trimmed = host.trim();
    if trimmed != host {
        return Err("replay target host must not include surrounding whitespace".to_string());
    }
    if trimmed.is_empty() {
        return Err("replay target host is required".to_string());
    }
    if trimmed.chars().any(char::is_whitespace)
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.contains('@')
        || trimmed.contains('?')
        || trimmed.contains('#')
    {
        return Err(format!("invalid replay target host: {trimmed}"));
    }
    if trimmed.starts_with('[') {
        let Some(end) = trimmed.find(']') else {
            return Err(format!("invalid replay target host: {trimmed}"));
        };
        if end != trimmed.len() - 1 {
            return Err("replay target host must not include a port; use target.port".to_string());
        }
        let inner = &trimmed[1..end];
        return inner
            .parse::<IpAddr>()
            .map(|_| ())
            .map_err(|_| format!("invalid replay target host: {trimmed}"));
    }
    if trimmed.contains(':') && trimmed.parse::<IpAddr>().is_err() {
        return Err("replay target host must not include a port; use target.port".to_string());
    }
    Ok(())
}

fn validate_port_text(port: &str, label: &str) -> std::result::Result<(), String> {
    let trimmed = port.trim();
    if trimmed != port {
        return Err(format!("{label} must not include surrounding whitespace"));
    }
    let parsed = trimmed
        .parse::<u16>()
        .map_err(|_| format!("invalid {label}: {port}"))?;
    if parsed == 0 {
        return Err(format!("invalid {label}: {port}"));
    }
    Ok(())
}

fn validate_sequence_definition(
    definition: &SequenceDefinition,
) -> std::result::Result<(), String> {
    validate_serialized_size(
        definition,
        "sequence definition",
        MAX_SEQUENCE_DEFINITION_BYTES,
    )?;
    validate_text_field(
        "sequence name",
        &definition.name,
        MAX_SEQUENCE_TEXT_FIELD_BYTES,
    )?;
    if definition.steps.len() > MAX_SEQUENCE_STEPS {
        return Err(format!(
            "sequence cannot contain more than {MAX_SEQUENCE_STEPS} steps"
        ));
    }
    for step in &definition.steps {
        validate_text_field(
            "sequence step label",
            &step.label,
            MAX_SEQUENCE_TEXT_FIELD_BYTES,
        )?;
        if let Some(request_text) = &step.request_text {
            validate_text_field(
                "sequence step request text",
                request_text,
                MAX_SEQUENCE_TEXT_FIELD_BYTES,
            )?;
        }
        if let Some(parse_error) = &step.request_parse_error {
            validate_text_field(
                "sequence step parse error",
                parse_error,
                MAX_SEQUENCE_TEXT_FIELD_BYTES,
            )?;
        }
        if step.extractions.len() > MAX_SEQUENCE_EXTRACTIONS_PER_STEP {
            return Err(format!(
                "sequence step {} cannot contain more than {MAX_SEQUENCE_EXTRACTIONS_PER_STEP} extractions",
                step.label
            ));
        }
        validate_editable_request(&step.request)
            .map_err(|error| format!("invalid request in sequence step {}: {error}", step.label))?;
        normalize_replay_http_version(step.http_version.as_deref()).map_err(|error| {
            format!(
                "invalid HTTP version in sequence step {}: {error}",
                step.label
            )
        })?;
        if let Some(target) = &step.target {
            validate_request_target_override(target).map_err(|error| {
                format!("invalid target in sequence step {}: {error}", step.label)
            })?;
        }
        for rule in &step.extractions {
            validate_text_field(
                "sequence extraction variable name",
                &rule.variable_name,
                MAX_SEQUENCE_TEXT_FIELD_BYTES,
            )?;
            validate_text_field(
                "sequence extraction pattern",
                &rule.pattern,
                MAX_SEQUENCE_TEXT_FIELD_BYTES,
            )?;
            if rule.variable_name.trim().is_empty() {
                return Err(format!(
                    "sequence step {} has an extraction with an empty variable name",
                    step.label
                ));
            }
            match rule.source {
                crate::sequence::ExtractionSource::ResponseBody => {
                    RegexBuilder::new(&rule.pattern).build().map_err(|error| {
                        format!(
                            "sequence step {} extraction {} has invalid regex: {error}",
                            step.label, rule.variable_name
                        )
                    })?;
                }
                crate::sequence::ExtractionSource::ResponseHeader => {
                    let header_name = rule.pattern.trim();
                    if header_name.is_empty() || header_name != rule.pattern {
                        return Err(format!(
                            "sequence step {} extraction {} has an invalid response header name",
                            step.label, rule.variable_name
                        ));
                    }
                    HeaderName::from_bytes(header_name.as_bytes()).map_err(|_| {
                        format!(
                            "sequence step {} extraction {} has an invalid response header name",
                            step.label, rule.variable_name
                        )
                    })?;
                }
            }
        }
    }
    Ok(())
}

fn validate_scanner_config(
    config: &crate::scanner::ScannerConfig,
) -> std::result::Result<(), String> {
    validate_serialized_size(config, "scanner config", MAX_SCANNER_CONFIG_BYTES)?;
    if config.custom_rules.len() > MAX_SCANNER_CUSTOM_RULES {
        return Err(format!(
            "scanner config cannot contain more than {MAX_SCANNER_CUSTOM_RULES} custom rules"
        ));
    }
    for rule in &config.custom_rules {
        validate_text_field("custom scanner rule id", &rule.id, MAX_SCANNER_FIELD_BYTES)?;
        validate_text_field(
            "custom scanner rule name",
            &rule.name,
            MAX_SCANNER_FIELD_BYTES,
        )?;
        validate_text_field(
            "custom scanner rule target",
            &rule.target,
            MAX_SCANNER_FIELD_BYTES,
        )?;
        validate_text_field(
            "custom scanner rule header name",
            &rule.header_name,
            MAX_SCANNER_FIELD_BYTES,
        )?;
        validate_text_field(
            "custom scanner rule pattern",
            &rule.pattern,
            MAX_SCANNER_FIELD_BYTES,
        )?;
        validate_text_field(
            "custom scanner rule category",
            &rule.category,
            MAX_SCANNER_FIELD_BYTES,
        )?;
        validate_text_field(
            "custom scanner rule description",
            &rule.description,
            MAX_SCANNER_FIELD_BYTES,
        )?;
        if rule.id.trim().is_empty() {
            return Err("custom scanner rule id is required".to_string());
        }
        if rule.name.trim().is_empty() {
            return Err(format!("custom scanner rule {} name is required", rule.id));
        }
        if rule.pattern.trim().is_empty() {
            return Err(format!(
                "custom scanner rule {} pattern is required",
                rule.id
            ));
        }
        match rule.target.as_str() {
            "response_body" | "response_header" | "request_header" => {}
            other => {
                return Err(format!(
                    "custom scanner rule {} has invalid target {}",
                    rule.id, other
                ));
            }
        }
        RegexBuilder::new(&rule.pattern).build().map_err(|error| {
            format!("custom scanner rule {} has invalid regex: {error}", rule.id)
        })?;
    }
    Ok(())
}

fn validate_match_replace_rules(rules: &[MatchReplaceRule]) -> std::result::Result<(), String> {
    validate_serialized_size(&rules, "match-replace rules", MAX_MATCH_REPLACE_RULES_BYTES)?;
    if rules.len() > MAX_MATCH_REPLACE_RULES {
        return Err(format!(
            "match-replace cannot contain more than {MAX_MATCH_REPLACE_RULES} rules"
        ));
    }
    for rule in rules {
        validate_text_field(
            "match-replace description",
            &rule.description,
            MAX_MATCH_REPLACE_FIELD_BYTES,
        )?;
        validate_text_field(
            "match-replace search",
            &rule.search,
            MAX_MATCH_REPLACE_FIELD_BYTES,
        )?;
        validate_text_field(
            "match-replace replacement",
            &rule.replace,
            MAX_MATCH_REPLACE_FIELD_BYTES,
        )?;
        if rule.regex && !rule.search.is_empty() {
            RegexBuilder::new(&rule.search)
                .case_insensitive(!rule.case_sensitive)
                .build()
                .map_err(|error| {
                    format!(
                        "match-replace rule {} has invalid regex: {error}",
                        rule.description
                    )
                })?;
        }
    }
    Ok(())
}

fn validate_text_field(label: &str, value: &str, limit: usize) -> std::result::Result<(), String> {
    if value.len() > limit {
        return Err(format!("{label} cannot exceed {limit} bytes"));
    }
    Ok(())
}

fn validate_serialized_size<T: Serialize>(
    value: &T,
    label: &str,
    limit: usize,
) -> std::result::Result<(), String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("failed to measure {label}: {error}"))?
        .len();
    if bytes > limit {
        return Err(format!("{label} cannot exceed {limit} stored bytes"));
    }
    Ok(())
}

fn normalize_replay_http_version(
    value: Option<&str>,
) -> std::result::Result<Option<String>, String> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    match value {
        "HTTP/1.0" | "1.0" => Ok(Some("HTTP/1.0".to_string())),
        "HTTP/1.1" | "1.1" => Ok(Some("HTTP/1.1".to_string())),
        "HTTP/2" | "HTTP/2.0" | "2" | "2.0" => Ok(Some("HTTP/2".to_string())),
        other => Err(format!("unsupported replay http_version: {other}")),
    }
}

impl From<TransactionListPage> for TransactionPageResponse {
    fn from(page: TransactionListPage) -> Self {
        Self {
            items: page.items,
            total: page.total,
            filtered_total: page.filtered_total,
            hidden_connect_total: page.hidden_connect_total,
            offset: page.offset,
            limit: page.limit,
            has_more: page.has_more,
        }
    }
}

#[derive(Debug, Deserialize)]
struct WebSocketQuery {
    session_id: Option<Uuid>,
    limit: Option<usize>,
    offset: Option<usize>,
    frame_limit: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
struct WebSocketPageResponse {
    items: Vec<crate::model::WebSocketSessionSummary>,
    total: usize,
    offset: usize,
    limit: usize,
    has_more: bool,
}

#[derive(Debug, Deserialize)]
struct EventLogQuery {
    session_id: Option<Uuid>,
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct EventsQuery {
    session_id: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
struct FuzzerQuery {
    session_id: Option<Uuid>,
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct OastQuery {
    session_id: Option<Uuid>,
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct RuntimeQuery {
    session_id: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
struct TargetSiteMapQuery {
    session_id: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
struct SessionScopedQuery {
    session_id: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
struct InterceptForwardPayload {
    request: EditableRequest,
}

#[derive(Debug, Deserialize)]
struct ResponseInterceptForwardPayload {
    response: EditableResponse,
}

#[derive(Debug, Deserialize)]
struct ReplaySendPayload {
    session_id: Option<Uuid>,
    request: EditableRequest,
    target: Option<RequestTargetOverride>,
    source_transaction_id: Option<Uuid>,
    http_version: Option<String>,
}

#[derive(Debug, Serialize)]
struct ReplaySendErrorResponse {
    error: String,
    record: Option<crate::model::TransactionRecord>,
}

fn replay_send_error_response(error: impl Into<String>) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(ReplaySendErrorResponse {
            error: error.into(),
            record: None,
        }),
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
struct CreateSessionPayload {
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AnnotationsPayload {
    #[serde(default, deserialize_with = "deserialize_double_option")]
    color_tag: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_double_option")]
    user_note: Option<Option<String>>,
}

fn validate_annotations_payload(payload: &AnnotationsPayload) -> std::result::Result<(), String> {
    if let Some(Some(color_tag)) = payload.color_tag.as_ref() {
        if !ALLOWED_COLOR_TAGS.contains(&color_tag.as_str()) {
            return Err("unsupported color tag".to_string());
        }
    }
    if let Some(Some(user_note)) = payload.user_note.as_ref() {
        validate_text_field("user note", user_note, MAX_ANNOTATION_NOTE_BYTES)?;
    }
    Ok(())
}

fn deserialize_double_option<'de, D>(deserializer: D) -> Result<Option<Option<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer).map(Some)
}

async fn get_settings(State(state): State<Arc<AppState>>) -> Json<crate::state::RuntimeInfo> {
    Json(state.runtime_info().await)
}

async fn get_app_version(State(state): State<Arc<AppState>>) -> Json<crate::state::AppVersionInfo> {
    Json(state.app_version_info().await)
}

async fn self_update(
    State(state): State<Arc<AppState>>,
) -> Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>> {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<crate::state::UpdateProgress>(32);

    tokio::spawn(async move {
        if let Err(err) = state.self_update(tx.clone()).await {
            let _ = tx
                .send(crate::state::UpdateProgress {
                    step: format!("error:{err:#}"),
                    percent: None,
                    downloaded: None,
                    total: None,
                })
                .await;
        }
    });

    Sse::new(stream! {
        while let Some(progress) = rx.recv().await {
            let data = serde_json::to_string(&progress).unwrap_or_default();
            yield Ok(Event::default().data(data));
        }
    })
}

async fn list_sessions(State(state): State<Arc<AppState>>) -> Json<Vec<SessionSummary>> {
    Json(state.list_sessions())
}

async fn create_session(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CreateSessionPayload>,
) -> Response {
    match state.create_session(payload.name).await {
        Ok(summary) => Json(summary).into_response(),
        Err(error) => session_operation_error_response(error),
    }
}

async fn activate_session(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    let id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    match state.activate_session(id).await {
        Ok(summary) => Json(summary).into_response(),
        Err(error) => session_operation_error_response(error),
    }
}

async fn delete_session(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    let id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    match state.delete_session(id).await {
        Ok(()) => Json(serde_json::json!({ "ok": true })).into_response(),
        Err(error) => session_operation_error_response(error),
    }
}

fn session_operation_error_response(error: anyhow::Error) -> Response {
    let message = error.to_string();
    let status = if message.contains("was not found") {
        StatusCode::NOT_FOUND
    } else if message.contains("cannot delete the active session")
        || message.contains("live captures are active")
        || message.contains("proxy activity is still running")
        || message.contains("capture persistence is pending")
    {
        StatusCode::CONFLICT
    } else if message.contains("failed to") {
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        StatusCode::BAD_REQUEST
    };
    (status, message).into_response()
}

async fn reveal_session_folder(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Response {
    let id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    match state.session_storage_path(id) {
        Ok(path) => {
            if let Err(error) = spawn_open_command(OPEN_PATH, std::iter::once(path.as_os_str())) {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!(
                        "failed to reveal session folder {}: {error}",
                        path.display()
                    ),
                )
                    .into_response();
            }
            Json(serde_json::json!({ "ok": true, "path": path.display().to_string() }))
                .into_response()
        }
        Err(error) => session_operation_error_response(error),
    }
}

async fn get_runtime_settings(
    State(state): State<Arc<AppState>>,
    Query(query): Query<RuntimeQuery>,
) -> Response {
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    Json(session.runtime.snapshot().await.redacted_for_read()).into_response()
}

async fn get_workspace_state(
    State(state): State<Arc<AppState>>,
    Query(query): Query<WorkspaceStateQuery>,
) -> Response {
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let mut snapshot = session.workspace.snapshot().await;
    snapshot.session_id = Some(session.id());
    Json(snapshot).into_response()
}

async fn update_workspace_state(
    State(state): State<Arc<AppState>>,
    Json(snapshot): Json<WorkspaceStateSnapshot>,
) -> Response {
    let Some(target_session_id) = snapshot.session_id else {
        let active_session = state.session().await;
        let mut current = active_session.workspace.snapshot().await;
        current.session_id = Some(active_session.id());
        return (StatusCode::CONFLICT, Json(current)).into_response();
    };
    let active_session = state.session().await;
    if target_session_id != active_session.id()
        && proxy::live_websocket_session_context(target_session_id).is_none()
        && proxy::pending_session_context(target_session_id).is_none()
        && !proxy::session_has_active_proxy_work(target_session_id)
        && !state.sessions.contains_session(target_session_id)
    {
        let mut current = active_session.workspace.snapshot().await;
        current.session_id = Some(active_session.id());
        return (StatusCode::CONFLICT, Json(current)).into_response();
    }
    let workspace_update_lock = state.workspace_update_lock(target_session_id).await;
    let _workspace_update_guard = workspace_update_lock.lock().await;
    let active_session = state.session().await;
    let session = if target_session_id == active_session.id() {
        active_session
    } else if proxy::session_has_active_proxy_work(target_session_id) {
        let mut current = active_session.workspace.snapshot().await;
        current.session_id = Some(active_session.id());
        return (StatusCode::CONFLICT, Json(current)).into_response();
    } else if let Some(session) = proxy::live_websocket_session_context(target_session_id) {
        session
    } else if let Some(session) = proxy::pending_session_context(target_session_id) {
        session
    } else if !state.sessions.contains_session(target_session_id) {
        let mut current = active_session.workspace.snapshot().await;
        current.session_id = Some(active_session.id());
        return (StatusCode::CONFLICT, Json(current)).into_response();
    } else {
        match state
            .session_context_for_id_operation_locked(target_session_id)
            .await
        {
            Ok(session) => session,
            Err(error) => return session_load_failure_response(target_session_id, error),
        }
    };
    let mut snapshot = snapshot;
    snapshot.fuzzer.migrate_attack_record_to_id();
    let mut current = session.workspace.snapshot().await;
    current.session_id = Some(session.id());
    if !can_replace_snapshot(&snapshot, &current) {
        return (StatusCode::CONFLICT, Json(current)).into_response();
    }
    if let Err(error) = validate_workspace_state(&snapshot) {
        return (StatusCode::BAD_REQUEST, error).into_response();
    }
    snapshot.session_id = Some(session.id());
    match state
        .replace_workspace_state_and_persist(&session, snapshot)
        .await
    {
        Ok(mut snapshot) => {
            snapshot.session_id = Some(session.id());
            Json(snapshot).into_response()
        }
        Err(WorkspaceReplaceError::Conflict(current)) => {
            let mut current = *current;
            current.session_id = Some(session.id());
            (StatusCode::CONFLICT, Json(current)).into_response()
        }
        Err(WorkspaceReplaceError::Persist(error)) => {
            tracing::warn!(%error, "failed to persist workspace state update");
            (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response()
        }
    }
}

fn action_session_conflict_response(session: &Arc<SessionContext>) -> Response {
    (
        StatusCode::CONFLICT,
        Json(serde_json::json!({
            "error": "active session changed",
            "session_id": session.id(),
        })),
    )
        .into_response()
}

fn active_session_conflict_response(state: &AppState) -> Response {
    (
        StatusCode::CONFLICT,
        Json(serde_json::json!({
            "error": "active session changed",
            "session_id": state.sessions.active_session_id(),
        })),
    )
        .into_response()
}

fn session_load_failure_response(session_id: Uuid, error: anyhow::Error) -> Response {
    if error.to_string().contains("was not found") {
        return StatusCode::NOT_FOUND.into_response();
    }
    tracing::warn!(
        %error,
        session_id = %session_id,
        "failed to load session context"
    );
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("failed to load session {session_id}: {error}"),
    )
        .into_response()
}

async fn resolve_session_for_optional_id(
    state: &Arc<AppState>,
    target_session_id: Option<Uuid>,
) -> std::result::Result<Arc<SessionContext>, Response> {
    let active_session = state.session().await;
    let Some(target_session_id) = target_session_id else {
        return Ok(active_session);
    };
    if target_session_id == active_session.id() {
        return Ok(active_session);
    }
    if proxy::session_has_active_proxy_work(target_session_id) {
        return Err(active_session_conflict_response(state));
    }
    if let Some(session) = proxy::live_websocket_session_context(target_session_id) {
        return Ok(session);
    }
    if let Some(session) = proxy::pending_session_context(target_session_id) {
        return Ok(session);
    }
    if !state.sessions.contains_session(target_session_id) {
        return Err(StatusCode::NOT_FOUND.into_response());
    }
    state
        .session_context_for_id(target_session_id)
        .await
        .map_err(|error| session_load_failure_response(target_session_id, error))
}

async fn resolve_read_session_for_optional_id(
    state: &Arc<AppState>,
    target_session_id: Option<Uuid>,
) -> std::result::Result<Arc<SessionContext>, Response> {
    let active_session = state.session().await;
    let Some(target_session_id) = target_session_id else {
        return Ok(active_session);
    };
    if target_session_id == active_session.id() {
        return Ok(active_session);
    }
    if let Some(session) = proxy::live_websocket_session_context(target_session_id) {
        return Ok(session);
    }
    if let Some(session) = proxy::pending_session_context(target_session_id) {
        return Ok(session);
    }
    if !state.sessions.contains_session(target_session_id) {
        return Err(StatusCode::NOT_FOUND.into_response());
    }
    state
        .session_context_for_id(target_session_id)
        .await
        .map_err(|error| session_load_failure_response(target_session_id, error))
}

async fn guard_session_write_operation(
    state: &Arc<AppState>,
    session: &Arc<SessionContext>,
    require_still_active: bool,
) -> std::result::Result<OwnedMutexGuard<()>, Response> {
    let operation_lock = state.session_operation_lock(session.id()).await;
    let guard = operation_lock.lock_owned().await;
    if !state.sessions.contains_session(session.id()) {
        return Err(action_session_conflict_response(session));
    }
    if require_still_active && state.sessions.active_session_id() != session.id() {
        return Err(active_session_conflict_response(state));
    }
    Ok(guard)
}

async fn begin_session_proxy_operation(
    state: &Arc<AppState>,
    session: &Arc<SessionContext>,
) -> std::result::Result<proxy::ActiveProxySessionGuard, Response> {
    let operation_lock = state.session_operation_lock(session.id()).await;
    let _operation_guard = operation_lock.lock().await;
    if !state.sessions.contains_session(session.id()) {
        return Err(action_session_conflict_response(session));
    }
    Ok(proxy::remember_active_proxy_session_owner(session.id()))
}

async fn resolve_session_for_required_id(
    state: &Arc<AppState>,
    target_session_id: Option<Uuid>,
) -> std::result::Result<Arc<SessionContext>, Response> {
    let Some(target_session_id) = target_session_id else {
        let active_session = state.session().await;
        return Err(action_session_conflict_response(&active_session));
    };
    match resolve_session_for_optional_id(state, Some(target_session_id)).await {
        Ok(session) => Ok(session),
        Err(response) if response.status() == StatusCode::NOT_FOUND => {
            Err(active_session_conflict_response(state))
        }
        Err(response) => Err(response),
    }
}

async fn ensure_ws_replay_connection_owner(
    state: &AppState,
    id: Uuid,
    session_id: Uuid,
) -> std::result::Result<(), Response> {
    if !state.sessions.contains_session(session_id) {
        return Err(StatusCode::NOT_FOUND.into_response());
    }
    match state.ws_replay.belongs_to_session(id, session_id).await {
        Some(true) => Ok(()),
        Some(false) => Err(active_session_conflict_response(state)),
        None => Err(StatusCode::NOT_FOUND.into_response()),
    }
}

async fn update_runtime_settings(
    State(state): State<Arc<AppState>>,
    Json(update): Json<RuntimeSettingsUpdate>,
) -> Response {
    let target_session_id = update.session_id;
    let session = match resolve_session_for_optional_id(&state, target_session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let _operation_guard =
        match guard_session_write_operation(&state, &session, target_session_id.is_none()).await {
            Ok(guard) => guard,
            Err(response) => return response,
        };
    let _mutation_guard = session.mutation_guard().await;
    let previous = session.runtime.snapshot().await;
    let previous_events = session
        .event_log
        .snapshot(Some(state.config.max_entries))
        .await;
    let snapshot = match session.runtime.update(update).await {
        Ok(snapshot) => snapshot,
        Err(error) => return (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    };
    session
        .event_log
        .push(
            EventLevel::Info,
            "runtime",
            "Runtime settings updated",
            format!(
                "intercept={}, websocket_capture={}, scope_entries={}",
                snapshot.intercept_enabled,
                snapshot.websocket_capture_enabled,
                snapshot.scope_patterns.len()
            ),
        )
        .await;
    // Sync OAST config when runtime settings change
    session
        .oast
        .update_config(crate::oast::OastConfig {
            enabled: snapshot.oast_enabled,
            server_url: snapshot.oast_server_url.clone(),
            token: snapshot.oast_token.clone(),
            polling_interval_secs: snapshot.oast_polling_interval_secs,
            provider: snapshot.oast_provider.clone(),
        })
        .await;

    if let Err(response) = persist_session_mutation_locked_or_response(&state, &session).await {
        session.runtime.replace_snapshot(previous.clone()).await;
        session.event_log.replace_all(previous_events).await;
        session
            .oast
            .update_config(crate::oast::OastConfig {
                enabled: previous.oast_enabled,
                server_url: previous.oast_server_url,
                token: previous.oast_token,
                polling_interval_secs: previous.oast_polling_interval_secs,
                provider: previous.oast_provider,
            })
            .await;
        persist_rolled_back_session_snapshot(&state, &session, "runtime settings update").await;
        return response;
    }
    Json(snapshot.redacted_for_read()).into_response()
}

async fn get_startup_settings(State(state): State<Arc<AppState>>) -> Json<StartupSettingsView> {
    let active_addr = state.get_active_proxy_addr().await;
    Json(state.startup.view(active_addr).await)
}

async fn get_ui_settings(State(state): State<Arc<AppState>>) -> Json<AppUiSettingsSnapshot> {
    Json(state.ui_settings.snapshot().await)
}

async fn update_ui_settings(
    State(state): State<Arc<AppState>>,
    Json(snapshot): Json<AppUiSettingsSnapshot>,
) -> Response {
    match state.ui_settings.replace_snapshot(snapshot).await {
        Ok(snapshot) => Json(snapshot).into_response(),
        Err(error) => (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response(),
    }
}

async fn update_startup_settings(
    State(state): State<Arc<AppState>>,
    Json(update): Json<StartupSettingsUpdate>,
) -> Response {
    match state.startup.update(update).await {
        Ok(snapshot) => {
            let active_addr = state.get_active_proxy_addr().await;
            let desired_addr = match snapshot.proxy_addr() {
                Ok(addr) => addr,
                Err(e) => {
                    return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
                }
            };

            // Try hot-rebind if address changed
            let (rebound, rebind_error) = if desired_addr != active_addr {
                match crate::proxy::rebind_proxy(state.clone(), desired_addr).await {
                    Ok(()) => (Some(true), None),
                    Err(err) => (Some(false), Some(err)),
                }
            } else {
                (None, None)
            };

            let new_active = state.get_active_proxy_addr().await;
            let mut view = state.startup.view(new_active).await;
            view.rebound = rebound;
            view.rebind_error = rebind_error.clone();

            let rebind_event = match (rebound, &rebind_error) {
                (Some(true), _) => Some((
                    EventLevel::Info,
                    "Proxy listener rebound",
                    format!("Proxy listener moved to {}", view.active_proxy_addr),
                )),
                (Some(false), Some(err)) => Some((
                    EventLevel::Warn,
                    "Proxy rebind failed",
                    format!(
                        "Could not rebind to {}: {}. Saved for next launch.",
                        view.proxy_addr, err
                    ),
                )),
                _ => None,
            };
            if let Some((level, title, message)) = rebind_event {
                let session = state.session().await;
                let _mutation_guard = session.mutation_guard().await;
                let previous_events = session
                    .event_log
                    .snapshot(Some(state.config.max_entries))
                    .await;
                session
                    .event_log
                    .push(level, "config", title, message)
                    .await;
                if let Err(error) = state
                    .persist_session_context_mutation_locked(&session)
                    .await
                {
                    session.event_log.replace_all(previous_events).await;
                    persist_rolled_back_session_snapshot(
                        &state,
                        &session,
                        "proxy rebind event log update",
                    )
                    .await;
                    tracing::warn!(
                        %error,
                        "failed to persist proxy rebind event log entry"
                    );
                }
            }

            Json(view).into_response()
        }
        Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

async fn list_event_log(
    State(state): State<Arc<AppState>>,
    Query(query): Query<EventLogQuery>,
) -> Response {
    if let Err(error) = validate_optional_limit(query.limit) {
        return (StatusCode::BAD_REQUEST, error).into_response();
    }
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    Json(session.event_log.list(query.limit).await).into_response()
}

async fn clear_event_log(
    State(state): State<Arc<AppState>>,
    Query(query): Query<EventLogQuery>,
) -> Response {
    let session = match resolve_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let _operation_guard =
        match guard_session_write_operation(&state, &session, query.session_id.is_none()).await {
            Ok(guard) => guard,
            Err(response) => return response,
        };
    let _mutation_guard = session.mutation_guard().await;
    let previous = session
        .event_log
        .snapshot(Some(state.config.max_entries))
        .await;
    session.event_log.clear().await;
    if persist_session_mutation_locked_or_status(&state, &session)
        .await
        .is_err()
    {
        session.event_log.replace_all(previous).await;
        persist_rolled_back_session_snapshot(&state, &session, "event log clear").await;
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    StatusCode::NO_CONTENT.into_response()
}

// ── Scanner findings ──

#[derive(Debug, Deserialize)]
struct FindingsQuery {
    session_id: Option<Uuid>,
    limit: Option<usize>,
}

#[derive(Debug, Serialize)]
struct FindingsCountResponse {
    count: usize,
}

async fn list_findings(
    State(state): State<Arc<AppState>>,
    Query(query): Query<FindingsQuery>,
) -> Response {
    if let Err(error) = validate_optional_limit(query.limit) {
        return (StatusCode::BAD_REQUEST, error).into_response();
    }
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    Json(session.scanner.list(query.limit).await).into_response()
}

async fn count_findings(
    State(state): State<Arc<AppState>>,
    Query(query): Query<SessionScopedQuery>,
) -> Response {
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    Json(FindingsCountResponse {
        count: session.scanner.count().await,
    })
    .into_response()
}

async fn get_finding(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(query): Query<SessionScopedQuery>,
) -> Response {
    let id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    match session.scanner.get(id).await {
        Some(finding) => Json(finding).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn clear_findings(
    State(state): State<Arc<AppState>>,
    Query(query): Query<SessionScopedQuery>,
) -> Response {
    let session = match resolve_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let _operation_guard =
        match guard_session_write_operation(&state, &session, query.session_id.is_none()).await {
            Ok(guard) => guard,
            Err(response) => return response,
        };
    let _mutation_guard = session.mutation_guard().await;
    let previous = session
        .scanner
        .snapshot(Some(state.config.max_entries))
        .await;
    session.scanner.clear().await;
    if persist_session_mutation_locked_or_status(&state, &session)
        .await
        .is_err()
    {
        session.scanner.replace_all(previous).await;
        persist_rolled_back_session_snapshot(&state, &session, "scanner findings clear").await;
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn get_scanner_config(
    State(state): State<Arc<AppState>>,
    Query(query): Query<SessionScopedQuery>,
) -> Response {
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    Json(session.scanner.get_config().await).into_response()
}

async fn update_scanner_config(
    State(state): State<Arc<AppState>>,
    Query(query): Query<SessionScopedQuery>,
    Json(config): Json<crate::scanner::ScannerConfig>,
) -> Response {
    if let Err(error) = validate_scanner_config(&config) {
        return (StatusCode::BAD_REQUEST, error).into_response();
    }
    let session = match resolve_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let _operation_guard =
        match guard_session_write_operation(&state, &session, query.session_id.is_none()).await {
            Ok(guard) => guard,
            Err(response) => return response,
        };
    let _mutation_guard = session.mutation_guard().await;
    let previous = session.scanner.get_config().await;
    session.scanner.update_config(config).await;
    if let Err(response) = persist_session_mutation_locked_or_response(&state, &session).await {
        session.scanner.update_config(previous).await;
        persist_rolled_back_session_snapshot(&state, &session, "scanner config update").await;
        return response;
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn download_root_pem(State(state): State<Arc<AppState>>) -> Response {
    download_bytes_response(
        state.certificates.root_pem_bytes(),
        "application/x-pem-file",
        "attachment; filename=\"sniper-root-ca.pem\"",
    )
}

async fn download_root_der(State(state): State<Arc<AppState>>) -> Response {
    download_bytes_response(
        state.certificates.root_der_bytes(),
        "application/pkix-cert",
        "attachment; filename=\"sniper-root-ca.der\"",
    )
}

async fn reveal_certificate_folder(State(state): State<Arc<AppState>>) -> Response {
    let export = state.certificates.export();
    match spawn_open_command(OPEN_PATH, ["-R", export.pem_path.as_str()]) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to reveal certificate folder: {error}"),
        )
            .into_response(),
    }
}

fn spawn_open_command<I, S>(program: &str, args: I) -> std::io::Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    std::process::Command::new(program)
        .args(args)
        .spawn()
        .map(|_| ())
}

async fn list_match_replace_rules(
    State(state): State<Arc<AppState>>,
    Query(query): Query<SessionScopedQuery>,
) -> Response {
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    Json(session.match_replace.snapshot().await).into_response()
}

async fn update_match_replace_rules(
    State(state): State<Arc<AppState>>,
    Query(query): Query<SessionScopedQuery>,
    Json(payload): Json<MatchReplaceRulesPayload>,
) -> Response {
    if let Err(error) = validate_match_replace_rules(&payload.rules) {
        return (StatusCode::BAD_REQUEST, error).into_response();
    }
    let session = match resolve_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let _operation_guard =
        match guard_session_write_operation(&state, &session, query.session_id.is_none()).await {
            Ok(guard) => guard,
            Err(response) => return response,
        };
    let _mutation_guard = session.mutation_guard().await;
    let previous_rules = session.match_replace.snapshot().await;
    let previous_events = session
        .event_log
        .snapshot(Some(state.config.max_entries))
        .await;
    let rules = session.match_replace.replace_all(payload.rules).await;
    session
        .event_log
        .push(
            EventLevel::Info,
            "match_replace",
            "Rules updated",
            format!("{} rule(s) active in configuration", rules.len()),
        )
        .await;
    if let Err(response) = persist_session_mutation_locked_or_response(&state, &session).await {
        session.match_replace.replace_all(previous_rules).await;
        session.event_log.replace_all(previous_events).await;
        persist_rolled_back_session_snapshot(&state, &session, "match/replace rules update").await;
        return response;
    }
    Json(rules).into_response()
}

async fn get_target_site_map(
    State(state): State<Arc<AppState>>,
    Query(query): Query<TargetSiteMapQuery>,
) -> Response {
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let records = session.store.site_map_records().await;
    let mut hosts = IndexMap::<String, TargetHostAccumulator>::new();

    for record in records {
        let host = hosts
            .entry(record.host.clone())
            .or_insert_with(|| TargetHostAccumulator {
                host: record.host.clone(),
                schemes: Vec::new(),
                request_count: 0,
                paths: IndexMap::new(),
            });

        host.request_count += 1;
        push_unique(&mut host.schemes, record.scheme.clone());

        let path = host
            .paths
            .entry(record.path.clone())
            .or_insert_with(|| TargetPathAccumulator {
                path: record.path.clone(),
                methods: Vec::new(),
                last_seen: record.started_at,
                status: record.status,
                note_count: 0,
                is_websocket: record.is_websocket,
            });
        push_unique(&mut path.methods, record.method.clone());
        if record.started_at > path.last_seen {
            path.last_seen = record.started_at;
            path.status = record.status;
        }
        path.note_count += record.note_count;
        path.is_websocket = path.is_websocket || record.is_websocket;
    }

    let mut site_map = Vec::with_capacity(hosts.len());
    for (_, host) in hosts {
        let mut paths = host
            .paths
            .into_iter()
            .map(|(_, path)| TargetPathNode {
                path: path.path,
                methods: path.methods,
                last_seen: path.last_seen,
                status: path.status,
                note_count: path.note_count,
                is_websocket: path.is_websocket,
            })
            .collect::<Vec<_>>();
        paths.sort_by(|left, right| right.last_seen.cmp(&left.last_seen));

        site_map.push(TargetHostNode {
            host: host.host.clone(),
            schemes: host.schemes,
            request_count: host.request_count,
            in_scope: session.runtime.is_in_scope(&host.host).await,
            paths,
        });
    }

    Json(site_map).into_response()
}

async fn list_transactions(
    State(state): State<Arc<AppState>>,
    Query(mut query): Query<TransactionQuery>,
) -> Response {
    const MAX_PAGE_LIMIT: usize = 10000;

    if let Err(error) = validate_transaction_query(&query) {
        return (StatusCode::BAD_REQUEST, error).into_response();
    }
    if let Some(limit) = query.limit {
        query.limit = Some(limit.clamp(1, MAX_PAGE_LIMIT));
    }
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let runtime = session.runtime.snapshot().await;
    let filters = transaction_list_filters(query, runtime.scope_patterns);
    Json(session.store.list(&filters).await).into_response()
}

async fn list_transactions_page(
    State(state): State<Arc<AppState>>,
    Query(mut query): Query<TransactionQuery>,
) -> Response {
    const DEFAULT_PAGE_LIMIT: usize = 5000;
    const MAX_PAGE_LIMIT: usize = 10000;

    if let Err(error) = validate_transaction_query(&query) {
        return (StatusCode::BAD_REQUEST, error).into_response();
    }
    query.limit = Some(
        query
            .limit
            .unwrap_or(DEFAULT_PAGE_LIMIT)
            .clamp(1, MAX_PAGE_LIMIT),
    );
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let runtime = session.runtime.snapshot().await;
    let filters = transaction_list_filters(query, runtime.scope_patterns);
    let page = session.store.list_page(&filters).await;
    Json(TransactionPageResponse::from(page)).into_response()
}

async fn get_transaction(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(query): Query<TransactionGetQuery>,
) -> Response {
    let id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    match session.store.get(id).await {
        Some(record) => Json(record).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn update_transaction_annotations(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(query): Query<TransactionGetQuery>,
    Json(payload): Json<AnnotationsPayload>,
) -> Response {
    let id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let session = match resolve_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let _operation_guard =
        match guard_session_write_operation(&state, &session, query.session_id.is_none()).await {
            Ok(guard) => guard,
            Err(response) => return response,
        };
    if let Err(message) = validate_annotations_payload(&payload) {
        return (StatusCode::BAD_REQUEST, message).into_response();
    }
    let _mutation_guard = session.mutation_guard().await;
    match session
        .store
        .update_annotations_durable(id, payload.color_tag, payload.user_note)
        .await
    {
        Ok(Some(update)) => Json(update.summary).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::warn!(
                ?error,
                transaction_id = %id,
                "failed to persist transaction annotation journal entry"
            );
            (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response()
        }
    }
}

async fn list_intercepts(
    State(state): State<Arc<AppState>>,
    Query(query): Query<SessionScopedQuery>,
) -> Response {
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    Json(session.intercepts.list().await).into_response()
}

async fn get_intercept(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(query): Query<SessionScopedQuery>,
) -> Response {
    let id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    match session.intercepts.get(id).await {
        Some(record) => Json(record).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn forward_intercept(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(query): Query<SessionScopedQuery>,
    Json(payload): Json<InterceptForwardPayload>,
) -> Response {
    let id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let session = match resolve_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    if session.intercepts.get(id).await.is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }
    if let Err(error) = validate_editable_request(&payload.request) {
        return (StatusCode::BAD_REQUEST, error).into_response();
    }

    let _operation_guard =
        match guard_session_write_operation(&state, &session, query.session_id.is_none()).await {
            Ok(guard) => guard,
            Err(response) => return response,
        };
    let _mutation_guard = session.mutation_guard().await;
    let previous_events = session
        .event_log
        .snapshot(Some(state.config.max_entries))
        .await;
    if let Err(error) = session.intercepts.forward(id, payload.request).await {
        return intercept_action_error_status(&error).into_response();
    }
    session
        .event_log
        .push(
            EventLevel::Info,
            "intercept",
            "Request forwarded",
            format!("Intercept item {id} forwarded"),
        )
        .await;
    persist_nonrollbackable_event_log_mutation(
        &state,
        &session,
        previous_events,
        "request intercept forward",
    )
    .await;
    StatusCode::NO_CONTENT.into_response()
}

async fn drop_intercept(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(query): Query<SessionScopedQuery>,
) -> Response {
    let id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let session = match resolve_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    if session.intercepts.get(id).await.is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }

    let _operation_guard =
        match guard_session_write_operation(&state, &session, query.session_id.is_none()).await {
            Ok(guard) => guard,
            Err(response) => return response,
        };
    let _mutation_guard = session.mutation_guard().await;
    let previous_events = session
        .event_log
        .snapshot(Some(state.config.max_entries))
        .await;
    if let Err(error) = session.intercepts.drop_request(id).await {
        return intercept_action_error_status(&error).into_response();
    }
    session
        .event_log
        .push(
            EventLevel::Warn,
            "intercept",
            "Request dropped",
            format!("Intercept item {id} dropped"),
        )
        .await;
    persist_nonrollbackable_event_log_mutation(
        &state,
        &session,
        previous_events,
        "request intercept drop",
    )
    .await;
    StatusCode::NO_CONTENT.into_response()
}

async fn forward_all_intercepts(
    State(state): State<Arc<AppState>>,
    Query(query): Query<SessionScopedQuery>,
) -> Response {
    let session = match resolve_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let _operation_guard =
        match guard_session_write_operation(&state, &session, query.session_id.is_none()).await {
            Ok(guard) => guard,
            Err(response) => return response,
        };
    let _mutation_guard = session.mutation_guard().await;
    let previous_events = session
        .event_log
        .snapshot(Some(state.config.max_entries))
        .await;
    let count = session.intercepts.forward_all().await;
    if count > 0 {
        session
            .event_log
            .push(
                EventLevel::Info,
                "intercept",
                "All requests forwarded",
                format!("{count} intercepted request(s) forwarded"),
            )
            .await;
        persist_nonrollbackable_event_log_mutation(
            &state,
            &session,
            previous_events,
            "request intercept forward all",
        )
        .await;
    }
    Json(serde_json::json!({
        "ok": true,
        "action": "forward-all",
        "forwarded": count,
    }))
    .into_response()
}

async fn list_intercept_rules(
    State(state): State<Arc<AppState>>,
    Query(query): Query<SessionScopedQuery>,
) -> Response {
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    Json(session.intercept_rules.list().await).into_response()
}

async fn upsert_intercept_rule(
    State(state): State<Arc<AppState>>,
    Query(query): Query<SessionScopedQuery>,
    Json(rule): Json<crate::intercept::InterceptRule>,
) -> Response {
    let session = match resolve_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let _operation_guard =
        match guard_session_write_operation(&state, &session, query.session_id.is_none()).await {
            Ok(guard) => guard,
            Err(response) => return response,
        };
    let _mutation_guard = session.mutation_guard().await;
    let previous = session.intercept_rules.snapshot().await;
    session.intercept_rules.upsert(rule).await;
    if persist_session_mutation_locked_or_status(&state, &session)
        .await
        .is_err()
    {
        session.intercept_rules.replace_all(previous).await;
        persist_rolled_back_session_snapshot(&state, &session, "intercept rule upsert").await;
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn delete_intercept_rule(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(query): Query<SessionScopedQuery>,
) -> Response {
    let id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let session = match resolve_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let _operation_guard =
        match guard_session_write_operation(&state, &session, query.session_id.is_none()).await {
            Ok(guard) => guard,
            Err(response) => return response,
        };
    let _mutation_guard = session.mutation_guard().await;
    let previous = session.intercept_rules.snapshot().await;
    if session.intercept_rules.delete(id).await {
        if let Err(response) = persist_session_mutation_locked_or_response(&state, &session).await {
            session.intercept_rules.replace_all(previous).await;
            persist_rolled_back_session_snapshot(&state, &session, "intercept rule delete").await;
            return response;
        }
        StatusCode::NO_CONTENT.into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

// ── Response Intercepts ──

async fn list_response_intercepts(
    State(state): State<Arc<AppState>>,
    Query(query): Query<SessionScopedQuery>,
) -> Response {
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    Json(session.response_intercepts.list().await).into_response()
}

async fn get_response_intercept(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(query): Query<SessionScopedQuery>,
) -> Response {
    let id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    match session.response_intercepts.get(id).await {
        Some(record) => Json(record).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn forward_response_intercept(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(query): Query<SessionScopedQuery>,
    Json(payload): Json<ResponseInterceptForwardPayload>,
) -> Response {
    let id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let session = match resolve_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    if session.response_intercepts.get(id).await.is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }
    if let Err(error) = validate_editable_response(&payload.response) {
        return (StatusCode::BAD_REQUEST, error).into_response();
    }

    let _operation_guard =
        match guard_session_write_operation(&state, &session, query.session_id.is_none()).await {
            Ok(guard) => guard,
            Err(response) => return response,
        };
    let _mutation_guard = session.mutation_guard().await;
    let previous_events = session
        .event_log
        .snapshot(Some(state.config.max_entries))
        .await;
    if let Err(error) = session
        .response_intercepts
        .forward(id, payload.response)
        .await
    {
        return intercept_action_error_status(&error).into_response();
    }
    session
        .event_log
        .push(
            EventLevel::Info,
            "intercept",
            "Response forwarded",
            format!("Response intercept item {id} forwarded"),
        )
        .await;
    persist_nonrollbackable_event_log_mutation(
        &state,
        &session,
        previous_events,
        "response intercept forward",
    )
    .await;
    StatusCode::NO_CONTENT.into_response()
}

async fn drop_response_intercept(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(query): Query<SessionScopedQuery>,
) -> Response {
    let id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let session = match resolve_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    if session.response_intercepts.get(id).await.is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }

    let _operation_guard =
        match guard_session_write_operation(&state, &session, query.session_id.is_none()).await {
            Ok(guard) => guard,
            Err(response) => return response,
        };
    let _mutation_guard = session.mutation_guard().await;
    let previous_events = session
        .event_log
        .snapshot(Some(state.config.max_entries))
        .await;
    if let Err(error) = session.response_intercepts.drop_response(id).await {
        return intercept_action_error_status(&error).into_response();
    }
    session
        .event_log
        .push(
            EventLevel::Warn,
            "intercept",
            "Response dropped",
            format!("Response intercept item {id} dropped"),
        )
        .await;
    persist_nonrollbackable_event_log_mutation(
        &state,
        &session,
        previous_events,
        "response intercept drop",
    )
    .await;
    StatusCode::NO_CONTENT.into_response()
}

async fn forward_all_response_intercepts(
    State(state): State<Arc<AppState>>,
    Query(query): Query<SessionScopedQuery>,
) -> Response {
    let session = match resolve_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let _operation_guard =
        match guard_session_write_operation(&state, &session, query.session_id.is_none()).await {
            Ok(guard) => guard,
            Err(response) => return response,
        };
    let _mutation_guard = session.mutation_guard().await;
    let previous_events = session
        .event_log
        .snapshot(Some(state.config.max_entries))
        .await;
    let count = session.response_intercepts.forward_all().await;
    if count > 0 {
        session
            .event_log
            .push(
                EventLevel::Info,
                "intercept",
                "All responses forwarded",
                format!("{count} intercepted response(s) forwarded"),
            )
            .await;
        persist_nonrollbackable_event_log_mutation(
            &state,
            &session,
            previous_events,
            "response intercept forward all",
        )
        .await;
    }
    Json(serde_json::json!({
        "ok": true,
        "action": "forward-all",
        "forwarded": count,
    }))
    .into_response()
}

// ── Sequences ──

#[derive(Debug, Deserialize)]
struct SequenceQuery {
    limit: Option<usize>,
    session_id: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
struct SequenceSessionQuery {
    session_id: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
struct SequenceUpsertPayload {
    session_id: Option<Uuid>,
    #[serde(flatten)]
    definition: SequenceDefinition,
}

#[derive(Debug, Deserialize)]
struct SequenceRunPayload {
    session_id: Option<Uuid>,
}

async fn list_sequences(
    State(state): State<Arc<AppState>>,
    Query(query): Query<SequenceSessionQuery>,
) -> Response {
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    Json(session.sequence.list_definitions().await).into_response()
}

async fn get_sequence(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(query): Query<SequenceSessionQuery>,
) -> Response {
    let id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    match session.sequence.get_definition(id).await {
        Some(definition) => Json(definition).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn upsert_sequence(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SequenceUpsertPayload>,
) -> Response {
    let session = match resolve_session_for_required_id(&state, payload.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let definition = payload.definition;
    if let Err(error) = validate_sequence_definition(&definition) {
        return (StatusCode::BAD_REQUEST, error).into_response();
    }
    let operation_lock = state.session_operation_lock(session.id()).await;
    let _operation_guard = operation_lock.lock().await;
    if !state.sessions.contains_session(session.id()) {
        return action_session_conflict_response(&session);
    }
    let _mutation_guard = session.mutation_guard().await;
    let previous = session.sequence.snapshot_definitions().await;
    session.sequence.upsert_definition(definition).await;
    if let Err(response) = persist_session_mutation_locked_or_response(&state, &session).await {
        session.sequence.replace_definitions(previous).await;
        persist_rolled_back_session_snapshot(&state, &session, "sequence upsert").await;
        return response;
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn delete_sequence(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(query): Query<SequenceSessionQuery>,
) -> Response {
    let id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let session = match resolve_session_for_required_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let operation_lock = state.session_operation_lock(session.id()).await;
    let _operation_guard = operation_lock.lock().await;
    if !state.sessions.contains_session(session.id()) {
        return action_session_conflict_response(&session);
    }
    let _mutation_guard = session.mutation_guard().await;
    let previous = session.sequence.snapshot_definitions().await;
    if session.sequence.delete_definition(id).await {
        if let Err(response) = persist_session_mutation_locked_or_response(&state, &session).await {
            session.sequence.replace_definitions(previous).await;
            persist_rolled_back_session_snapshot(&state, &session, "sequence delete").await;
            return response;
        }
        StatusCode::NO_CONTENT.into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

async fn run_sequence(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(payload): Json<SequenceRunPayload>,
) -> Response {
    let id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => return (StatusCode::BAD_REQUEST, "Invalid sequence ID").into_response(),
    };
    let session = match resolve_session_for_required_id(&state, payload.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let operation_lock = state.session_operation_lock(session.id()).await;
    let _operation_guard = operation_lock.lock().await;
    if !state.sessions.contains_session(session.id()) {
        return action_session_conflict_response(&session);
    }
    let definition = match session.sequence.get_definition(id).await {
        Some(def) => def,
        None => return (StatusCode::NOT_FOUND, "Sequence not found").into_response(),
    };
    if let Err(error) = validate_sequence_definition(&definition) {
        return (StatusCode::BAD_REQUEST, error).into_response();
    }
    let _session_owner = crate::proxy::remember_active_proxy_session_owner(session.id());
    drop(_operation_guard);
    match sequence::run_sequence(state, session, definition).await {
        Ok(record) => Json(record).into_response(),
        Err(error) => (sequence_run_error_status(&error), error.to_string()).into_response(),
    }
}

async fn list_sequence_runs(
    State(state): State<Arc<AppState>>,
    Query(query): Query<SequenceQuery>,
) -> Response {
    if let Err(error) = validate_optional_limit(query.limit) {
        return (StatusCode::BAD_REQUEST, error).into_response();
    }
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    Json(session.sequence.list_runs(query.limit).await).into_response()
}

async fn get_sequence_run(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(query): Query<SequenceSessionQuery>,
) -> Response {
    let id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    match session.sequence.get_run(id).await {
        Some(run) => Json(run).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn send_replay(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ReplaySendPayload>,
) -> Response {
    let session = match resolve_session_for_required_id(&state, payload.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let http_version = match normalize_replay_http_version(payload.http_version.as_deref()) {
        Ok(value) => value,
        Err(error) => return replay_send_error_response(error),
    };
    if let Some(target) = payload.target.as_ref() {
        if let Err(error) = validate_request_target_override(target) {
            return replay_send_error_response(error);
        }
    }
    if let Err(error) = validate_editable_request(&payload.request) {
        return replay_send_error_response(error);
    }
    let _session_owner = match begin_session_proxy_operation(&state, &session).await {
        Ok(owner) => owner,
        Err(response) => {
            return response;
        }
    };
    match proxy::try_send_replay_request_for_session(
        state,
        session,
        payload.request,
        payload.target,
        payload.source_transaction_id,
        http_version,
    )
    .await
    {
        Ok(record) => Json(record).into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(ReplaySendErrorResponse {
                error: error.to_string(),
                record: error.record().cloned(),
            }),
        )
            .into_response(),
    }
}

fn fuzzer_attack_error_status(error: &anyhow::Error) -> StatusCode {
    if error
        .chain()
        .any(|cause| cause.is::<fuzzer::FuzzerPersistenceError>())
    {
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        StatusCode::BAD_REQUEST
    }
}

fn intercept_action_error_status(error: &anyhow::Error) -> StatusCode {
    if error.to_string().contains("was not found") {
        StatusCode::NOT_FOUND
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    }
}

fn sequence_run_error_status(error: &anyhow::Error) -> StatusCode {
    if error
        .chain()
        .any(|cause| cause.is::<sequence::SequencePersistenceError>())
    {
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        StatusCode::BAD_REQUEST
    }
}

async fn list_fuzzer_attacks(
    State(state): State<Arc<AppState>>,
    Query(query): Query<FuzzerQuery>,
) -> Response {
    if let Err(error) = validate_optional_limit(query.limit) {
        return (StatusCode::BAD_REQUEST, error).into_response();
    }
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    Json(session.fuzzer.list(query.limit).await).into_response()
}

async fn get_fuzzer_attack(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(query): Query<FuzzerQuery>,
) -> Response {
    let id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    match session.fuzzer.get(id).await {
        Some(record) => Json(record).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn run_fuzzer_attack(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<FuzzerAttackPayload>,
) -> Response {
    let session = match resolve_session_for_required_id(&state, payload.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    if let Err(error) = validate_editable_request(&payload.template) {
        return (StatusCode::BAD_REQUEST, error).into_response();
    }
    let http_version = match normalize_replay_http_version(payload.http_version.as_deref()) {
        Ok(value) => value,
        Err(error) => return (StatusCode::BAD_REQUEST, error).into_response(),
    };
    if let Some(target) = payload.target.as_ref() {
        if let Err(error) = validate_request_target_override(target) {
            return (StatusCode::BAD_REQUEST, error).into_response();
        }
    }
    if let Err(error) = fuzzer::validate_expanded_requests(
        &payload.template,
        &payload.payloads,
        validate_editable_request,
    ) {
        return (StatusCode::BAD_REQUEST, error.to_string()).into_response();
    }
    let _session_owner = match begin_session_proxy_operation(&state, &session).await {
        Ok(owner) => owner,
        Err(response) => return response,
    };
    match fuzzer::run_attack_for_session(
        state,
        session,
        payload.template,
        payload.payloads,
        payload.source_transaction_id,
        http_version,
        payload.target,
    )
    .await
    {
        Ok(record) => Json(record).into_response(),
        Err(error) => (fuzzer_attack_error_status(&error), error.to_string()).into_response(),
    }
}

async fn list_websockets(
    State(state): State<Arc<AppState>>,
    Query(query): Query<WebSocketQuery>,
) -> Response {
    if let Err(error) = validate_optional_limit(query.limit) {
        return (StatusCode::BAD_REQUEST, error).into_response();
    }
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let page = session
        .websockets
        .list_page(query.limit, query.offset)
        .await;
    Json(page.items).into_response()
}

async fn list_websockets_page(
    State(state): State<Arc<AppState>>,
    Query(query): Query<WebSocketQuery>,
) -> Response {
    if let Err(error) = validate_optional_limit(query.limit) {
        return (StatusCode::BAD_REQUEST, error).into_response();
    }
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let page = session
        .websockets
        .list_page(query.limit, query.offset)
        .await;
    Json(WebSocketPageResponse {
        items: page.items,
        total: page.total,
        offset: page.offset,
        limit: page.limit,
        has_more: page.has_more,
    })
    .into_response()
}

async fn get_websocket(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(query): Query<WebSocketQuery>,
) -> Response {
    let id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let frame_limit = Some(websocket_detail_frame_limit(query.frame_limit));
    match session.websockets.get_windowed(id, frame_limit).await {
        Some(record) => Json(record).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

fn websocket_detail_frame_limit(frame_limit: Option<usize>) -> usize {
    frame_limit
        .unwrap_or(DEFAULT_WEBSOCKET_DETAIL_FRAME_LIMIT)
        .min(MAX_WEBSOCKET_DETAIL_FRAME_LIMIT)
}

// --- WebSocket Replay handlers ---

#[derive(Debug, Deserialize)]
struct WsReplayConnectPayload {
    session_id: Option<Uuid>,
    id: Uuid,
    scheme: String,
    host: String,
    port: u16,
    path: String,
    #[serde(default)]
    headers: Vec<crate::model::HeaderRecord>,
}

async fn ws_replay_connect(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<WsReplayConnectPayload>,
) -> Response {
    let session = match resolve_session_for_required_id(&state, payload.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let url = match build_ws_replay_url(&payload.scheme, &payload.host, payload.port, &payload.path)
    {
        Ok(url) => url,
        Err(error) => return (StatusCode::BAD_REQUEST, error).into_response(),
    };
    let extra_headers = match validate_ws_replay_headers(&payload.headers) {
        Ok(headers) => headers,
        Err(error) => return (StatusCode::BAD_REQUEST, error).into_response(),
    };

    let operation_lock = state.session_operation_lock(session.id()).await;
    let _operation_guard = operation_lock.lock().await;
    if !state.sessions.contains_session(session.id()) {
        return action_session_conflict_response(&session);
    }
    if let Some(false) = state
        .ws_replay
        .belongs_to_session(payload.id, session.id())
        .await
    {
        return active_session_conflict_response(&state);
    }
    let upstream_insecure = session.runtime.upstream_insecure().await;

    match state
        .ws_replay
        .connect(
            payload.id,
            session.id(),
            &url,
            extra_headers,
            upstream_insecure,
        )
        .await
    {
        Ok(()) => Json(serde_json::json!({"ok": true})).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

fn validate_ws_replay_headers(
    headers: &[crate::model::HeaderRecord],
) -> std::result::Result<Vec<(String, String)>, String> {
    for header in headers {
        let name = header.name.trim();
        if name != header.name {
            return Err(format!(
                "WebSocket replay header name must not include surrounding whitespace: {}",
                header.name
            ));
        }
        HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| format!("invalid WebSocket replay header name: {name}"))?;
        HeaderValue::from_str(&header.value)
            .map_err(|_| format!("invalid WebSocket replay header value for {name}"))?;
    }
    let sanitized = proxy::websocket_forward_headers_from_records(headers);
    let extra_headers = sanitized
        .iter()
        .map(|(name, value)| {
            Ok((
                name.as_str().to_string(),
                value
                    .to_str()
                    .map_err(|_| format!("invalid WebSocket replay header value for {name}"))?
                    .to_string(),
            ))
        })
        .collect::<std::result::Result<Vec<_>, String>>()?;
    Ok(extra_headers)
}

fn build_ws_replay_url(
    scheme: &str,
    host: &str,
    port: u16,
    path: &str,
) -> std::result::Result<String, String> {
    if port == 0 {
        return Err("WebSocket port must be greater than zero".to_string());
    }
    let ws_scheme = match scheme.trim().to_ascii_lowercase().as_str() {
        "wss" | "https" => "wss",
        "ws" | "http" => "ws",
        value => return Err(format!("unsupported WebSocket scheme: {value}")),
    };
    let host = host.trim();
    if host.is_empty() {
        return Err("WebSocket host is required".to_string());
    }
    if host.chars().any(char::is_whitespace)
        || host.contains('/')
        || host.contains('\\')
        || host.contains('@')
        || host.contains('?')
        || host.contains('#')
    {
        return Err("WebSocket host must not include URL components".to_string());
    }
    let (authority_host, port) = normalize_ws_replay_authority(host, port)?;
    let path = normalize_ws_replay_path(path)?;

    Ok(format!("{ws_scheme}://{authority_host}:{port}{path}"))
}

fn normalize_ws_replay_path(path: &str) -> std::result::Result<String, String> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Ok("/".to_string());
    }
    if trimmed != path {
        return Err("WebSocket path must not include surrounding whitespace".to_string());
    }
    if !trimmed.starts_with('/') || trimmed.starts_with("//") {
        return Err("WebSocket path must start with a single '/'".to_string());
    }
    if trimmed
        .chars()
        .any(|char| char.is_control() || char.is_whitespace())
    {
        return Err("WebSocket path must not include whitespace".to_string());
    }
    if trimmed.contains('#') {
        return Err("WebSocket path must not include a fragment".to_string());
    }
    trimmed
        .parse::<PathAndQuery>()
        .map_err(|_| format!("invalid WebSocket path: {path}"))?;
    Ok(trimmed.to_string())
}

fn default_ws_replay_port(scheme: &str) -> u16 {
    match scheme.to_ascii_lowercase().as_str() {
        "ws" | "http" => 80,
        _ => 443,
    }
}

fn normalize_ws_replay_authority(
    host: &str,
    fallback_port: u16,
) -> std::result::Result<(String, u16), String> {
    if host.starts_with('[') {
        let Some(end) = host.find(']') else {
            return Err("invalid bracketed IPv6 host".to_string());
        };
        let inner = &host[1..end];
        if inner.trim().is_empty() {
            return Err("WebSocket host is required".to_string());
        }
        if inner.parse::<Ipv6Addr>().is_err() {
            return Err("invalid bracketed IPv6 host".to_string());
        }
        let suffix = &host[end + 1..];
        let port = if suffix.is_empty() {
            fallback_port
        } else if let Some(port) = suffix.strip_prefix(':') {
            parse_ws_replay_port(port)?
        } else {
            return Err("invalid bracketed IPv6 host".to_string());
        };
        return Ok((format!("[{inner}]"), port));
    }

    if host.parse::<IpAddr>().is_ok() && host.contains(':') {
        return Ok((format!("[{host}]"), fallback_port));
    }

    if host.matches(':').count() == 1 {
        let Some((host_part, port_part)) = host.rsplit_once(':') else {
            return Err("invalid WebSocket host".to_string());
        };
        if host_part.trim().is_empty() {
            return Err("WebSocket host is required".to_string());
        }
        return Ok((host_part.to_string(), parse_ws_replay_port(port_part)?));
    }

    if host.contains(':') {
        return Err("IPv6 WebSocket hosts with ports must be bracketed".to_string());
    }

    Ok((host.to_string(), fallback_port))
}

fn parse_ws_replay_port(port: &str) -> std::result::Result<u16, String> {
    let port = port
        .parse::<u16>()
        .map_err(|_| format!("invalid WebSocket port: {port}"))?;
    if port == 0 {
        return Err("WebSocket port must be greater than zero".to_string());
    }
    Ok(port)
}

#[derive(Debug, Deserialize)]
struct WsReplaySendPayload {
    session_id: Option<Uuid>,
    id: Uuid,
    body: String,
    #[serde(default)]
    binary: bool,
    kind: Option<WsReplaySendKind>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WsReplaySendKind {
    Text,
    Binary,
    Ping,
    Pong,
}

async fn ws_replay_send(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<WsReplaySendPayload>,
) -> Response {
    let Some(session_id) = payload.session_id else {
        return active_session_conflict_response(&state);
    };
    if let Err(response) = ensure_ws_replay_connection_owner(&state, payload.id, session_id).await {
        return response;
    }
    let kind = payload.kind.unwrap_or(if payload.binary {
        WsReplaySendKind::Binary
    } else {
        WsReplaySendKind::Text
    });
    let result = match kind {
        WsReplaySendKind::Text => state.ws_replay.send_text(payload.id, payload.body).await,
        WsReplaySendKind::Binary => match decode_ws_replay_payload(&payload.body) {
            Ok(data) => state.ws_replay.send_binary(payload.id, data).await,
            Err(error) => Err(error),
        },
        WsReplaySendKind::Ping => match decode_ws_replay_control_payload(&payload.body) {
            Ok(data) => state.ws_replay.send_ping(payload.id, data).await,
            Err(error) => Err(error),
        },
        WsReplaySendKind::Pong => match decode_ws_replay_control_payload(&payload.body) {
            Ok(data) => state.ws_replay.send_pong(payload.id, data).await,
            Err(error) => Err(error),
        },
    };

    match result {
        Ok(()) => Json(serde_json::json!({"ok": true})).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

fn decode_ws_replay_payload(body: &str) -> anyhow::Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(body)
        .map_err(|error| anyhow::anyhow!("invalid base64: {}", error))
}

fn decode_ws_replay_control_payload(body: &str) -> anyhow::Result<Vec<u8>> {
    let data = decode_ws_replay_payload(body)?;
    if data.len() > 125 {
        return Err(anyhow::anyhow!(
            "WebSocket control frame payloads cannot exceed 125 bytes"
        ));
    }
    Ok(data)
}

#[derive(Debug, Deserialize)]
struct WsReplayDisconnectPayload {
    session_id: Option<Uuid>,
    id: Uuid,
    #[serde(default)]
    remove: bool,
}

async fn ws_replay_disconnect(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<WsReplayDisconnectPayload>,
) -> Response {
    let Some(session_id) = payload.session_id else {
        return active_session_conflict_response(&state);
    };
    let result = if payload.remove {
        if !state.sessions.contains_session(session_id) {
            return StatusCode::NOT_FOUND.into_response();
        }
        if let Some(false) = state
            .ws_replay
            .belongs_to_session(payload.id, session_id)
            .await
        {
            return active_session_conflict_response(&state);
        }
        state.ws_replay.remove(payload.id).await;
        Ok(())
    } else {
        if let Err(response) =
            ensure_ws_replay_connection_owner(&state, payload.id, session_id).await
        {
            return response;
        }
        state.ws_replay.disconnect(payload.id).await
    };
    match result {
        Ok(()) => Json(serde_json::json!({"ok": true})).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

#[derive(Debug, Deserialize)]
struct WsFramesSinceQuery {
    #[serde(default)]
    since: usize,
    session_id: Option<Uuid>,
}

async fn ws_replay_snapshot(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(query): Query<WsFramesSinceQuery>,
) -> Response {
    let id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let Some(session_id) = query.session_id else {
        return active_session_conflict_response(&state);
    };
    if let Err(response) = ensure_ws_replay_connection_owner(&state, id, session_id).await {
        return response;
    }
    match state.ws_replay.snapshot(id).await {
        Some(snapshot) => Json(snapshot).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn ws_replay_frames(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(query): Query<WsFramesSinceQuery>,
) -> Response {
    let id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let Some(session_id) = query.session_id else {
        return active_session_conflict_response(&state);
    };
    if let Err(response) = ensure_ws_replay_connection_owner(&state, id, session_id).await {
        return response;
    }
    match state.ws_replay.frames_since(id, query.since).await {
        Some((status, error, frames)) => Json(serde_json::json!({
            "status": status,
            "error": error,
            "frames": frames,
        }))
        .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn events(
    State(state): State<Arc<AppState>>,
    Query(query): Query<EventsQuery>,
    headers: HeaderMap,
) -> Response {
    let explicit_event_session = query.session_id.is_some();
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let last_event_sequence = headers
        .get("last-event-id")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    let session_id = session.id();
    let mut transaction_receiver = session.store.subscribe();
    let mut log_receiver = session.event_log.subscribe();
    let mut finding_receiver = session.scanner.subscribe();
    let mut websocket_receiver = session.websockets.subscribe();
    let latest_sequence = session.store.latest_sequence();

    let stream = stream! {
        let mut session_check = tokio::time::interval(Duration::from_millis(500));
        session_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        if last_event_sequence.is_some_and(|last_sequence| latest_sequence > last_sequence) {
            yield Ok::<Event, Infallible>(Event::default()
                .event("transactions_gap")
                .data("reconnect"));
        }
        loop {
            tokio::select! {
                result = transaction_receiver.recv() => {
                    match result {
                        Ok(summary) => {
                            if let Ok(payload) = serde_json::to_string(&summary) {
                                yield Ok(Event::default()
                                    .event("transaction")
                                    .id(summary.sequence.to_string())
                                    .data(payload));
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                            yield Ok(Event::default()
                                .event("transactions_gap")
                                .data("lagged"));
                            continue;
                        },
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
                result = log_receiver.recv() => {
                    match result {
                        Ok(entry) => {
                            if let Ok(payload) = serde_json::to_string(&entry) {
                                yield Ok(Event::default().event("event_log").data(payload));
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                            yield Ok(Event::default()
                                .event("event_log_gap")
                                .data("lagged"));
                            continue;
                        },
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
                result = finding_receiver.recv() => {
                    match result {
                        Ok(summary) => {
                            if let Ok(payload) = serde_json::to_string(&summary) {
                                yield Ok(Event::default().event("finding").data(payload));
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                            yield Ok(Event::default()
                                .event("findings_gap")
                                .data("lagged"));
                            continue;
                        },
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
                result = websocket_receiver.recv() => {
                    match result {
                        Ok(summary) => {
                            if let Ok(payload) = serde_json::to_string(&summary) {
                                yield Ok(Event::default().event("websocket").data(payload));
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                            yield Ok(Event::default()
                                .event("websockets_gap")
                                .data("lagged"));
                            continue;
                        },
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
                _ = session_check.tick() => {
                    if !state.sessions.contains_session(session_id) {
                        yield Ok(Event::default()
                            .event("session_deleted")
                            .data(session_id.to_string()));
                        break;
                    }
                    if !explicit_event_session && state.sessions.active_session_id() != session_id {
                        yield Ok(Event::default()
                            .event("session_changed")
                            .data(state.sessions.active_session_id().to_string()));
                        break;
                    }
                }
            }
        }
    };

    Sse::new(stream)
        .keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(10))
                .text("keepalive"),
        )
        .into_response()
}

async fn index() -> Response {
    (
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/html; charset=utf-8"),
            ),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("no-cache, no-store, must-revalidate"),
            ),
        ],
        include_str!("../web/index.html"),
    )
        .into_response()
}

async fn decoder_index() -> Response {
    serve_decoder_asset("popup.html").await
}

async fn decoder_asset(Path(path): Path<String>) -> Response {
    serve_decoder_asset(&path).await
}

async fn favicon_svg() -> Response {
    asset_response("image/svg+xml", include_str!("../web/favicon.svg"))
}

async fn logo_svg() -> Response {
    asset_response("image/svg+xml", include_str!("../web/logo.svg"))
}

async fn bungee_font() -> Response {
    binary_asset_response(
        "font/ttf",
        include_bytes!("../web/fonts/Bungee-Regular.ttf"),
    )
}

async fn styles_css() -> Response {
    asset_response("text/css; charset=utf-8", include_str!("../web/styles.css"))
}

async fn app_js() -> Response {
    asset_response(
        "application/javascript; charset=utf-8",
        include_str!("../web/app.js"),
    )
}

async fn codemirror_js() -> Response {
    asset_response(
        "application/javascript; charset=utf-8",
        include_str!("../web/codemirror.bundle.js"),
    )
}

fn asset_response(content_type: &'static str, body: &'static str) -> Response {
    (
        [
            (header::CONTENT_TYPE, HeaderValue::from_static(content_type)),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("no-cache, no-store, must-revalidate"),
            ),
        ],
        body,
    )
        .into_response()
}

fn binary_asset_response(content_type: &'static str, body: &'static [u8]) -> Response {
    (
        [(header::CONTENT_TYPE, HeaderValue::from_static(content_type))],
        body,
    )
        .into_response()
}

async fn serve_decoder_asset(path: &str) -> Response {
    let relative = match sanitize_relative_path(path) {
        Some(path) => path,
        None => return StatusCode::BAD_REQUEST.into_response(),
    };

    let key = relative.to_string_lossy().replace('\\', "/");
    match DecoderAssets::get(&key) {
        Some(content) => {
            let content_type = content_type_for_path(&relative);
            (
                [(header::CONTENT_TYPE, HeaderValue::from_static(content_type))],
                content.data.into_owned(),
            )
                .into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

fn sanitize_relative_path(path: &str) -> Option<PathBuf> {
    let normalized = if path.is_empty() { "popup.html" } else { path };
    let mut output = PathBuf::new();

    for component in PathBuf::from(normalized).components() {
        match component {
            Component::Normal(segment) => output.push(segment),
            Component::CurDir => {}
            _ => return None,
        }
    }

    if output.as_os_str().is_empty() {
        output.push("popup.html");
    }

    Some(output)
}

fn content_type_for_path(path: &std::path::Path) -> &'static str {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js") => "application/javascript; charset=utf-8",
        Some("json") => "application/json; charset=utf-8",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("svg") => "image/svg+xml",
        Some("txt") => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

fn download_bytes_response(
    bytes: &[u8],
    content_type: &'static str,
    content_disposition: &'static str,
) -> Response {
    (
        [
            (header::CONTENT_TYPE, HeaderValue::from_static(content_type)),
            (
                header::CONTENT_DISPOSITION,
                HeaderValue::from_static(content_disposition),
            ),
        ],
        bytes.to_vec(),
    )
        .into_response()
}

struct TargetHostAccumulator {
    host: String,
    schemes: Vec<String>,
    request_count: usize,
    paths: IndexMap<String, TargetPathAccumulator>,
}

struct TargetPathAccumulator {
    path: String,
    methods: Vec<String>,
    last_seen: chrono::DateTime<chrono::Utc>,
    status: Option<u16>,
    note_count: usize,
    is_websocket: bool,
}

fn push_unique(values: &mut Vec<String>, value: String) {
    if !values.iter().any(|existing| existing == &value) {
        values.push(value);
    }
}

async fn persist_session_mutation_locked_result(
    state: &Arc<AppState>,
    session: &Arc<SessionContext>,
) -> std::result::Result<(), String> {
    state
        .persist_session_context_mutation_locked(session)
        .await
        .map(|_| ())
        .map_err(|error| {
            let message = error.to_string();
            tracing::warn!(
                ?error,
                session_id = %session.id(),
                "failed to persist session"
            );
            message
        })
}

async fn persist_session_mutation_locked_or_response(
    state: &Arc<AppState>,
    session: &Arc<SessionContext>,
) -> std::result::Result<(), Response> {
    persist_session_mutation_locked_result(state, session)
        .await
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error).into_response())
}

async fn persist_session_mutation_locked_or_status(
    state: &Arc<AppState>,
    session: &Arc<SessionContext>,
) -> std::result::Result<(), StatusCode> {
    persist_session_mutation_locked_result(state, session)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

async fn persist_rolled_back_session_snapshot(
    state: &Arc<AppState>,
    session: &Arc<SessionContext>,
    action: &'static str,
) {
    if let Err(error) = state.persist_session_context_mutation_locked(session).await {
        tracing::warn!(
            %error,
            action,
            session_id = %session.id(),
            "failed to fully persist rolled back session state"
        );
    }
}

async fn persist_nonrollbackable_event_log_mutation(
    state: &Arc<AppState>,
    session: &Arc<SessionContext>,
    previous_events: Vec<EventLogEntry>,
    action: &'static str,
) {
    if let Err(error) = persist_session_mutation_locked_result(state, session).await {
        session.event_log.replace_all(previous_events).await;
        persist_rolled_back_session_snapshot(state, session, action).await;
        tracing::warn!(
            %error,
            action,
            session_id = %session.id(),
            "live action succeeded but event log persistence failed"
        );
    }
}

// ── OAST ──

async fn list_oast_callbacks(
    State(state): State<Arc<AppState>>,
    Query(query): Query<OastQuery>,
) -> Response {
    if let Err(error) = validate_optional_limit(query.limit) {
        return (StatusCode::BAD_REQUEST, error).into_response();
    }
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    Json(session.oast.list(query.limit).await).into_response()
}

async fn get_oast_callback(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(query): Query<OastQuery>,
) -> Response {
    let id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    match session.oast.get(id).await {
        Some(callback) => Json(callback).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn clear_oast_callbacks(
    State(state): State<Arc<AppState>>,
    Query(query): Query<OastQuery>,
) -> Response {
    let session = match resolve_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let _operation_guard =
        match guard_session_write_operation(&state, &session, query.session_id.is_none()).await {
            Ok(guard) => guard,
            Err(response) => return response,
        };
    let _mutation_guard = session.mutation_guard().await;
    let previous = session.oast.snapshot().await;
    let previous_cleared_keys = session.oast.snapshot_cleared_keys().await;
    session.oast.clear().await;
    if persist_session_mutation_locked_or_status(&state, &session)
        .await
        .is_err()
    {
        session.oast.restore(previous).await;
        session
            .oast
            .restore_cleared_keys(previous_cleared_keys)
            .await;
        persist_rolled_back_session_snapshot(&state, &session, "OAST callbacks clear").await;
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    StatusCode::NO_CONTENT.into_response()
}

#[derive(Serialize)]
struct OastPayloadResponse {
    correlation_id: String,
    payload: String,
}

async fn generate_oast_payload(
    State(state): State<Arc<AppState>>,
    Query(query): Query<OastQuery>,
) -> Response {
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    // Try provider-aware generation first (uses registered Interactsh state)
    if let Some((cid, payload)) = crate::oast::generate_payload(&session.oast).await {
        return Json(OastPayloadResponse {
            correlation_id: cid,
            payload,
        })
        .into_response();
    }
    let config = session.runtime.snapshot().await;
    if !config.oast_enabled {
        return (
            StatusCode::CONFLICT,
            "OAST is disabled. Enable OAST before generating a payload.",
        )
            .into_response();
    }
    if config.oast_provider == crate::oast::OastProvider::Interactsh {
        return (
            StatusCode::CONFLICT,
            "Interactsh is not registered yet. Wait for OAST registration or check provider settings.",
        )
            .into_response();
    }
    if config.oast_server_url.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            "OAST server URL is required before generating a payload.",
        )
            .into_response();
    }
    // Fallback: generic generation for BOAST/custom-compatible providers.
    let correlation_id = crate::oast::generate_correlation_id();
    let payload = crate::oast::build_oast_payload(&config.oast_server_url, &correlation_id);
    Json(OastPayloadResponse {
        correlation_id,
        payload,
    })
    .into_response()
}

#[derive(Serialize)]
struct OastStatusResponse {
    provider: String,
    registered: bool,
    correlation_id: Option<String>,
    payload_domain: Option<String>,
}

async fn oast_status(
    State(state): State<Arc<AppState>>,
    Query(query): Query<OastQuery>,
) -> Response {
    let session = match resolve_read_session_for_optional_id(&state, query.session_id).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let config = session.oast.get_config().await;
    let provider = format!("{}", config.provider);
    let reg = session.oast.get_registration_info().await;
    Json(OastStatusResponse {
        provider,
        registered: reg.is_some(),
        correlation_id: reg.as_ref().map(|(cid, _)| cid.clone()),
        payload_domain: reg.map(|(_, domain)| domain),
    })
    .into_response()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{
        extract::{Path, Query, State},
        http::{HeaderMap, HeaderValue, StatusCode, Uri},
        Json,
    };
    use chrono::Utc;
    use http_body_util::BodyExt;
    use serde::de::DeserializeOwned;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use uuid::Uuid;

    use super::{
        build_ws_replay_url, decode_ws_replay_control_payload, fuzzer_attack_error_status,
        get_target_site_map, normalize_replay_http_version, persist_bound_runtime_state,
        sequence_run_error_status, validate_annotations_payload, validate_editable_request,
        validate_editable_response, validate_match_replace_rules, validate_since,
        validate_status_code, validate_status_range, validate_transaction_query,
        validate_ws_replay_headers, AnnotationsPayload, TransactionQuery,
    };
    use crate::{
        config::AppConfig,
        event_log::EventLevel,
        fuzzer::{FuzzerAttackRecord, FuzzerAttackStatus},
        intercept::{
            InterceptRecord, InterceptResolution, InterceptRule, InterceptScope,
            ResponseInterceptRecord, ResponseInterceptResolution,
        },
        match_replace::{
            MatchReplaceRule, MatchReplaceRulesPayload, MatchReplaceScope, MatchReplaceTarget,
        },
        model::{
            BodyEncoding, EditableRequest, EditableResponse, HeaderRecord, MessageRecord,
            RequestTargetOverride, TransactionRecord, WebSocketFrameDirection, WebSocketFrameKind,
            WebSocketFrameRecord, WebSocketSessionRecord, WebSocketSessionSummary,
        },
        oast::{OastCallback, OastProvider},
        runtime::{RuntimeSettingsSnapshot, RuntimeSettingsUpdate},
        scanner::{CustomRule, FindingSummary, ScannerConfig, ScannerFinding, Severity},
        sequence::{ExtractionRule, ExtractionSource, SequenceDefinition, SequenceStep},
        state::AppState,
        workspace::{
            FuzzerWorkspaceState, ReplayHistoryEntryState, ReplayTabState, ReplayWorkspaceState,
            WorkspaceStateSnapshot,
        },
        ws_replay::WsReplayFrame,
    };

    #[test]
    fn spawn_open_command_reports_launch_failure() {
        let result = super::spawn_open_command(
            "/path/that/does/not/exist/sniper-open",
            std::iter::empty::<&str>(),
        );

        assert!(result.is_err());
    }

    async fn response_json<T: DeserializeOwned>(response: axum::response::Response) -> T {
        assert!(response.status().is_success());
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body should be readable");
        serde_json::from_slice(&body).expect("response body should be valid JSON")
    }

    async fn response_body_json(response: axum::response::Response) -> serde_json::Value {
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body should be readable");
        serde_json::from_slice(&body).expect("response body should be valid JSON")
    }

    fn test_app_config(name: &str) -> AppConfig {
        AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            body_preview_bytes: 4096,
            data_dir: std::env::temp_dir().join(format!("{name}-{}", uuid::Uuid::new_v4())),
        }
    }

    fn test_editable_request(path: &str) -> EditableRequest {
        EditableRequest {
            scheme: "https".to_string(),
            host: "example.test".to_string(),
            method: "GET".to_string(),
            path: path.to_string(),
            headers: vec![HeaderRecord {
                name: "host".to_string(),
                value: "example.test".to_string(),
            }],
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        }
    }

    fn test_editable_response(status: u16) -> EditableResponse {
        EditableResponse {
            status,
            headers: Vec::new(),
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
        }
    }

    #[test]
    fn local_api_write_guard_rejects_cross_site_fetch_metadata() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("127.0.0.1:8734"));
        headers.insert("sec-fetch-site", HeaderValue::from_static("cross-site"));
        let uri = Uri::from_static("/api/self-update");

        assert!(!super::is_allowed_browser_write(&headers, &uri));
    }

    #[test]
    fn local_api_write_guard_allows_non_browser_writes_without_browser_origins() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("127.0.0.1:8734"));
        let uri = Uri::from_static("/api/self-update");

        assert!(super::is_allowed_browser_write(&headers, &uri));
    }

    #[test]
    fn local_api_host_guard_rejects_rebound_hostnames() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("attacker.test:23001"));
        let uri = Uri::from_static("/api/runtime");

        assert!(!super::request_host_is_allowed_local_api(&headers, &uri));
    }

    #[test]
    fn local_api_host_guard_allows_loopback_literals_and_localhost() {
        let mut headers = HeaderMap::new();
        let uri = Uri::from_static("/api/runtime");

        headers.insert("host", HeaderValue::from_static("127.0.0.1:23001"));
        assert!(super::request_host_is_allowed_local_api(&headers, &uri));

        headers.insert("host", HeaderValue::from_static("[::1]:23001"));
        assert!(super::request_host_is_allowed_local_api(&headers, &uri));

        headers.insert("host", HeaderValue::from_static("localhost:23001"));
        assert!(super::request_host_is_allowed_local_api(&headers, &uri));
    }

    #[test]
    fn local_api_host_guard_rejects_invalid_loopback_like_authorities() {
        let mut headers = HeaderMap::new();
        let uri = Uri::from_static("/api/runtime");

        headers.insert("host", HeaderValue::from_static("[::1]evil:23001"));
        assert!(!super::request_host_is_allowed_local_api(&headers, &uri));

        headers.insert("host", HeaderValue::from_static("127.0.0.1:23001:extra"));
        assert!(!super::request_host_is_allowed_local_api(&headers, &uri));
    }

    #[tokio::test]
    async fn runtime_state_persists_bound_ui_and_active_proxy_addresses() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-api-runtime-state-test-{}",
            uuid::Uuid::new_v4()
        ));
        let state = Arc::new(
            AppState::new(AppConfig {
                proxy_addr: "127.0.0.1:18080".parse().unwrap(),
                ui_addr: "127.0.0.1:23001".parse().unwrap(),
                max_entries: 32,
                body_preview_bytes: 1024,
                data_dir: data_dir.clone(),
            })
            .unwrap(),
        );
        let active_proxy = "127.0.0.1:18081".parse().unwrap();
        let bound_ui = "127.0.0.1:23002".parse().unwrap();
        state.set_active_proxy_addr(active_proxy).await;
        state.set_proxy_online(true);

        persist_bound_runtime_state(&state, bound_ui).await.unwrap();

        let snapshot = crate::runtime_state::load_runtime_state(&data_dir)
            .unwrap()
            .expect("runtime state should exist");
        assert_eq!(snapshot.proxy_addr, "127.0.0.1:18081");
        assert_eq!(snapshot.ui_addr, "127.0.0.1:23002");
        assert!(snapshot.proxy_online);

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[test]
    fn transaction_filter_validation_rejects_invalid_ranges() {
        assert!(validate_status_range("2xx").is_some());
        assert!(validate_status_range("200-299").is_some());
        assert!(validate_status_range("0-999").is_none());
        assert!(validate_status_range("599-100").is_none());
        assert!(validate_status_code(200).is_some());
        assert!(validate_status_code(999).is_none());
        assert!(validate_since("1h").is_some());
        assert!(validate_since("-1h").is_none());
        assert!(validate_since("0m").is_none());
    }

    #[test]
    fn transaction_query_validation_rejects_zero_limit() {
        let query = TransactionQuery {
            limit: Some(0),
            ..TransactionQuery::default()
        };

        assert!(validate_transaction_query(&query).is_err());
    }

    #[test]
    fn fuzzer_persistence_errors_are_reported_as_server_errors() {
        let persistence_error: anyhow::Error =
            crate::fuzzer::FuzzerPersistenceError::new(anyhow::anyhow!("session snapshot failed"))
                .into();
        assert_eq!(
            fuzzer_attack_error_status(&persistence_error),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            fuzzer_attack_error_status(&anyhow::anyhow!("Request template is missing markers")),
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn sequence_persistence_errors_are_reported_as_server_errors() {
        let persistence_error: anyhow::Error = crate::sequence::SequencePersistenceError::new(
            anyhow::anyhow!("session snapshot failed"),
        )
        .into();
        assert_eq!(
            sequence_run_error_status(&persistence_error),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            sequence_run_error_status(&anyhow::anyhow!("Sequence has no steps")),
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn replay_http_version_validation_rejects_unsupported_versions() {
        assert_eq!(
            normalize_replay_http_version(Some("HTTP/2")).unwrap(),
            Some("HTTP/2".to_string())
        );
        assert!(normalize_replay_http_version(Some("HTTP/3")).is_err());
    }

    #[test]
    fn editable_response_validation_rejects_invalid_status_and_headers() {
        let mut response = EditableResponse {
            status: 200,
            headers: vec![HeaderRecord {
                name: "X-Test".to_string(),
                value: "ok".to_string(),
            }],
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
        };
        assert!(validate_editable_response(&response).is_ok());

        response.status = 700;
        assert!(validate_editable_response(&response).is_err());

        response.status = 200;
        response.headers[0].name = "Bad Header".to_string();
        assert!(validate_editable_response(&response).is_err());

        response.headers[0].name = "X-Test".to_string();
        response.headers[0].value = "ok\r\nInjected: yes".to_string();
        assert!(validate_editable_response(&response).is_err());
    }

    #[test]
    fn editable_request_validation_rejects_invalid_body_framing() {
        let mut request = EditableRequest {
            scheme: "https".to_string(),
            host: "example.test".to_string(),
            method: "POST".to_string(),
            path: "/".to_string(),
            headers: vec![HeaderRecord {
                name: "Content-Length".to_string(),
                value: "2".to_string(),
            }],
            body: "body".to_string(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        };

        assert!(validate_editable_request(&request)
            .unwrap_err()
            .contains("does not match body length"));

        request.headers = vec![HeaderRecord {
            name: "Transfer-Encoding".to_string(),
            value: "gzip, chunked".to_string(),
        }];
        assert!(validate_editable_request(&request)
            .unwrap_err()
            .contains("Transfer-Encoding: chunked"));
    }

    #[test]
    fn editable_request_validation_checks_base64_decoded_content_length() {
        let mut request = EditableRequest {
            scheme: "https".to_string(),
            host: "example.test".to_string(),
            method: "POST".to_string(),
            path: "/".to_string(),
            headers: vec![HeaderRecord {
                name: "Content-Length".to_string(),
                value: "2".to_string(),
            }],
            body: "/wA=".to_string(),
            body_encoding: BodyEncoding::Base64,
            preview_truncated: false,
        };

        assert!(validate_editable_request(&request).is_ok());

        request.headers[0].value = "4".to_string();
        assert!(validate_editable_request(&request)
            .unwrap_err()
            .contains("does not match body length"));
    }

    #[test]
    fn editable_response_validation_rejects_invalid_body_framing() {
        let response = EditableResponse {
            status: 200,
            headers: vec![HeaderRecord {
                name: "Content-Length".to_string(),
                value: "2".to_string(),
            }],
            body: "body".to_string(),
            body_encoding: BodyEncoding::Utf8,
        };

        assert!(validate_editable_response(&response)
            .unwrap_err()
            .contains("does not match body length"));
    }

    #[test]
    fn editable_response_validation_checks_base64_decoded_content_length() {
        let mut response = EditableResponse {
            status: 200,
            headers: vec![HeaderRecord {
                name: "Content-Length".to_string(),
                value: "2".to_string(),
            }],
            body: "/wA=".to_string(),
            body_encoding: BodyEncoding::Base64,
        };

        assert!(validate_editable_response(&response).is_ok());

        response.headers[0].value = "4".to_string();
        assert!(validate_editable_response(&response)
            .unwrap_err()
            .contains("does not match body length"));
    }

    #[test]
    fn ws_replay_control_payload_rejects_oversized_body() {
        use base64::Engine;

        let max_body = base64::engine::general_purpose::STANDARD.encode(vec![0_u8; 125]);
        assert_eq!(
            decode_ws_replay_control_payload(&max_body).unwrap().len(),
            125
        );

        let oversized_body = base64::engine::general_purpose::STANDARD.encode(vec![0_u8; 126]);
        let error = decode_ws_replay_control_payload(&oversized_body).unwrap_err();
        assert!(error.to_string().contains("cannot exceed 125 bytes"));
    }

    #[test]
    fn optional_csv_filters_ignore_empty_values() {
        assert_eq!(super::optional_csv_param(Some(" , ".to_string())), None);
        assert_eq!(
            super::optional_csv_param(Some("json, HTML ".to_string())),
            Some(vec!["json".to_string(), "html".to_string()])
        );
    }

    #[test]
    fn match_replace_validation_rejects_invalid_regex_search() {
        let mut rule = MatchReplaceRule {
            id: uuid::Uuid::new_v4(),
            enabled: true,
            description: "bad regex".to_string(),
            scope: MatchReplaceScope::Request,
            target: MatchReplaceTarget::Path,
            search: "(".to_string(),
            replace: "x".to_string(),
            regex: true,
            case_sensitive: true,
        };

        assert!(validate_match_replace_rules(&[rule.clone()]).is_err());
        rule.regex = false;
        assert!(validate_match_replace_rules(&[rule]).is_ok());
    }

    #[test]
    fn match_replace_validation_rejects_oversized_rule_sets() {
        let rule = MatchReplaceRule {
            id: uuid::Uuid::new_v4(),
            enabled: true,
            description: "large".to_string(),
            scope: MatchReplaceScope::Request,
            target: MatchReplaceTarget::Path,
            search: "x".repeat(super::MAX_MATCH_REPLACE_FIELD_BYTES + 1),
            replace: String::new(),
            regex: false,
            case_sensitive: true,
        };
        assert!(validate_match_replace_rules(&[rule])
            .unwrap_err()
            .contains("match-replace search"));

        let rules = (0..=super::MAX_MATCH_REPLACE_RULES)
            .map(|_| MatchReplaceRule {
                id: uuid::Uuid::new_v4(),
                enabled: true,
                description: "rule".to_string(),
                scope: MatchReplaceScope::Request,
                target: MatchReplaceTarget::Path,
                search: "x".to_string(),
                replace: String::new(),
                regex: false,
                case_sensitive: true,
            })
            .collect::<Vec<_>>();
        assert!(validate_match_replace_rules(&rules)
            .unwrap_err()
            .contains("more than"));
    }

    #[test]
    fn annotation_validation_limits_color_and_note_size() {
        assert!(validate_annotations_payload(&AnnotationsPayload {
            color_tag: Some(Some("blue".to_string())),
            user_note: Some(Some("short note".to_string())),
        })
        .is_ok());
        assert!(validate_annotations_payload(&AnnotationsPayload {
            color_tag: Some(None),
            user_note: Some(None),
        })
        .is_ok());

        assert_eq!(
            validate_annotations_payload(&AnnotationsPayload {
                color_tag: Some(Some("chartreuse".to_string())),
                user_note: None,
            })
            .unwrap_err(),
            "unsupported color tag"
        );
        assert!(validate_annotations_payload(&AnnotationsPayload {
            color_tag: None,
            user_note: Some(Some("x".repeat(super::MAX_ANNOTATION_NOTE_BYTES + 1))),
        })
        .unwrap_err()
        .contains("user note"));
    }

    #[test]
    fn sequence_validation_rejects_invalid_response_header_extractions() {
        let request = EditableRequest {
            scheme: "https".to_string(),
            host: "example.test".to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            headers: Vec::new(),
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        };
        let mut definition = SequenceDefinition {
            id: uuid::Uuid::new_v4(),
            name: "header extraction".to_string(),
            steps: vec![SequenceStep {
                id: uuid::Uuid::new_v4(),
                label: "step".to_string(),
                request,
                source_transaction_id: None,
                http_version: None,
                target: None,
                request_text: None,
                request_parse_error: None,
                extractions: vec![ExtractionRule {
                    variable_name: "session".to_string(),
                    source: ExtractionSource::ResponseHeader,
                    pattern: "Bad Header".to_string(),
                    group: 1,
                }],
            }],
        };

        assert!(super::validate_sequence_definition(&definition).is_err());
        definition.steps[0].extractions[0].pattern = "x-session".to_string();
        assert!(super::validate_sequence_definition(&definition).is_ok());
    }

    #[test]
    fn sequence_validation_rejects_oversized_definitions() {
        let request = EditableRequest {
            scheme: "https".to_string(),
            host: "example.test".to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            headers: Vec::new(),
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        };
        let step = SequenceStep {
            id: uuid::Uuid::new_v4(),
            label: "step".to_string(),
            request,
            source_transaction_id: None,
            http_version: None,
            target: None,
            request_text: None,
            request_parse_error: None,
            extractions: Vec::new(),
        };
        let mut definition = SequenceDefinition {
            id: uuid::Uuid::new_v4(),
            name: "sequence".to_string(),
            steps: vec![step.clone(); super::MAX_SEQUENCE_STEPS + 1],
        };
        assert!(super::validate_sequence_definition(&definition)
            .unwrap_err()
            .contains("more than"));

        definition.steps = vec![SequenceStep {
            label: "x".repeat(super::MAX_SEQUENCE_TEXT_FIELD_BYTES + 1),
            ..step
        }];
        assert!(super::validate_sequence_definition(&definition)
            .unwrap_err()
            .contains("sequence step label"));
    }

    #[test]
    fn ws_replay_url_builder_handles_ipv6_and_paths() {
        assert_eq!(
            build_ws_replay_url("https", "::1", 9443, "/socket").unwrap(),
            "wss://[::1]:9443/socket"
        );
        assert_eq!(
            build_ws_replay_url("ws", "[2001:db8::1]", 80, "").unwrap(),
            "ws://[2001:db8::1]:80/"
        );
        assert_eq!(
            build_ws_replay_url("wss", "example.test:8443", 443, "/chat").unwrap(),
            "wss://example.test:8443/chat"
        );
        assert_eq!(
            build_ws_replay_url("wss", "[2001:db8::1]:9443", 443, "/").unwrap(),
            "wss://[2001:db8::1]:9443/"
        );
        assert!(build_ws_replay_url("ftp", "example.test", 80, "/").is_err());
        assert!(build_ws_replay_url("wss", "example.test", 0, "/").is_err());
        assert!(build_ws_replay_url("wss", "example.test", 443, "socket").is_err());
        assert!(build_ws_replay_url("wss", "example.test", 443, "//socket").is_err());
        assert!(build_ws_replay_url("wss", "example.test", 443, "/socket#frag").is_err());
        assert!(build_ws_replay_url("wss", "example.test/path", 443, "/").is_err());
        assert!(build_ws_replay_url("wss", "example.test?x=1", 443, "/").is_err());
        assert!(build_ws_replay_url("wss", "example.test#frag", 443, "/").is_err());
        assert!(build_ws_replay_url("wss", "bad host.test", 443, "/").is_err());
        assert!(build_ws_replay_url("wss", "example.test:notaport", 443, "/").is_err());
        assert!(build_ws_replay_url("wss", "[not-ip]", 443, "/").is_err());
        assert!(build_ws_replay_url("wss", "[2001:db8::1]:70000", 443, "/").is_err());
    }

    #[test]
    fn ws_replay_header_validation_rejects_invalid_values() {
        assert!(validate_ws_replay_headers(&[HeaderRecord {
            name: "Authorization".to_string(),
            value: "Bearer abc\ndef".to_string(),
        }])
        .is_err());
        assert!(validate_ws_replay_headers(&[HeaderRecord {
            name: " Authorization ".to_string(),
            value: "Bearer abc".to_string(),
        }])
        .is_err());

        let headers = validate_ws_replay_headers(&[
            HeaderRecord {
                name: "Connection".to_string(),
                value: "Upgrade, X-Hop".to_string(),
            },
            HeaderRecord {
                name: "Sec-WebSocket-Key".to_string(),
                value: "ignored".to_string(),
            },
            HeaderRecord {
                name: "Proxy-Authorization".to_string(),
                value: "Basic secret".to_string(),
            },
            HeaderRecord {
                name: "X-Hop".to_string(),
                value: "secret".to_string(),
            },
            HeaderRecord {
                name: "X-Test".to_string(),
                value: "ok".to_string(),
            },
        ])
        .expect("valid replay headers should pass");
        assert_eq!(headers, vec![("x-test".to_string(), "ok".to_string())]);
    }

    #[test]
    fn ws_replay_connect_payload_defaults_missing_headers() {
        let payload: super::WsReplayConnectPayload = serde_json::from_value(serde_json::json!({
            "id": "33333333-3333-3333-3333-333333333333",
            "scheme": "ws",
            "host": "127.0.0.1",
            "port": 8080,
            "path": "/"
        }))
        .expect("headers should default to empty");

        assert!(payload.headers.is_empty());
    }

    #[tokio::test]
    async fn ws_replay_owner_check_rejects_deleted_session() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-ws-replay-deleted-session-{}",
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
        let deleted_session_id = state.session().await.id();
        state
            .create_session(Some("replacement".to_string()))
            .await
            .unwrap();
        state.delete_session(deleted_session_id).await.unwrap();

        let response =
            super::ensure_ws_replay_connection_owner(&state, Uuid::new_v4(), deleted_session_id)
                .await
                .unwrap_err();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[test]
    fn scanner_config_rejects_empty_custom_rule_pattern() {
        let mut config = ScannerConfig::default();
        config.custom_rules.push(CustomRule {
            id: "empty-pattern".to_string(),
            name: "Empty pattern".to_string(),
            enabled: true,
            target: "response_body".to_string(),
            header_name: String::new(),
            pattern: "  ".to_string(),
            severity: Severity::Info,
            category: "custom".to_string(),
            description: String::new(),
        });

        assert!(super::validate_scanner_config(&config).is_err());
    }

    #[test]
    fn scanner_config_rejects_oversized_custom_rule_sets() {
        let rule = CustomRule {
            id: "custom".to_string(),
            name: "Custom".to_string(),
            enabled: true,
            target: "response_body".to_string(),
            header_name: String::new(),
            pattern: "x".to_string(),
            severity: Severity::Info,
            category: "custom".to_string(),
            description: String::new(),
        };
        let config = ScannerConfig {
            custom_rules: vec![rule.clone(); super::MAX_SCANNER_CUSTOM_RULES + 1],
            ..ScannerConfig::default()
        };
        assert!(super::validate_scanner_config(&config)
            .unwrap_err()
            .contains("custom rules"));

        let config = ScannerConfig {
            custom_rules: vec![CustomRule {
                pattern: "x".repeat(super::MAX_SCANNER_FIELD_BYTES + 1),
                ..rule
            }],
            ..ScannerConfig::default()
        };
        assert!(super::validate_scanner_config(&config)
            .unwrap_err()
            .contains("custom scanner rule pattern"));
    }

    #[test]
    fn sequence_validation_rejects_invalid_extraction_regex() {
        let request = crate::model::EditableRequest {
            scheme: "https".to_string(),
            host: "example.test".to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            headers: Vec::new(),
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        };
        let definition = SequenceDefinition {
            id: uuid::Uuid::new_v4(),
            name: "test".to_string(),
            steps: vec![SequenceStep {
                id: uuid::Uuid::new_v4(),
                label: "extract".to_string(),
                request,
                source_transaction_id: None,
                http_version: None,
                target: None,
                request_text: None,
                request_parse_error: None,
                extractions: vec![ExtractionRule {
                    variable_name: "token".to_string(),
                    source: ExtractionSource::ResponseBody,
                    pattern: "(".to_string(),
                    group: 1,
                }],
            }],
        };
        assert!(super::validate_sequence_definition(&definition).is_err());
    }

    #[test]
    fn sequence_validation_rejects_invalid_http_version() {
        let request = crate::model::EditableRequest {
            scheme: "https".to_string(),
            host: "example.test".to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            headers: Vec::new(),
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        };
        let mut definition = SequenceDefinition {
            id: uuid::Uuid::new_v4(),
            name: "test".to_string(),
            steps: vec![SequenceStep {
                id: uuid::Uuid::new_v4(),
                label: "h2".to_string(),
                request,
                source_transaction_id: None,
                http_version: Some("HTTP/2".to_string()),
                target: None,
                request_text: None,
                request_parse_error: None,
                extractions: Vec::new(),
            }],
        };

        assert!(super::validate_sequence_definition(&definition).is_ok());
        definition.steps[0].http_version = Some("HTTP/3".to_string());
        assert!(super::validate_sequence_definition(&definition).is_err());
    }

    #[test]
    fn sequence_validation_rejects_invalid_target_override() {
        let request = crate::model::EditableRequest {
            scheme: "https".to_string(),
            host: "example.test".to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            headers: Vec::new(),
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        };
        let definition = SequenceDefinition {
            id: uuid::Uuid::new_v4(),
            name: "test".to_string(),
            steps: vec![SequenceStep {
                id: uuid::Uuid::new_v4(),
                label: "bad target".to_string(),
                request,
                source_transaction_id: None,
                http_version: None,
                target: Some(RequestTargetOverride {
                    scheme: "ftp".to_string(),
                    host: "example.test".to_string(),
                    port: "443".to_string(),
                }),
                request_text: None,
                request_parse_error: None,
                extractions: Vec::new(),
            }],
        };

        assert!(super::validate_sequence_definition(&definition).is_err());
    }

    #[test]
    fn replay_target_validation_rejects_ambiguous_hosts() {
        for host in [
            "victim.test@127.0.0.1",
            "127.0.0.1/path",
            "127.0.0.1?x=1",
            "example.test:8443",
            "bad host.test",
            "https://example.test",
        ] {
            let target = RequestTargetOverride {
                scheme: "https".to_string(),
                host: host.to_string(),
                port: "443".to_string(),
            };

            assert!(
                super::validate_request_target_override(&target).is_err(),
                "{host} should be rejected"
            );
        }

        let target = RequestTargetOverride {
            scheme: "https".to_string(),
            host: "::1".to_string(),
            port: "443".to_string(),
        };
        assert!(super::validate_request_target_override(&target).is_ok());

        let target = RequestTargetOverride {
            scheme: " https ".to_string(),
            host: "example.test".to_string(),
            port: "443".to_string(),
        };
        assert!(super::validate_request_target_override(&target).is_err());

        let target = RequestTargetOverride {
            scheme: "https".to_string(),
            host: " example.test ".to_string(),
            port: "443".to_string(),
        };
        assert!(super::validate_request_target_override(&target).is_err());

        let target = RequestTargetOverride {
            scheme: "https".to_string(),
            host: "example.test".to_string(),
            port: " 443 ".to_string(),
        };
        assert!(super::validate_request_target_override(&target).is_err());
    }

    #[test]
    fn editable_request_validation_rejects_invalid_headers() {
        let mut request = crate::model::EditableRequest {
            scheme: "https".to_string(),
            host: "example.test".to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            headers: vec![HeaderRecord {
                name: "X-Test".to_string(),
                value: "ok".to_string(),
            }],
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        };
        assert!(super::validate_editable_request(&request).is_ok());

        request.headers[0].name = "Bad Header".to_string();
        assert!(super::validate_editable_request(&request).is_err());

        request.headers[0].name.clear();
        assert!(super::validate_editable_request(&request).is_err());

        request.headers[0].name = "X-Test".to_string();
        request.headers[0].value = "ok\r\nInjected: yes".to_string();
        assert!(super::validate_editable_request(&request).is_err());

        request.headers[0].value = "ok".to_string();
        request.headers[0].name = " X-Test ".to_string();
        assert!(super::validate_editable_request(&request).is_err());

        request.headers[0].name = "X-Test".to_string();
        request.scheme = "ftp".to_string();
        assert!(super::validate_editable_request(&request).is_err());

        request.scheme = "https".to_string();
        request.host = "example.test/path".to_string();
        assert!(super::validate_editable_request(&request).is_err());

        request.host = "example.test:443:444".to_string();
        assert!(super::validate_editable_request(&request).is_err());

        request.host = "::1".to_string();
        assert!(super::validate_editable_request(&request).is_err());

        request.host = "example.test".to_string();
        request.path = "relative".to_string();
        assert!(super::validate_editable_request(&request).is_err());

        request.path = "/with#fragment".to_string();
        assert!(super::validate_editable_request(&request).is_err());

        request.path = "/".to_string();
        request.method = " GET ".to_string();
        assert!(super::validate_editable_request(&request).is_err());

        request.method = "GET".to_string();
        request.method = "GE/T".to_string();
        assert!(super::validate_editable_request(&request).is_err());

        request.method = "CONNECT".to_string();
        assert!(super::validate_editable_request(&request).is_err());

        request.method = "GET".to_string();
        request.headers = vec![
            HeaderRecord {
                name: "Host".to_string(),
                value: "first.example".to_string(),
            },
            HeaderRecord {
                name: "host".to_string(),
                value: "second.example".to_string(),
            },
        ];
        assert!(super::validate_editable_request(&request)
            .unwrap_err()
            .contains("multiple Host headers"));
    }

    #[test]
    fn workspace_validation_rejects_partial_replay_target_fields() {
        let mut snapshot = WorkspaceStateSnapshot::default();
        snapshot.replay.tabs.push(ReplayTabState {
            id: "partial-target".to_string(),
            sequence: 1,
            target_scheme: "https".to_string(),
            target_host: "example.test".to_string(),
            target_port: String::new(),
            ..ReplayTabState::default()
        });

        assert!(super::validate_workspace_state(&snapshot).is_err());
    }

    #[test]
    fn workspace_validation_rejects_oversized_replay_custom_label() {
        let mut snapshot = WorkspaceStateSnapshot::default();
        snapshot.replay.tabs.push(ReplayTabState {
            id: "named-tab".to_string(),
            sequence: 1,
            custom_label: "x".repeat(81),
            ..ReplayTabState::default()
        });

        assert!(super::validate_workspace_state(&snapshot).is_err());
    }

    #[test]
    fn workspace_validation_rejects_unbounded_durable_metadata() {
        let mut snapshot = WorkspaceStateSnapshot {
            client_id: Some("x".repeat(super::MAX_WORKSPACE_CLIENT_ID_BYTES + 1)),
            ..WorkspaceStateSnapshot::default()
        };
        let error = super::validate_workspace_state(&snapshot).unwrap_err();
        assert!(error.contains("workspace client id"));

        snapshot.client_id = None;
        snapshot.fuzzer.target_request_authority =
            Some("x".repeat(crate::workspace::MAX_WORKSPACE_SERIALIZED_BYTES));
        let error = super::validate_workspace_state(&snapshot).unwrap_err();
        assert!(error.contains("serialized bytes"));
    }

    #[tokio::test]
    async fn request_forward_all_returns_json_count() {
        let state =
            Arc::new(AppState::new(test_app_config("sniper-forward-all-requests")).unwrap());
        let session = state.session().await;
        let queue = session.intercepts.clone();
        let first = InterceptRecord {
            id: Uuid::new_v4(),
            started_at: Utc::now(),
            peer_addr: "127.0.0.1:12345".to_string(),
            request: test_editable_request("/one"),
            is_websocket: false,
        };
        let second = InterceptRecord {
            id: Uuid::new_v4(),
            started_at: Utc::now(),
            peer_addr: "127.0.0.1:12346".to_string(),
            request: test_editable_request("/two"),
            is_websocket: false,
        };
        let first_task = tokio::spawn({
            let queue = queue.clone();
            async move { queue.enqueue(first).await }
        });
        let second_task = tokio::spawn({
            let queue = queue.clone();
            async move { queue.enqueue(second).await }
        });
        for _ in 0..20 {
            if session.intercepts.list().await.len() == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(session.intercepts.list().await.len(), 2);

        let response = super::forward_all_intercepts(
            State(state.clone()),
            Query(super::SessionScopedQuery { session_id: None }),
        )
        .await;
        let payload = response_body_json(response).await;

        assert_eq!(payload["ok"], true);
        assert_eq!(payload["action"], "forward-all");
        assert_eq!(payload["forwarded"], 2);
        assert!(session.intercepts.list().await.is_empty());
        assert!(matches!(
            first_task.await.unwrap(),
            InterceptResolution::Forward(_)
        ));
        assert!(matches!(
            second_task.await.unwrap(),
            InterceptResolution::Forward(_)
        ));
    }

    #[tokio::test]
    async fn response_forward_all_returns_json_count() {
        let state =
            Arc::new(AppState::new(test_app_config("sniper-forward-all-responses")).unwrap());
        let session = state.session().await;
        let queue = session.response_intercepts.clone();
        let first = ResponseInterceptRecord {
            id: Uuid::new_v4(),
            started_at: Utc::now(),
            scheme: "https".to_string(),
            host: "example.test".to_string(),
            method: "GET".to_string(),
            path: "/one".to_string(),
            status: 200,
            response: test_editable_response(200),
        };
        let second = ResponseInterceptRecord {
            id: Uuid::new_v4(),
            started_at: Utc::now(),
            scheme: "https".to_string(),
            host: "example.test".to_string(),
            method: "GET".to_string(),
            path: "/two".to_string(),
            status: 204,
            response: test_editable_response(204),
        };
        let first_task = tokio::spawn({
            let queue = queue.clone();
            async move { queue.enqueue(first).await }
        });
        let second_task = tokio::spawn({
            let queue = queue.clone();
            async move { queue.enqueue(second).await }
        });
        for _ in 0..20 {
            if session.response_intercepts.list().await.len() == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(session.response_intercepts.list().await.len(), 2);

        let response = super::forward_all_response_intercepts(
            State(state.clone()),
            Query(super::SessionScopedQuery { session_id: None }),
        )
        .await;
        let payload = response_body_json(response).await;

        assert_eq!(payload["ok"], true);
        assert_eq!(payload["action"], "forward-all");
        assert_eq!(payload["forwarded"], 2);
        assert!(session.response_intercepts.list().await.is_empty());
        assert!(matches!(
            first_task.await.unwrap(),
            ResponseInterceptResolution::Forward(_)
        ));
        assert!(matches!(
            second_task.await.unwrap(),
            ResponseInterceptResolution::Forward(_)
        ));
    }

    #[test]
    fn workspace_validation_rejects_oversized_replay_text_state() {
        let mut snapshot = WorkspaceStateSnapshot::default();
        snapshot.replay.tabs.push(ReplayTabState {
            id: "large-tab".to_string(),
            sequence: 1,
            request_text: "x".repeat(super::MAX_WORKSPACE_TEXT_FIELD_BYTES + 1),
            ..ReplayTabState::default()
        });

        let error = super::validate_workspace_state(&snapshot).unwrap_err();
        assert!(error.contains("replay tab request text"));
    }

    #[test]
    fn workspace_validation_rejects_oversized_replay_history_state() {
        let mut snapshot = WorkspaceStateSnapshot::default();
        snapshot.replay.tabs.push(ReplayTabState {
            id: "history-tab".to_string(),
            sequence: 1,
            history_entries: vec![
                ReplayHistoryEntryState::default();
                super::MAX_WORKSPACE_REPLAY_HISTORY_ENTRIES_PER_TAB + 1
            ],
            ..ReplayTabState::default()
        });

        let error = super::validate_workspace_state(&snapshot).unwrap_err();
        assert!(error.contains("too many history entries"));
    }

    #[test]
    fn workspace_validation_rejects_oversized_fuzzer_payload_text_state() {
        let mut snapshot = WorkspaceStateSnapshot {
            fuzzer: FuzzerWorkspaceState {
                payloads_text: "x\n".repeat(super::MAX_WORKSPACE_FUZZER_PAYLOAD_LINES + 1),
                ..FuzzerWorkspaceState::default()
            },
            ..WorkspaceStateSnapshot::default()
        };

        let error = super::validate_workspace_state(&snapshot).unwrap_err();
        assert!(error.contains("fuzzer payload text"));

        snapshot.fuzzer.payloads_text =
            "x".repeat(super::MAX_WORKSPACE_FUZZER_PAYLOAD_TEXT_BYTES + 1);
        let error = super::validate_workspace_state(&snapshot).unwrap_err();
        assert!(error.contains("fuzzer payload text"));
    }

    #[test]
    fn workspace_validation_allows_empty_replay_drafts() {
        let mut snapshot = WorkspaceStateSnapshot::default();
        snapshot.replay.tabs.push(ReplayTabState {
            id: "draft".to_string(),
            sequence: 1,
            base_request: Some(EditableRequest {
                scheme: "https".to_string(),
                host: String::new(),
                method: "GET".to_string(),
                path: "/".to_string(),
                headers: Vec::new(),
                body: String::new(),
                body_encoding: BodyEncoding::Utf8,
                preview_truncated: false,
            }),
            target_scheme: "https".to_string(),
            target_host: String::new(),
            target_port: "443".to_string(),
            ..ReplayTabState::default()
        });

        assert!(super::validate_workspace_state(&snapshot).is_ok());
    }

    #[test]
    fn workspace_validation_rejects_invalid_websocket_tab_fields() {
        let mut snapshot = WorkspaceStateSnapshot::default();
        snapshot.replay.tabs.push(ReplayTabState {
            id: Uuid::new_v4().to_string(),
            tab_type: "websocket".to_string(),
            sequence: 1,
            ws_scheme: "wss".to_string(),
            ws_host: String::new(),
            ws_port: serde_json::json!(443),
            ws_path: "/".to_string(),
            ..ReplayTabState::default()
        });
        assert!(super::validate_workspace_state(&snapshot).is_ok());

        snapshot.replay.tabs[0].ws_scheme = "https".to_string();
        assert!(super::validate_workspace_state(&snapshot).is_err());

        snapshot.replay.tabs[0].ws_scheme = "wss".to_string();
        snapshot.replay.tabs[0].ws_host = "example.test".to_string();
        snapshot.replay.tabs[0].ws_port = serde_json::json!("notaport");
        assert!(super::validate_workspace_state(&snapshot).is_err());

        snapshot.replay.tabs[0].ws_port = serde_json::json!(443);
        snapshot.replay.tabs[0].ws_headers = vec![serde_json::json!({
            "name": "Authorization",
            "value": "Bearer abc\nInjected: yes"
        })];
        assert!(super::validate_workspace_state(&snapshot).is_err());

        snapshot.replay.tabs[0].ws_headers.clear();
        snapshot.replay.tabs[0].ws_setup_queue = vec![serde_json::json!({
            "kind": "ping",
            "body": "not base64",
            "body_encoded": true
        })];
        assert!(super::validate_workspace_state(&snapshot).is_err());

        snapshot.replay.tabs[0].ws_setup_queue.clear();
        snapshot.replay.tabs[0].ws_setup_notice = "Auto-send setup disabled.".to_string();
        assert!(super::validate_workspace_state(&snapshot).is_ok());
    }

    #[test]
    fn workspace_validation_rejects_non_uuid_websocket_replay_tab_id() {
        let mut snapshot = WorkspaceStateSnapshot::default();
        snapshot.replay.tabs.push(ReplayTabState {
            id: "ws-draft".to_string(),
            tab_type: "websocket".to_string(),
            sequence: 1,
            ws_scheme: "wss".to_string(),
            ws_host: "example.test".to_string(),
            ws_port: serde_json::json!(443),
            ws_path: "/".to_string(),
            ..ReplayTabState::default()
        });

        let error = super::validate_workspace_state(&snapshot).unwrap_err();
        assert!(error.contains("id must be a UUID"));
    }

    #[test]
    fn workspace_validation_rejects_websocket_state_on_non_websocket_tabs() {
        fn assert_rejects(tab: ReplayTabState) {
            let mut snapshot = WorkspaceStateSnapshot::default();
            snapshot.replay.tabs.push(tab);
            let error = super::validate_workspace_state(&snapshot).unwrap_err();
            assert!(error.contains("must not include websocket state"));
        }

        assert_rejects(ReplayTabState {
            id: "http-draft".to_string(),
            sequence: 1,
            ws_setup_notice: "websocket only".to_string(),
            ..ReplayTabState::default()
        });
        assert_rejects(ReplayTabState {
            id: "http-draft".to_string(),
            sequence: 1,
            ws_selected_frame_index: Some(0),
            ..ReplayTabState::default()
        });
        assert_rejects(ReplayTabState {
            id: "http-draft".to_string(),
            sequence: 1,
            ws_frame_window_start: Some(0),
            ..ReplayTabState::default()
        });
    }

    #[test]
    fn workspace_validation_rejects_oversized_websocket_headers() {
        let mut snapshot = WorkspaceStateSnapshot::default();
        snapshot.replay.tabs.push(ReplayTabState {
            id: Uuid::new_v4().to_string(),
            tab_type: "websocket".to_string(),
            sequence: 1,
            ws_headers: (0..=super::MAX_WORKSPACE_WS_HEADERS)
                .map(|index| {
                    serde_json::json!({
                        "name": format!("X-Test-{index}"),
                        "value": "ok"
                    })
                })
                .collect(),
            ..ReplayTabState::default()
        });

        let error = super::validate_workspace_state(&snapshot).unwrap_err();
        assert!(error.contains("too many headers"));

        snapshot.replay.tabs[0].ws_headers = vec![serde_json::json!({
            "name": "X-Large",
            "value": "x".repeat(super::MAX_WORKSPACE_WS_HEADER_BYTES)
        })];
        let error = super::validate_workspace_state(&snapshot).unwrap_err();
        assert!(error.contains("WebSocket header cannot exceed"));
    }

    #[test]
    fn workspace_validation_checks_websocket_replay_frames() {
        let mut snapshot = WorkspaceStateSnapshot::default();
        let frame = WsReplayFrame {
            index: 0,
            captured_at: Utc::now().to_rfc3339(),
            direction: WebSocketFrameDirection::ClientToServer,
            kind: WebSocketFrameKind::Text,
            body: "hello".to_string(),
            body_encoding: BodyEncoding::Utf8,
            body_size: 5,
            preview_truncated: false,
        };
        snapshot.replay.tabs.push(ReplayTabState {
            id: Uuid::new_v4().to_string(),
            tab_type: "websocket".to_string(),
            sequence: 1,
            ws_scheme: "wss".to_string(),
            ws_host: "example.test".to_string(),
            ws_port: serde_json::json!(443),
            ws_path: "/".to_string(),
            ws_frames: vec![frame.clone()],
            ..ReplayTabState::default()
        });
        assert!(super::validate_workspace_state(&snapshot).is_ok());

        snapshot.replay.tabs[0].ws_frames[0].body =
            "x".repeat(super::MAX_WORKSPACE_WS_FRAME_BODY_BYTES + 1);
        snapshot.replay.tabs[0].ws_frames[0].body_size =
            snapshot.replay.tabs[0].ws_frames[0].body.len();
        assert!(super::validate_workspace_state(&snapshot).is_err());

        snapshot.replay.tabs[0].ws_frames[0].body = "hello".to_string();
        snapshot.replay.tabs[0].ws_frames[0].body_size = 10;
        snapshot.replay.tabs[0].ws_frames[0].preview_truncated = false;
        assert!(super::validate_workspace_state(&snapshot).is_err());

        snapshot.replay.tabs[0].ws_frames[0].preview_truncated = true;
        assert!(super::validate_workspace_state(&snapshot).is_ok());

        snapshot.replay.tabs[0].ws_frames[0].captured_at = "not-a-timestamp".to_string();
        assert!(super::validate_workspace_state(&snapshot).is_err());

        let mut oversized_workspace = WorkspaceStateSnapshot::default();
        oversized_workspace.replay.tabs = (0..3)
            .map(|tab_index| ReplayTabState {
                id: Uuid::new_v4().to_string(),
                tab_type: "websocket".to_string(),
                sequence: tab_index + 1,
                ws_frames: vec![frame.clone(); super::MAX_WORKSPACE_WS_FRAMES],
                ..ReplayTabState::default()
            })
            .collect();
        assert!(super::validate_workspace_state(&oversized_workspace).is_err());
    }

    #[test]
    fn workspace_validation_rejects_inconsistent_replay_tabs() {
        let mut snapshot = WorkspaceStateSnapshot::default();
        snapshot.replay.active_tab_id = Some("missing".to_string());
        snapshot.replay.tabs.push(ReplayTabState {
            id: "tab-a".to_string(),
            sequence: 1,
            history_index: Some(0),
            ..ReplayTabState::default()
        });
        assert!(super::validate_workspace_state(&snapshot).is_err());

        snapshot.replay.active_tab_id = Some("tab-a".to_string());
        assert!(super::validate_workspace_state(&snapshot).is_err());

        snapshot.replay.tabs[0].history_index = None;
        snapshot.replay.tabs.push(ReplayTabState {
            id: "tab-a".to_string(),
            sequence: 2,
            ..ReplayTabState::default()
        });
        assert!(super::validate_workspace_state(&snapshot).is_err());
    }

    #[tokio::test]
    async fn target_site_map_counts_notes_once_per_record() {
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            body_preview_bytes: 4096,
            data_dir: std::env::temp_dir()
                .join(format!("sniper-test-target-notes-{}", uuid::Uuid::new_v4())),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let message = MessageRecord {
            headers: vec![HeaderRecord {
                name: "host".to_string(),
                value: "example.test".to_string(),
            }],
            body_preview: String::new(),
            body_encoding: BodyEncoding::Utf8,
            body_size: 0,
            decoded_body_size: None,
            preview_truncated: false,
            content_type: None,
            content_decoded: false,
        };

        let session = state.session().await;
        let mut record = TransactionRecord::http(
            Utc::now(),
            "GET".to_string(),
            "https".to_string(),
            "example.test".to_string(),
            "/hello".to_string(),
            Some(200),
            1,
            message.clone(),
            Some(message),
            vec!["one note".to_string()],
            None,
            None,
        );
        record.user_note = Some("manual note".to_string());
        session.store.insert(record).await;

        let site_map: Vec<crate::target::TargetHostNode> = response_json(
            get_target_site_map(
                State(state),
                Query(super::TargetSiteMapQuery { session_id: None }),
            )
            .await,
        )
        .await;
        assert_eq!(site_map.len(), 1);
        assert_eq!(site_map[0].paths.len(), 1);
        assert_eq!(site_map[0].paths[0].note_count, 2);
    }

    #[tokio::test]
    async fn runtime_update_waits_for_session_operation_lock() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-runtime-op-lock-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let operation_lock = state.session_operation_lock(session.id()).await;
        let operation_guard = operation_lock.lock().await;

        let blocked = tokio::time::timeout(
            Duration::from_millis(30),
            super::update_runtime_settings(
                State(state.clone()),
                Json(RuntimeSettingsUpdate {
                    session_id: Some(session.id()),
                    intercept_enabled: Some(true),
                    ..RuntimeSettingsUpdate::default()
                }),
            ),
        )
        .await;
        assert!(blocked.is_err());

        drop(operation_guard);
        let runtime: RuntimeSettingsSnapshot = response_json(
            super::update_runtime_settings(
                State(state.clone()),
                Json(RuntimeSettingsUpdate {
                    session_id: Some(session.id()),
                    intercept_enabled: Some(true),
                    ..RuntimeSettingsUpdate::default()
                }),
            )
            .await,
        )
        .await;
        assert!(runtime.intercept_enabled);

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn implicit_runtime_update_rejects_active_session_change_after_lock_wait() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-runtime-active-race-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let original = state.session().await;
        let operation_lock = state.session_operation_lock(original.id()).await;
        let operation_guard = operation_lock.lock().await;

        let mut update_future = Box::pin(super::update_runtime_settings(
            State(state.clone()),
            Json(RuntimeSettingsUpdate {
                session_id: None,
                intercept_enabled: Some(true),
                ..RuntimeSettingsUpdate::default()
            }),
        ));

        let blocked = tokio::time::timeout(Duration::from_millis(30), &mut update_future).await;
        assert!(blocked.is_err());
        state
            .create_session(Some("new active".to_string()))
            .await
            .unwrap();
        drop(operation_guard);

        let response = update_future.await;
        assert_eq!(response.status(), super::StatusCode::CONFLICT);
        assert!(!original.runtime.snapshot().await.intercept_enabled);

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn oast_clear_waits_for_session_operation_lock() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-oast-clear-op-lock-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let callback_id = Uuid::new_v4();
        session
            .oast
            .push(OastCallback {
                id: callback_id,
                received_at: Utc::now(),
                protocol: "dns".to_string(),
                remote_addr: "127.0.0.1".to_string(),
                raw_data: "callback".to_string(),
                correlation_id: "correlation".to_string(),
            })
            .await;
        let operation_lock = state.session_operation_lock(session.id()).await;
        let operation_guard = operation_lock.lock().await;

        let blocked = tokio::time::timeout(
            Duration::from_millis(30),
            super::clear_oast_callbacks(
                State(state.clone()),
                Query(super::OastQuery {
                    session_id: Some(session.id()),
                    limit: None,
                }),
            ),
        )
        .await;
        assert!(blocked.is_err());
        assert!(session.oast.get(callback_id).await.is_some());

        drop(operation_guard);
        let response = super::clear_oast_callbacks(
            State(state.clone()),
            Query(super::OastQuery {
                session_id: Some(session.id()),
                limit: None,
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(session.oast.list(None).await.is_empty());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn runtime_event_oast_and_site_map_can_use_pinned_inactive_session() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-pinned-runtime-event-oast-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let active = state.session().await;
        let inactive_metadata = state
            .sessions
            .create_session(Some("Inactive".to_string()))
            .unwrap();
        let inactive = state.sessions.load_context(inactive_metadata.id).unwrap();

        active
            .event_log
            .push(EventLevel::Info, "active", "Active event", "active")
            .await;
        inactive
            .event_log
            .push(EventLevel::Info, "inactive", "Inactive event", "inactive")
            .await;
        let message = MessageRecord {
            headers: vec![HeaderRecord {
                name: "host".to_string(),
                value: "inactive.test".to_string(),
            }],
            body_preview: String::new(),
            body_encoding: BodyEncoding::Utf8,
            body_size: 0,
            decoded_body_size: None,
            preview_truncated: false,
            content_type: None,
            content_decoded: false,
        };
        inactive
            .store
            .insert(TransactionRecord::http(
                Utc::now(),
                "GET".to_string(),
                "https".to_string(),
                "inactive.test".to_string(),
                "/pinned".to_string(),
                Some(204),
                1,
                message.clone(),
                Some(message),
                Vec::new(),
                None,
                None,
            ))
            .await;
        let callback_id = Uuid::new_v4();
        inactive
            .oast
            .push(OastCallback {
                id: callback_id,
                received_at: Utc::now(),
                protocol: "dns".to_string(),
                remote_addr: "127.0.0.1".to_string(),
                raw_data: "inactive callback".to_string(),
                correlation_id: "inactive-correlation".to_string(),
            })
            .await;
        inactive.persist().await.unwrap();

        let runtime: RuntimeSettingsSnapshot = response_json(
            super::update_runtime_settings(
                State(state.clone()),
                Json(RuntimeSettingsUpdate {
                    session_id: Some(inactive.id()),
                    oast_enabled: Some(true),
                    oast_server_url: Some("https://inactive-oast.test".to_string()),
                    oast_provider: Some(OastProvider::Boast),
                    ..RuntimeSettingsUpdate::default()
                }),
            )
            .await,
        )
        .await;
        assert!(runtime.oast_enabled);
        assert_eq!(runtime.oast_provider, OastProvider::Boast);

        let active_proxy_owner = crate::proxy::remember_active_proxy_session_owner(inactive.id());

        let runtime_read: RuntimeSettingsSnapshot = response_json(
            super::get_runtime_settings(
                State(state.clone()),
                Query(super::RuntimeQuery {
                    session_id: Some(inactive.id()),
                }),
            )
            .await,
        )
        .await;
        assert_eq!(runtime_read.oast_provider, OastProvider::Boast);

        let workspace_read: WorkspaceStateSnapshot = response_json(
            super::get_workspace_state(
                State(state.clone()),
                Query(super::WorkspaceStateQuery {
                    session_id: Some(inactive.id()),
                }),
            )
            .await,
        )
        .await;
        assert_eq!(workspace_read.session_id, Some(inactive.id()));

        let inactive_events: Vec<crate::event_log::EventLogEntry> = response_json(
            super::list_event_log(
                State(state.clone()),
                Query(super::EventLogQuery {
                    session_id: Some(inactive.id()),
                    limit: Some(10),
                }),
            )
            .await,
        )
        .await;
        assert_eq!(inactive_events.len(), 2);
        assert!(inactive_events
            .iter()
            .any(|entry| entry.title == "Runtime settings updated"));
        assert!(inactive_events
            .iter()
            .any(|entry| entry.title == "Inactive event"));

        let site_map: Vec<crate::target::TargetHostNode> = response_json(
            get_target_site_map(
                State(state.clone()),
                Query(super::TargetSiteMapQuery {
                    session_id: Some(inactive.id()),
                }),
            )
            .await,
        )
        .await;
        assert_eq!(site_map.len(), 1);
        assert_eq!(site_map[0].host, "inactive.test");

        let callbacks: Vec<serde_json::Value> = response_json(
            super::list_oast_callbacks(
                State(state.clone()),
                Query(super::OastQuery {
                    session_id: Some(inactive.id()),
                    limit: None,
                }),
            )
            .await,
        )
        .await;
        assert_eq!(callbacks.len(), 1);
        let callback_id_text = callback_id.to_string();
        assert_eq!(callbacks[0]["id"].as_str(), Some(callback_id_text.as_str()));

        let callback: serde_json::Value = response_json(
            super::get_oast_callback(
                State(state.clone()),
                Path(callback_id_text.clone()),
                Query(super::OastQuery {
                    session_id: Some(inactive.id()),
                    limit: None,
                }),
            )
            .await,
        )
        .await;
        assert_eq!(callback["id"].as_str(), Some(callback_id_text.as_str()));

        let oast_status: serde_json::Value = response_json(
            super::oast_status(
                State(state.clone()),
                Query(super::OastQuery {
                    session_id: Some(inactive.id()),
                    limit: None,
                }),
            )
            .await,
        )
        .await;
        assert_eq!(oast_status["provider"], "boast");

        let payload_response = super::generate_oast_payload(
            State(state.clone()),
            Query(super::OastQuery {
                session_id: Some(inactive.id()),
                limit: None,
            }),
        )
        .await;
        assert_eq!(payload_response.status(), StatusCode::OK);

        let events_response = super::events(
            State(state.clone()),
            Query(super::EventsQuery {
                session_id: Some(inactive.id()),
            }),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(events_response.status(), StatusCode::OK);
        let mut events_body = events_response.into_body();
        let maybe_event =
            tokio::time::timeout(Duration::from_millis(150), events_body.frame()).await;
        if let Ok(Some(Ok(frame))) = maybe_event {
            if let Ok(bytes) = frame.into_data() {
                let text = String::from_utf8_lossy(&bytes);
                assert!(
                    !text.contains("session_changed"),
                    "explicit inactive session event stream must not emit session_changed: {text}"
                );
            }
        }

        let missing_events_response = super::events(
            State(state.clone()),
            Query(super::EventsQuery {
                session_id: Some(Uuid::new_v4()),
            }),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(missing_events_response.status(), StatusCode::NOT_FOUND);

        let blocked_clear_response = super::clear_event_log(
            State(state.clone()),
            Query(super::EventLogQuery {
                session_id: Some(inactive.id()),
                limit: None,
            }),
        )
        .await;
        assert_eq!(blocked_clear_response.status(), StatusCode::CONFLICT);

        drop(active_proxy_owner);

        let clear_response = super::clear_event_log(
            State(state.clone()),
            Query(super::EventLogQuery {
                session_id: Some(inactive.id()),
                limit: None,
            }),
        )
        .await;
        assert_eq!(clear_response.status(), StatusCode::NO_CONTENT);

        let inactive_events_after_clear: Vec<crate::event_log::EventLogEntry> = response_json(
            super::list_event_log(
                State(state.clone()),
                Query(super::EventLogQuery {
                    session_id: Some(inactive.id()),
                    limit: Some(10),
                }),
            )
            .await,
        )
        .await;
        assert!(inactive_events_after_clear.is_empty());
        assert_eq!(active.event_log.list(Some(10)).await.len(), 1);

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[tokio::test]
    async fn scanner_rules_and_match_replace_can_use_pinned_inactive_session() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-pinned-scanner-rules-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let active = state.session().await;
        let inactive_metadata = state
            .sessions
            .create_session(Some("Inactive".to_string()))
            .unwrap();
        let inactive = state.sessions.load_context(inactive_metadata.id).unwrap();
        let inactive_id = inactive.id();

        let active_finding = ScannerFinding {
            id: Uuid::new_v4(),
            record_id: Uuid::new_v4(),
            found_at: Utc::now(),
            severity: Severity::Info,
            category: "active".to_string(),
            title: "Active finding".to_string(),
            detail: String::new(),
            evidence: String::new(),
            host: "active.test".to_string(),
            path: "/".to_string(),
        };
        let inactive_finding = ScannerFinding {
            id: Uuid::new_v4(),
            record_id: Uuid::new_v4(),
            found_at: Utc::now(),
            severity: Severity::High,
            category: "inactive".to_string(),
            title: "Inactive finding".to_string(),
            detail: String::new(),
            evidence: String::new(),
            host: "inactive.test".to_string(),
            path: "/finding".to_string(),
        };
        active.scanner.replace_all(vec![active_finding]).await;
        inactive
            .scanner
            .replace_all(vec![inactive_finding.clone()])
            .await;
        inactive.persist().await.unwrap();

        let match_rule = MatchReplaceRule {
            id: Uuid::new_v4(),
            enabled: true,
            description: "inactive only".to_string(),
            scope: MatchReplaceScope::Request,
            target: MatchReplaceTarget::Path,
            search: "/old".to_string(),
            replace: "/new".to_string(),
            regex: false,
            case_sensitive: true,
        };
        let response = super::update_match_replace_rules(
            State(state.clone()),
            Query(super::SessionScopedQuery {
                session_id: Some(inactive_id),
            }),
            Json(MatchReplaceRulesPayload {
                rules: vec![match_rule.clone()],
            }),
        )
        .await;
        assert!(response.status().is_success());

        let intercept_rule = InterceptRule {
            id: Uuid::new_v4(),
            enabled: true,
            scope: InterceptScope::Both,
            host_pattern: "inactive.test".to_string(),
            path_pattern: "/api".to_string(),
            method_filter: vec!["GET".to_string()],
        };
        let response = super::upsert_intercept_rule(
            State(state.clone()),
            Query(super::SessionScopedQuery {
                session_id: Some(inactive_id),
            }),
            Json(intercept_rule.clone()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let mut scanner_config = inactive.scanner.get_config().await;
        scanner_config.enabled = false;
        let response = super::update_scanner_config(
            State(state.clone()),
            Query(super::SessionScopedQuery {
                session_id: Some(inactive_id),
            }),
            Json(scanner_config.clone()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let active_proxy_owner = crate::proxy::remember_active_proxy_session_owner(inactive_id);

        let inactive_config: ScannerConfig = response_json(
            super::get_scanner_config(
                State(state.clone()),
                Query(super::SessionScopedQuery {
                    session_id: Some(inactive_id),
                }),
            )
            .await,
        )
        .await;
        assert!(!inactive_config.enabled);

        let inactive_rules: Vec<MatchReplaceRule> = response_json(
            super::list_match_replace_rules(
                State(state.clone()),
                Query(super::SessionScopedQuery {
                    session_id: Some(inactive_id),
                }),
            )
            .await,
        )
        .await;
        assert_eq!(inactive_rules.len(), 1);
        assert_eq!(inactive_rules[0].id, match_rule.id);
        assert!(active.match_replace.snapshot().await.is_empty());

        let inactive_intercept_rules: Vec<InterceptRule> = response_json(
            super::list_intercept_rules(
                State(state.clone()),
                Query(super::SessionScopedQuery {
                    session_id: Some(inactive_id),
                }),
            )
            .await,
        )
        .await;
        assert_eq!(inactive_intercept_rules.len(), 1);
        assert_eq!(inactive_intercept_rules[0].id, intercept_rule.id);
        assert!(active.intercept_rules.list().await.is_empty());

        let inactive_findings: Vec<FindingSummary> = response_json(
            super::list_findings(
                State(state.clone()),
                Query(super::FindingsQuery {
                    session_id: Some(inactive_id),
                    limit: Some(10),
                }),
            )
            .await,
        )
        .await;
        assert_eq!(inactive_findings.len(), 1);
        assert_eq!(inactive_findings[0].id, inactive_finding.id);

        let inactive_findings_count = response_json::<serde_json::Value>(
            super::count_findings(
                State(state.clone()),
                Query(super::SessionScopedQuery {
                    session_id: Some(inactive_id),
                }),
            )
            .await,
        )
        .await;
        assert_eq!(inactive_findings_count["count"], 1);

        let finding: ScannerFinding = response_json(
            super::get_finding(
                State(state.clone()),
                Path(inactive_finding.id.to_string()),
                Query(super::SessionScopedQuery {
                    session_id: Some(inactive_id),
                }),
            )
            .await,
        )
        .await;
        assert_eq!(finding.id, inactive_finding.id);

        drop(active_proxy_owner);

        let reloaded = state.sessions.load_context(inactive_id).unwrap();
        assert!(!reloaded.scanner.get_config().await.enabled);
        assert!(active.scanner.get_config().await.enabled);

        let response = super::clear_findings(
            State(state.clone()),
            Query(super::SessionScopedQuery {
                session_id: Some(inactive_id),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let reloaded_after_clear = state.sessions.load_context(inactive_id).unwrap();
        assert!(reloaded_after_clear.scanner.list(Some(10)).await.is_empty());
        assert_eq!(active.scanner.list(Some(10)).await.len(), 1);

        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[tokio::test]
    async fn annotation_update_persists_via_journal_without_registry_metadata_rewrite() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-annotation-registry-bypass-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let message = MessageRecord {
            headers: vec![HeaderRecord {
                name: "host".to_string(),
                value: "example.test".to_string(),
            }],
            body_preview: String::new(),
            body_encoding: BodyEncoding::Utf8,
            body_size: 0,
            decoded_body_size: None,
            preview_truncated: false,
            content_type: None,
            content_decoded: false,
        };
        let record = TransactionRecord::http(
            Utc::now(),
            "GET".to_string(),
            "https".to_string(),
            "example.test".to_string(),
            "/annotate".to_string(),
            Some(200),
            1,
            message.clone(),
            Some(message),
            Vec::new(),
            None,
            None,
        );
        let id = record.id;
        session.store.insert(record).await;

        let storage_dir = session.storage_dir().to_path_buf();
        let registry_path = storage_dir
            .parent()
            .expect("session dir should have registry parent")
            .join("registry.json");
        std::fs::remove_file(&registry_path).unwrap();
        std::fs::create_dir(&registry_path).unwrap();

        let response = super::update_transaction_annotations(
            State(state.clone()),
            Path(id.to_string()),
            Query(super::TransactionGetQuery { session_id: None }),
            Json(super::AnnotationsPayload {
                color_tag: Some(Some("blue".to_string())),
                user_note: Some(Some("durable snapshot".to_string())),
            }),
        )
        .await;

        assert_eq!(response.status(), super::StatusCode::OK);
        let live = session.store.get(id).await.unwrap();
        assert_eq!(live.color_tag.as_deref(), Some("blue"));
        assert_eq!(live.user_note.as_deref(), Some("durable snapshot"));

        let reloaded = state.sessions.load_context(session.id()).unwrap();
        let durable = reloaded.store.get(id).await.unwrap();
        assert_eq!(durable.color_tag.as_deref(), Some("blue"));
        assert_eq!(durable.user_note.as_deref(), Some("durable snapshot"));

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn workspace_update_persists_without_registry_metadata_rewrite() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-workspace-registry-bypass-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let mut snapshot = session.workspace.snapshot().await;
        snapshot.session_id = Some(session.id());
        snapshot.client_id = Some("test-ui".to_string());
        snapshot.client_version = 1;
        snapshot.replay = ReplayWorkspaceState {
            active_tab_id: Some("committed-workspace-tab".to_string()),
            tabs: vec![ReplayTabState {
                id: "committed-workspace-tab".to_string(),
                sequence: 1,
                ..ReplayTabState::default()
            }],
            ..ReplayWorkspaceState::default()
        };

        let registry_path = session
            .storage_dir()
            .parent()
            .expect("session dir should have registry parent")
            .join("registry.json");
        std::fs::remove_file(&registry_path).unwrap();
        std::fs::create_dir(&registry_path).unwrap();

        let response = super::update_workspace_state(State(state.clone()), Json(snapshot)).await;

        assert_eq!(response.status(), super::StatusCode::OK);
        let live = session.workspace.snapshot().await;
        assert_eq!(
            live.replay.active_tab_id.as_deref(),
            Some("committed-workspace-tab")
        );

        let reloaded = state.sessions.load_context(session.id()).unwrap();
        let durable = reloaded.workspace.snapshot().await;
        assert_eq!(
            durable.replay.active_tab_id.as_deref(),
            Some("committed-workspace-tab")
        );

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn workspace_update_rejects_snapshot_for_unknown_session() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-workspace-session-guard-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let active_session = state.session().await;

        let mut snapshot = WorkspaceStateSnapshot {
            session_id: Some(Uuid::new_v4()),
            client_id: Some("test-ui".to_string()),
            client_version: 1,
            ..WorkspaceStateSnapshot::default()
        };
        snapshot.replay.active_tab_id = Some("unknown-session-tab".to_string());

        let response = super::update_workspace_state(State(state.clone()), Json(snapshot)).await;

        assert_eq!(response.status(), super::StatusCode::CONFLICT);
        let active = active_session.workspace.snapshot().await;
        assert!(active.replay.active_tab_id.is_none());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn workspace_update_rejects_snapshot_without_session_id() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-workspace-missing-session-guard-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let active_session = state.session().await;

        let mut snapshot = WorkspaceStateSnapshot {
            client_id: Some("legacy-ui".to_string()),
            client_version: 1,
            ..WorkspaceStateSnapshot::default()
        };
        snapshot.replay.active_tab_id = Some("legacy-tab".to_string());
        snapshot.replay.tabs.push(ReplayTabState {
            id: "legacy-tab".to_string(),
            sequence: 1,
            ..ReplayTabState::default()
        });

        let response = super::update_workspace_state(State(state.clone()), Json(snapshot)).await;

        assert_eq!(response.status(), super::StatusCode::CONFLICT);
        let active = active_session.workspace.snapshot().await;
        assert!(active.replay.active_tab_id.is_none());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn workspace_update_migrates_legacy_fuzzer_attack_record_to_id_only() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-workspace-fuzzer-id-only-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let attack = FuzzerAttackRecord {
            id: Uuid::new_v4(),
            started_at: Utc::now(),
            completed_at: Utc::now(),
            status: FuzzerAttackStatus::Completed,
            template: EditableRequest {
                scheme: "https".to_string(),
                host: "fuzzer.example".to_string(),
                method: "GET".to_string(),
                path: "/".to_string(),
                headers: Vec::new(),
                body: String::new(),
                body_encoding: BodyEncoding::Utf8,
                preview_truncated: false,
            },
            payload_count: 1,
            marker_count: 0,
            results: Vec::new(),
            notes: Vec::new(),
        };
        let attack_id = attack.id;
        let snapshot = WorkspaceStateSnapshot {
            session_id: Some(session.id()),
            client_id: Some("test-ui".to_string()),
            client_version: 1,
            fuzzer: FuzzerWorkspaceState {
                attack_record: Some(attack),
                ..FuzzerWorkspaceState::default()
            },
            ..WorkspaceStateSnapshot::default()
        };

        let response = super::update_workspace_state(State(state.clone()), Json(snapshot)).await;

        assert_eq!(response.status(), super::StatusCode::OK);
        let saved: WorkspaceStateSnapshot = response_json(response).await;
        assert_eq!(saved.fuzzer.attack_record_id, Some(attack_id));
        assert!(saved.fuzzer.attack_record.is_none());
        let durable = session.workspace.snapshot().await;
        assert_eq!(durable.fuzzer.attack_record_id, Some(attack_id));
        assert!(durable.fuzzer.attack_record.is_none());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn workspace_update_saves_snapshot_for_inactive_session_id() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-workspace-inactive-save-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let inactive = state.session().await;
        state
            .create_session(Some("new active".to_string()))
            .await
            .unwrap();

        let mut snapshot = WorkspaceStateSnapshot {
            session_id: Some(inactive.id()),
            client_id: Some("test-ui".to_string()),
            client_version: 1,
            ..WorkspaceStateSnapshot::default()
        };
        snapshot.replay.active_tab_id = Some("inactive-tab".to_string());
        snapshot.replay.tabs.push(ReplayTabState {
            id: "inactive-tab".to_string(),
            sequence: 1,
            ..ReplayTabState::default()
        });

        let response = super::update_workspace_state(State(state.clone()), Json(snapshot)).await;

        assert_eq!(response.status(), super::StatusCode::OK);
        let active = state.session().await;
        assert!(active
            .workspace
            .snapshot()
            .await
            .replay
            .active_tab_id
            .is_none());
        let reloaded = state.sessions.load_context(inactive.id()).unwrap();
        assert_eq!(
            reloaded
                .workspace
                .snapshot()
                .await
                .replay
                .active_tab_id
                .as_deref(),
            Some("inactive-tab")
        );

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn workspace_update_rejects_inactive_session_with_pending_active_proxy_work() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-workspace-active-proxy-guard-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let inactive = state.session().await;
        state
            .create_session(Some("new active".to_string()))
            .await
            .unwrap();

        let pending_generation = crate::proxy::remember_pending_persist_context_for_test(&inactive);
        let active_proxy_owner = crate::proxy::remember_active_proxy_session_owner(inactive.id());

        let read_response = super::get_workspace_state(
            State(state.clone()),
            Query(super::WorkspaceStateQuery {
                session_id: Some(inactive.id()),
            }),
        )
        .await;
        assert_eq!(read_response.status(), super::StatusCode::OK);

        let mut snapshot = WorkspaceStateSnapshot {
            session_id: Some(inactive.id()),
            client_id: Some("test-ui".to_string()),
            client_version: 1,
            ..WorkspaceStateSnapshot::default()
        };
        snapshot.replay.active_tab_id = Some("blocked-inactive-tab".to_string());
        snapshot.replay.tabs.push(ReplayTabState {
            id: "blocked-inactive-tab".to_string(),
            sequence: 1,
            ..ReplayTabState::default()
        });

        let response = super::update_workspace_state(State(state.clone()), Json(snapshot)).await;

        assert_eq!(response.status(), super::StatusCode::CONFLICT);
        assert!(inactive
            .workspace
            .snapshot()
            .await
            .replay
            .active_tab_id
            .is_none());

        drop(active_proxy_owner);
        assert!(crate::proxy::forget_pending_persist_context_for_test(
            inactive.id(),
            pending_generation
        ));

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn replay_send_rejects_payload_for_wrong_session_before_sending() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-replay-send-session-guard-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;

        let response = super::send_replay(
            State(state.clone()),
            Json(super::ReplaySendPayload {
                session_id: Some(Uuid::new_v4()),
                request: EditableRequest {
                    scheme: "https".to_string(),
                    host: "example.test".to_string(),
                    method: "GET".to_string(),
                    path: "/".to_string(),
                    headers: Vec::new(),
                    body: String::new(),
                    body_encoding: BodyEncoding::Utf8,
                    preview_truncated: false,
                },
                target: None,
                source_transaction_id: None,
                http_version: None,
            }),
        )
        .await;

        assert_eq!(response.status(), super::StatusCode::CONFLICT);
        assert!(session.store.snapshot(Some(10)).await.is_empty());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn replay_send_rejects_missing_session_before_sending() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-replay-send-missing-session-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;

        let response = super::send_replay(
            State(state.clone()),
            Json(super::ReplaySendPayload {
                session_id: None,
                request: EditableRequest {
                    scheme: "https".to_string(),
                    host: "example.test".to_string(),
                    method: "GET".to_string(),
                    path: "/".to_string(),
                    headers: Vec::new(),
                    body: String::new(),
                    body_encoding: BodyEncoding::Utf8,
                    preview_truncated: false,
                },
                target: None,
                source_transaction_id: None,
                http_version: None,
            }),
        )
        .await;

        assert_eq!(response.status(), super::StatusCode::CONFLICT);
        assert!(session.store.snapshot(Some(10)).await.is_empty());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn replay_send_validation_errors_use_json_error_body() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-replay-send-json-error-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;

        let response = super::send_replay(
            State(state.clone()),
            Json(super::ReplaySendPayload {
                session_id: Some(session.id()),
                request: EditableRequest {
                    scheme: "https".to_string(),
                    host: "example.test".to_string(),
                    method: "GET".to_string(),
                    path: "/".to_string(),
                    headers: Vec::new(),
                    body: String::new(),
                    body_encoding: BodyEncoding::Utf8,
                    preview_truncated: false,
                },
                target: None,
                source_transaction_id: None,
                http_version: Some("HTTP/3".to_string()),
            }),
        )
        .await;

        assert_eq!(response.status(), super::StatusCode::BAD_REQUEST);
        let body = response_body_json(response).await;
        assert_eq!(body.get("record"), Some(&serde_json::Value::Null));
        assert!(body
            .get("error")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .contains("unsupported replay http_version"));
        assert!(session.store.snapshot(Some(10)).await.is_empty());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn replay_send_releases_session_operation_lock_while_upstream_is_pending() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-replay-send-lock-release-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let session_id = session.id();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0u8; 1024];
            let _ = stream.read(&mut buffer).await.unwrap();
            let _ = accepted_tx.send(());
            let _ = release_rx.await;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
        });

        let response_task = tokio::spawn(super::send_replay(
            State(state.clone()),
            Json(super::ReplaySendPayload {
                session_id: Some(session_id),
                request: EditableRequest {
                    scheme: "http".to_string(),
                    host: addr.to_string(),
                    method: "GET".to_string(),
                    path: "/".to_string(),
                    headers: Vec::new(),
                    body: String::new(),
                    body_encoding: BodyEncoding::Utf8,
                    preview_truncated: false,
                },
                target: None,
                source_transaction_id: None,
                http_version: None,
            }),
        ));

        tokio::time::timeout(Duration::from_secs(2), accepted_rx)
            .await
            .expect("replay should reach the upstream server")
            .expect("upstream accept marker should be sent");
        assert!(crate::proxy::session_has_active_proxy_work(session_id));

        let operation_lock = state.session_operation_lock(session_id).await;
        let operation_guard =
            tokio::time::timeout(Duration::from_millis(200), operation_lock.lock())
                .await
                .expect(
                    "replay must not hold the session operation lock while waiting on upstream",
                );
        drop(operation_guard);

        let _ = release_tx.send(());
        let response = response_task.await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn replay_send_rejects_wrong_session_before_validating_payload() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-replay-invalid-session-guard-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());

        let response = super::send_replay(
            State(state),
            Json(super::ReplaySendPayload {
                session_id: Some(Uuid::new_v4()),
                request: EditableRequest {
                    scheme: "ftp".to_string(),
                    host: String::new(),
                    method: "CONNECT".to_string(),
                    path: String::new(),
                    headers: Vec::new(),
                    body: String::new(),
                    body_encoding: BodyEncoding::Utf8,
                    preview_truncated: false,
                },
                target: None,
                source_transaction_id: None,
                http_version: Some("HTTP/3".to_string()),
            }),
        )
        .await;

        assert_eq!(response.status(), super::StatusCode::CONFLICT);

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn fuzzer_run_rejects_payload_for_wrong_session_before_attack() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-fuzzer-session-guard-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;

        let response = super::run_fuzzer_attack(
            State(state.clone()),
            Json(crate::fuzzer::FuzzerAttackPayload {
                session_id: Some(Uuid::new_v4()),
                template: EditableRequest {
                    scheme: "https".to_string(),
                    host: "example.test".to_string(),
                    method: "GET".to_string(),
                    path: "/$payload$".to_string(),
                    headers: Vec::new(),
                    body: String::new(),
                    body_encoding: BodyEncoding::Utf8,
                    preview_truncated: false,
                },
                payloads: vec!["one".to_string()],
                source_transaction_id: None,
                http_version: None,
                target: None,
            }),
        )
        .await;

        assert_eq!(response.status(), super::StatusCode::CONFLICT);
        assert!(session.fuzzer.list(Some(10)).await.is_empty());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn fuzzer_run_rejects_missing_session_before_attack() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-fuzzer-missing-session-guard-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;

        let response = super::run_fuzzer_attack(
            State(state.clone()),
            Json(crate::fuzzer::FuzzerAttackPayload {
                session_id: None,
                template: EditableRequest {
                    scheme: "https".to_string(),
                    host: "example.test".to_string(),
                    method: "GET".to_string(),
                    path: "/$payload$".to_string(),
                    headers: Vec::new(),
                    body: String::new(),
                    body_encoding: BodyEncoding::Utf8,
                    preview_truncated: false,
                },
                payloads: vec!["one".to_string()],
                source_transaction_id: None,
                http_version: None,
                target: None,
            }),
        )
        .await;

        assert_eq!(response.status(), super::StatusCode::CONFLICT);
        assert!(session.fuzzer.list(Some(10)).await.is_empty());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn fuzzer_run_rejects_wrong_session_before_validating_payload() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-fuzzer-invalid-session-guard-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());

        let response = super::run_fuzzer_attack(
            State(state),
            Json(crate::fuzzer::FuzzerAttackPayload {
                session_id: Some(Uuid::new_v4()),
                template: EditableRequest {
                    scheme: "ftp".to_string(),
                    host: String::new(),
                    method: "CONNECT".to_string(),
                    path: String::new(),
                    headers: Vec::new(),
                    body: String::new(),
                    body_encoding: BodyEncoding::Utf8,
                    preview_truncated: false,
                },
                payloads: Vec::new(),
                source_transaction_id: None,
                http_version: Some("HTTP/3".to_string()),
                target: None,
            }),
        )
        .await;

        assert_eq!(response.status(), super::StatusCode::CONFLICT);

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn fuzzer_run_rejects_payload_expansion_that_invalidates_request() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-fuzzer-expanded-request-validation-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;

        let response = super::run_fuzzer_attack(
            State(state.clone()),
            Json(crate::fuzzer::FuzzerAttackPayload {
                session_id: Some(session.id()),
                template: EditableRequest {
                    scheme: "https".to_string(),
                    host: "example.test".to_string(),
                    method: "POST".to_string(),
                    path: "/".to_string(),
                    headers: vec![HeaderRecord {
                        name: "Content-Length".to_string(),
                        value: "9".to_string(),
                    }],
                    body: "$payload$".to_string(),
                    body_encoding: BodyEncoding::Utf8,
                    preview_truncated: false,
                },
                payloads: vec!["abc".to_string()],
                source_transaction_id: None,
                http_version: None,
                target: None,
            }),
        )
        .await;

        assert_eq!(response.status(), super::StatusCode::BAD_REQUEST);
        assert!(session.fuzzer.list(Some(10)).await.is_empty());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[test]
    fn session_operation_conflicts_include_proxy_lifecycle_guards() {
        let response = super::session_operation_error_response(anyhow::anyhow!(
            "cannot delete a session while proxy activity is still running"
        ));
        assert_eq!(response.status(), super::StatusCode::CONFLICT);

        let response = super::session_operation_error_response(anyhow::anyhow!(
            "cannot delete a session while capture persistence is pending"
        ));
        assert_eq!(response.status(), super::StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn ws_replay_disconnect_returns_not_found_for_unknown_connection() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-ws-replay-disconnect-missing-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;

        let response = super::ws_replay_disconnect(
            State(state),
            Json(super::WsReplayDisconnectPayload {
                session_id: Some(session.id()),
                id: Uuid::new_v4(),
                remove: false,
            }),
        )
        .await;

        assert_eq!(response.status(), super::StatusCode::NOT_FOUND);
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn ws_replay_remove_is_idempotent_for_unknown_connection() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-ws-replay-remove-missing-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;

        let response = super::ws_replay_disconnect(
            State(state),
            Json(super::WsReplayDisconnectPayload {
                session_id: Some(session.id()),
                id: Uuid::new_v4(),
                remove: true,
            }),
        )
        .await;

        assert_eq!(response.status(), super::StatusCode::OK);
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn ws_replay_remove_rejects_unknown_session() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-ws-replay-remove-unknown-session-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());

        let response = super::ws_replay_disconnect(
            State(state),
            Json(super::WsReplayDisconnectPayload {
                session_id: Some(Uuid::new_v4()),
                id: Uuid::new_v4(),
                remove: true,
            }),
        )
        .await;

        assert_eq!(response.status(), super::StatusCode::NOT_FOUND);
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn transaction_read_paths_can_use_pinned_inactive_session() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-transaction-pinned-session-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let original = state.session().await;
        let original_id = original.id();
        let message = MessageRecord {
            headers: vec![HeaderRecord {
                name: "host".to_string(),
                value: "inactive.example".to_string(),
            }],
            body_preview: String::new(),
            body_encoding: BodyEncoding::Utf8,
            body_size: 0,
            decoded_body_size: None,
            preview_truncated: false,
            content_type: None,
            content_decoded: false,
        };
        let record = TransactionRecord::http(
            Utc::now(),
            "GET".to_string(),
            "https".to_string(),
            "inactive.example".to_string(),
            "/pinned".to_string(),
            Some(200),
            1,
            message.clone(),
            Some(message),
            Vec::new(),
            None,
            None,
        );
        let record_id = record.id;
        original.store.insert(record).await;
        state.persist_session_context(&original).await.unwrap();
        state
            .create_session(Some("new active".to_string()))
            .await
            .unwrap();

        let active_response = super::get_transaction(
            State(state.clone()),
            Path(record_id.to_string()),
            Query(super::TransactionGetQuery { session_id: None }),
        )
        .await;
        assert_eq!(active_response.status(), super::StatusCode::NOT_FOUND);

        let active_list_response = super::list_transactions(
            State(state.clone()),
            Query(super::TransactionQuery::default()),
        )
        .await;
        let active_list: Vec<crate::model::TransactionSummary> =
            response_json(active_list_response).await;
        assert!(active_list.is_empty());

        {
            let _active_proxy_owner =
                crate::proxy::remember_active_proxy_session_owner(original_id);

            let pinned_response = super::get_transaction(
                State(state.clone()),
                Path(record_id.to_string()),
                Query(super::TransactionGetQuery {
                    session_id: Some(original_id),
                }),
            )
            .await;
            assert_eq!(pinned_response.status(), super::StatusCode::OK);

            let pinned_list_response = super::list_transactions(
                State(state.clone()),
                Query(super::TransactionQuery {
                    session_id: Some(original_id),
                    ..super::TransactionQuery::default()
                }),
            )
            .await;
            let pinned_list: Vec<crate::model::TransactionSummary> =
                response_json(pinned_list_response).await;
            assert_eq!(pinned_list.len(), 1);
            assert_eq!(pinned_list[0].id, record_id);

            let pinned_page_response = super::list_transactions_page(
                State(state.clone()),
                Query(super::TransactionQuery {
                    session_id: Some(original_id),
                    ..super::TransactionQuery::default()
                }),
            )
            .await;
            let pinned_page: super::TransactionPageResponse =
                response_json(pinned_page_response).await;
            assert_eq!(pinned_page.items.len(), 1);
            assert_eq!(pinned_page.items[0].id, record_id);
        }

        let active_annotation_response = super::update_transaction_annotations(
            State(state.clone()),
            Path(record_id.to_string()),
            Query(super::TransactionGetQuery { session_id: None }),
            Json(super::AnnotationsPayload {
                color_tag: Some(Some("red".to_string())),
                user_note: None,
            }),
        )
        .await;
        assert_eq!(
            active_annotation_response.status(),
            super::StatusCode::NOT_FOUND
        );

        let pinned_annotation_response = super::update_transaction_annotations(
            State(state.clone()),
            Path(record_id.to_string()),
            Query(super::TransactionGetQuery {
                session_id: Some(original_id),
            }),
            Json(super::AnnotationsPayload {
                color_tag: Some(Some("blue".to_string())),
                user_note: Some(Some("inactive note".to_string())),
            }),
        )
        .await;
        assert_eq!(pinned_annotation_response.status(), super::StatusCode::OK);
        let annotated_session = state.sessions.load_context(original_id).unwrap();
        let annotated = annotated_session.store.get(record_id).await.unwrap();
        assert_eq!(annotated.color_tag.as_deref(), Some("blue"));
        assert_eq!(annotated.user_note.as_deref(), Some("inactive note"));

        let pinned_page_response = super::list_transactions_page(
            State(state.clone()),
            Query(super::TransactionQuery {
                session_id: Some(original_id),
                ..super::TransactionQuery::default()
            }),
        )
        .await;
        let pinned_page: super::TransactionPageResponse = response_json(pinned_page_response).await;
        assert_eq!(pinned_page.items.len(), 1);
        assert_eq!(pinned_page.items[0].id, record_id);

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn fuzzer_and_websocket_read_paths_can_use_pinned_inactive_session() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-fuzzer-websocket-pinned-session-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let original = state.session().await;
        let original_id = original.id();
        let template = EditableRequest {
            scheme: "https".to_string(),
            host: "inactive.example".to_string(),
            method: "GET".to_string(),
            path: "/fuzz".to_string(),
            headers: Vec::new(),
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        };
        let attack = FuzzerAttackRecord {
            id: Uuid::new_v4(),
            started_at: Utc::now(),
            completed_at: Utc::now(),
            status: FuzzerAttackStatus::Completed,
            template,
            payload_count: 1,
            marker_count: 0,
            results: Vec::new(),
            notes: vec!["inactive attack".to_string()],
        };
        let attack_id = attack.id;
        original.fuzzer.insert(attack).await;
        let message = MessageRecord {
            headers: vec![HeaderRecord {
                name: "host".to_string(),
                value: "inactive.example".to_string(),
            }],
            body_preview: String::new(),
            body_encoding: BodyEncoding::Utf8,
            body_size: 0,
            decoded_body_size: None,
            preview_truncated: false,
            content_type: None,
            content_decoded: false,
        };
        let websocket = WebSocketSessionRecord {
            id: Uuid::new_v4(),
            started_at: Utc::now(),
            closed_at: Some(Utc::now()),
            duration_ms: Some(1),
            scheme: "wss".to_string(),
            host: "inactive.example".to_string(),
            path: "/socket".to_string(),
            status: Some(101),
            request: message.clone(),
            response: Some(message),
            frames: Vec::new(),
            notes: vec!["inactive websocket".to_string()],
        };
        let websocket_id = websocket.id;
        original.websockets.open(websocket).await;
        state.persist_session_context(&original).await.unwrap();
        state
            .create_session(Some("new active".to_string()))
            .await
            .unwrap();

        let active_fuzzer_response = super::get_fuzzer_attack(
            State(state.clone()),
            Path(attack_id.to_string()),
            Query(super::FuzzerQuery {
                session_id: None,
                limit: None,
            }),
        )
        .await;
        assert_eq!(
            active_fuzzer_response.status(),
            super::StatusCode::NOT_FOUND
        );
        let active_proxy_owner = crate::proxy::remember_active_proxy_session_owner(original_id);

        let pinned_fuzzer_response = super::get_fuzzer_attack(
            State(state.clone()),
            Path(attack_id.to_string()),
            Query(super::FuzzerQuery {
                session_id: Some(original_id),
                limit: None,
            }),
        )
        .await;
        assert_eq!(pinned_fuzzer_response.status(), super::StatusCode::OK);
        let pinned_fuzzer_list = super::list_fuzzer_attacks(
            State(state.clone()),
            Query(super::FuzzerQuery {
                session_id: Some(original_id),
                limit: None,
            }),
        )
        .await;
        let pinned_fuzzer_summaries: Vec<crate::fuzzer::FuzzerAttackSummary> =
            response_json(pinned_fuzzer_list).await;
        assert_eq!(pinned_fuzzer_summaries.len(), 1);
        assert_eq!(pinned_fuzzer_summaries[0].id, attack_id);

        let active_websocket_response = super::get_websocket(
            State(state.clone()),
            Path(websocket_id.to_string()),
            Query(super::WebSocketQuery {
                session_id: None,
                limit: None,
                offset: None,
                frame_limit: None,
            }),
        )
        .await;
        assert_eq!(
            active_websocket_response.status(),
            super::StatusCode::NOT_FOUND
        );
        let pinned_websocket_response = super::get_websocket(
            State(state.clone()),
            Path(websocket_id.to_string()),
            Query(super::WebSocketQuery {
                session_id: Some(original_id),
                limit: None,
                offset: None,
                frame_limit: None,
            }),
        )
        .await;
        assert_eq!(pinned_websocket_response.status(), super::StatusCode::OK);
        let pinned_websocket_list = super::list_websockets_page(
            State(state),
            Query(super::WebSocketQuery {
                session_id: Some(original_id),
                limit: None,
                offset: None,
                frame_limit: None,
            }),
        )
        .await;
        let pinned_websocket_page: super::WebSocketPageResponse =
            response_json(pinned_websocket_list).await;
        assert_eq!(pinned_websocket_page.items.len(), 1);
        assert_eq!(pinned_websocket_page.items[0].id, websocket_id);
        drop(active_proxy_owner);

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn websocket_detail_frame_limit_returns_tail_frames_without_changing_summary_count() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-websocket-frame-limit-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let websocket = WebSocketSessionRecord {
            id: Uuid::new_v4(),
            started_at: Utc::now(),
            closed_at: Some(Utc::now()),
            duration_ms: Some(1),
            scheme: "wss".to_string(),
            host: "example.test".to_string(),
            path: "/socket".to_string(),
            status: Some(101),
            request: MessageRecord::from_headers_and_body(&HeaderMap::new(), &[], 1024),
            response: None,
            frames: (1..=1002)
                .map(|index| WebSocketFrameRecord {
                    index,
                    captured_at: Utc::now(),
                    direction: WebSocketFrameDirection::ServerToClient,
                    kind: WebSocketFrameKind::Text,
                    body_preview: format!("frame-{index}"),
                    body_encoding: BodyEncoding::Utf8,
                    body_size: 0,
                    preview_truncated: false,
                })
                .collect(),
            notes: Vec::new(),
        };
        let websocket_id = websocket.id;
        session.websockets.open(websocket).await;

        let detail_response = super::get_websocket(
            State(state.clone()),
            Path(websocket_id.to_string()),
            Query(super::WebSocketQuery {
                session_id: Some(session.id()),
                limit: None,
                offset: None,
                frame_limit: Some(2),
            }),
        )
        .await;
        assert_eq!(detail_response.status(), super::StatusCode::OK);
        let detail: WebSocketSessionRecord = response_json(detail_response).await;
        assert_eq!(
            detail
                .frames
                .iter()
                .map(|frame| frame.index)
                .collect::<Vec<_>>(),
            vec![1001, 1002]
        );

        let empty_detail_response = super::get_websocket(
            State(state.clone()),
            Path(websocket_id.to_string()),
            Query(super::WebSocketQuery {
                session_id: Some(session.id()),
                limit: None,
                offset: None,
                frame_limit: Some(0),
            }),
        )
        .await;
        assert_eq!(empty_detail_response.status(), super::StatusCode::OK);
        let empty_detail: WebSocketSessionRecord = response_json(empty_detail_response).await;
        assert!(empty_detail.frames.is_empty());

        let default_detail_response = super::get_websocket(
            State(state.clone()),
            Path(websocket_id.to_string()),
            Query(super::WebSocketQuery {
                session_id: Some(session.id()),
                limit: None,
                offset: None,
                frame_limit: None,
            }),
        )
        .await;
        assert_eq!(default_detail_response.status(), super::StatusCode::OK);
        let default_detail: WebSocketSessionRecord = response_json(default_detail_response).await;
        assert_eq!(default_detail.frames.len(), 1000);
        assert_eq!(default_detail.frames[0].index, 3);
        assert_eq!(default_detail.frames[999].index, 1002);

        let oversized_detail_response = super::get_websocket(
            State(state.clone()),
            Path(websocket_id.to_string()),
            Query(super::WebSocketQuery {
                session_id: Some(session.id()),
                limit: None,
                offset: None,
                frame_limit: Some(50_000),
            }),
        )
        .await;
        assert_eq!(oversized_detail_response.status(), super::StatusCode::OK);
        let oversized_detail: WebSocketSessionRecord =
            response_json(oversized_detail_response).await;
        assert_eq!(oversized_detail.frames.len(), 1000);
        assert_eq!(oversized_detail.frames[0].index, 3);

        let legacy_list_response = super::list_websockets(
            State(state.clone()),
            Query(super::WebSocketQuery {
                session_id: Some(session.id()),
                limit: Some(10),
                offset: None,
                frame_limit: None,
            }),
        )
        .await;
        let legacy_list: Vec<WebSocketSessionSummary> = response_json(legacy_list_response).await;
        assert_eq!(legacy_list[0].frame_count, 1002);
        assert_eq!(legacy_list[0].last_frame_index, Some(1002));

        let list_response = super::list_websockets_page(
            State(state),
            Query(super::WebSocketQuery {
                session_id: Some(session.id()),
                limit: Some(10),
                offset: None,
                frame_limit: None,
            }),
        )
        .await;
        let page: super::WebSocketPageResponse = response_json(list_response).await;
        assert_eq!(page.items[0].frame_count, 1002);
        assert_eq!(page.items[0].last_frame_index, Some(1002));

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn websocket_events_stream_emits_summary_update() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-websocket-events-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let events_response = super::events(
            State(state),
            Query(super::EventsQuery {
                session_id: Some(session.id()),
            }),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(events_response.status(), super::StatusCode::OK);
        let mut events_body = events_response.into_body();

        let websocket = WebSocketSessionRecord {
            id: Uuid::new_v4(),
            started_at: Utc::now(),
            closed_at: None,
            duration_ms: None,
            scheme: "wss".to_string(),
            host: "events.example".to_string(),
            path: "/socket".to_string(),
            status: Some(101),
            request: MessageRecord::from_headers_and_body(&HeaderMap::new(), &[], 1024),
            response: None,
            frames: Vec::new(),
            notes: Vec::new(),
        };
        let websocket_id = websocket.id;
        session.websockets.open(websocket).await;

        let mut text = String::new();
        for _ in 0..8 {
            let frame = tokio::time::timeout(Duration::from_secs(1), events_body.frame())
                .await
                .expect("websocket event stream should yield a frame")
                .expect("websocket event stream should remain open")
                .expect("websocket event frame should be ok");
            if let Ok(bytes) = frame.into_data() {
                text.push_str(&String::from_utf8_lossy(&bytes));
            }
            if text.contains("event: websocket") && text.contains(&websocket_id.to_string()) {
                break;
            }
        }

        assert!(
            text.contains("event: websocket"),
            "event stream should include websocket summary event: {text}"
        );
        assert!(
            text.contains(&websocket_id.to_string()),
            "websocket event should include summary id {websocket_id}: {text}"
        );

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn pinned_transaction_read_reports_corrupt_registered_session_as_server_error() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-corrupt-pinned-session-read-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let original_id = state
            .sessions
            .create_session(Some("corrupt inactive".to_string()))
            .unwrap()
            .id;

        let storage_dir = state.sessions.session_storage_path(original_id).unwrap();
        std::fs::remove_dir_all(&storage_dir).unwrap();
        std::fs::write(&storage_dir, b"not a directory").unwrap();

        let response = super::get_transaction(
            State(state.clone()),
            Path(uuid::Uuid::new_v4().to_string()),
            Query(super::TransactionGetQuery {
                session_id: Some(original_id),
            }),
        )
        .await;
        assert_eq!(response.status(), super::StatusCode::INTERNAL_SERVER_ERROR);

        let _ = std::fs::remove_file(storage_dir);
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn workspace_update_reports_corrupt_registered_session_as_server_error() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-corrupt-pinned-workspace-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let original_id = state
            .sessions
            .create_session(Some("corrupt inactive".to_string()))
            .unwrap()
            .id;

        let storage_dir = state.sessions.session_storage_path(original_id).unwrap();
        std::fs::remove_dir_all(&storage_dir).unwrap();
        std::fs::write(&storage_dir, b"not a directory").unwrap();

        let response = super::update_workspace_state(
            State(state.clone()),
            Json(WorkspaceStateSnapshot {
                session_id: Some(original_id),
                ..WorkspaceStateSnapshot::default()
            }),
        )
        .await;
        assert_eq!(response.status(), super::StatusCode::INTERNAL_SERVER_ERROR);

        let _ = std::fs::remove_file(storage_dir);
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn workspace_update_returns_conflict_before_validating_stale_payload() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-workspace-stale-invalid-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let mut current = WorkspaceStateSnapshot::default();
        current.replay.active_tab_id = Some("current".to_string());
        current.replay.tabs.push(ReplayTabState {
            id: "current".to_string(),
            sequence: 1,
            ..ReplayTabState::default()
        });
        let current = session.workspace.replace_snapshot(current).await;
        assert_eq!(current.revision, 1);

        let mut stale = WorkspaceStateSnapshot {
            session_id: Some(session.id()),
            ..WorkspaceStateSnapshot::default()
        };
        stale.replay.tabs.push(ReplayTabState {
            id: "bad-stale".to_string(),
            sequence: 1,
            base_request: Some(EditableRequest {
                scheme: "ftp".to_string(),
                host: "bad host".to_string(),
                method: "GET".to_string(),
                path: "/".to_string(),
                headers: Vec::new(),
                body: String::new(),
                body_encoding: BodyEncoding::Utf8,
                preview_truncated: false,
            }),
            ..ReplayTabState::default()
        });

        let response = super::update_workspace_state(State(state), Json(stale)).await;

        assert_eq!(response.status(), super::StatusCode::CONFLICT);
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn scanner_config_update_rolls_back_when_persist_fails() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-scanner-config-rollback-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let mut next_config = session.scanner.get_config().await;
        assert!(next_config.enabled);
        next_config.enabled = false;

        let storage_dir = session.storage_dir().to_path_buf();
        std::fs::remove_dir_all(&storage_dir).unwrap();
        std::fs::write(&storage_dir, b"not a directory").unwrap();

        let response = super::update_scanner_config(
            State(state),
            Query(super::SessionScopedQuery { session_id: None }),
            Json(next_config),
        )
        .await;

        assert_eq!(response.status(), super::StatusCode::INTERNAL_SERVER_ERROR);
        assert!(session.scanner.get_config().await.enabled);

        let _ = std::fs::remove_file(storage_dir);
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn scanner_config_update_rewrites_durable_snapshot_after_registry_metadata_failure() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-scanner-config-registry-rollback-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let mut next_config = session.scanner.get_config().await;
        assert!(next_config.enabled);
        next_config.enabled = false;

        let registry_path = session
            .storage_dir()
            .parent()
            .expect("session dir should have registry parent")
            .join("registry.json");
        std::fs::remove_file(&registry_path).unwrap();
        std::fs::create_dir(&registry_path).unwrap();

        let response = super::update_scanner_config(
            State(state.clone()),
            Query(super::SessionScopedQuery { session_id: None }),
            Json(next_config),
        )
        .await;

        assert_eq!(response.status(), super::StatusCode::INTERNAL_SERVER_ERROR);
        assert!(session.scanner.get_config().await.enabled);

        let reloaded = state.sessions.load_context(session.id()).unwrap();
        assert!(reloaded.scanner.get_config().await.enabled);

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn sequence_upsert_rejects_missing_session_before_saving() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-sequence-missing-session-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let definition = SequenceDefinition {
            id: uuid::Uuid::new_v4(),
            name: "Missing session".to_string(),
            steps: Vec::new(),
        };

        let response = super::upsert_sequence(
            State(state),
            Json(super::SequenceUpsertPayload {
                session_id: None,
                definition,
            }),
        )
        .await;

        assert_eq!(response.status(), super::StatusCode::CONFLICT);
        assert!(session.sequence.list_definitions().await.is_empty());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn sequence_run_rejects_wrong_session_before_running() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-sequence-wrong-session-run-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let definition = SequenceDefinition {
            id: uuid::Uuid::new_v4(),
            name: "Wrong session run".to_string(),
            steps: Vec::new(),
        };
        session.sequence.upsert_definition(definition.clone()).await;

        let response = super::run_sequence(
            State(state),
            Path(definition.id.to_string()),
            Json(super::SequenceRunPayload {
                session_id: Some(Uuid::new_v4()),
            }),
        )
        .await;

        assert_eq!(response.status(), super::StatusCode::CONFLICT);
        assert!(session.sequence.list_runs(None).await.is_empty());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn sequence_run_releases_session_operation_lock_while_upstream_is_pending() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-sequence-run-lock-release-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let session_id = session.id();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0u8; 1024];
            let _ = stream.read(&mut buffer).await.unwrap();
            let _ = accepted_tx.send(());
            let _ = release_rx.await;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
        });

        let definition = SequenceDefinition {
            id: uuid::Uuid::new_v4(),
            name: "Lock release".to_string(),
            steps: vec![SequenceStep {
                id: uuid::Uuid::new_v4(),
                label: "Slow upstream".to_string(),
                request: EditableRequest {
                    scheme: "http".to_string(),
                    host: addr.to_string(),
                    method: "GET".to_string(),
                    path: "/".to_string(),
                    headers: Vec::new(),
                    body: String::new(),
                    body_encoding: BodyEncoding::Utf8,
                    preview_truncated: false,
                },
                source_transaction_id: None,
                http_version: None,
                target: None,
                request_text: None,
                request_parse_error: None,
                extractions: Vec::new(),
            }],
        };
        session.sequence.upsert_definition(definition.clone()).await;

        let response_task = tokio::spawn(super::run_sequence(
            State(state.clone()),
            Path(definition.id.to_string()),
            Json(super::SequenceRunPayload {
                session_id: Some(session_id),
            }),
        ));

        tokio::time::timeout(Duration::from_secs(2), accepted_rx)
            .await
            .expect("sequence should reach the upstream server")
            .expect("upstream accept marker should be sent");
        assert!(crate::proxy::session_has_active_proxy_work(session_id));

        let operation_lock = state.session_operation_lock(session_id).await;
        let operation_guard =
            tokio::time::timeout(Duration::from_millis(200), operation_lock.lock())
                .await
                .expect(
                    "sequence must not hold the session operation lock while waiting on upstream",
                );
        drop(operation_guard);

        let _ = release_tx.send(());
        let response = response_task.await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn sequence_reads_and_writes_use_pinned_inactive_session() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-sequence-pinned-inactive-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let inactive = state.session().await;
        let inactive_id = inactive.id();
        let inactive_definition = SequenceDefinition {
            id: uuid::Uuid::new_v4(),
            name: "Inactive sequence".to_string(),
            steps: Vec::new(),
        };
        inactive
            .sequence
            .upsert_definition(inactive_definition.clone())
            .await;
        state.persist_session_context(&inactive).await.unwrap();
        state
            .create_session(Some("new active".to_string()))
            .await
            .unwrap();

        let active_response = super::get_sequence(
            State(state.clone()),
            Path(inactive_definition.id.to_string()),
            Query(super::SequenceSessionQuery { session_id: None }),
        )
        .await;
        assert_eq!(active_response.status(), super::StatusCode::NOT_FOUND);

        let active_proxy_owner = crate::proxy::remember_active_proxy_session_owner(inactive_id);

        let pinned_response = super::get_sequence(
            State(state.clone()),
            Path(inactive_definition.id.to_string()),
            Query(super::SequenceSessionQuery {
                session_id: Some(inactive_id),
            }),
        )
        .await;
        assert_eq!(pinned_response.status(), super::StatusCode::OK);

        let pinned_definitions: Vec<SequenceDefinition> = response_json(
            super::list_sequences(
                State(state.clone()),
                Query(super::SequenceSessionQuery {
                    session_id: Some(inactive_id),
                }),
            )
            .await,
        )
        .await;
        assert_eq!(pinned_definitions.len(), 1);
        assert_eq!(pinned_definitions[0].id, inactive_definition.id);

        let pinned_runs: Vec<crate::sequence::SequenceRunRecord> = response_json(
            super::list_sequence_runs(
                State(state.clone()),
                Query(super::SequenceQuery {
                    session_id: Some(inactive_id),
                    limit: None,
                }),
            )
            .await,
        )
        .await;
        assert!(pinned_runs.is_empty());

        drop(active_proxy_owner);

        let active_definition = SequenceDefinition {
            id: uuid::Uuid::new_v4(),
            name: "Must not save to active".to_string(),
            steps: Vec::new(),
        };
        let response = super::upsert_sequence(
            State(state.clone()),
            Json(super::SequenceUpsertPayload {
                session_id: Some(inactive_id),
                definition: active_definition.clone(),
            }),
        )
        .await;
        assert_eq!(response.status(), super::StatusCode::NO_CONTENT);

        let active = state.session().await;
        assert!(active.sequence.list_definitions().await.is_empty());
        let reloaded = state.sessions.load_context(inactive_id).unwrap();
        assert!(reloaded
            .sequence
            .get_definition(active_definition.id)
            .await
            .is_some());

        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn sequence_upsert_rolls_back_when_persist_fails() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-sequence-upsert-rollback-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let definition = SequenceDefinition {
            id: uuid::Uuid::new_v4(),
            name: "Rollback sequence".to_string(),
            steps: Vec::new(),
        };

        let storage_dir = session.storage_dir().to_path_buf();
        std::fs::remove_dir_all(&storage_dir).unwrap();
        std::fs::write(&storage_dir, b"not a directory").unwrap();

        let response = super::upsert_sequence(
            State(state),
            Json(super::SequenceUpsertPayload {
                session_id: Some(session.id()),
                definition,
            }),
        )
        .await;

        assert_eq!(response.status(), super::StatusCode::INTERNAL_SERVER_ERROR);
        assert!(session.sequence.list_definitions().await.is_empty());

        let _ = std::fs::remove_file(storage_dir);
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn sequence_run_returns_500_when_session_snapshot_persist_fails() {
        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-sequence-run-rollback-{}",
            uuid::Uuid::new_v4()
        ));
        let config = AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 100,
            body_preview_bytes: 4096,
            data_dir: data_dir.clone(),
        };
        let state = Arc::new(AppState::new(config).unwrap());
        let session = state.session().await;
        let definition = SequenceDefinition {
            id: uuid::Uuid::new_v4(),
            name: "Rollback sequence run".to_string(),
            steps: vec![SequenceStep {
                id: uuid::Uuid::new_v4(),
                label: "closed local port".to_string(),
                request: EditableRequest {
                    scheme: "http".to_string(),
                    host: "127.0.0.1".to_string(),
                    method: "GET".to_string(),
                    path: "/".to_string(),
                    headers: vec![HeaderRecord {
                        name: "Host".to_string(),
                        value: "127.0.0.1".to_string(),
                    }],
                    body: String::new(),
                    body_encoding: BodyEncoding::Utf8,
                    preview_truncated: false,
                },
                source_transaction_id: None,
                http_version: None,
                target: Some(RequestTargetOverride {
                    scheme: "http".to_string(),
                    host: "127.0.0.1".to_string(),
                    port: "9".to_string(),
                }),
                request_text: None,
                request_parse_error: None,
                extractions: Vec::new(),
            }],
        };
        session.sequence.upsert_definition(definition.clone()).await;

        let storage_dir = session.storage_dir().to_path_buf();
        std::fs::remove_dir_all(&storage_dir).unwrap();
        std::fs::write(&storage_dir, b"not a directory").unwrap();

        let response = super::run_sequence(
            State(state),
            Path(definition.id.to_string()),
            Json(super::SequenceRunPayload {
                session_id: Some(session.id()),
            }),
        )
        .await;

        assert_eq!(response.status(), super::StatusCode::INTERNAL_SERVER_ERROR);
        assert!(session.sequence.list_runs(None).await.is_empty());

        let _ = std::fs::remove_file(storage_dir);
        let _ = std::fs::remove_dir_all(data_dir);
    }
}
