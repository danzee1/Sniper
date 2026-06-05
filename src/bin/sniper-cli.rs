use std::{
    env, fs,
    io::{self, Read, Write},
    net::IpAddr,
    path::PathBuf,
};

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::{ArgAction, ArgGroup, Args, Parser, Subcommand};
use reqwest::{Method, StatusCode};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use sniper::{
    certificate::default_data_dir,
    fuzzer::FuzzerAttackRecord,
    intercept::{
        InterceptRecord, InterceptRule, InterceptSummary, ResponseInterceptRecord,
        ResponseInterceptSummary,
    },
    match_replace::{MatchReplaceRule, MatchReplaceRulesPayload},
    model::{
        BodyEncoding, EditableRequest, EditableResponse, HeaderRecord, RequestTargetOverride,
        TransactionRecord, TransactionSummary, WebSocketSessionRecord, WebSocketSessionSummary,
    },
    runtime::RuntimeSettingsSnapshot,
    runtime_state::load_runtime_state,
    sequence::{SequenceDefinition, SequenceRunRecord, SequenceRunSummary},
    session::SessionSummary,
    skills,
    workspace::{
        FuzzerWorkspaceState, ReplayHistoryEntryState, ReplayTabState, ReplayWorkspaceState,
        WorkspaceStateSnapshot,
    },
};
use url::Url;
use uuid::Uuid;

const CLI_REPEATER_HISTORY_LIMIT: usize = 30;
const MAX_CLI_INPUT_BYTES: usize = 64 * 1024 * 1024;
const CLI_API_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

#[derive(Parser, Debug)]
#[command(name = "sniper-cli", version = env!("CARGO_PKG_VERSION"), about = "Operate a local Sniper proxy through its JSON API.")]
struct Cli {
    #[arg(long, global = true)]
    api: Option<String>,

    #[command(subcommand)]
    command: Command,
}

fn parse_nonzero_usize(value: &str) -> std::result::Result<usize, String> {
    let parsed = value
        .parse::<usize>()
        .map_err(|error| format!("invalid limit: {error}"))?;
    if parsed == 0 {
        Err("limit must be greater than zero".to_string())
    } else {
        Ok(parsed)
    }
}

#[derive(Subcommand, Debug)]
enum Command {
    Session {
        #[command(subcommand)]
        command: SessionCommand,
    },
    Capture {
        #[command(subcommand)]
        command: CaptureCommand,
    },
    #[command(name = "scope", visible_alias = "target")]
    Scope {
        #[command(subcommand)]
        command: TargetCommand,
    },
    #[command(name = "replay", visible_alias = "repeater")]
    Replay {
        #[command(subcommand)]
        command: ReplayCommand,
    },
    Fuzzer {
        #[command(subcommand)]
        command: FuzzerCommand,
    },
    Sequence {
        #[command(subcommand)]
        command: SequenceCommand,
    },
    Skills {
        #[command(subcommand)]
        command: SkillsCommand,
    },
    #[command(name = "http", visible_alias = "history", hide = true)]
    History {
        #[command(subcommand)]
        command: HistoryCommand,
    },
    #[command(hide = true)]
    Intercept {
        #[command(subcommand)]
        command: InterceptCommand,
    },
    #[command(name = "web-socket", visible_alias = "websocket", hide = true)]
    Websocket {
        #[command(subcommand)]
        command: WebSocketCommand,
    },
    #[command(name = "auto-replace", visible_alias = "match-replace", hide = true)]
    AutoReplace {
        #[command(subcommand)]
        command: AutoReplaceCommand,
    },
}

#[derive(Subcommand, Debug)]
enum CaptureCommand {
    #[command(name = "http", visible_alias = "history")]
    Http {
        #[command(subcommand)]
        command: HistoryCommand,
    },
    Intercept {
        #[command(subcommand)]
        command: InterceptCommand,
    },
    #[command(name = "response-intercept")]
    ResponseIntercept {
        #[command(subcommand)]
        command: ResponseInterceptCommand,
    },
    #[command(name = "intercept-rule")]
    InterceptRule {
        #[command(subcommand)]
        command: InterceptRuleCommand,
    },
    #[command(name = "web-socket", visible_alias = "websocket")]
    WebSocket {
        #[command(subcommand)]
        command: WebSocketCommand,
    },
    #[command(name = "auto-replace", visible_alias = "match-replace")]
    AutoReplace {
        #[command(subcommand)]
        command: AutoReplaceCommand,
    },
    Oast {
        #[command(subcommand)]
        command: OastCommand,
    },
}

#[derive(Subcommand, Debug)]
enum SessionCommand {
    List,
    Create(CreateSessionArgs),
    Switch(SessionSwitchArgs),
}

#[derive(Args, Debug)]
struct CreateSessionArgs {
    #[arg(long)]
    name: Option<String>,
}

#[derive(Args, Debug)]
struct SessionSwitchArgs {
    #[arg(long)]
    id: Uuid,
}

#[derive(Subcommand, Debug)]
enum HistoryCommand {
    List(HistoryListArgs),
    Get(HistoryGetArgs),
    Replay(HistoryReplayArgs),
    Fuzzer(HistoryFuzzerArgs),
    Annotate(HistoryAnnotateArgs),
}

#[derive(Args, Debug, Default)]
struct HistoryListArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
    #[arg(long)]
    query: Option<String>,
    #[arg(long)]
    method: Option<String>,
    #[arg(long, value_parser = parse_nonzero_usize)]
    limit: Option<usize>,
    /// Return rows after this zero-based offset. Uses the paged history API.
    #[arg(long)]
    offset: Option<usize>,
    /// Include pagination metadata instead of the legacy array-only output.
    #[arg(long)]
    page: bool,
    /// Filter by host (substring match)
    #[arg(long)]
    host: Option<String>,
    /// Filter by exact HTTP status code
    #[arg(long, value_parser = clap::value_parser!(u16).range(100..=599))]
    status: Option<u16>,
    /// Filter by status range, e.g. "4xx" or "200-299"
    #[arg(long)]
    status_range: Option<String>,
    /// Filter by time, e.g. "2024-01-01" or "1h" (relative)
    #[arg(long)]
    since: Option<String>,
    /// Filter by response MIME type (substring match), e.g. "json" or "text/html"
    #[arg(long)]
    mime: Option<String>,
}

#[derive(Args, Debug)]
struct HistoryGetArgs {
    #[arg(long)]
    id: Uuid,
    #[arg(long)]
    session_id: Option<Uuid>,
}

#[derive(Args, Debug, Default)]
struct HistoryReplayArgs {
    #[arg(long)]
    id: Uuid,
    #[arg(long)]
    session_id: Option<Uuid>,
    #[arg(long)]
    scheme: Option<String>,
    #[arg(long)]
    host: Option<String>,
    #[arg(long)]
    port: Option<String>,
}

#[derive(Args, Debug)]
struct HistoryFuzzerArgs {
    #[arg(long)]
    id: Uuid,
    #[arg(long)]
    session_id: Option<Uuid>,
    #[arg(long)]
    scheme: Option<String>,
    #[arg(long)]
    host: Option<String>,
    #[arg(long)]
    port: Option<String>,
}

#[derive(Args, Debug)]
struct HistoryAnnotateArgs {
    #[arg(long)]
    id: Uuid,
    #[arg(long)]
    session_id: Option<Uuid>,
    /// Set color tag (e.g. red, orange, yellow, green, blue, purple). Use --clear-color to remove.
    #[arg(long, conflicts_with = "clear_color")]
    color: Option<String>,
    /// Remove the color tag.
    #[arg(long, conflicts_with = "color")]
    clear_color: bool,
    /// Set a user note on the transaction.
    #[arg(long, conflicts_with = "clear_note")]
    note: Option<String>,
    /// Remove the user note.
    #[arg(long, conflicts_with = "note")]
    clear_note: bool,
}

#[derive(Subcommand, Debug)]
enum TargetCommand {
    GetScope(TargetSessionArgs),
    SetScope(TargetSetScopeArgs),
}

#[derive(Args, Debug, Default)]
struct TargetSessionArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
}

#[derive(Args, Debug, Default)]
#[command(group(
    ArgGroup::new("scope_source")
        .args(["patterns", "file", "stdin", "clear"])
        .multiple(false)
        .required(true)
))]
struct TargetSetScopeArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
    /// Clear all scope patterns.
    #[arg(long)]
    clear: bool,
    #[arg(long = "pattern", action = ArgAction::Append)]
    patterns: Vec<String>,
    #[arg(long)]
    file: Option<PathBuf>,
    #[arg(long)]
    stdin: bool,
}

#[derive(Subcommand, Debug)]
enum ReplayCommand {
    List(ReplayListArgs),
    Open(ReplayOpenArgs),
    Update(ReplayUpdateArgs),
    Send(ReplaySendArgs),
}

#[derive(Args, Debug, Default)]
struct ReplayListArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
}

#[derive(Args, Debug, Default)]
#[command(group(
    ArgGroup::new("request_source")
        .args(["transaction_id", "request_file", "stdin"])
        .multiple(false)
))]
struct ReplayOpenArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
    #[arg(long)]
    transaction_id: Option<Uuid>,
    #[arg(long)]
    request_file: Option<PathBuf>,
    #[arg(long)]
    stdin: bool,
    #[arg(long)]
    scheme: Option<String>,
    #[arg(long)]
    host: Option<String>,
    #[arg(long)]
    port: Option<String>,
}

#[derive(Args, Debug, Default)]
#[command(group(
    ArgGroup::new("request_source")
        .args(["request_file", "stdin"])
        .multiple(false)
))]
struct ReplayUpdateArgs {
    #[arg(long)]
    tab_id: String,
    #[arg(long)]
    session_id: Option<Uuid>,
    #[arg(long)]
    request_file: Option<PathBuf>,
    #[arg(long)]
    stdin: bool,
    #[arg(long)]
    scheme: Option<String>,
    #[arg(long)]
    host: Option<String>,
    #[arg(long)]
    port: Option<String>,
}

#[derive(Args, Debug)]
struct ReplaySendArgs {
    #[arg(long)]
    tab_id: String,
    #[arg(long)]
    session_id: Option<Uuid>,
}

#[derive(Subcommand, Debug)]
enum FuzzerCommand {
    SetTemplate(FuzzerSetTemplateArgs),
    SetPayloads(FuzzerSetPayloadsArgs),
    Run(FuzzerRunArgs),
    /// Show fuzzer attack status by ID
    Status(FuzzerStatusArgs),
    /// Show fuzzer attack results by ID
    Results(FuzzerResultsArgs),
    /// List past fuzzer attacks
    List(FuzzerListArgs),
}

#[derive(Args, Debug, Default)]
struct FuzzerRunArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
    /// Mark async intent in output; the current Sniper API still returns after completion
    #[arg(long, alias = "async")]
    r#async: bool,
}

#[derive(Args, Debug)]
struct FuzzerStatusArgs {
    #[arg(long)]
    id: Uuid,
    #[arg(long)]
    session_id: Option<Uuid>,
}

#[derive(Args, Debug)]
struct FuzzerResultsArgs {
    #[arg(long)]
    id: Uuid,
    #[arg(long)]
    session_id: Option<Uuid>,
}

#[derive(Args, Debug, Default)]
struct FuzzerListArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
    #[arg(long, value_parser = parse_nonzero_usize)]
    limit: Option<usize>,
}

#[derive(Args, Debug, Default)]
#[command(group(
    ArgGroup::new("request_source")
        .args(["transaction_id", "request_file", "stdin"])
        .multiple(false)
))]
struct FuzzerSetTemplateArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
    #[arg(long)]
    transaction_id: Option<Uuid>,
    #[arg(long)]
    request_file: Option<PathBuf>,
    #[arg(long)]
    stdin: bool,
    #[arg(long)]
    scheme: Option<String>,
    #[arg(long)]
    host: Option<String>,
    #[arg(long)]
    port: Option<String>,
}

#[derive(Args, Debug, Default)]
#[command(group(
    ArgGroup::new("payload_source")
        .args(["payloads", "file", "stdin"])
        .multiple(false)
))]
struct FuzzerSetPayloadsArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
    #[arg(long = "payload", action = ArgAction::Append)]
    payloads: Vec<String>,
    #[arg(long)]
    file: Option<PathBuf>,
    #[arg(long)]
    stdin: bool,
}

#[derive(Subcommand, Debug)]
enum InterceptCommand {
    On(InterceptSessionArgs),
    Off(InterceptSessionArgs),
    List(InterceptSessionArgs),
    Forward(InterceptForwardArgs),
    Drop(InterceptDropArgs),
}

#[derive(Args, Debug, Default)]
struct InterceptSessionArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
}

#[derive(Args, Debug, Default)]
#[command(group(
    ArgGroup::new("request_source")
        .args(["request_file", "stdin"])
        .multiple(false)
))]
struct InterceptForwardArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
    #[arg(long)]
    id: Uuid,
    #[arg(long)]
    request_file: Option<PathBuf>,
    #[arg(long)]
    stdin: bool,
}

#[derive(Args, Debug)]
struct InterceptDropArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
    #[arg(long)]
    id: Uuid,
}

#[derive(Subcommand, Debug)]
enum WebSocketCommand {
    List(WebSocketListArgs),
    Get(WebSocketGetArgs),
}

#[derive(Subcommand, Debug)]
enum AutoReplaceCommand {
    List(AutoReplaceSessionArgs),
    Set(AutoReplaceSetArgs),
}

#[derive(Args, Debug, Default)]
struct AutoReplaceSessionArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
}

#[derive(Subcommand, Debug)]
enum OastCommand {
    /// Show OAST registration status and provider info
    Status(OastSessionArgs),
    /// List received OAST callbacks
    List(OastListArgs),
    /// Get full details of a specific callback
    Get(OastGetArgs),
    /// Generate a new OAST payload
    Generate(OastSessionArgs),
    /// Clear all OAST callbacks
    Clear(OastSessionArgs),
    /// Configure OAST provider settings
    Configure(OastConfigureArgs),
}

#[derive(Args, Debug, Default)]
struct OastSessionArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
}

#[derive(Args, Debug, Default)]
struct OastListArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
    #[arg(long, value_parser = parse_nonzero_usize)]
    limit: Option<usize>,
}

#[derive(Args, Debug)]
struct OastGetArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
    #[arg(long)]
    id: Uuid,
}

#[derive(Args, Debug, Default)]
struct OastConfigureArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
    /// Provider: interactsh, boast, or custom
    #[arg(long, value_parser = ["interactsh", "boast", "custom"])]
    provider: Option<String>,
    /// OAST server URL
    #[arg(long)]
    url: Option<String>,
    /// Authentication token
    #[arg(long)]
    token: Option<String>,
    /// Polling interval in seconds
    #[arg(long)]
    interval: Option<u64>,
    /// Enable OAST
    #[arg(long, conflicts_with = "disable")]
    enable: bool,
    /// Disable OAST
    #[arg(long, conflicts_with = "enable")]
    disable: bool,
}

#[derive(Args, Debug, Default)]
struct WebSocketListArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
    #[arg(long, value_parser = parse_nonzero_usize)]
    limit: Option<usize>,
    /// Include pagination metadata instead of printing the legacy array shape.
    #[arg(long)]
    page: bool,
}

#[derive(Args, Debug)]
struct WebSocketGetArgs {
    #[arg(long)]
    id: Uuid,
    #[arg(long)]
    session_id: Option<Uuid>,
}

#[derive(Subcommand, Debug)]
enum SkillsCommand {
    Install(SkillsInstallArgs),
}

#[derive(Args, Debug, Default)]
struct SkillsInstallArgs {
    #[arg(long)]
    codex: bool,
    #[arg(long)]
    claude: bool,
    #[arg(long)]
    all: bool,
    #[arg(long)]
    codex_dir: Option<PathBuf>,
    #[arg(long)]
    claude_dir: Option<PathBuf>,
}

#[derive(Args, Debug, Default)]
#[command(group(
    ArgGroup::new("rules_source")
        .args(["file", "stdin"])
        .multiple(false)
))]
struct AutoReplaceSetArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
    #[arg(long)]
    file: Option<PathBuf>,
    #[arg(long)]
    stdin: bool,
}

#[derive(Subcommand, Debug)]
enum ResponseInterceptCommand {
    List(ResponseInterceptSessionArgs),
    Get(ResponseInterceptGetArgs),
    Forward(ResponseInterceptForwardArgs),
    Drop(ResponseInterceptDropArgs),
    #[command(name = "forward-all")]
    ForwardAll(ResponseInterceptSessionArgs),
}

#[derive(Args, Debug, Default)]
struct ResponseInterceptSessionArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
}

#[derive(Args, Debug)]
struct ResponseInterceptGetArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
    #[arg(long)]
    id: Uuid,
}

#[derive(Args, Debug)]
#[command(group(
    ArgGroup::new("response_source")
        .args(["response_file", "stdin"])
        .multiple(false)
))]
struct ResponseInterceptForwardArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
    #[arg(long)]
    id: Uuid,
    #[arg(long)]
    response_file: Option<PathBuf>,
    #[arg(long)]
    stdin: bool,
}

#[derive(Args, Debug)]
struct ResponseInterceptDropArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
    #[arg(long)]
    id: Uuid,
}

#[derive(Subcommand, Debug)]
enum InterceptRuleCommand {
    List(InterceptRuleSessionArgs),
    Create(InterceptRuleCreateArgs),
    Delete(InterceptRuleDeleteArgs),
}

#[derive(Args, Debug, Default)]
struct InterceptRuleSessionArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
}

#[derive(Args, Debug)]
#[command(group(
    ArgGroup::new("matcher")
        .args(["host_pattern", "path_pattern", "method_filter", "all"])
        .multiple(true)
        .required(true)
))]
struct InterceptRuleCreateArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
    #[arg(long, default_value = "both", value_parser = ["request", "response", "both"])]
    scope: String,
    /// Create a rule that matches all traffic. Required when no matcher is supplied.
    #[arg(long)]
    all: bool,
    #[arg(long)]
    host_pattern: Option<String>,
    #[arg(long)]
    path_pattern: Option<String>,
    #[arg(long = "method", action = ArgAction::Append)]
    method_filter: Vec<String>,
    #[arg(long)]
    enabled: Option<bool>,
}

#[derive(Args, Debug)]
struct InterceptRuleDeleteArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
    #[arg(long)]
    id: Uuid,
}

#[derive(Subcommand, Debug)]
enum SequenceCommand {
    List(SequenceListArgs),
    Get(SequenceGetArgs),
    Create(SequenceCreateArgs),
    Run(SequenceRunArgs),
    #[command(name = "run-get")]
    RunGet(SequenceRunGetArgs),
    Delete(SequenceDeleteArgs),
    Runs(SequenceRunsArgs),
}

#[derive(Args, Debug, Default)]
struct SequenceListArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
}

#[derive(Args, Debug)]
struct SequenceGetArgs {
    #[arg(long)]
    id: Uuid,
    #[arg(long)]
    session_id: Option<Uuid>,
}

#[derive(Args, Debug)]
#[command(group(
    ArgGroup::new("sequence_source")
        .args(["file", "stdin"])
        .multiple(false)
))]
struct SequenceCreateArgs {
    #[arg(long)]
    file: Option<PathBuf>,
    #[arg(long)]
    stdin: bool,
    #[arg(long)]
    session_id: Option<Uuid>,
}

#[derive(Args, Debug)]
struct SequenceRunArgs {
    #[arg(long)]
    id: Uuid,
    #[arg(long)]
    session_id: Option<Uuid>,
}

#[derive(Args, Debug)]
struct SequenceRunGetArgs {
    #[arg(long)]
    id: Uuid,
    #[arg(long)]
    session_id: Option<Uuid>,
}

#[derive(Args, Debug)]
struct SequenceDeleteArgs {
    #[arg(long)]
    id: Uuid,
    #[arg(long)]
    session_id: Option<Uuid>,
}

#[derive(Args, Debug, Default)]
struct SequenceRunsArgs {
    #[arg(long)]
    session_id: Option<Uuid>,
    #[arg(long, value_parser = parse_nonzero_usize)]
    limit: Option<usize>,
}

#[derive(Serialize)]
struct ResponseInterceptForwardPayload {
    response: EditableResponse,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum AutoReplaceInput {
    Rules(Vec<MatchReplaceRule>),
    Payload(MatchReplaceRulesPayload),
}

#[derive(Deserialize)]
#[serde(untagged)]
enum HistoryListResponse {
    Items(Vec<TransactionSummary>),
    Page {
        items: Vec<TransactionSummary>,
        #[serde(default)]
        total: Option<usize>,
        #[serde(default)]
        filtered_total: Option<usize>,
        #[serde(default)]
        hidden_connect_total: Option<usize>,
        #[serde(default)]
        offset: Option<usize>,
        #[serde(default)]
        limit: Option<usize>,
        #[serde(default)]
        has_more: Option<bool>,
    },
}

impl HistoryListResponse {
    fn into_cli_output(self, include_page: bool) -> serde_json::Value {
        match self {
            Self::Items(items) if include_page => serde_json::json!({
                "items": items,
                "total": null,
                "filtered_total": null,
                "hidden_connect_total": null,
                "offset": null,
                "limit": null,
                "has_more": null,
            }),
            Self::Items(items) => serde_json::json!(items),
            Self::Page {
                items,
                total,
                filtered_total,
                hidden_connect_total,
                offset,
                limit,
                has_more,
            } if include_page => serde_json::json!({
                "items": items,
                "total": total,
                "filtered_total": filtered_total,
                "hidden_connect_total": hidden_connect_total,
                "offset": offset,
                "limit": limit,
                "has_more": has_more,
            }),
            Self::Page { items, .. } => serde_json::json!(items),
        }
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum WebSocketListResponse {
    Items(Vec<WebSocketSessionSummary>),
    Page {
        items: Vec<WebSocketSessionSummary>,
        #[serde(default)]
        total: Option<usize>,
        #[serde(default)]
        limit: Option<usize>,
        #[serde(default)]
        has_more: Option<bool>,
    },
}

impl WebSocketListResponse {
    fn into_cli_output(self, include_page: bool) -> serde_json::Value {
        match self {
            Self::Items(items) if include_page => serde_json::json!({
                "items": items,
                "total": null,
                "limit": null,
                "has_more": null,
            }),
            Self::Items(items) => serde_json::json!(items),
            Self::Page {
                items,
                total,
                limit,
                has_more,
            } if include_page => serde_json::json!({
                "items": items,
                "total": total,
                "limit": limit,
                "has_more": has_more,
            }),
            Self::Page { items, .. } => serde_json::json!(items),
        }
    }
}

#[derive(Clone)]
struct ApiClient {
    base_url: String,
    client: reqwest::Client,
    long_client: reqwest::Client,
}

impl ApiClient {
    async fn discover(cli_api: Option<String>) -> Result<Self> {
        let probe_client = reqwest::Client::builder()
            .no_proxy()
            .timeout(CLI_API_TIMEOUT)
            .build()
            .context("failed to build sniper-cli discovery HTTP client")?;
        let base_url = discover_api_base_url(cli_api, &probe_client).await?;
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(CLI_API_TIMEOUT)
            .build()
            .context("failed to build sniper-cli HTTP client")?;
        let long_client = reqwest::Client::builder()
            .no_proxy()
            .build()
            .context("failed to build sniper-cli long-running HTTP client")?;
        Ok(Self {
            base_url,
            client,
            long_client,
        })
    }

    async fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        self.request_json(Method::GET, path, Option::<()>::None)
            .await
    }

    async fn post_json<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        self.request_json(Method::POST, path, Some(body)).await
    }

    async fn post_json_long<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        self.request_json_with_client(&self.long_client, Method::POST, path, Some(body))
            .await
    }

    async fn send_replay(&self, payload: &ReplaySendPayload) -> Result<ReplaySendApiResult> {
        let path = "/api/replay/send";
        let response = self
            .long_client
            .post(self.url(path))
            .json(payload)
            .send()
            .await
            .with_context(|| format!("failed to POST {}", path))?;
        let status = response.status();
        if status.is_success() {
            return response
                .json::<TransactionRecord>()
                .await
                .map(ReplaySendApiResult::Success)
                .with_context(|| format!("failed to decode JSON response from {}", path));
        }
        if status == StatusCode::BAD_REQUEST {
            let message = response.text().await.unwrap_or_else(|_| String::new());
            let body = match serde_json::from_str::<ReplaySendErrorBody>(&message) {
                Ok(body) => body,
                Err(_) => {
                    let detail = if message.trim().is_empty() {
                        status.to_string()
                    } else {
                        message
                    };
                    bail!("request to {} failed ({}): {}", path, status, detail);
                }
            };
            if body.record.is_some() {
                return Ok(ReplaySendApiResult::StoredError(body));
            }
            bail!("request to {} failed ({}): {}", path, status, body.error);
        }
        let message = response.text().await.unwrap_or_else(|_| String::new());
        let detail = if message.trim().is_empty() {
            status.to_string()
        } else {
            message
        };
        bail!("request to {} failed ({}): {}", path, status, detail);
    }

    async fn post_status<B: Serialize>(&self, path: &str, body: &B) -> Result<StatusCode> {
        let response = self
            .client
            .post(self.url(path))
            .json(body)
            .send()
            .await
            .with_context(|| format!("failed to POST {}", path))?;
        let status = response.status();
        if !status.is_success() {
            let message = response.text().await.unwrap_or_else(|_| String::new());
            let detail = if message.trim().is_empty() {
                status.to_string()
            } else {
                message
            };
            bail!("request to {} failed ({}): {}", path, status, detail);
        }
        Ok(status)
    }

    async fn delete_status(&self, path: &str) -> Result<StatusCode> {
        let response = self
            .client
            .delete(self.url(path))
            .send()
            .await
            .with_context(|| format!("failed to DELETE {}", path))?;
        let status = response.status();
        if !status.is_success() {
            let message = response.text().await.unwrap_or_else(|_| String::new());
            let detail = if message.trim().is_empty() {
                status.to_string()
            } else {
                message
            };
            bail!("request to {} failed ({}): {}", path, status, detail);
        }
        Ok(status)
    }

    async fn request_json<B: Serialize, T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<B>,
    ) -> Result<T> {
        let request = self.client.request(method.clone(), self.url(path));
        self.send_json_request(request, method, path, body).await
    }

    async fn request_json_with_client<B: Serialize, T: DeserializeOwned>(
        &self,
        client: &reqwest::Client,
        method: Method,
        path: &str,
        body: Option<B>,
    ) -> Result<T> {
        let request = client.request(method.clone(), self.url(path));
        self.send_json_request(request, method, path, body).await
    }

    async fn send_json_request<B: Serialize, T: DeserializeOwned>(
        &self,
        request: reqwest::RequestBuilder,
        method: Method,
        path: &str,
        body: Option<B>,
    ) -> Result<T> {
        let response = match body {
            Some(body) => request.json(&body).send().await,
            None => request.send().await,
        }
        .with_context(|| format!("failed to {} {}", method, path))?;

        let status = response.status();
        if !status.is_success() {
            let message = response.text().await.unwrap_or_else(|_| String::new());
            let detail = if message.trim().is_empty() {
                status.to_string()
            } else {
                message
            };
            bail!("request to {} failed ({}): {}", path, status, detail);
        }

        response
            .json::<T>()
            .await
            .with_context(|| format!("failed to decode JSON response from {}", path))
    }

    fn url(&self, path: &str) -> String {
        format!(
            "{}/{}",
            self.base_url.trim_end_matches('/'),
            path.trim_start_matches('/')
        )
    }
}

const CLI_WORKSPACE_CLIENT_ID: &str = "sniper-cli";

async fn post_workspace_state(
    api: &ApiClient,
    workspace: &mut WorkspaceStateSnapshot,
) -> Result<WorkspaceStateSnapshot> {
    prepare_cli_workspace_save(workspace);
    api.post_json("/api/workspace-state", workspace).await
}

async fn load_workspace_state(
    api: &ApiClient,
    explicit_session_id: Option<Uuid>,
) -> Result<WorkspaceStateSnapshot> {
    let session_id = resolve_session_id_arg(api, explicit_session_id).await?;
    api.get_json(&session_query_path("/api/workspace-state", session_id))
        .await
}

fn prepare_cli_workspace_save(workspace: &mut WorkspaceStateSnapshot) {
    workspace.client_id = Some(CLI_WORKSPACE_CLIENT_ID.to_string());
    workspace.client_version = workspace.client_version.saturating_add(1).max(1);
}

#[derive(Serialize)]
struct ScopeOutput {
    scope_patterns: Vec<String>,
}

#[derive(Serialize)]
struct InterceptActionResult {
    ok: bool,
    action: &'static str,
    id: Uuid,
}

#[derive(Serialize)]
struct RuntimeUpdatePayload {
    session_id: Option<Uuid>,
    intercept_enabled: Option<bool>,
    websocket_capture_enabled: Option<bool>,
    scope_patterns: Option<Vec<String>>,
}

#[derive(Serialize)]
struct CreateSessionPayload {
    name: Option<String>,
}

#[derive(Serialize)]
struct ReplaySendPayload {
    session_id: Option<Uuid>,
    request: EditableRequest,
    target: Option<RequestTargetOverride>,
    source_transaction_id: Option<Uuid>,
    http_version: Option<String>,
}

enum ReplaySendApiResult {
    Success(TransactionRecord),
    StoredError(ReplaySendErrorBody),
}

#[derive(Deserialize)]
struct ReplaySendErrorBody {
    error: String,
    record: Option<TransactionRecord>,
}

#[derive(Serialize)]
struct FuzzerRunPayload {
    session_id: Option<Uuid>,
    template: EditableRequest,
    payloads: Vec<String>,
    source_transaction_id: Option<Uuid>,
    http_version: Option<String>,
    target: Option<RequestTargetOverride>,
}

#[derive(Serialize)]
struct SessionIdPayload {
    session_id: Option<Uuid>,
}

#[derive(Serialize)]
struct SequenceUpsertPayload<'a> {
    session_id: Option<Uuid>,
    #[serde(flatten)]
    definition: &'a SequenceDefinition,
}

#[derive(Deserialize)]
struct SequenceCreateInput {
    session_id: Option<Uuid>,
    #[serde(flatten)]
    definition: SequenceDefinition,
}

#[derive(Serialize)]
struct InterceptForwardPayload {
    request: EditableRequest,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    run(cli).await
}

async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Skills {
            command: SkillsCommand::Install(args),
        } => {
            let result = install_skills(args)?;
            print_json(&result)
        }
        command => {
            let api = ApiClient::discover(cli.api).await?;
            match command {
                Command::Session { command } => handle_session(api, command).await,
                Command::Capture { command } => match command {
                    CaptureCommand::Http { command } => handle_history(api, command).await,
                    CaptureCommand::Intercept { command } => handle_intercept(api, command).await,
                    CaptureCommand::WebSocket { command } => handle_websocket(api, command).await,
                    CaptureCommand::AutoReplace { command } => {
                        handle_auto_replace(api, command).await
                    }
                    CaptureCommand::ResponseIntercept { command } => {
                        handle_response_intercept(api, command).await
                    }
                    CaptureCommand::InterceptRule { command } => {
                        handle_intercept_rule(api, command).await
                    }
                    CaptureCommand::Oast { command } => handle_oast(api, command).await,
                },
                Command::Scope { command } => handle_target(api, command).await,
                Command::Replay { command } => handle_replay(api, command).await,
                Command::Fuzzer { command } => handle_fuzzer(api, command).await,
                Command::Sequence { command } => handle_sequence(api, command).await,
                Command::Skills { .. } => unreachable!(),
                Command::History { command } => handle_history(api, command).await,
                Command::Intercept { command } => handle_intercept(api, command).await,
                Command::Websocket { command } => handle_websocket(api, command).await,
                Command::AutoReplace { command } => handle_auto_replace(api, command).await,
            }
        }
    }
}

async fn handle_session(api: ApiClient, command: SessionCommand) -> Result<()> {
    match command {
        SessionCommand::List => {
            let sessions: Vec<SessionSummary> = api.get_json("/api/sessions").await?;
            print_json(&sessions)
        }
        SessionCommand::Create(args) => {
            let session: SessionSummary = api
                .post_json("/api/sessions", &CreateSessionPayload { name: args.name })
                .await?;
            print_json(&session)
        }
        SessionCommand::Switch(args) => {
            let session: SessionSummary = api
                .post_json(&format!("/api/sessions/{}/activate", args.id), &json!({}))
                .await?;
            print_json(&session)
        }
    }
}

async fn active_session_id(api: &ApiClient) -> Result<Option<Uuid>> {
    let sessions: Vec<SessionSummary> = api.get_json("/api/sessions").await?;
    Ok(active_session_id_from_summaries(&sessions))
}

fn active_session_id_from_summaries(sessions: &[SessionSummary]) -> Option<Uuid> {
    sessions
        .iter()
        .find(|session| session.active)
        .or_else(|| sessions.first())
        .map(|session| session.id)
}

async fn resolve_session_id_arg(
    api: &ApiClient,
    explicit_session_id: Option<Uuid>,
) -> Result<Option<Uuid>> {
    let active_session_id = if explicit_session_id.is_some() {
        None
    } else {
        active_session_id(api).await?
    };
    Ok(explicit_or_active_session_id(
        explicit_session_id,
        active_session_id,
    ))
}

fn explicit_or_active_session_id(
    explicit_session_id: Option<Uuid>,
    active_session_id: Option<Uuid>,
) -> Option<Uuid> {
    explicit_session_id.or(active_session_id)
}

async fn handle_history(api: ApiClient, command: HistoryCommand) -> Result<()> {
    match command {
        HistoryCommand::List(args) => {
            let include_page = args.page;
            let use_paged_api = include_page || args.offset.is_some();
            let mut params = Vec::new();
            let session_id = match args.session_id {
                Some(session_id) => Some(session_id),
                None => active_session_id(&api).await?,
            };
            if let Some(session_id) = session_id {
                params.push(("session_id".to_string(), session_id.to_string()));
            }
            if let Some(query) = args.query {
                params.push(("q".to_string(), query));
            }
            if let Some(method) = args.method {
                params.push(("method".to_string(), method));
            }
            if let Some(limit) = args.limit {
                params.push(("limit".to_string(), limit.to_string()));
            }
            if let Some(offset) = args.offset {
                params.push(("offset".to_string(), offset.to_string()));
            }
            if let Some(host) = args.host {
                params.push(("host".to_string(), host));
            }
            if let Some(status) = args.status {
                params.push(("status".to_string(), status.to_string()));
            }
            if let Some(status_range) = args.status_range {
                params.push(("status_range".to_string(), status_range));
            }
            if let Some(since) = args.since {
                params.push(("since".to_string(), since));
            }
            if let Some(mime) = args.mime {
                params.push(("mime".to_string(), mime));
            }
            let query = encode_query(params);
            let endpoint = if use_paged_api {
                "/api/transactions-page"
            } else {
                "/api/transactions"
            };
            let path = if query.is_empty() {
                endpoint.to_string()
            } else {
                format!("{endpoint}?{query}")
            };
            let history: HistoryListResponse = api.get_json(&path).await?;
            print_json(&history.into_cli_output(include_page))
        }
        HistoryCommand::Get(args) => {
            let session_id = match args.session_id {
                Some(session_id) => Some(session_id),
                None => active_session_id(&api).await?,
            };
            let record: TransactionRecord = api
                .get_json(&transaction_detail_path(args.id, session_id))
                .await?;
            print_json(&record)
        }
        HistoryCommand::Replay(args) => {
            let tab = open_replay_tab(
                &api,
                ReplayOpenInput {
                    session_id: args.session_id,
                    transaction_id: Some(args.id),
                    request_file: None,
                    stdin: false,
                    scheme: args.scheme,
                    host: args.host,
                    port: args.port,
                },
            )
            .await?;
            print_json(&tab)
        }
        HistoryCommand::Fuzzer(args) => {
            let mut workspace = load_workspace_state(&api, args.session_id).await?;
            let (base_request, source_transaction_id, request_text) =
                resolve_request_source(&api, workspace.session_id, Some(args.id), None, false)
                    .await?;
            let target = build_optional_target_override(
                args.scheme,
                args.host,
                args.port,
                base_request.as_ref(),
            )?;
            let target_request_authority = target
                .as_ref()
                .and(base_request.as_ref())
                .map(fuzzer_target_request_authority_for_request);
            workspace.fuzzer.base_request = base_request;
            workspace.fuzzer.source_transaction_id = source_transaction_id;
            workspace.fuzzer.target = target;
            workspace.fuzzer.target_request_authority = target_request_authority;
            workspace.fuzzer.request_text = request_text;
            workspace.fuzzer.notice.clear();
            workspace.fuzzer.attack_record = None;
            let snapshot = post_workspace_state(&api, &mut workspace).await?;
            print_json(&snapshot.fuzzer)
        }
        HistoryCommand::Annotate(args) => {
            let color_tag: Option<Option<String>> = if args.clear_color {
                Some(None)
            } else {
                args.color.map(Some)
            };
            let user_note: Option<Option<String>> = if args.clear_note {
                Some(None)
            } else {
                args.note.map(Some)
            };
            if color_tag.is_none() && user_note.is_none() {
                bail!("provide at least one of --color, --clear-color, --note, or --clear-note");
            }
            let payload = build_annotations_payload(color_tag, user_note);
            let session_id = resolve_session_id_arg(&api, args.session_id).await?;
            let path = session_query_path(
                &format!("/api/transactions/{}/annotations", args.id),
                session_id,
            );
            let summary: TransactionSummary = api
                .request_json(Method::PATCH, &path, Some(&payload))
                .await?;
            print_json(&summary)
        }
    }
}

fn build_annotations_payload(
    color_tag: Option<Option<String>>,
    user_note: Option<Option<String>>,
) -> Value {
    let mut payload = serde_json::Map::new();
    if let Some(value) = color_tag {
        payload.insert("color_tag".to_string(), json!(value));
    }
    if let Some(value) = user_note {
        payload.insert("user_note".to_string(), json!(value));
    }
    Value::Object(payload)
}

fn oast_fields_for_output(
    runtime: serde_json::Value,
) -> serde_json::Map<String, serde_json::Value> {
    let mut fields: serde_json::Map<String, serde_json::Value> = runtime
        .as_object()
        .map(|object| {
            object
                .iter()
                .filter(|(key, _)| key.starts_with("oast_") && key.as_str() != "oast_token")
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect()
        })
        .unwrap_or_default();
    let token_configured = runtime
        .get("oast_token")
        .and_then(|value| value.as_str())
        .is_some_and(|value| !value.is_empty());
    fields.insert("oast_token_configured".to_string(), json!(token_configured));
    fields
}

async fn handle_target(api: ApiClient, command: TargetCommand) -> Result<()> {
    match command {
        TargetCommand::GetScope(args) => {
            let session_id = resolve_session_id_arg(&api, args.session_id).await?;
            let path = session_query_path("/api/runtime", session_id);
            let runtime: RuntimeSettingsSnapshot = api.get_json(&path).await?;
            print_json(&ScopeOutput {
                scope_patterns: runtime.scope_patterns,
            })
        }
        TargetCommand::SetScope(args) => {
            let session_id = resolve_session_id_arg(&api, args.session_id).await?;
            let scope_patterns = if args.clear {
                Vec::new()
            } else {
                read_lines_input(args.patterns, args.file, args.stdin)?
            };
            let runtime: RuntimeSettingsSnapshot = api
                .post_json(
                    "/api/runtime",
                    &RuntimeUpdatePayload {
                        session_id,
                        intercept_enabled: None,
                        websocket_capture_enabled: None,
                        scope_patterns: Some(scope_patterns),
                    },
                )
                .await?;
            print_json(&ScopeOutput {
                scope_patterns: runtime.scope_patterns,
            })
        }
    }
}

async fn handle_replay(api: ApiClient, command: ReplayCommand) -> Result<()> {
    match command {
        ReplayCommand::List(args) => {
            let workspace = load_workspace_state(&api, args.session_id).await?;
            print_json(&workspace.replay)
        }
        ReplayCommand::Open(args) => {
            let tab = open_replay_tab(
                &api,
                ReplayOpenInput {
                    session_id: args.session_id,
                    transaction_id: args.transaction_id,
                    request_file: args.request_file,
                    stdin: args.stdin,
                    scheme: args.scheme,
                    host: args.host,
                    port: args.port,
                },
            )
            .await?;
            print_json(&tab)
        }
        ReplayCommand::Update(args) => {
            let mut workspace = load_workspace_state(&api, args.session_id).await?;
            let tab = find_replay_tab_mut(&mut workspace.replay, &args.tab_id)?;
            let explicit_target_update =
                args.scheme.is_some() || args.host.is_some() || args.port.is_some();
            if args.request_file.is_some() || args.stdin {
                let target_followed_previous_request =
                    replay_tab_target_matches_request(tab, tab.base_request.as_ref())
                        .unwrap_or(false);
                let (parsed_request, request_text) = read_raw_request_input(
                    args.request_file,
                    args.stdin,
                    tab.base_request.as_ref(),
                )?;
                if !request_text.trim().is_empty() {
                    tab.request_text = request_text;
                    tab.base_request = Some(parsed_request.request.clone());
                    tab.http_version_mode = parsed_request.http_version.unwrap_or_default();
                    tab.response_record = None;
                    tab.notice.clear();
                    if !explicit_target_update && target_followed_previous_request {
                        sync_replay_tab_target_to_request(tab, &parsed_request.request)?;
                    }
                }
            }
            if explicit_target_update {
                let current_target_fallback = replay_tab_target_as_request(tab);
                let preserve_current_port = replay_update_should_preserve_current_port(
                    args.host.as_deref(),
                    args.port.as_deref(),
                    tab.target_port.as_str(),
                );
                let mut normalized = normalize_target_inputs(
                    args.scheme.clone(),
                    args.host.clone(),
                    args.port.clone(),
                    current_target_fallback
                        .as_ref()
                        .or(tab.base_request.as_ref()),
                )?;
                if preserve_current_port {
                    normalized.port = normalize_replay_port(&tab.target_port)?;
                }
                if !normalized.scheme.is_empty() {
                    tab.target_scheme = normalized.scheme;
                }
                if !normalized.host.is_empty() {
                    tab.target_host = normalized.host;
                }
                if !normalized.port.is_empty() {
                    tab.target_port = normalized.port;
                }
                tab.response_record = None;
            }
            let snapshot = post_workspace_state(&api, &mut workspace).await?;
            let tab = find_replay_tab(&snapshot.replay, &args.tab_id)?;
            print_json(tab)
        }
        ReplayCommand::Send(args) => {
            let mut workspace = load_workspace_state(&api, args.session_id).await?;
            let tab = find_replay_tab_mut(&mut workspace.replay, &args.tab_id)?.clone();
            let parsed_request = parse_editable_raw_request_with_version(
                &tab.request_text,
                tab.base_request.as_ref(),
            )?;
            let http_version = replay_send_http_version(&tab, &parsed_request);
            let request = parsed_request.request;
            let target = replay_send_target_for_tab(&tab, &request)?;
            let replay_result = api
                .send_replay(&ReplaySendPayload {
                    session_id: workspace.session_id,
                    request: request.clone(),
                    target: target.clone(),
                    source_transaction_id: tab.source_transaction_id,
                    http_version,
                })
                .await?;
            let (record, replay_error) = match replay_result {
                ReplaySendApiResult::Success(record) => (record, None),
                ReplaySendApiResult::StoredError(body) => {
                    let record = body
                        .record
                        .context("replay failed without a stored transaction record")?;
                    (record, Some(body.error))
                }
            };

            let tab_mut = find_replay_tab_mut(&mut workspace.replay, &args.tab_id)?;
            tab_mut.base_request = Some(request.clone());
            if let Some(target) = target.as_ref() {
                tab_mut.target_scheme = target.scheme.clone();
                tab_mut.target_host = target.host.clone();
                tab_mut.target_port = target.port.clone();
            }
            tab_mut.response_record = Some(record.clone());
            tab_mut.notice = replay_error.clone().unwrap_or_default();
            let history_entry = ReplayHistoryEntryState {
                request: Some(request),
                request_text: tab_mut.request_text.clone(),
                http_version_mode: tab_mut.http_version_mode.clone(),
                response_record: Some(record.clone()),
                notice: replay_error.clone().unwrap_or_default(),
                target_scheme: tab_mut.target_scheme.clone(),
                target_host: tab_mut.target_host.clone(),
                target_port: tab_mut.target_port.clone(),
            };
            push_replay_history_entry(tab_mut, history_entry);

            let workspace_save_error = post_workspace_state(&api, &mut workspace).await.err();
            if let Some(error) = replay_error {
                print_json(&json!({ "error": error, "record": record }))?;
                if let Some(save_error) = workspace_save_error {
                    bail!(
                        "replay failed after storing transaction record: {error}; workspace state was not saved: {save_error}"
                    );
                }
                bail!("replay failed after storing transaction record: {error}");
            } else {
                print_json(&record)?;
                if let Some(save_error) = workspace_save_error {
                    bail!("replay was sent, but workspace state was not saved: {save_error}");
                }
                Ok(())
            }
        }
    }
}

async fn handle_fuzzer(api: ApiClient, command: FuzzerCommand) -> Result<()> {
    match command {
        FuzzerCommand::SetTemplate(args) => {
            let mut workspace = load_workspace_state(&api, args.session_id).await?;
            let (base_request, source_transaction_id, request_text) = resolve_request_source(
                &api,
                workspace.session_id,
                args.transaction_id,
                args.request_file,
                args.stdin,
            )
            .await?;
            let target = build_optional_target_override(
                args.scheme,
                args.host,
                args.port,
                base_request.as_ref(),
            )?;
            let target_request_authority = target
                .as_ref()
                .and(base_request.as_ref())
                .map(fuzzer_target_request_authority_for_request);
            workspace.fuzzer.base_request = base_request;
            workspace.fuzzer.source_transaction_id = source_transaction_id;
            workspace.fuzzer.target = target;
            workspace.fuzzer.target_request_authority = target_request_authority;
            workspace.fuzzer.request_text = request_text;
            workspace.fuzzer.notice.clear();
            workspace.fuzzer.attack_record = None;
            let snapshot = post_workspace_state(&api, &mut workspace).await?;
            print_json(&snapshot.fuzzer)
        }
        FuzzerCommand::SetPayloads(args) => {
            let mut workspace = load_workspace_state(&api, args.session_id).await?;
            workspace.fuzzer.payloads_text =
                read_payloads_input(args.payloads, args.file, args.stdin)?;
            workspace.fuzzer.notice.clear();
            workspace.fuzzer.attack_record = None;
            let snapshot = post_workspace_state(&api, &mut workspace).await?;
            print_json(&snapshot.fuzzer)
        }
        FuzzerCommand::Run(args) => {
            let mut workspace = load_workspace_state(&api, args.session_id).await?;
            let parsed_template = parse_editable_raw_request_with_version(
                &workspace.fuzzer.request_text,
                workspace.fuzzer.base_request.as_ref(),
            )?;
            let target =
                fuzzer_active_target_for_request(&workspace.fuzzer, &parsed_template.request);
            let template = parsed_template.request;
            let payloads = split_payload_lines(&workspace.fuzzer.payloads_text);
            if payloads.is_empty() {
                bail!("fuzzer payloads are empty");
            }

            let record: FuzzerAttackRecord = api
                .post_json_long(
                    "/api/fuzzer/attacks",
                    &FuzzerRunPayload {
                        session_id: workspace.session_id,
                        template,
                        payloads,
                        source_transaction_id: workspace.fuzzer.source_transaction_id,
                        http_version: parsed_template.http_version,
                        target,
                    },
                )
                .await?;
            workspace.fuzzer.attack_record = Some(record.clone());
            workspace.fuzzer.notice.clear();
            let workspace_save_error = post_workspace_state(&api, &mut workspace).await.err();

            if args.r#async {
                print_json(&json!({
                    "async_requested": true,
                    "message": "Fuzzer attack completed. The current Sniper API creates attacks synchronously, so the CLI waits until the server returns the attack record.",
                    "attack": record,
                }))?;
            } else {
                print_json(&record)?;
            }
            if let Some(save_error) = workspace_save_error {
                bail!("fuzzer attack completed, but workspace state was not saved: {save_error}");
            }
            ensure_cli_record_not_failed("fuzzer attack", &record)?;
            Ok(())
        }
        FuzzerCommand::Status(args) => {
            let session_id = resolve_session_id_arg(&api, args.session_id).await?;
            let record: FuzzerAttackRecord = api
                .get_json(&session_query_path(
                    &format!("/api/fuzzer/attacks/{}", args.id),
                    session_id,
                ))
                .await?;
            print_json(&json!({
                "id": record.id,
                "status": record.status,
                "started_at": record.started_at,
                "completed_at": record.completed_at,
                "payload_count": record.payload_count,
                "result_count": record.results.len(),
                "marker_count": record.marker_count,
            }))
        }
        FuzzerCommand::Results(args) => {
            let session_id = resolve_session_id_arg(&api, args.session_id).await?;
            let record: FuzzerAttackRecord = api
                .get_json(&session_query_path(
                    &format!("/api/fuzzer/attacks/{}", args.id),
                    session_id,
                ))
                .await?;
            print_json(&record)
        }
        FuzzerCommand::List(args) => {
            let mut params = Vec::new();
            let session_id = resolve_session_id_arg(&api, args.session_id).await?;
            if let Some(session_id) = session_id {
                params.push(("session_id".to_string(), session_id.to_string()));
            }
            if let Some(limit) = args.limit {
                params.push(("limit".to_string(), limit.to_string()));
            }
            let query = encode_query(params);
            let path = if query.is_empty() {
                "/api/fuzzer/attacks".to_string()
            } else {
                format!("/api/fuzzer/attacks?{query}")
            };
            let attacks: Vec<serde_json::Value> = api.get_json(&path).await?;
            print_json(&attacks)
        }
    }
}

async fn handle_intercept(api: ApiClient, command: InterceptCommand) -> Result<()> {
    match command {
        InterceptCommand::On(args) => {
            let session_id = resolve_session_id_arg(&api, args.session_id).await?;
            let runtime: RuntimeSettingsSnapshot = api
                .post_json(
                    "/api/runtime",
                    &RuntimeUpdatePayload {
                        session_id,
                        intercept_enabled: Some(true),
                        websocket_capture_enabled: None,
                        scope_patterns: None,
                    },
                )
                .await?;
            print_json(&runtime)
        }
        InterceptCommand::Off(args) => {
            let session_id = resolve_session_id_arg(&api, args.session_id).await?;
            let runtime: RuntimeSettingsSnapshot = api
                .post_json(
                    "/api/runtime",
                    &RuntimeUpdatePayload {
                        session_id,
                        intercept_enabled: Some(false),
                        websocket_capture_enabled: None,
                        scope_patterns: None,
                    },
                )
                .await?;
            print_json(&runtime)
        }
        InterceptCommand::List(args) => {
            let session_id = resolve_session_id_arg(&api, args.session_id).await?;
            let path = session_query_path("/api/intercepts", session_id);
            let intercepts: Vec<InterceptSummary> = api.get_json(&path).await?;
            print_json(&intercepts)
        }
        InterceptCommand::Forward(args) => {
            let session_id = resolve_session_id_arg(&api, args.session_id).await?;
            let detail_path =
                session_query_path(&format!("/api/intercepts/{}", args.id), session_id);
            let intercept: InterceptRecord = api.get_json(&detail_path).await?;
            let request = if args.request_file.is_some() || args.stdin {
                read_raw_request_input(args.request_file, args.stdin, Some(&intercept.request))?
                    .0
                    .request
            } else {
                intercept.request
            };
            let action_path =
                session_query_path(&format!("/api/intercepts/{}/forward", args.id), session_id);
            api.post_status(&action_path, &InterceptForwardPayload { request })
                .await?;
            print_json(&InterceptActionResult {
                ok: true,
                action: "forward",
                id: args.id,
            })
        }
        InterceptCommand::Drop(args) => {
            let session_id = resolve_session_id_arg(&api, args.session_id).await?;
            let path = session_query_path(&format!("/api/intercepts/{}/drop", args.id), session_id);
            api.post_status(&path, &json!({})).await?;
            print_json(&InterceptActionResult {
                ok: true,
                action: "drop",
                id: args.id,
            })
        }
    }
}

async fn handle_websocket(api: ApiClient, command: WebSocketCommand) -> Result<()> {
    match command {
        WebSocketCommand::List(args) => {
            let mut params = Vec::new();
            let session_id = resolve_session_id_arg(&api, args.session_id).await?;
            if let Some(session_id) = session_id {
                params.push(("session_id".to_string(), session_id.to_string()));
            }
            if let Some(limit) = args.limit {
                params.push(("limit".to_string(), limit.to_string()));
            }
            let query = encode_query(params);
            let path = if query.is_empty() {
                "/api/websockets".to_string()
            } else {
                format!("/api/websockets?{query}")
            };
            let websockets: WebSocketListResponse = api.get_json(&path).await?;
            print_json(&websockets.into_cli_output(args.page))
        }
        WebSocketCommand::Get(args) => {
            let session_id = resolve_session_id_arg(&api, args.session_id).await?;
            let websocket: WebSocketSessionRecord = api
                .get_json(&session_query_path(
                    &format!("/api/websockets/{}", args.id),
                    session_id,
                ))
                .await?;
            print_json(&websocket)
        }
    }
}

async fn handle_auto_replace(api: ApiClient, command: AutoReplaceCommand) -> Result<()> {
    match command {
        AutoReplaceCommand::List(args) => {
            let session_id = resolve_session_id_arg(&api, args.session_id).await?;
            let path = session_query_path("/api/match-replace", session_id);
            let rules: Vec<MatchReplaceRule> = api.get_json(&path).await?;
            print_json(&rules)
        }
        AutoReplaceCommand::Set(args) => {
            let session_id = resolve_session_id_arg(&api, args.session_id).await?;
            let raw = read_text_input(args.file, args.stdin)?;
            let parsed: AutoReplaceInput = serde_json::from_str(&raw).context(
                "failed to parse auto-replace JSON; expected either an array of rules or {\"rules\": [...]}",
            )?;
            let payload = match parsed {
                AutoReplaceInput::Rules(rules) => MatchReplaceRulesPayload { rules },
                AutoReplaceInput::Payload(payload) => payload,
            };
            let path = session_query_path("/api/match-replace", session_id);
            let rules: Vec<MatchReplaceRule> = api.post_json(&path, &payload).await?;
            print_json(&rules)
        }
    }
}

async fn handle_response_intercept(
    api: ApiClient,
    command: ResponseInterceptCommand,
) -> Result<()> {
    match command {
        ResponseInterceptCommand::List(args) => {
            let session_id = resolve_session_id_arg(&api, args.session_id).await?;
            let path = session_query_path("/api/response-intercepts", session_id);
            let items: Vec<ResponseInterceptSummary> = api.get_json(&path).await?;
            print_json(&items)
        }
        ResponseInterceptCommand::Get(args) => {
            let session_id = resolve_session_id_arg(&api, args.session_id).await?;
            let path =
                session_query_path(&format!("/api/response-intercepts/{}", args.id), session_id);
            let item: ResponseInterceptRecord = api.get_json(&path).await?;
            print_json(&item)
        }
        ResponseInterceptCommand::Forward(args) => {
            let session_id = resolve_session_id_arg(&api, args.session_id).await?;
            let detail_path =
                session_query_path(&format!("/api/response-intercepts/{}", args.id), session_id);
            let item: ResponseInterceptRecord = api.get_json(&detail_path).await?;
            let response = if args.response_file.is_some() || args.stdin {
                read_raw_response_input(args.response_file, args.stdin, Some(&item.response))?
            } else {
                item.response
            };
            let action_path = session_query_path(
                &format!("/api/response-intercepts/{}/forward", args.id),
                session_id,
            );
            api.post_status(&action_path, &ResponseInterceptForwardPayload { response })
                .await?;
            print_json(&InterceptActionResult {
                ok: true,
                action: "forward",
                id: args.id,
            })
        }
        ResponseInterceptCommand::Drop(args) => {
            let session_id = resolve_session_id_arg(&api, args.session_id).await?;
            let path = session_query_path(
                &format!("/api/response-intercepts/{}/drop", args.id),
                session_id,
            );
            api.post_status(&path, &json!({})).await?;
            print_json(&InterceptActionResult {
                ok: true,
                action: "drop",
                id: args.id,
            })
        }
        ResponseInterceptCommand::ForwardAll(args) => {
            let session_id = resolve_session_id_arg(&api, args.session_id).await?;
            let path = session_query_path("/api/response-intercepts/forward-all", session_id);
            api.post_status(&path, &json!({})).await?;
            print_json(&json!({ "ok": true, "action": "forward-all" }))
        }
    }
}

async fn handle_intercept_rule(api: ApiClient, command: InterceptRuleCommand) -> Result<()> {
    match command {
        InterceptRuleCommand::List(args) => {
            let session_id = resolve_session_id_arg(&api, args.session_id).await?;
            let path = session_query_path("/api/intercept-rules", session_id);
            let rules: Vec<InterceptRule> = api.get_json(&path).await?;
            print_json(&rules)
        }
        InterceptRuleCommand::Create(args) => {
            let session_id = resolve_session_id_arg(&api, args.session_id).await?;
            let _explicit_all = args.all;
            let rule = json!({
                "id": Uuid::new_v4(),
                "enabled": args.enabled.unwrap_or(true),
                "scope": args.scope,
                "host_pattern": args.host_pattern.unwrap_or_default(),
                "path_pattern": args.path_pattern.unwrap_or_default(),
                "method_filter": if args.method_filter.is_empty() { vec![] } else { args.method_filter },
            });
            let path = session_query_path("/api/intercept-rules", session_id);
            api.post_status(&path, &rule).await?;
            print_json(&rule)
        }
        InterceptRuleCommand::Delete(args) => {
            let session_id = resolve_session_id_arg(&api, args.session_id).await?;
            let path = session_query_path(&format!("/api/intercept-rules/{}", args.id), session_id);
            api.delete_status(&path).await?;
            print_json(&json!({ "ok": true, "deleted": args.id }))
        }
    }
}

async fn handle_sequence(api: ApiClient, command: SequenceCommand) -> Result<()> {
    match command {
        SequenceCommand::List(args) => {
            let session_id = resolve_session_id_arg(&api, args.session_id).await?;
            let path = session_query_path("/api/sequences", session_id);
            let defs: Vec<SequenceDefinition> = api.get_json(&path).await?;
            print_json(&defs)
        }
        SequenceCommand::Get(args) => {
            let session_id = resolve_session_id_arg(&api, args.session_id).await?;
            let path = session_query_path(&format!("/api/sequences/{}", args.id), session_id);
            let def: SequenceDefinition = api.get_json(&path).await?;
            print_json(&def)
        }
        SequenceCommand::Create(args) => {
            let SequenceCreateArgs {
                file,
                stdin,
                session_id,
            } = args;
            let raw = read_text_input(file, stdin)?;
            let input: SequenceCreateInput =
                serde_json::from_str(&raw).context("failed to parse sequence JSON")?;
            if session_id.is_some() && input.session_id.is_some() && session_id != input.session_id
            {
                bail!("sequence JSON session_id conflicts with --session-id");
            }
            let target_session_id = session_id.or(input.session_id);
            let session_id = resolve_session_id_arg(&api, target_session_id).await?;
            let def = input.definition;
            api.post_status(
                "/api/sequences",
                &SequenceUpsertPayload {
                    session_id,
                    definition: &def,
                },
            )
            .await?;
            print_json(&def)
        }
        SequenceCommand::Run(args) => {
            let session_id = resolve_session_id_arg(&api, args.session_id).await?;
            let result: serde_json::Value = api
                .post_json_long(
                    &format!("/api/sequences/{}/run", args.id),
                    &SessionIdPayload { session_id },
                )
                .await?;
            print_json(&result)?;
            ensure_json_status_not_failed("sequence run", &result)?;
            Ok(())
        }
        SequenceCommand::RunGet(args) => {
            let session_id = resolve_session_id_arg(&api, args.session_id).await?;
            let path = session_query_path(&format!("/api/sequence-runs/{}", args.id), session_id);
            let run: SequenceRunRecord = api.get_json(&path).await?;
            print_json(&run)
        }
        SequenceCommand::Delete(args) => {
            let session_id = resolve_session_id_arg(&api, args.session_id).await?;
            let path = session_query_path(&format!("/api/sequences/{}", args.id), session_id);
            api.delete_status(&path).await?;
            print_json(&json!({ "ok": true, "deleted": args.id }))
        }
        SequenceCommand::Runs(args) => {
            let session_id = resolve_session_id_arg(&api, args.session_id).await?;
            let mut params = Vec::new();
            if let Some(limit) = args.limit {
                params.push(("limit".to_string(), limit.to_string()));
            }
            let query = encode_query(params);
            let base_path = if query.is_empty() {
                "/api/sequence-runs".to_string()
            } else {
                format!("/api/sequence-runs?{query}")
            };
            let path = session_query_path(&base_path, session_id);
            let runs: Vec<SequenceRunSummary> = api.get_json(&path).await?;
            print_json(&runs)
        }
    }
}

async fn handle_oast(api: ApiClient, command: OastCommand) -> Result<()> {
    match command {
        OastCommand::Status(args) => {
            let session_id = resolve_session_id_arg(&api, args.session_id).await?;
            let path = session_query_path("/api/oast/status", session_id);
            let status: serde_json::Value = api.get_json(&path).await?;
            print_json(&status)
        }
        OastCommand::List(args) => {
            let session_id = resolve_session_id_arg(&api, args.session_id).await?;
            let mut params = Vec::new();
            if let Some(session_id) = session_id {
                params.push(("session_id".to_string(), session_id.to_string()));
            }
            if let Some(limit) = args.limit {
                params.push(("limit".to_string(), limit.to_string()));
            }
            let query = encode_query(params);
            let path = if query.is_empty() {
                "/api/oast/callbacks".to_string()
            } else {
                format!("/api/oast/callbacks?{query}")
            };
            let callbacks: Vec<serde_json::Value> = api.get_json(&path).await?;
            print_json(&callbacks)
        }
        OastCommand::Get(args) => {
            let session_id = resolve_session_id_arg(&api, args.session_id).await?;
            let path = session_query_path(&format!("/api/oast/callbacks/{}", args.id), session_id);
            let cb: serde_json::Value = api.get_json(&path).await?;
            print_json(&cb)
        }
        OastCommand::Generate(args) => {
            let session_id = resolve_session_id_arg(&api, args.session_id).await?;
            let path = session_query_path("/api/oast/generate", session_id);
            let result: serde_json::Value = api
                .request_json::<(), serde_json::Value>(reqwest::Method::POST, &path, None)
                .await?;
            print_json(&result)
        }
        OastCommand::Clear(args) => {
            let session_id = resolve_session_id_arg(&api, args.session_id).await?;
            let path = session_query_path("/api/oast/callbacks/clear", session_id);
            api.post_status(&path, &serde_json::json!({})).await?;
            print_json(&serde_json::json!({"status": "cleared"}))
        }
        OastCommand::Configure(args) => {
            let session_id = resolve_session_id_arg(&api, args.session_id).await?;
            let mut update = serde_json::Map::new();
            if let Some(session_id) = session_id {
                update.insert("session_id".into(), serde_json::json!(session_id));
            }
            if let Some(provider) = args.provider {
                update.insert("oast_provider".into(), serde_json::Value::String(provider));
            }
            if let Some(url) = args.url {
                update.insert("oast_server_url".into(), serde_json::Value::String(url));
            }
            if let Some(token) = args.token {
                update.insert("oast_token".into(), serde_json::Value::String(token));
            }
            if let Some(interval) = args.interval {
                update.insert(
                    "oast_polling_interval_secs".into(),
                    serde_json::json!(interval),
                );
            }
            if args.enable {
                update.insert("oast_enabled".into(), serde_json::Value::Bool(true));
            }
            if args.disable {
                update.insert("oast_enabled".into(), serde_json::Value::Bool(false));
            }
            if update.len() == usize::from(session_id.is_some()) {
                // Just show current settings
                let path = session_query_path("/api/runtime", session_id);
                let runtime: serde_json::Value = api.get_json(&path).await?;
                print_json(&oast_fields_for_output(runtime))
            } else {
                let result: serde_json::Value = api
                    .post_json("/api/runtime", &serde_json::Value::Object(update))
                    .await?;
                print_json(&oast_fields_for_output(result))
            }
        }
    }
}

struct ReplayOpenInput {
    session_id: Option<Uuid>,
    transaction_id: Option<Uuid>,
    request_file: Option<PathBuf>,
    stdin: bool,
    scheme: Option<String>,
    host: Option<String>,
    port: Option<String>,
}

async fn open_replay_tab(api: &ApiClient, input: ReplayOpenInput) -> Result<ReplayTabState> {
    let ReplayOpenInput {
        session_id,
        transaction_id,
        request_file,
        stdin,
        scheme,
        host,
        port,
    } = input;
    let mut workspace = load_workspace_state(api, session_id).await?;
    let (base_request, source_transaction_id, request_text) = resolve_request_source(
        api,
        workspace.session_id,
        transaction_id,
        request_file,
        stdin,
    )
    .await?;
    let normalized = normalize_target_inputs(scheme, host, port, base_request.as_ref())?;
    let sequence = workspace.replay.tab_sequence + 1;
    let tab = ReplayTabState {
        id: Uuid::new_v4().to_string(),
        sequence,
        base_request,
        source_transaction_id,
        notice: String::new(),
        request_text,
        response_record: None,
        target_scheme: normalized.scheme,
        target_host: normalized.host,
        target_port: normalized.port,
        history_entries: Vec::new(),
        history_index: None,
        ..Default::default()
    };
    workspace.replay.tab_sequence = sequence;
    workspace.replay.active_tab_id = Some(tab.id.clone());
    workspace.replay.tabs.push(tab.clone());
    let snapshot = post_workspace_state(api, &mut workspace).await?;
    let tab = find_replay_tab(&snapshot.replay, &tab.id)?;
    Ok(tab.clone())
}

fn replay_tab_target_as_request(tab: &ReplayTabState) -> Option<EditableRequest> {
    let scheme = tab.target_scheme.trim();
    let host = tab.target_host.trim();
    let port = tab.target_port.trim();
    if scheme.is_empty() || host.is_empty() {
        return None;
    }
    let default_port = default_port_for_scheme(scheme).to_string();
    let host = if port.is_empty() || port == default_port {
        host.to_string()
    } else {
        let port = normalize_replay_port(port).ok()?.parse::<u16>().ok()?;
        format_request_authority(host, Some(port))
    };
    Some(EditableRequest {
        scheme: scheme.to_string(),
        host,
        method: "GET".to_string(),
        path: "/".to_string(),
        headers: Vec::new(),
        body: String::new(),
        body_encoding: BodyEncoding::Utf8,
        preview_truncated: false,
    })
}

fn push_replay_history_entry(tab: &mut ReplayTabState, entry: ReplayHistoryEntryState) {
    if let Some(index) = tab.history_index {
        if !tab.history_entries.is_empty() {
            let normalized_index = index.min(tab.history_entries.len() - 1);
            tab.history_entries.truncate(normalized_index + 1);
        }
    }
    tab.history_entries.push(entry);
    if tab.history_entries.len() > CLI_REPEATER_HISTORY_LIMIT {
        let overflow = tab.history_entries.len() - CLI_REPEATER_HISTORY_LIMIT;
        tab.history_entries.drain(0..overflow);
    }
    tab.history_index = tab.history_entries.len().checked_sub(1);
}

fn replay_update_should_preserve_current_port(
    host: Option<&str>,
    port: Option<&str>,
    current_port: &str,
) -> bool {
    if port.is_some_and(|value| !value.trim().is_empty()) || current_port.trim().is_empty() {
        return false;
    }
    let Some(host) = host.map(str::trim).filter(|value| !value.is_empty()) else {
        return true;
    };
    if host.starts_with("http://") || host.starts_with("https://") {
        return false;
    }
    split_host_port(host).is_none()
}

async fn resolve_request_source(
    api: &ApiClient,
    session_id: Option<Uuid>,
    transaction_id: Option<Uuid>,
    request_file: Option<PathBuf>,
    stdin: bool,
) -> Result<(Option<EditableRequest>, Option<Uuid>, String)> {
    if let Some(transaction_id) = transaction_id {
        let record: TransactionRecord = api
            .get_json(&transaction_detail_path(transaction_id, session_id))
            .await?;
        let request = record.editable_request();
        let request_text =
            build_editable_raw_request_with_version(&request, record.http_version.as_deref());
        return Ok((Some(request), Some(transaction_id), request_text));
    }

    if request_file.is_some() || stdin {
        let (parsed, request_text) = read_raw_request_input(request_file, stdin, None)?;
        return Ok((Some(parsed.request), None, request_text));
    }

    let request = default_editable_request();
    let request_text = build_editable_raw_request(&request);
    Ok((Some(request), None, request_text))
}

fn transaction_detail_path(transaction_id: Uuid, session_id: Option<Uuid>) -> String {
    match session_id {
        Some(session_id) => {
            let query = encode_query(vec![("session_id".to_string(), session_id.to_string())]);
            format!("/api/transactions/{transaction_id}?{query}")
        }
        None => format!("/api/transactions/{transaction_id}"),
    }
}

fn session_query_path(path: &str, session_id: Option<Uuid>) -> String {
    match session_id {
        Some(session_id) => {
            let query = encode_query(vec![("session_id".to_string(), session_id.to_string())]);
            let separator = if path.contains('?') { '&' } else { '?' };
            format!("{path}{separator}{query}")
        }
        None => path.to_string(),
    }
}

fn default_editable_request() -> EditableRequest {
    EditableRequest {
        scheme: "https".to_string(),
        host: "example.com".to_string(),
        method: "GET".to_string(),
        path: "/".to_string(),
        headers: vec![HeaderRecord {
            name: "host".to_string(),
            value: "example.com".to_string(),
        }],
        body: String::new(),
        body_encoding: BodyEncoding::Utf8,
        preview_truncated: false,
    }
}

fn normalize_target_inputs(
    scheme: Option<String>,
    host: Option<String>,
    port: Option<String>,
    fallback: Option<&EditableRequest>,
) -> Result<NormalizedTarget> {
    let requested_scheme = scheme
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty());
    let requested_host = host
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let requested_port = port
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(|value| normalize_replay_port(&value))
        .transpose()?;
    let fallback_scheme = fallback
        .map(|request| request.scheme.clone())
        .unwrap_or_else(|| "https".to_string());
    let fallback_scheme = validate_replay_scheme(&fallback_scheme)?;
    let fallback_host = fallback
        .map(|request| strip_host_port(&request.host).to_string())
        .unwrap_or_default();
    let fallback_explicit_port = fallback
        .and_then(|request| extract_port(&request.host))
        .and_then(|port| normalize_replay_port(&port).ok());

    let mut scheme = requested_scheme
        .clone()
        .unwrap_or_else(|| fallback_scheme.clone());
    let mut host = requested_host.clone().unwrap_or(fallback_host);
    let mut parsed_host_port = None;
    let mut host_url_without_port = false;

    if is_absolute_http_url(&host) {
        let parsed =
            Url::parse(&host).with_context(|| format!("invalid replay target URL: {host}"))?;
        if !parsed.username().is_empty()
            || parsed.password().is_some()
            || (parsed.path() != "/" && !parsed.path().is_empty())
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            bail!("replay target URL must not include path, query, fragment, or credentials");
        }
        let url_scheme = parsed.scheme().to_ascii_lowercase();
        if let Some(requested_scheme) = requested_scheme.as_deref() {
            if requested_scheme != url_scheme {
                bail!(
                    "replay target URL scheme conflicts with --scheme: URL uses {url_scheme}, --scheme uses {requested_scheme}"
                );
            }
        }
        scheme = url_scheme;
        host = parsed
            .host_str()
            .ok_or_else(|| anyhow!("replay target URL is missing a host"))?
            .to_string();
        if let Some(url_port) = parsed.port() {
            parsed_host_port = Some(normalize_replay_port(&url_port.to_string())?);
        } else {
            host_url_without_port = true;
        }
    } else if let Some((parsed_host, parsed_port)) = split_host_port(&host.clone()) {
        host = parsed_host.to_string();
        parsed_host_port = Some(normalize_replay_port(parsed_port)?);
    }

    let scheme = validate_replay_scheme(&scheme)?;
    validate_replay_target_host(&host)?;
    let scheme_changed_from_fallback = requested_scheme.is_some() && scheme != fallback_scheme;
    if let (Some(requested_port), Some(parsed_host_port)) =
        (requested_port.as_deref(), parsed_host_port.as_deref())
    {
        if requested_port != parsed_host_port {
            bail!(
                "replay target URL port conflicts with --port: URL uses {parsed_host_port}, --port uses {requested_port}"
            );
        }
    }
    let port = requested_port
        .or(parsed_host_port)
        .or_else(|| {
            (!host_url_without_port && !scheme_changed_from_fallback)
                .then_some(fallback_explicit_port)
                .flatten()
        })
        .unwrap_or_else(|| default_port_for_scheme(&scheme).to_string());

    Ok(NormalizedTarget { scheme, host, port })
}

fn validate_replay_target_host(host: &str) -> Result<()> {
    let host = host.trim();
    if host.is_empty() {
        bail!("replay target host is required");
    }
    if host.chars().any(char::is_whitespace)
        || host.contains('/')
        || host.contains('\\')
        || host.contains('@')
        || host.contains('?')
        || host.contains('#')
    {
        bail!("invalid replay target host: {host}");
    }
    if host.starts_with('[') {
        let Some(end) = host.find(']') else {
            bail!("invalid replay target host: {host}");
        };
        if end != host.len() - 1 {
            bail!("replay target host must not include a port; use --port");
        }
        host[1..end]
            .parse::<IpAddr>()
            .with_context(|| format!("invalid replay target host: {host}"))?;
        return Ok(());
    }
    if host.contains(':') && host.parse::<IpAddr>().is_err() {
        bail!("replay target host must not include a port; use --port");
    }
    Ok(())
}

fn build_target_override(
    scheme: &str,
    host: &str,
    port: &str,
) -> Result<Option<RequestTargetOverride>> {
    let host = host.trim();
    if host.is_empty() {
        return Ok(None);
    }
    let port = if port.trim().is_empty() {
        default_port_for_scheme(scheme).to_string()
    } else {
        normalize_replay_port(port)?
    };

    Ok(Some(RequestTargetOverride {
        scheme: validate_replay_scheme(scheme)?,
        host: host.to_string(),
        port,
    }))
}

fn replay_tab_target_matches_request(
    tab: &ReplayTabState,
    request: Option<&EditableRequest>,
) -> Result<bool> {
    let Some(request) = request else {
        return Ok(false);
    };
    let Some(tab_target) =
        build_target_override(&tab.target_scheme, &tab.target_host, &tab.target_port)?
    else {
        return Ok(false);
    };
    let request_target = normalize_target_inputs(None, None, None, Some(request))?;
    Ok(normalized_targets_equivalent(
        &NormalizedTarget {
            scheme: tab_target.scheme,
            host: tab_target.host,
            port: tab_target.port,
        },
        &request_target,
    ))
}

fn sync_replay_tab_target_to_request(
    tab: &mut ReplayTabState,
    request: &EditableRequest,
) -> Result<()> {
    let normalized = normalize_target_inputs(None, None, None, Some(request))?;
    tab.target_scheme = normalized.scheme;
    tab.target_host = normalized.host;
    tab.target_port = normalized.port;
    Ok(())
}

fn replay_send_target_for_tab(
    tab: &ReplayTabState,
    request: &EditableRequest,
) -> Result<Option<RequestTargetOverride>> {
    let stored = build_target_override(&tab.target_scheme, &tab.target_host, &tab.target_port)?;
    if replay_tab_target_is_stale_default(tab, request, stored.as_ref())? {
        return Ok(None);
    }
    if let Some(target) = stored.as_ref() {
        let stored_target = NormalizedTarget {
            scheme: target.scheme.clone(),
            host: target.host.clone(),
            port: target.port.clone(),
        };
        let request_target = normalize_target_inputs(None, None, None, Some(request))?;
        if normalized_targets_equivalent(&stored_target, &request_target) {
            return Ok(None);
        }
    }
    Ok(stored)
}

fn replay_tab_target_is_stale_default(
    tab: &ReplayTabState,
    request: &EditableRequest,
    target: Option<&RequestTargetOverride>,
) -> Result<bool> {
    let (Some(base_request), Some(target)) = (tab.base_request.as_ref(), target) else {
        return Ok(false);
    };
    let stored = NormalizedTarget {
        scheme: target.scheme.clone(),
        host: target.host.clone(),
        port: target.port.clone(),
    };
    let base = normalize_target_inputs(None, None, None, Some(base_request))?;
    let derived = normalize_target_inputs(None, None, None, Some(request))?;
    Ok(normalized_targets_equivalent(&stored, &base)
        && !normalized_targets_equivalent(&derived, &base))
}

fn normalized_targets_equivalent(left: &NormalizedTarget, right: &NormalizedTarget) -> bool {
    if !left.scheme.eq_ignore_ascii_case(&right.scheme) {
        return false;
    }
    request_authorities_equivalent(
        &target_authority(left),
        &target_authority(right),
        &left.scheme,
    )
}

fn target_authority(target: &NormalizedTarget) -> String {
    let port = target.port.parse::<u16>().ok();
    format_request_authority(&target.host, port)
}

fn fuzzer_active_target_for_request(
    fuzzer: &FuzzerWorkspaceState,
    request: &EditableRequest,
) -> Option<RequestTargetOverride> {
    let target = fuzzer.target.as_ref()?;
    if let Some(saved_authority) = fuzzer.target_request_authority.as_deref() {
        let (saved_scheme, saved_authority) = parse_saved_fuzzer_target_authority(saved_authority)?;
        if !saved_scheme.eq_ignore_ascii_case(&request.scheme) {
            return None;
        }
        if !request_authorities_equivalent(&saved_authority, &request.host, &request.scheme) {
            return None;
        }
    }
    let target_normalized = normalize_target_inputs(
        Some(target.scheme.clone()),
        Some(target.host.clone()),
        Some(target.port.clone()),
        Some(request),
    )
    .ok()?;
    let request_target = normalize_target_inputs(None, None, None, Some(request)).ok()?;
    if normalized_targets_equivalent(&target_normalized, &request_target) {
        return None;
    }
    Some(target.clone())
}

fn fuzzer_target_request_authority_for_request(request: &EditableRequest) -> String {
    format!("{}://{}", request.scheme, request.host.trim())
}

fn parse_saved_fuzzer_target_authority(value: &str) -> Option<(String, String)> {
    let parsed = Url::parse(value.trim()).ok()?;
    let scheme = parsed.scheme().to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return None;
    }
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || (parsed.path() != "/" && !parsed.path().is_empty())
    {
        return None;
    }
    let host = parsed.host_str()?;
    Some((scheme, format_request_authority(host, parsed.port())))
}

fn validate_replay_scheme(scheme: &str) -> Result<String> {
    let normalized = scheme.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "http" | "https" => Ok(normalized),
        _ => bail!("unsupported replay target scheme: {scheme}"),
    }
}

fn build_optional_target_override(
    scheme: Option<String>,
    host: Option<String>,
    port: Option<String>,
    fallback: Option<&EditableRequest>,
) -> Result<Option<RequestTargetOverride>> {
    let has_override = [&scheme, &host, &port].iter().any(|value| {
        value
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
    });
    if !has_override {
        return Ok(None);
    }

    let normalized = normalize_target_inputs(scheme, host, port, fallback)?;
    build_target_override(&normalized.scheme, &normalized.host, &normalized.port)
}

fn normalize_replay_port(port: &str) -> Result<String> {
    let port = port.trim();
    let parsed = port
        .parse::<u16>()
        .with_context(|| format!("invalid replay target port: {port}"))?;
    if parsed == 0 {
        bail!("invalid replay target port: {port}");
    }
    Ok(parsed.to_string())
}

fn split_payload_lines(payloads_text: &str) -> Vec<String> {
    if payloads_text.is_empty() {
        return Vec::new();
    }
    let mut lines = payloads_text.split('\n').collect::<Vec<_>>();
    if payloads_text.ends_with('\n') {
        lines.pop();
    }
    lines
        .into_iter()
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
        .map(ToOwned::to_owned)
        .collect()
}

fn read_payloads_input(
    payloads: Vec<String>,
    file: Option<PathBuf>,
    stdin: bool,
) -> Result<String> {
    if !payloads.is_empty() {
        let mut text = payloads.join("\n");
        if payloads.last().is_some_and(|payload| payload.is_empty()) {
            text.push('\n');
        }
        return Ok(text);
    }

    if file.is_some() || stdin {
        return read_text_input(file, stdin);
    }

    bail!("provide payloads with --payload, --file, or --stdin")
}

fn read_lines_input(
    patterns: Vec<String>,
    file: Option<PathBuf>,
    stdin: bool,
) -> Result<Vec<String>> {
    if !patterns.is_empty() {
        return Ok(patterns);
    }
    let text = if file.is_some() || stdin {
        read_text_input(file, stdin)?
    } else {
        String::new()
    };
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect())
}

fn read_text_input(file: Option<PathBuf>, stdin: bool) -> Result<String> {
    let bytes = read_bytes_input(file, stdin)?;
    String::from_utf8(bytes).context("input is not valid UTF-8")
}

fn read_bytes_input(file: Option<PathBuf>, stdin: bool) -> Result<Vec<u8>> {
    if let Some(file) = file {
        return read_file_bytes_limited(&file);
    }

    if stdin {
        let mut stdin = io::stdin();
        return read_limited_to_end(&mut stdin, "stdin", MAX_CLI_INPUT_BYTES);
    }

    bail!("expected --file or --stdin")
}

fn read_file_bytes_limited(file: &PathBuf) -> Result<Vec<u8>> {
    let metadata =
        fs::metadata(file).with_context(|| format!("failed to inspect {}", file.display()))?;
    if !metadata.is_file() {
        bail!("{} is not a regular file", file.display());
    }
    if metadata.len() > MAX_CLI_INPUT_BYTES as u64 {
        bail!(
            "{} cannot exceed {} bytes",
            file.display(),
            MAX_CLI_INPUT_BYTES
        );
    }
    let mut handle =
        fs::File::open(file).with_context(|| format!("failed to read {}", file.display()))?;
    read_limited_to_end(
        &mut handle,
        &format!("{}", file.display()),
        MAX_CLI_INPUT_BYTES,
    )
}

fn read_limited_to_end<R: Read>(reader: &mut R, label: &str, limit: usize) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    reader
        .take(limit.saturating_add(1) as u64)
        .read_to_end(&mut buf)
        .with_context(|| format!("failed to read {label}"))?;
    if buf.len() > limit {
        bail!("{label} cannot exceed {limit} bytes");
    }
    Ok(buf)
}

fn read_raw_request_input(
    file: Option<PathBuf>,
    stdin: bool,
    fallback: Option<&EditableRequest>,
) -> Result<(ParsedEditableRequest, String)> {
    let bytes = read_bytes_input(file, stdin)?;
    ensure_raw_http_input_not_empty(&bytes, "request")?;
    let parsed = parse_editable_raw_request_bytes_with_version(&bytes, fallback)?;
    let request_text = if parsed.request.body_encoding == BodyEncoding::Utf8 {
        String::from_utf8(bytes.clone()).unwrap_or_else(|_| {
            build_editable_raw_request_with_version(&parsed.request, parsed.http_version.as_deref())
        })
    } else {
        build_editable_raw_request_with_version(&parsed.request, parsed.http_version.as_deref())
    };
    Ok((parsed, request_text))
}

fn read_raw_response_input(
    file: Option<PathBuf>,
    stdin: bool,
    fallback: Option<&EditableResponse>,
) -> Result<EditableResponse> {
    let bytes = read_bytes_input(file, stdin)?;
    ensure_raw_http_input_not_empty(&bytes, "response")?;
    parse_editable_raw_response_bytes(&bytes, fallback)
}

fn ensure_raw_http_input_not_empty(bytes: &[u8], label: &str) -> Result<()> {
    if bytes.is_empty() || bytes.iter().all(u8::is_ascii_whitespace) {
        bail!("{label} input is empty");
    }
    Ok(())
}

async fn discover_api_base_url(
    cli_api: Option<String>,
    client: &reqwest::Client,
) -> Result<String> {
    if let Some(api) = cli_api {
        return Ok(normalize_api_base_url(&api));
    }

    if let Ok(api) = env::var("SNIPER_API_ADDR") {
        if !api.trim().is_empty() {
            return Ok(normalize_api_base_url(&api));
        }
    }

    let data_dir = default_data_dir();
    let runtime_state = load_runtime_state(&data_dir).with_context(|| {
        format!(
            "failed to read Sniper runtime-state; it may be mid-update or stale at {}",
            data_dir.display()
        )
    })?;
    if let Some(runtime_state) = runtime_state {
        let url = runtime_state.api_base_url();
        if probe_sniper_api_base_url(&url, client).await.is_ok() {
            return Ok(url);
        }
        // Probe failed — stale runtime-state
        bail!(
            "Sniper API at {} is not responding (stale runtime-state from {}). \
             Either start Sniper Desktop or pass --api http://HOST:PORT explicitly.",
            runtime_state.ui_addr,
            runtime_state.updated_at.format("%Y-%m-%d %H:%M:%S")
        )
    }

    bail!("could not discover Sniper API address; pass --api or start sniper-desktop first")
}

async fn probe_sniper_api_base_url(url: &str, client: &reqwest::Client) -> Result<()> {
    let response = client
        .get(format!("{url}/api/settings"))
        .timeout(std::time::Duration::from_secs(2))
        .send()
        .await
        .with_context(|| format!("failed to probe Sniper API at {url}"))?;
    let status = response.status();
    if !status.is_success() {
        bail!("Sniper API probe returned {status}");
    }
    let payload: serde_json::Value = response
        .json()
        .await
        .context("Sniper API probe response was not JSON")?;
    if !sniper_settings_probe_matches(&payload) {
        bail!("Sniper API probe response did not match the expected /api/settings schema");
    }
    Ok(())
}

fn sniper_settings_probe_matches(payload: &serde_json::Value) -> bool {
    let features = payload
        .get("features")
        .and_then(serde_json::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    payload
        .get("proxy_addr")
        .is_some_and(serde_json::Value::is_string)
        && payload
            .get("ui_addr")
            .is_some_and(serde_json::Value::is_string)
        && payload
            .get("data_dir")
            .is_some_and(serde_json::Value::is_string)
        && payload
            .get("max_entries")
            .is_some_and(serde_json::Value::is_number)
        && features.contains(&"http_capture")
        && features.contains(&"session_storage")
        && features.contains(&"replay")
}

fn normalize_api_base_url(raw: &str) -> String {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else {
        format!("http://{trimmed}")
    }
}

fn build_editable_raw_request(request: &EditableRequest) -> String {
    build_editable_raw_request_with_version(request, None)
}

fn build_editable_raw_request_with_version(
    request: &EditableRequest,
    http_version: Option<&str>,
) -> String {
    let mut headers = request.headers.clone();
    let has_host = headers
        .iter()
        .any(|header| header.name.eq_ignore_ascii_case("host"));
    if !has_host && !request.host.trim().is_empty() {
        headers.insert(
            0,
            HeaderRecord {
                name: "host".to_string(),
                value: request.host.clone(),
            },
        );
    }
    if !request.body.is_empty() {
        let body_len = request
            .try_body_bytes()
            .map(|body| body.len())
            .unwrap_or_else(|_| request.body.len());
        normalize_content_length_for_raw_editor(&mut headers, body_len);
    }

    let mut lines = Vec::with_capacity(headers.len() + 2);
    let path = if request.path.trim().is_empty() {
        "/"
    } else {
        request.path.as_str()
    };
    let http_version = normalize_http_version(http_version).unwrap_or("HTTP/1.1");
    lines.push(format!(
        "{} {} {}",
        request.method.trim(),
        path,
        http_version
    ));
    lines.extend(
        headers
            .iter()
            .map(|header| format!("{}: {}", header.name, header.value)),
    );
    let head = lines.join("\n");
    if request.body.is_empty() {
        head.trim_end().to_string()
    } else {
        format!("{}\n\n{}", head, request.body)
    }
}

fn normalize_content_length_for_raw_editor(headers: &mut Vec<HeaderRecord>, body_len: usize) {
    let mut updated = Vec::with_capacity(headers.len());
    let mut saw_content_length = false;
    for mut header in headers.drain(..) {
        if header.name.eq_ignore_ascii_case("content-length") {
            if saw_content_length {
                continue;
            }
            header.value = body_len.to_string();
            saw_content_length = true;
        }
        updated.push(header);
    }
    *headers = updated;
}

#[derive(Debug)]
struct ParsedEditableRequest {
    request: EditableRequest,
    http_version: Option<String>,
}

enum RawRequestBody {
    Text(String),
    Bytes(Vec<u8>),
}

impl RawRequestBody {
    fn wire_len(&self, body_encoding: Option<&BodyEncoding>, label: &str) -> Result<usize> {
        match self {
            Self::Bytes(value) => Ok(value.len()),
            Self::Text(value) if matches!(body_encoding, Some(BodyEncoding::Base64)) => STANDARD
                .decode(value)
                .map(|body| body.len())
                .with_context(|| format!("{label} body is not valid base64")),
            Self::Text(value) => Ok(value.len()),
        }
    }
}

#[cfg(test)]
fn parse_editable_raw_request(
    text: &str,
    fallback: Option<&EditableRequest>,
) -> Result<EditableRequest> {
    Ok(parse_editable_raw_request_with_version(text, fallback)?.request)
}

fn parse_editable_raw_request_with_version(
    text: &str,
    fallback: Option<&EditableRequest>,
) -> Result<ParsedEditableRequest> {
    let (head, body) = split_raw_http_message(text);
    parse_editable_raw_request_parts(head, RawRequestBody::Text(body), fallback)
}

fn parse_editable_raw_request_bytes_with_version(
    bytes: &[u8],
    fallback: Option<&EditableRequest>,
) -> Result<ParsedEditableRequest> {
    let (head, body) = split_raw_http_message_bytes(bytes)?;
    parse_editable_raw_request_parts(head, RawRequestBody::Bytes(body), fallback)
}

fn parse_editable_raw_request_parts(
    head: String,
    raw_body: RawRequestBody,
    fallback: Option<&EditableRequest>,
) -> Result<ParsedEditableRequest> {
    let mut lines = head.lines();
    let fallback_start_line = fallback.map(|request| {
        format!(
            "{} {} HTTP/1.1",
            request.method,
            if request.path.trim().is_empty() {
                "/"
            } else {
                request.path.as_str()
            }
        )
    });
    let start_line = lines
        .next()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .or(fallback_start_line)
        .unwrap_or_else(|| "GET / HTTP/1.1".to_string());

    let mut start_parts = start_line.split_whitespace();
    let method = start_parts
        .next()
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| "GET".to_string());
    if !is_http_method_token(&method) {
        bail!("invalid HTTP method: {method}");
    }
    let target = start_parts.next().unwrap_or("/");
    let raw_http_version = start_parts.next();
    if start_parts.next().is_some() {
        bail!("invalid request line: too many fields");
    }
    let http_version = match raw_http_version {
        Some(value) => Some(
            normalize_http_version(Some(value))
                .map(str::to_string)
                .ok_or_else(|| anyhow!("unsupported HTTP version: {value}"))?,
        ),
        None => None,
    };

    let mut scheme = fallback
        .map(|request| request.scheme.clone())
        .unwrap_or_else(|| "https".to_string());
    let mut host = fallback
        .map(|request| request.host.clone())
        .unwrap_or_default();
    let mut absolute_target_authority: Option<String> = None;
    let mut path;
    let mut absolute_form = false;

    if is_absolute_http_url(target) {
        let parsed = Url::parse(target)
            .with_context(|| format!("request target is not a valid URL: {target}"))?;
        if !parsed.username().is_empty() || parsed.password().is_some() {
            bail!("absolute request target must not include credentials");
        }
        if parsed.fragment().is_some() {
            bail!("absolute request target must not include a fragment");
        }
        absolute_form = true;
        scheme = parsed.scheme().to_ascii_lowercase();
        let parsed_host = parsed
            .host_str()
            .ok_or_else(|| anyhow!("request target is missing a host"))?
            .to_string();
        let parsed_port = parsed.port();
        host = format_request_authority(&parsed_host, parsed_port);
        absolute_target_authority = Some(host.clone());
        path = format!(
            "{}{}",
            parsed.path(),
            parsed
                .query()
                .map(|value| format!("?{value}"))
                .unwrap_or_default()
        );
    } else {
        path = target.to_string();
    }

    let headers: Vec<HeaderRecord> = lines
        .map(|line| {
            let line = line.trim_end();
            if line.is_empty() {
                return Ok(None);
            }
            let (name, value) = line
                .split_once(':')
                .ok_or_else(|| anyhow!("invalid request header line: {line}"))?;
            Ok(Some(HeaderRecord {
                name: name.trim().to_string(),
                value: value.trim().to_string(),
            }))
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect();
    validate_raw_request_host_headers(&headers)?;
    let inferred_text_encoding = match &raw_body {
        RawRequestBody::Text(body) => infer_text_body_encoding(
            &headers,
            body,
            fallback.map(|request| &request.body_encoding),
        )?,
        RawRequestBody::Bytes(_) => None,
    };
    let body_len = raw_body.wire_len(inferred_text_encoding.as_ref(), "request")?;
    validate_raw_http_body_framing(&headers, body_len)?;

    let (body, body_encoding) = match raw_body {
        RawRequestBody::Text(body) => (body, inferred_text_encoding.unwrap_or(BodyEncoding::Utf8)),
        RawRequestBody::Bytes(body) => {
            let content_type = headers
                .iter()
                .find(|header| header.name.eq_ignore_ascii_case("content-type"))
                .map(|header| header.value.as_str());
            encode_raw_request_body(content_type, &body)
        }
    };

    if let Some(host_header) = headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("host"))
    {
        if absolute_form {
            let target_host = absolute_target_authority.as_deref().unwrap_or(host.trim());
            let header_host = host_header.value.trim();
            if !request_authorities_equivalent(target_host, header_host, &scheme) {
                bail!(
                    "absolute request target host {target_host} does not match Host header {header_host}"
                );
            }
        } else {
            host = host_header.value.clone();
        }
    }

    if host.trim().is_empty() {
        bail!("request is missing a Host header");
    }

    if method == "CONNECT" {
        bail!("CONNECT authority-form requests are not supported by Replay");
    }

    if path != "*" && !path.starts_with('/') {
        path = format!("/{path}");
    }

    let preview_truncated = fallback.is_some_and(|request| {
        request.preview_truncated && request.body == body && request.body_encoding == body_encoding
    });
    let request = EditableRequest {
        scheme,
        host,
        method,
        path,
        headers,
        body,
        body_encoding,
        preview_truncated,
    };
    request
        .try_body_bytes()
        .context("request body is not valid base64")?;
    Ok(ParsedEditableRequest {
        request,
        http_version,
    })
}

fn is_http_method_token(method: &str) -> bool {
    !method.trim().is_empty() && method.bytes().all(is_http_token_byte)
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

fn is_absolute_http_url(value: &str) -> bool {
    let value = value.trim_start();
    value
        .get(..7)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("http://"))
        || value
            .get(..8)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("https://"))
}

fn validate_raw_request_host_headers(headers: &[HeaderRecord]) -> Result<()> {
    let host_count = headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("host"))
        .count();
    if host_count > 1 {
        bail!("raw request must not include multiple Host headers");
    }
    Ok(())
}

fn infer_text_body_encoding(
    headers: &[HeaderRecord],
    body: &str,
    fallback_encoding: Option<&BodyEncoding>,
) -> Result<Option<BodyEncoding>> {
    if matches!(fallback_encoding, Some(BodyEncoding::Base64)) {
        return Ok(Some(BodyEncoding::Base64));
    }

    let Some(expected_len) = declared_content_length(headers)? else {
        return Ok(fallback_encoding.cloned());
    };
    if expected_len == body.len() {
        return Ok(fallback_encoding.cloned());
    }
    if fallback_encoding.is_none() {
        if let Ok(decoded) = STANDARD.decode(body) {
            if decoded.len() == expected_len {
                return Ok(Some(BodyEncoding::Base64));
            }
        }
    }
    Ok(fallback_encoding.cloned())
}

fn validate_raw_http_body_framing(headers: &[HeaderRecord], body_len: usize) -> Result<()> {
    if headers.iter().any(|header| {
        header.name.eq_ignore_ascii_case("transfer-encoding")
            && header
                .value
                .split(',')
                .any(|value| value.trim().eq_ignore_ascii_case("chunked"))
    }) {
        bail!("raw HTTP input with Transfer-Encoding: chunked is not supported");
    }

    if let Some(expected) = declared_content_length(headers)? {
        if expected != body_len {
            bail!("Content-Length {expected} does not match raw body length {body_len}");
        }
    }
    Ok(())
}

fn declared_content_length(headers: &[HeaderRecord]) -> Result<Option<usize>> {
    let mut content_length: Option<usize> = None;
    for header in headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("content-length"))
    {
        let parsed = header
            .value
            .trim()
            .parse::<usize>()
            .with_context(|| format!("invalid Content-Length: {}", header.value))?;
        if let Some(previous) = content_length {
            if previous != parsed {
                bail!("conflicting Content-Length headers");
            }
        }
        content_length = Some(parsed);
    }
    Ok(content_length)
}

fn split_raw_http_message(text: &str) -> (String, String) {
    if let Some(index) = text.find("\r\n\r\n") {
        return (
            text[..index].replace("\r\n", "\n"),
            text[index + 4..].to_string(),
        );
    }
    if let Some(index) = text.find("\n\n") {
        return (
            text[..index].replace("\r\n", "\n"),
            text[index + 2..].to_string(),
        );
    }
    (text.replace("\r\n", "\n"), String::new())
}

fn split_raw_http_message_bytes(bytes: &[u8]) -> Result<(String, Vec<u8>)> {
    let (head, body) =
        if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            (&bytes[..index], bytes[index + 4..].to_vec())
        } else if let Some(index) = bytes.windows(2).position(|window| window == b"\n\n") {
            (&bytes[..index], bytes[index + 2..].to_vec())
        } else {
            (bytes, Vec::new())
        };
    let head = std::str::from_utf8(head)
        .context("request headers are not valid UTF-8")?
        .replace("\r\n", "\n");
    Ok((head, body))
}

fn encode_raw_request_body(content_type: Option<&str>, body: &[u8]) -> (String, BodyEncoding) {
    if is_textual_raw_request_body(content_type, body) {
        (
            String::from_utf8(body.to_vec()).unwrap_or_default(),
            BodyEncoding::Utf8,
        )
    } else {
        (STANDARD.encode(body), BodyEncoding::Base64)
    }
}

fn is_textual_raw_request_body(content_type: Option<&str>, sample: &[u8]) -> bool {
    if sample.is_empty() {
        return true;
    }

    let valid_utf8 = std::str::from_utf8(sample).is_ok() && !sample.contains(&0);
    if let Some(content_type) = content_type {
        let normalized = content_type.to_ascii_lowercase();
        if normalized.starts_with("text/")
            || normalized.contains("json")
            || normalized.contains("xml")
            || normalized.contains("javascript")
            || normalized.contains("x-www-form-urlencoded")
            || normalized.contains("graphql")
            || normalized.contains("yaml")
        {
            return valid_utf8;
        }
    }

    valid_utf8
}

fn normalize_http_version(value: Option<&str>) -> Option<&'static str> {
    let normalized = value?.trim().to_ascii_uppercase();
    match normalized.as_str() {
        "HTTP/1.0" | "1.0" => Some("HTTP/1.0"),
        "HTTP/1.1" | "1.1" => Some("HTTP/1.1"),
        "HTTP/2" | "HTTP/2.0" | "2" | "2.0" => Some("HTTP/2"),
        _ => None,
    }
}

fn replay_send_http_version(
    tab: &ReplayTabState,
    parsed_request: &ParsedEditableRequest,
) -> Option<String> {
    parsed_request
        .http_version
        .clone()
        .or_else(|| normalize_http_version(Some(&tab.http_version_mode)).map(str::to_string))
}

fn encode_query(params: Vec<(String, String)>) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in params {
        serializer.append_pair(&key, &value);
    }
    serializer.finish()
}

fn print_json<T: Serialize>(value: &T) -> Result<()> {
    let mut stdout = io::stdout().lock();
    serde_json::to_writer_pretty(&mut stdout, value).context("failed to encode JSON output")?;
    stdout.write_all(b"\n").context("failed to write stdout")
}

fn ensure_cli_record_not_failed<T: Serialize>(label: &str, value: &T) -> Result<()> {
    let value = serde_json::to_value(value).context("failed to inspect JSON status")?;
    ensure_json_status_not_failed(label, &value)
}

fn ensure_json_status_not_failed(label: &str, value: &Value) -> Result<()> {
    if value.get("status").and_then(Value::as_str) == Some("failed") {
        bail!("{label} failed");
    }
    Ok(())
}

fn find_replay_tab<'a>(
    replay: &'a ReplayWorkspaceState,
    tab_id: &str,
) -> Result<&'a ReplayTabState> {
    replay
        .tabs
        .iter()
        .find(|tab| tab.id == tab_id)
        .ok_or_else(|| anyhow!("replay tab not found: {tab_id}"))
}

fn find_replay_tab_mut<'a>(
    replay: &'a mut ReplayWorkspaceState,
    tab_id: &str,
) -> Result<&'a mut ReplayTabState> {
    replay
        .tabs
        .iter_mut()
        .find(|tab| tab.id == tab_id)
        .ok_or_else(|| anyhow!("replay tab not found: {tab_id}"))
}

fn split_host_port(value: &str) -> Option<(&str, &str)> {
    if value.starts_with('[') {
        let end = value.find(']')?;
        let remainder = value.get(end + 1..)?;
        let port = remainder.strip_prefix(':')?;
        return port
            .chars()
            .all(|char| char.is_ascii_digit())
            .then_some((&value[1..end], port));
    }
    if value.matches(':').count() != 1 {
        return None;
    }
    let (host, port) = value.rsplit_once(':')?;
    if !host.is_empty() && port.chars().all(|char| char.is_ascii_digit()) {
        Some((host, port))
    } else {
        None
    }
}

fn strip_host_port(value: &str) -> &str {
    split_host_port(value)
        .map(|(host, _)| host)
        .unwrap_or(value)
}

fn extract_port(value: &str) -> Option<String> {
    split_host_port(value).map(|(_, port)| port.to_string())
}

fn format_request_authority(host: &str, port: Option<u16>) -> String {
    let needs_brackets = host.contains(':') && !host.starts_with('[') && !host.ends_with(']');
    let authority_host = if needs_brackets {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    match port {
        Some(port) => format!("{authority_host}:{port}"),
        None => authority_host,
    }
}

fn request_authorities_equivalent(left: &str, right: &str, scheme: &str) -> bool {
    let Some((left_host, left_port)) = normalize_request_authority(left, scheme) else {
        return left.trim().eq_ignore_ascii_case(right.trim());
    };
    let Some((right_host, right_port)) = normalize_request_authority(right, scheme) else {
        return false;
    };
    left_host.eq_ignore_ascii_case(&right_host) && left_port == right_port
}

fn normalize_request_authority(authority: &str, scheme: &str) -> Option<(String, u16)> {
    let authority = authority.trim();
    if authority.is_empty() {
        return None;
    }
    if let Some((host, port)) = split_host_port(authority) {
        let port = port.parse::<u16>().ok()?;
        return Some((strip_ipv6_brackets(host).to_string(), port));
    }
    Some((
        strip_ipv6_brackets(authority).to_string(),
        default_port_for_scheme(scheme),
    ))
}

fn strip_ipv6_brackets(value: &str) -> &str {
    value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(value)
}

fn default_port_for_scheme(scheme: &str) -> u16 {
    if scheme.eq_ignore_ascii_case("http") {
        80
    } else {
        443
    }
}

fn install_skills(args: SkillsInstallArgs) -> Result<skills::SkillsInstallResult> {
    let install_codex = args.all || args.codex;
    let install_claude = args.all || args.claude;
    if !install_codex && !install_claude {
        bail!("select at least one destination with --codex, --claude, or --all");
    }

    let codex_root = install_codex.then(|| {
        args.codex_dir
            .clone()
            .unwrap_or_else(skills::default_codex_skills_dir)
    });
    let claude_root = install_claude.then(|| {
        args.claude_dir
            .clone()
            .unwrap_or_else(skills::default_claude_skills_dir)
    });
    if let (Some(codex_root), Some(claude_root)) = (&codex_root, &claude_root) {
        skills::ensure_distinct_skill_install_targets(codex_root, claude_root)?;
    }

    let mut installed = Vec::new();
    if let Some(root) = codex_root {
        let path =
            skills::install_skill_folder(&root, skills::SKILL_NAME, skills::CODEX_SKILL_TEMPLATE)?;
        installed.push(skills::InstalledSkill {
            agent: "codex",
            path: path.display().to_string(),
        });
    }
    if let Some(root) = claude_root {
        let path =
            skills::install_skill_folder(&root, skills::SKILL_NAME, skills::CLAUDE_SKILL_TEMPLATE)?;
        installed.push(skills::InstalledSkill {
            agent: "claude",
            path: path.display().to_string(),
        });
    }

    Ok(skills::SkillsInstallResult { installed })
}

struct NormalizedTarget {
    scheme: String,
    host: String,
    port: String,
}

#[cfg(test)]
fn parse_editable_raw_response(
    text: &str,
    fallback: Option<&EditableResponse>,
) -> Result<EditableResponse> {
    let (head, body) = split_raw_http_message(text);
    parse_editable_raw_response_parts(head, RawRequestBody::Text(body), fallback)
}

fn parse_editable_raw_response_bytes(
    bytes: &[u8],
    fallback: Option<&EditableResponse>,
) -> Result<EditableResponse> {
    let (head, body) = split_raw_http_message_bytes(bytes)?;
    parse_editable_raw_response_parts(head, RawRequestBody::Bytes(body), fallback)
}

fn parse_editable_raw_response_parts(
    head: String,
    raw_body: RawRequestBody,
    fallback: Option<&EditableResponse>,
) -> Result<EditableResponse> {
    let mut lines = head.lines();
    let first_line = lines.next();
    let (status, header_lines): (u16, Vec<&str>) = match first_line {
        Some(line) if line.trim().is_empty() => (
            fallback.map(|f| f.status).unwrap_or(200),
            lines.collect::<Vec<_>>(),
        ),
        Some(line) if line.trim_start().starts_with("HTTP/") => {
            let status = parse_response_status_line(line)?;
            (status, lines.collect::<Vec<_>>())
        }
        Some(line) if line.contains(':') => {
            let mut header_lines = Vec::new();
            header_lines.push(line);
            header_lines.extend(lines);
            (fallback.map(|f| f.status).unwrap_or(200), header_lines)
        }
        Some(line) => bail!("invalid response status line: {line}"),
        None => (fallback.map(|f| f.status).unwrap_or(200), Vec::new()),
    };
    let headers: Vec<HeaderRecord> = header_lines
        .into_iter()
        .map(|line| {
            let idx = line
                .find(':')
                .ok_or_else(|| anyhow!("invalid response header line: {line}"))?;
            Ok(HeaderRecord {
                name: line[..idx].trim().to_string(),
                value: line[idx + 1..].trim().to_string(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let inferred_text_encoding = match &raw_body {
        RawRequestBody::Text(body) => infer_text_body_encoding(
            &headers,
            body,
            fallback.map(|response| &response.body_encoding),
        )?,
        RawRequestBody::Bytes(_) => None,
    };
    let body_len = raw_body.wire_len(inferred_text_encoding.as_ref(), "response")?;
    validate_raw_http_body_framing(&headers, body_len)?;
    let (body, body_encoding) = match raw_body {
        RawRequestBody::Text(body) => (body, inferred_text_encoding.unwrap_or(BodyEncoding::Utf8)),
        RawRequestBody::Bytes(body) => {
            let content_type = headers
                .iter()
                .find(|header| header.name.eq_ignore_ascii_case("content-type"))
                .map(|header| header.value.as_str());
            encode_raw_request_body(content_type, &body)
        }
    };
    let response = EditableResponse {
        status,
        headers,
        body,
        body_encoding,
    };
    response
        .try_body_bytes()
        .context("response body is not valid base64")?;
    Ok(response)
}

fn parse_response_status_line(status_line: &str) -> Result<u16> {
    let mut parts = status_line.split_whitespace();
    let version = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/") {
        bail!("invalid response status line: {status_line}");
    }
    let status = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing response status code"))?
        .parse::<u16>()
        .with_context(|| format!("invalid response status code in line: {status_line}"))?;
    if !(100..=599).contains(&status) {
        bail!("response status code out of range: {status}");
    }
    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::{
        active_session_id_from_summaries, build_annotations_payload, build_editable_raw_request,
        build_editable_raw_request_with_version, default_editable_request,
        ensure_json_status_not_failed, explicit_or_active_session_id,
        fuzzer_active_target_for_request, fuzzer_target_request_authority_for_request,
        install_skills, normalize_api_base_url, normalize_replay_port, normalize_target_inputs,
        oast_fields_for_output, parse_editable_raw_request,
        parse_editable_raw_request_bytes_with_version, parse_editable_raw_request_with_version,
        parse_editable_raw_response, parse_editable_raw_response_bytes, prepare_cli_workspace_save,
        push_replay_history_entry, read_limited_to_end, read_payloads_input,
        read_raw_request_input, read_raw_response_input, read_text_input, replay_send_http_version,
        replay_tab_target_as_request, replay_tab_target_matches_request,
        replay_update_should_preserve_current_port, session_query_path,
        sniper_settings_probe_matches, split_host_port, split_payload_lines, strip_host_port,
        sync_replay_tab_target_to_request, transaction_detail_path, Cli, Command, HistoryCommand,
        HistoryListResponse, SequenceCommand, SequenceCreateInput, SkillsInstallArgs,
        WebSocketListResponse, CLI_REPEATER_HISTORY_LIMIT, MAX_CLI_INPUT_BYTES,
    };
    use chrono::Utc;
    use clap::Parser;
    use sniper::model::{
        BodyEncoding, EditableRequest, EditableResponse, HeaderRecord, RequestTargetOverride,
    };
    use sniper::session::SessionSummary;
    use sniper::skills;
    use sniper::workspace::{
        FuzzerWorkspaceState, ReplayHistoryEntryState, ReplayTabState, WorkspaceStateSnapshot,
    };
    use std::fs;
    use uuid::Uuid;

    #[test]
    fn parse_raw_request_respects_host_header() {
        let request = parse_editable_raw_request(
            "GET /hello HTTP/1.1\nHost: example.com\nUser-Agent: test\n\nbody",
            None,
        )
        .unwrap();
        assert_eq!(request.method, "GET");
        assert_eq!(request.host, "example.com");
        assert_eq!(request.path, "/hello");
        assert_eq!(request.body, "body");
    }

    #[test]
    fn transaction_detail_path_pins_session_when_available() {
        let transaction_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let session_id = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();

        assert_eq!(
            transaction_detail_path(transaction_id, Some(session_id)),
            "/api/transactions/11111111-1111-1111-1111-111111111111?session_id=22222222-2222-2222-2222-222222222222"
        );
        assert_eq!(
            transaction_detail_path(transaction_id, None),
            "/api/transactions/11111111-1111-1111-1111-111111111111"
        );
    }

    fn test_session_summary(id: Uuid, active: bool) -> SessionSummary {
        SessionSummary {
            id,
            name: "session".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_opened_at: Utc::now(),
            request_count: 0,
            websocket_count: 0,
            event_count: 0,
            fuzzer_count: 0,
            rule_count: 0,
            storage_path: String::new(),
            active,
        }
    }

    #[test]
    fn active_session_id_prefers_active_session_without_workspace_state() {
        let first = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let active = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();
        let sessions = vec![
            test_session_summary(first, false),
            test_session_summary(active, true),
        ];

        assert_eq!(active_session_id_from_summaries(&sessions), Some(active));
    }

    #[test]
    fn read_text_input_rejects_oversized_regular_file() {
        let dir = std::env::temp_dir().join(format!("sniper-cli-input-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("large.txt");
        let file = fs::File::create(&path).unwrap();
        file.set_len((MAX_CLI_INPUT_BYTES + 1) as u64).unwrap();

        let error = read_text_input(Some(path), false).unwrap_err();

        assert!(error.to_string().contains("cannot exceed"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn read_text_input_rejects_non_regular_file() {
        let dir =
            std::env::temp_dir().join(format!("sniper-cli-input-dir-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();

        let error = read_text_input(Some(dir.clone()), false).unwrap_err();

        assert!(error.to_string().contains("not a regular file"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn read_limited_to_end_rejects_streams_over_limit() {
        let mut reader = std::io::Cursor::new(vec![1, 2, 3, 4]);

        let error = read_limited_to_end(&mut reader, "fixture", 3).unwrap_err();

        assert!(error.to_string().contains("cannot exceed 3 bytes"));
    }

    #[test]
    fn active_session_id_falls_back_to_first_session() {
        let first = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let sessions = vec![test_session_summary(first, false)];

        assert_eq!(active_session_id_from_summaries(&sessions), Some(first));
        assert_eq!(active_session_id_from_summaries(&[]), None);
    }

    #[test]
    fn explicit_session_id_overrides_active_session_id() {
        let explicit = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let active = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();

        assert_eq!(
            explicit_or_active_session_id(Some(explicit), Some(active)),
            Some(explicit)
        );
        assert_eq!(
            explicit_or_active_session_id(None, Some(active)),
            Some(active)
        );
        assert_eq!(explicit_or_active_session_id(None, None), None);
    }

    #[test]
    fn session_query_path_appends_encoded_session_id() {
        let session_id = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();

        assert_eq!(
            session_query_path("/api/sequences/abc", Some(session_id)),
            "/api/sequences/abc?session_id=22222222-2222-2222-2222-222222222222"
        );
        assert_eq!(
            session_query_path("/api/sequences/abc?force=true", Some(session_id)),
            "/api/sequences/abc?force=true&session_id=22222222-2222-2222-2222-222222222222"
        );
        assert_eq!(
            session_query_path("/api/sequences/abc", None),
            "/api/sequences/abc"
        );
    }

    #[test]
    fn build_raw_request_restores_host_header() {
        let request = EditableRequest {
            scheme: "https".to_string(),
            host: "example.com".to_string(),
            method: "POST".to_string(),
            path: "/submit".to_string(),
            headers: vec![HeaderRecord {
                name: "content-type".to_string(),
                value: "application/json".to_string(),
            }],
            body: "{\"ok\":true}".to_string(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        };
        let text = build_editable_raw_request(&request);
        assert!(text.contains("Host:") || text.contains("host:"));
        assert!(text.starts_with("POST /submit HTTP/1.1"));
    }

    #[test]
    fn raw_request_parser_and_builder_preserve_method_case() {
        let parsed = parse_editable_raw_request_with_version(
            "gEt-Custom /case HTTP/1.1\nHost: example.com\n\n",
            None,
        )
        .unwrap();

        assert_eq!(parsed.request.method, "gEt-Custom");
        let text = build_editable_raw_request_with_version(
            &parsed.request,
            parsed.http_version.as_deref(),
        );
        assert!(text.starts_with("gEt-Custom /case HTTP/1.1"));
    }

    #[test]
    fn annotation_payload_only_includes_requested_fields() {
        assert_eq!(
            build_annotations_payload(Some(Some("red".to_string())), None),
            serde_json::json!({ "color_tag": "red" })
        );
        assert_eq!(
            build_annotations_payload(None, Some(None)),
            serde_json::json!({ "user_note": null })
        );
    }

    #[test]
    fn oast_output_redacts_token_and_reports_configured_state() {
        let fields = oast_fields_for_output(serde_json::json!({
            "oast_enabled": true,
            "oast_token": "secret-token",
            "oast_provider": "custom"
        }));

        assert_eq!(fields.get("oast_token"), None);
        assert_eq!(
            fields.get("oast_token_configured"),
            Some(&serde_json::json!(true))
        );
        assert_eq!(
            fields.get("oast_provider"),
            Some(&serde_json::json!("custom"))
        );
    }

    #[test]
    fn raw_request_parser_preserves_http_version() {
        let parsed = parse_editable_raw_request_with_version(
            "GET /hello HTTP/2\nHost: example.com\n\n",
            None,
        )
        .unwrap();
        assert_eq!(parsed.request.host, "example.com");
        assert_eq!(parsed.http_version.as_deref(), Some("HTTP/2"));
    }

    #[test]
    fn replay_send_prefers_request_line_http_version() {
        let parsed = parse_editable_raw_request_with_version(
            "GET /hello HTTP/1.1\nHost: example.com\n\n",
            None,
        )
        .unwrap();
        let tab = ReplayTabState {
            http_version_mode: "http/2".to_string(),
            ..Default::default()
        };

        assert_eq!(
            replay_send_http_version(&tab, &parsed).as_deref(),
            Some("HTTP/1.1")
        );
    }

    #[test]
    fn cli_status_helper_rejects_failed_records() {
        assert!(ensure_json_status_not_failed(
            "sequence run",
            &serde_json::json!({ "status": "completed" }),
        )
        .is_ok());
        assert!(ensure_json_status_not_failed(
            "sequence run",
            &serde_json::json!({ "status": "failed" }),
        )
        .is_err());
    }

    #[test]
    fn sequence_create_input_preserves_api_session_id() {
        let session_id = Uuid::new_v4();
        let sequence_id = Uuid::new_v4();
        let input: SequenceCreateInput = serde_json::from_value(serde_json::json!({
            "session_id": session_id,
            "id": sequence_id,
            "name": "demo",
            "steps": [],
        }))
        .unwrap();

        assert_eq!(input.session_id, Some(session_id));
        assert_eq!(input.definition.id, sequence_id);
    }

    #[test]
    fn raw_request_input_rejects_empty_explicit_source() {
        let path =
            std::env::temp_dir().join(format!("sniper-cli-empty-request-{}.http", Uuid::new_v4()));
        fs::write(&path, b" \n\t").unwrap();
        let fallback = default_editable_request();

        let error = read_raw_request_input(Some(path.clone()), false, Some(&fallback))
            .unwrap_err()
            .to_string();
        let _ = fs::remove_file(path);

        assert!(error.contains("request input is empty"));
    }

    #[test]
    fn raw_response_input_rejects_empty_explicit_source() {
        let path =
            std::env::temp_dir().join(format!("sniper-cli-empty-response-{}.http", Uuid::new_v4()));
        fs::write(&path, b"").unwrap();
        let fallback = EditableResponse {
            status: 200,
            headers: Vec::new(),
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
        };

        let error = read_raw_response_input(Some(path.clone()), false, Some(&fallback))
            .unwrap_err()
            .to_string();
        let _ = fs::remove_file(path);

        assert!(error.contains("response input is empty"));
    }

    #[test]
    fn raw_request_parser_preserves_fallback_truncated_preview_state() {
        let fallback = EditableRequest {
            scheme: "https".to_string(),
            host: "example.com".to_string(),
            method: "POST".to_string(),
            path: "/upload".to_string(),
            headers: vec![HeaderRecord {
                name: "host".to_string(),
                value: "example.com".to_string(),
            }],
            body: "prefix-$payload$".to_string(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: true,
        };

        let parsed = parse_editable_raw_request_with_version(
            "POST /upload HTTP/1.1\nHost: example.com\n\nprefix-$payload$",
            Some(&fallback),
        )
        .unwrap();

        assert!(parsed.request.preview_truncated);
    }

    #[test]
    fn raw_request_parser_preserves_absolute_form_authority() {
        let request = parse_editable_raw_request(
            "GET http://target.example:8080/admin HTTP/1.1\nHost: target.example:8080\n\n",
            None,
        )
        .unwrap();

        assert_eq!(request.scheme, "http");
        assert_eq!(request.host, "target.example:8080");
        assert_eq!(request.path, "/admin");
    }

    #[test]
    fn raw_request_parser_accepts_mixed_case_absolute_form_url() {
        let request = parse_editable_raw_request(
            "GET HtTpS://target.example/admin HTTP/1.1\nHost: target.example\n\n",
            None,
        )
        .unwrap();

        assert_eq!(request.scheme, "https");
        assert_eq!(request.host, "target.example");
        assert_eq!(request.path, "/admin");
    }

    #[test]
    fn raw_request_parser_accepts_absolute_form_default_port_equivalence() {
        let request = parse_editable_raw_request(
            "GET http://target.example/admin HTTP/1.1\nHost: target.example:80\n\n",
            None,
        )
        .unwrap();

        assert_eq!(request.scheme, "http");
        assert_eq!(request.host, "target.example");
        assert_eq!(request.path, "/admin");
    }

    #[test]
    fn raw_request_parser_preserves_ipv6_absolute_form_authority() {
        let request = parse_editable_raw_request(
            "GET http://[::1]:8080/admin HTTP/1.1\nHost: [::1]:8080\n\n",
            None,
        )
        .unwrap();

        assert_eq!(request.scheme, "http");
        assert_eq!(request.host, "[::1]:8080");
        assert_eq!(request.path, "/admin");
    }

    #[test]
    fn raw_request_parser_rejects_conflicting_absolute_form_host() {
        let error = parse_editable_raw_request(
            "GET http://target.example:8080/admin HTTP/1.1\nHost: attacker.example\n\n",
            None,
        )
        .unwrap_err();

        assert!(error.to_string().contains("does not match Host header"));
    }

    #[test]
    fn raw_request_parser_rejects_duplicate_host_headers() {
        let error = parse_editable_raw_request(
            "GET /dup HTTP/1.1\nHost: first.example\nHost: second.example\n\n",
            None,
        )
        .unwrap_err();

        assert!(error.to_string().contains("multiple Host headers"));
    }

    #[test]
    fn raw_request_parser_rejects_absolute_form_credentials_and_fragments() {
        let credentials = parse_editable_raw_request(
            "GET http://user:pass@target.example/admin HTTP/1.1\nHost: target.example\n\n",
            None,
        )
        .unwrap_err();
        assert!(credentials.to_string().contains("credentials"));

        let fragment = parse_editable_raw_request(
            "GET http://target.example/admin#frag HTTP/1.1\nHost: target.example\n\n",
            None,
        )
        .unwrap_err();
        assert!(fragment.to_string().contains("fragment"));
    }

    #[test]
    fn raw_http_parser_rejects_unsupported_framing() {
        let chunked = parse_editable_raw_request(
            "POST /upload HTTP/1.1\nHost: example.com\nTransfer-Encoding: chunked\n\n4\nbody\n0\n\n",
            None,
        )
        .unwrap_err();
        assert!(chunked.to_string().contains("Transfer-Encoding: chunked"));

        let bad_length = parse_editable_raw_request(
            "POST /upload HTTP/1.1\nHost: example.com\nContent-Length: 2\n\nbody",
            None,
        )
        .unwrap_err();
        assert!(bad_length
            .to_string()
            .contains("does not match raw body length"));

        let chunked_response = parse_editable_raw_response(
            "HTTP/1.1 200 OK\nTransfer-Encoding: chunked\n\n4\nbody\n0\n\n",
            None,
        )
        .unwrap_err();
        assert!(chunked_response
            .to_string()
            .contains("Transfer-Encoding: chunked"));
    }

    #[test]
    fn fuzzer_target_is_cleared_when_saved_authority_is_stale() {
        let request = EditableRequest {
            scheme: "https".to_string(),
            host: "current.example".to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            headers: Vec::new(),
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        };
        let fuzzer = FuzzerWorkspaceState {
            target: Some(RequestTargetOverride {
                scheme: "https".to_string(),
                host: "override.example".to_string(),
                port: "443".to_string(),
            }),
            target_request_authority: Some("https://old.example".to_string()),
            ..Default::default()
        };

        assert!(fuzzer_active_target_for_request(&fuzzer, &request).is_none());
    }

    #[test]
    fn fuzzer_target_survives_matching_saved_authority() {
        let request = EditableRequest {
            scheme: "https".to_string(),
            host: "current.example:443".to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            headers: Vec::new(),
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        };
        let fuzzer = FuzzerWorkspaceState {
            target: Some(RequestTargetOverride {
                scheme: "https".to_string(),
                host: "override.example".to_string(),
                port: "443".to_string(),
            }),
            target_request_authority: Some("https://current.example".to_string()),
            ..Default::default()
        };

        let target = fuzzer_active_target_for_request(&fuzzer, &request).unwrap();
        assert_eq!(target.host, "override.example");
    }

    #[test]
    fn fuzzer_target_survives_missing_saved_authority_for_legacy_workspace() {
        let request = EditableRequest {
            scheme: "https".to_string(),
            host: "current.example".to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            headers: Vec::new(),
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        };
        let fuzzer = FuzzerWorkspaceState {
            target: Some(RequestTargetOverride {
                scheme: "https".to_string(),
                host: "override.example".to_string(),
                port: "443".to_string(),
            }),
            target_request_authority: None,
            ..Default::default()
        };

        let target = fuzzer_active_target_for_request(&fuzzer, &request).unwrap();
        assert_eq!(target.host, "override.example");
    }

    #[test]
    fn fuzzer_target_with_missing_saved_authority_still_skips_equivalent_target() {
        let request = EditableRequest {
            scheme: "https".to_string(),
            host: "current.example:443".to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            headers: Vec::new(),
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        };
        let fuzzer = FuzzerWorkspaceState {
            target: Some(RequestTargetOverride {
                scheme: "https".to_string(),
                host: "current.example".to_string(),
                port: "443".to_string(),
            }),
            target_request_authority: None,
            ..Default::default()
        };

        assert!(fuzzer_active_target_for_request(&fuzzer, &request).is_none());
    }

    #[test]
    fn fuzzer_target_is_cleared_when_saved_authority_is_invalid() {
        let request = EditableRequest {
            scheme: "https".to_string(),
            host: "current.example".to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            headers: Vec::new(),
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        };
        let fuzzer = FuzzerWorkspaceState {
            target: Some(RequestTargetOverride {
                scheme: "https".to_string(),
                host: "override.example".to_string(),
                port: "443".to_string(),
            }),
            target_request_authority: Some("not a url".to_string()),
            ..Default::default()
        };

        assert!(fuzzer_active_target_for_request(&fuzzer, &request).is_none());
    }

    #[test]
    fn fuzzer_target_authority_persistence_uses_request_authority() {
        let request = EditableRequest {
            scheme: "https".to_string(),
            host: "current.example:8443".to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            headers: Vec::new(),
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        };

        assert_eq!(
            fuzzer_target_request_authority_for_request(&request),
            "https://current.example:8443"
        );
    }

    #[test]
    fn raw_request_parser_preserves_asterisk_form_target() {
        let request =
            parse_editable_raw_request("OPTIONS * HTTP/1.1\nHost: example.com\n\n", None).unwrap();

        assert_eq!(request.method, "OPTIONS");
        assert_eq!(request.path, "*");
    }

    #[test]
    fn raw_request_parser_rejects_connect_authority_form() {
        let error = parse_editable_raw_request(
            "CONNECT example.com:443 HTTP/1.1\nHost: example.com:443\n\n",
            None,
        )
        .unwrap_err();

        assert!(error.to_string().contains("CONNECT authority-form"));
    }

    #[test]
    fn raw_request_parser_rejects_extra_request_line_tokens() {
        let error =
            parse_editable_raw_request("GET / HTTP/1.1 trailing\nHost: example.com\n\n", None)
                .unwrap_err();

        assert!(error.to_string().contains("too many fields"));
    }

    #[test]
    fn raw_request_parser_rejects_malformed_header_lines() {
        let error =
            parse_editable_raw_request("GET / HTTP/1.1\nNot-A-Header\n\n", None).unwrap_err();

        assert!(error.to_string().contains("invalid request header line"));
    }

    #[test]
    fn raw_request_parser_rejects_invalid_method_tokens() {
        let error =
            parse_editable_raw_request("GE/T / HTTP/1.1\nHost: example.com\n\n", None).unwrap_err();

        assert!(error.to_string().contains("invalid HTTP method"));
    }

    #[test]
    fn raw_request_parser_preserves_body_crlf() {
        let request = parse_editable_raw_request(
            "POST /hello HTTP/1.1\r\nHost: example.com\r\n\r\na\r\nb",
            None,
        )
        .unwrap();
        assert_eq!(request.body, "a\r\nb");
    }

    #[test]
    fn raw_request_byte_parser_encodes_binary_body_as_base64() {
        let parsed = parse_editable_raw_request_bytes_with_version(
          b"POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/octet-stream\r\n\r\n\xff\x00",
            None,
        )
        .unwrap();

        assert_eq!(parsed.request.host, "example.com");
        assert_eq!(parsed.request.body_encoding, BodyEncoding::Base64);
        assert_eq!(parsed.request.body, "/wA=");
        assert_eq!(parsed.request.try_body_bytes().unwrap(), vec![0xff, 0x00]);
    }

    #[test]
    fn binary_raw_request_rebuild_updates_content_length_for_editor_body() {
        let parsed = parse_editable_raw_request_bytes_with_version(
            b"POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/octet-stream\r\nContent-Length: 2\r\n\r\n\xff\x00",
            None,
        )
        .unwrap();

        let text = build_editable_raw_request_with_version(
            &parsed.request,
            parsed.http_version.as_deref(),
        );
        assert!(text.contains("Content-Length: 2"));
        let reparsed = parse_editable_raw_request_with_version(&text, None)
            .expect("rebuilt binary request should parse without hidden fallback state");

        assert_eq!(reparsed.request.body_encoding, BodyEncoding::Base64);
        assert_eq!(reparsed.request.try_body_bytes().unwrap(), vec![0xff, 0x00]);
    }

    #[test]
    fn binary_raw_request_parser_rejects_encoded_content_length() {
        let fallback = EditableRequest {
            scheme: "https".to_string(),
            host: "example.com".to_string(),
            method: "POST".to_string(),
            path: "/upload".to_string(),
            headers: Vec::new(),
            body: "/wA=".to_string(),
            body_encoding: BodyEncoding::Base64,
            preview_truncated: false,
        };

        let error = parse_editable_raw_request_with_version(
            "POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\n/wA=",
            Some(&fallback),
        )
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("does not match raw body length 2"));
    }

    #[test]
    fn raw_response_parser_preserves_body_crlf() {
        let response = parse_editable_raw_response(
            "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\n\r\na\r\nb",
            None,
        )
        .unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, "a\r\nb");
    }

    #[test]
    fn raw_response_byte_parser_encodes_binary_body_as_base64() {
        let response = parse_editable_raw_response_bytes(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\n\xff\x00",
            None,
        )
        .unwrap();

        assert_eq!(response.status, 200);
        assert_eq!(response.body_encoding, BodyEncoding::Base64);
        assert_eq!(response.body, "/wA=");
        assert_eq!(response.try_body_bytes().unwrap(), vec![0xff, 0x00]);
    }

    #[test]
    fn binary_raw_response_parser_infers_base64_from_content_length() {
        let response = parse_editable_raw_response(
            "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 2\r\n\r\n/wA=",
            None,
        )
        .unwrap();

        assert_eq!(response.status, 200);
        assert_eq!(response.body_encoding, BodyEncoding::Base64);
        assert_eq!(response.try_body_bytes().unwrap(), vec![0xff, 0x00]);
    }

    #[test]
    fn build_raw_request_uses_supplied_http_version() {
        let request = EditableRequest {
            scheme: "https".to_string(),
            host: "example.com".to_string(),
            method: "POST".to_string(),
            path: "/submit".to_string(),
            headers: Vec::new(),
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        };
        let text = build_editable_raw_request_with_version(&request, Some("HTTP/2"));
        assert!(text.starts_with("POST /submit HTTP/2"));
    }

    #[test]
    fn build_raw_request_preserves_trailing_body_bytes() {
        let request = EditableRequest {
            scheme: "https".to_string(),
            host: "example.com".to_string(),
            method: "POST".to_string(),
            path: "/submit".to_string(),
            headers: Vec::new(),
            body: "abc \n\t".to_string(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        };

        let text = build_editable_raw_request(&request);
        assert!(text.ends_with("abc \n\t"));
    }

    #[test]
    fn normalize_target_defaults_port_from_final_scheme() {
        let fallback = EditableRequest {
            scheme: "https".to_string(),
            host: "example.com".to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            headers: Vec::new(),
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        };

        let target =
            normalize_target_inputs(Some("http".to_string()), None, None, Some(&fallback)).unwrap();
        assert_eq!(target.scheme, "http");
        assert_eq!(target.host, "example.com");
        assert_eq!(target.port, "80");

        let fallback_with_port = EditableRequest {
            host: "example.com:443".to_string(),
            ..fallback.clone()
        };
        let target = normalize_target_inputs(
            Some("http".to_string()),
            None,
            None,
            Some(&fallback_with_port),
        )
        .unwrap();
        assert_eq!(target.scheme, "http");
        assert_eq!(target.host, "example.com");
        assert_eq!(target.port, "80");

        let target = normalize_target_inputs(
            None,
            Some("http://other.example".to_string()),
            None,
            Some(&fallback),
        )
        .unwrap();
        assert_eq!(target.scheme, "http");
        assert_eq!(target.host, "other.example");
        assert_eq!(target.port, "80");

        let target = normalize_target_inputs(
            None,
            Some("HtTpS://mixed.example:9443".to_string()),
            None,
            Some(&fallback),
        )
        .unwrap();
        assert_eq!(target.scheme, "https");
        assert_eq!(target.host, "mixed.example");
        assert_eq!(target.port, "9443");
    }

    #[test]
    fn replay_update_partial_target_uses_current_tab_target_as_fallback() {
        let tab = ReplayTabState {
            target_scheme: "https".to_string(),
            target_host: "override.example".to_string(),
            target_port: "9443".to_string(),
            ..Default::default()
        };
        let fallback = replay_tab_target_as_request(&tab).unwrap();

        let mut target =
            normalize_target_inputs(Some("http".to_string()), None, None, Some(&fallback)).unwrap();
        if replay_update_should_preserve_current_port(None, None, tab.target_port.as_str()) {
            target.port = normalize_replay_port(&tab.target_port).unwrap();
        }

        assert_eq!(target.scheme, "http");
        assert_eq!(target.host, "override.example");
        assert_eq!(target.port, "9443");
    }

    #[test]
    fn replay_update_plain_host_preserves_current_tab_port() {
        let tab = ReplayTabState {
            target_scheme: "https".to_string(),
            target_host: "override.example".to_string(),
            target_port: "9443".to_string(),
            ..Default::default()
        };
        let fallback = replay_tab_target_as_request(&tab).unwrap();

        let mut target =
            normalize_target_inputs(None, Some("new.example".to_string()), None, Some(&fallback))
                .unwrap();
        if replay_update_should_preserve_current_port(
            Some("new.example"),
            None,
            tab.target_port.as_str(),
        ) {
            target.port = normalize_replay_port(&tab.target_port).unwrap();
        }

        assert_eq!(target.scheme, "https");
        assert_eq!(target.host, "new.example");
        assert_eq!(target.port, "9443");
    }

    #[test]
    fn replay_update_url_target_updates_scheme_host_and_port_together() {
        let tab = ReplayTabState {
            target_scheme: "https".to_string(),
            target_host: "override.example".to_string(),
            target_port: "9443".to_string(),
            ..Default::default()
        };
        let fallback = replay_tab_target_as_request(&tab).unwrap();

        let target = normalize_target_inputs(
            None,
            Some("https://new.example:8443".to_string()),
            None,
            Some(&fallback),
        )
        .unwrap();

        assert_eq!(target.scheme, "https");
        assert_eq!(target.host, "new.example");
        assert_eq!(target.port, "8443");
    }

    #[test]
    fn cli_replay_history_is_capped_like_browser_history() {
        fn entry(path: &str) -> ReplayHistoryEntryState {
            ReplayHistoryEntryState {
                request: Some(EditableRequest {
                    path: path.to_string(),
                    ..default_editable_request()
                }),
                request_text: format!("GET {path} HTTP/1.1\nHost: example.com"),
                ..Default::default()
            }
        }

        let mut tab = ReplayTabState::default();
        for index in 0..(CLI_REPEATER_HISTORY_LIMIT + 1) {
            push_replay_history_entry(&mut tab, entry(&format!("/{index}")));
        }

        assert_eq!(tab.history_entries.len(), CLI_REPEATER_HISTORY_LIMIT);
        assert_eq!(tab.history_index, Some(CLI_REPEATER_HISTORY_LIMIT - 1));
        assert_eq!(
            tab.history_entries
                .first()
                .and_then(|entry| entry.request.as_ref())
                .map(|request| request.path.as_str()),
            Some("/1")
        );
    }

    #[test]
    fn cli_replay_history_drops_forward_entries_before_append() {
        fn entry(path: &str) -> ReplayHistoryEntryState {
            ReplayHistoryEntryState {
                request: Some(EditableRequest {
                    path: path.to_string(),
                    ..default_editable_request()
                }),
                request_text: format!("GET {path} HTTP/1.1\nHost: example.com"),
                ..Default::default()
            }
        }

        let mut tab = ReplayTabState {
            history_entries: vec![entry("/old-0"), entry("/old-1"), entry("/old-2")],
            history_index: Some(0),
            ..Default::default()
        };

        push_replay_history_entry(&mut tab, entry("/new"));

        assert_eq!(tab.history_entries.len(), 2);
        assert_eq!(tab.history_index, Some(1));
        assert_eq!(
            tab.history_entries
                .last()
                .and_then(|entry| entry.request.as_ref())
                .map(|request| request.path.as_str()),
            Some("/new")
        );
    }

    #[test]
    fn normalize_target_rejects_url_components_and_host_ports() {
        assert!(normalize_target_inputs(
            None,
            Some("https://victim.test@127.0.0.1".to_string()),
            None,
            None,
        )
        .is_err());
        assert!(normalize_target_inputs(
            None,
            Some("https://example.test/path".to_string()),
            None,
            None,
        )
        .is_err());
        assert!(normalize_target_inputs(
            None,
            Some("example.test:notaport".to_string()),
            None,
            None,
        )
        .is_err());
        assert!(normalize_target_inputs(
            Some("http".to_string()),
            Some("https://example.test".to_string()),
            None,
            None,
        )
        .is_err());
    }

    #[test]
    fn normalize_target_rejects_invalid_user_supplied_ports() {
        assert!(
            normalize_target_inputs(None, Some("example.com:70000".to_string()), None, None,)
                .is_err()
        );
        assert!(normalize_target_inputs(
            None,
            Some("example.com".to_string()),
            Some("0".to_string()),
            None,
        )
        .is_err());
        assert!(normalize_target_inputs(
            None,
            Some("https://example.com:70000/".to_string()),
            None,
            None,
        )
        .is_err());
    }

    #[test]
    fn normalize_target_rejects_conflicting_host_and_explicit_ports() {
        assert!(normalize_target_inputs(
            None,
            Some("https://example.com:9443".to_string()),
            Some("443".to_string()),
            None,
        )
        .is_err());
        assert!(normalize_target_inputs(
            None,
            Some("example.com:9443".to_string()),
            Some("443".to_string()),
            None,
        )
        .is_err());
        let target = normalize_target_inputs(
            None,
            Some("https://example.com:9443".to_string()),
            Some("9443".to_string()),
            None,
        )
        .unwrap();
        assert_eq!(target.port, "9443");
    }

    #[test]
    fn normalize_target_rejects_invalid_user_supplied_scheme() {
        assert!(normalize_target_inputs(
            Some("ftp".to_string()),
            Some("example.com".to_string()),
            None,
            None,
        )
        .is_err());
    }

    #[test]
    fn replay_target_follows_raw_request_update_only_when_it_was_default() {
        let old_request = default_editable_request();
        let new_request = EditableRequest {
            host: "new.example.com".to_string(),
            headers: vec![HeaderRecord {
                name: "host".to_string(),
                value: "new.example.com".to_string(),
            }],
            ..old_request.clone()
        };
        let mut default_tab = ReplayTabState {
            base_request: Some(old_request.clone()),
            target_scheme: "https".to_string(),
            target_host: "example.com".to_string(),
            target_port: "443".to_string(),
            ..Default::default()
        };

        assert!(
            replay_tab_target_matches_request(&default_tab, default_tab.base_request.as_ref())
                .unwrap()
        );
        sync_replay_tab_target_to_request(&mut default_tab, &new_request).unwrap();
        assert_eq!(default_tab.target_host, "new.example.com");

        let custom_tab = ReplayTabState {
            base_request: Some(old_request),
            target_scheme: "https".to_string(),
            target_host: "override.example.com".to_string(),
            target_port: "443".to_string(),
            ..Default::default()
        };
        assert!(
            !replay_tab_target_matches_request(&custom_tab, custom_tab.base_request.as_ref())
                .unwrap()
        );
    }

    #[test]
    fn cli_workspace_save_rewrites_browser_client_identity() {
        let mut workspace = WorkspaceStateSnapshot {
            revision: 7,
            session_id: Some(uuid::Uuid::new_v4()),
            client_id: Some("browser-client".to_string()),
            client_version: 41,
            ..Default::default()
        };
        let session_id = workspace.session_id;

        prepare_cli_workspace_save(&mut workspace);

        assert_eq!(workspace.revision, 7);
        assert_eq!(workspace.session_id, session_id);
        assert_eq!(workspace.client_id.as_deref(), Some("sniper-cli"));
        assert_eq!(workspace.client_version, 42);
    }

    #[test]
    fn oast_configure_rejects_enable_disable_conflict() {
        assert!(Cli::try_parse_from([
            "sniper-cli",
            "capture",
            "oast",
            "configure",
            "--enable",
            "--disable",
        ])
        .is_err());
    }

    #[test]
    fn oast_configure_parses_supported_capture_path() {
        assert!(
            Cli::try_parse_from(["sniper-cli", "capture", "oast", "configure", "--enable",])
                .is_ok()
        );
    }

    #[test]
    fn history_annotate_rejects_set_and_clear_conflicts() {
        let id = Uuid::new_v4().to_string();
        assert!(Cli::try_parse_from([
            "sniper-cli",
            "history",
            "annotate",
            "--id",
            &id,
            "--color",
            "red",
            "--clear-color",
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "sniper-cli",
            "history",
            "annotate",
            "--id",
            &id,
            "--note",
            "hello",
            "--clear-note",
        ])
        .is_err());
    }

    #[test]
    fn history_list_supports_paged_and_legacy_array_shapes() {
        let item = serde_json::json!({
            "id": Uuid::new_v4(),
            "started_at": Utc::now(),
            "kind": "http",
            "sequence": 42,
            "method": "GET",
            "scheme": "https",
            "host": "history.example.test",
            "path": "/search",
            "status": 200,
            "duration_ms": 17,
            "request_bytes": 100,
            "response_bytes": 200,
            "note_count": 0,
            "has_response": true,
            "content_type": "application/json",
            "is_websocket": false,
            "has_match_replace": false,
            "has_user_note": false
        });
        let page: HistoryListResponse = serde_json::from_value(serde_json::json!({
            "items": [item.clone()],
            "total": 12,
            "filtered_total": 8,
            "hidden_connect_total": 1,
            "offset": 5,
            "limit": 1,
            "has_more": true
        }))
        .unwrap();
        let legacy_page_output = page.into_cli_output(false);
        assert_eq!(legacy_page_output[0]["host"], "history.example.test");

        let page: HistoryListResponse = serde_json::from_value(serde_json::json!({
            "items": [item.clone()],
            "total": 12,
            "filtered_total": 8,
            "hidden_connect_total": 1,
            "offset": 5,
            "limit": 1,
            "has_more": true
        }))
        .unwrap();
        let page_output = page.into_cli_output(true);
        assert_eq!(page_output["items"][0]["path"], "/search");
        assert_eq!(page_output["total"], 12);
        assert_eq!(page_output["filtered_total"], 8);
        assert_eq!(page_output["hidden_connect_total"], 1);
        assert_eq!(page_output["offset"], 5);
        assert_eq!(page_output["limit"], 1);
        assert_eq!(page_output["has_more"], true);

        let legacy: HistoryListResponse =
            serde_json::from_value(serde_json::json!([item])).unwrap();
        let legacy_output = legacy.into_cli_output(false);
        assert_eq!(legacy_output[0]["sequence"], 42);
    }

    #[test]
    fn history_list_accepts_offset_and_page_flags() {
        let parsed = Cli::try_parse_from([
            "sniper-cli",
            "history",
            "list",
            "--limit",
            "50",
            "--offset",
            "100",
            "--page",
        ])
        .unwrap();
        let Command::History {
            command: HistoryCommand::List(args),
        } = parsed.command
        else {
            panic!("expected history list");
        };
        assert_eq!(args.limit, Some(50));
        assert_eq!(args.offset, Some(100));
        assert!(args.page);
    }

    fn parse_sequence_command(args: &[&str]) -> SequenceCommand {
        let parsed = Cli::try_parse_from(args).unwrap();
        let Command::Sequence { command } = parsed.command else {
            panic!("expected sequence command");
        };
        command
    }

    #[test]
    fn sequence_commands_accept_explicit_session_id() {
        let sequence_id = "11111111-1111-1111-1111-111111111111";
        let session_id = "22222222-2222-2222-2222-222222222222";
        let expected_session_id = Uuid::parse_str(session_id).unwrap();

        match parse_sequence_command(&[
            "sniper-cli",
            "sequence",
            "list",
            "--session-id",
            session_id,
        ]) {
            SequenceCommand::List(args) => assert_eq!(args.session_id, Some(expected_session_id)),
            _ => panic!("expected sequence list"),
        }

        match parse_sequence_command(&[
            "sniper-cli",
            "sequence",
            "get",
            "--id",
            sequence_id,
            "--session-id",
            session_id,
        ]) {
            SequenceCommand::Get(args) => assert_eq!(args.session_id, Some(expected_session_id)),
            _ => panic!("expected sequence get"),
        }

        match parse_sequence_command(&[
            "sniper-cli",
            "sequence",
            "create",
            "--session-id",
            session_id,
        ]) {
            SequenceCommand::Create(args) => assert_eq!(args.session_id, Some(expected_session_id)),
            _ => panic!("expected sequence create"),
        }

        match parse_sequence_command(&[
            "sniper-cli",
            "sequence",
            "run",
            "--id",
            sequence_id,
            "--session-id",
            session_id,
        ]) {
            SequenceCommand::Run(args) => assert_eq!(args.session_id, Some(expected_session_id)),
            _ => panic!("expected sequence run"),
        }

        match parse_sequence_command(&[
            "sniper-cli",
            "sequence",
            "delete",
            "--id",
            sequence_id,
            "--session-id",
            session_id,
        ]) {
            SequenceCommand::Delete(args) => assert_eq!(args.session_id, Some(expected_session_id)),
            _ => panic!("expected sequence delete"),
        }

        match parse_sequence_command(&[
            "sniper-cli",
            "sequence",
            "runs",
            "--session-id",
            session_id,
            "--limit",
            "10",
        ]) {
            SequenceCommand::Runs(args) => {
                assert_eq!(args.session_id, Some(expected_session_id));
                assert_eq!(args.limit, Some(10));
            }
            _ => panic!("expected sequence runs"),
        }
    }

    #[test]
    fn cli_rejects_ambiguous_input_sources() {
        let id = Uuid::new_v4().to_string();
        assert!(Cli::try_parse_from([
            "sniper-cli",
            "replay",
            "open",
            "--transaction-id",
            &id,
            "--request-file",
            "request.http",
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "sniper-cli",
            "fuzzer",
            "set-template",
            "--request-file",
            "request.http",
            "--stdin",
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "sniper-cli",
            "fuzzer",
            "set-payloads",
            "--payload",
            "admin",
            "--file",
            "payloads.txt",
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "sniper-cli",
            "capture",
            "intercept",
            "forward",
            "--id",
            &id,
            "--request-file",
            "request.http",
            "--stdin",
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "sniper-cli",
            "auto-replace",
            "set",
            "--file",
            "rules.json",
            "--stdin",
        ])
        .is_err());
    }

    #[test]
    fn cli_requires_scope_source_for_set_scope() {
        assert!(Cli::try_parse_from(["sniper-cli", "scope", "set-scope"]).is_err());
        assert!(Cli::try_parse_from([
            "sniper-cli",
            "scope",
            "set-scope",
            "--pattern",
            "*.example.com",
        ])
        .is_ok());
        assert!(Cli::try_parse_from(["sniper-cli", "scope", "set-scope", "--clear"]).is_ok());
    }

    #[test]
    fn cli_requires_explicit_matcher_for_intercept_rule_create() {
        assert!(
            Cli::try_parse_from(["sniper-cli", "capture", "intercept-rule", "create",]).is_err()
        );
        assert!(Cli::try_parse_from([
            "sniper-cli",
            "capture",
            "intercept-rule",
            "create",
            "--host-pattern",
            "*.example.com",
        ])
        .is_ok());
        assert!(Cli::try_parse_from([
            "sniper-cli",
            "capture",
            "intercept-rule",
            "create",
            "--all",
        ])
        .is_ok());
    }

    #[test]
    fn cli_rejects_invalid_finite_option_values() {
        assert!(Cli::try_parse_from([
            "sniper-cli",
            "capture",
            "intercept-rule",
            "create",
            "--scope",
            "req",
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "sniper-cli",
            "capture",
            "oast",
            "configure",
            "--provider",
            "interact",
        ])
        .is_err());
        assert!(Cli::try_parse_from(["sniper-cli", "history", "list", "--limit", "0"]).is_err());
        assert!(Cli::try_parse_from(["sniper-cli", "fuzzer", "list", "--limit", "0"]).is_err());
        assert!(Cli::try_parse_from([
            "sniper-cli",
            "capture",
            "websocket",
            "list",
            "--limit",
            "0",
        ])
        .is_err());
        assert!(
            Cli::try_parse_from(["sniper-cli", "capture", "oast", "list", "--limit", "0",])
                .is_err()
        );
        assert!(Cli::try_parse_from(["sniper-cli", "sequence", "runs", "--limit", "0"]).is_err());
    }

    #[test]
    fn split_payload_lines_preserves_significant_whitespace() {
        assert_eq!(
            split_payload_lines(" admin \n\r\n\t\nvalue\r\n"),
            vec![
                " admin ".to_string(),
                "".to_string(),
                "\t".to_string(),
                "value".to_string()
            ]
        );
    }

    #[test]
    fn split_payload_lines_preserves_explicit_empty_payloads() {
        assert_eq!(split_payload_lines(""), Vec::<String>::new());
        assert_eq!(split_payload_lines("\n"), vec!["".to_string()]);
        assert_eq!(split_payload_lines("value\n"), vec!["value".to_string()]);
        assert_eq!(
            split_payload_lines("value\n\n"),
            vec!["value".to_string(), "".to_string()]
        );
    }

    #[test]
    fn read_payloads_input_encodes_trailing_empty_cli_payloads() {
        let text =
            read_payloads_input(vec!["value".to_string(), "".to_string()], None, false).unwrap();
        assert_eq!(
            split_payload_lines(&text),
            vec!["value".to_string(), "".to_string()]
        );
    }

    #[test]
    fn websocket_list_response_accepts_page_and_legacy_array_shapes() {
        let item = serde_json::json!({
            "id": Uuid::new_v4(),
            "started_at": Utc::now(),
            "closed_at": null,
            "duration_ms": null,
            "scheme": "wss",
            "host": "ws.example.test",
            "path": "/socket",
            "status": 101,
            "frame_count": 2,
            "note_count": 0
        });
        let page: WebSocketListResponse = serde_json::from_value(serde_json::json!({
            "items": [item.clone()],
            "total": 1,
            "limit": 5000,
            "has_more": false
        }))
        .unwrap();
        let legacy_page_output = page.into_cli_output(false);
        assert_eq!(legacy_page_output[0]["host"], "ws.example.test");

        let legacy: WebSocketListResponse =
            serde_json::from_value(serde_json::json!([item])).unwrap();
        let legacy_output = legacy.into_cli_output(false);
        assert_eq!(legacy_output[0]["path"], "/socket");

        let page: WebSocketListResponse = serde_json::from_value(serde_json::json!({
            "items": [item.clone()],
            "total": 1,
            "limit": 5000,
            "has_more": false
        }))
        .unwrap();
        let page_output = page.into_cli_output(true);
        assert_eq!(page_output["items"][0]["host"], "ws.example.test");
        assert_eq!(page_output["total"], 1);
        assert_eq!(page_output["limit"], 5000);
        assert_eq!(page_output["has_more"], false);
        assert!(page_output.get("offset").is_none());
    }

    #[test]
    fn host_port_splitter_handles_ipv6_addresses() {
        assert_eq!(
            split_host_port("example.com:8443"),
            Some(("example.com", "8443"))
        );
        assert_eq!(split_host_port("[::1]:8443"), Some(("::1", "8443")));
        assert_eq!(split_host_port("::1"), None);
        assert_eq!(strip_host_port("::1"), "::1");
        assert_eq!(strip_host_port("[::1]:8443"), "::1");
    }

    #[test]
    fn parse_raw_request_rejects_invalid_base64_body() {
        let fallback = EditableRequest {
            scheme: "https".to_string(),
            host: "example.com".to_string(),
            method: "POST".to_string(),
            path: "/submit".to_string(),
            headers: Vec::new(),
            body: String::new(),
            body_encoding: BodyEncoding::Base64,
            preview_truncated: false,
        };
        let error = parse_editable_raw_request(
            "POST /submit HTTP/1.1\nHost: example.com\n\nnot base64!",
            Some(&fallback),
        )
        .unwrap_err();
        assert!(error.to_string().contains("not valid base64"));
    }

    #[test]
    fn parse_raw_response_rejects_invalid_status_line() {
        let fallback = EditableResponse {
            status: 204,
            headers: Vec::new(),
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
        };

        let error =
            parse_editable_raw_response("HTTP/1.1 nope\ncontent-type: text/plain", Some(&fallback))
                .unwrap_err();
        assert!(error.to_string().contains("invalid response status code"));
    }

    #[test]
    fn raw_response_parser_rejects_malformed_header_lines() {
        let error =
            parse_editable_raw_response("HTTP/1.1 200 OK\nNot-A-Header\n\n", None).unwrap_err();

        assert!(error.to_string().contains("invalid response header line"));
    }

    #[test]
    fn normalize_api_base_accepts_host_port() {
        assert_eq!(
            normalize_api_base_url("127.0.0.1:19081"),
            "http://127.0.0.1:19081"
        );
    }

    #[test]
    fn sniper_settings_probe_requires_sniper_markers() {
        let valid = serde_json::json!({
            "proxy_addr": "127.0.0.1:18080",
            "ui_addr": "127.0.0.1:19090",
            "data_dir": "/tmp/sniper",
            "max_entries": 5000,
            "features": ["http_capture", "session_storage", "replay"]
        });
        assert!(sniper_settings_probe_matches(&valid));

        let wrong_service = serde_json::json!({
            "proxy_addr": "127.0.0.1:18080",
            "ui_addr": "127.0.0.1:19090",
            "data_dir": "/tmp/other",
            "max_entries": 5000,
            "features": ["health"]
        });
        assert!(!sniper_settings_probe_matches(&wrong_service));
    }

    #[test]
    fn codex_default_skills_dir_uses_hidden_folder() {
        let path = skills::default_codex_skills_dir();
        assert!(path.to_string_lossy().contains(".codex/skills") || path.ends_with("skills"));
    }

    #[test]
    fn claude_default_skills_dir_uses_hidden_folder() {
        let path = skills::default_claude_skills_dir();
        assert!(path.to_string_lossy().contains(".claude/skills") || path.ends_with("skills"));
    }

    #[test]
    fn install_skill_folder_writes_skill_markdown() {
        let root = std::env::temp_dir().join(format!("sniper-skill-test-{}", Uuid::new_v4()));
        let skill_dir =
            skills::install_skill_folder(&root, "sniper-operator", "# test skill\n").unwrap();
        fs::write(skill_dir.join("notes.md"), "keep me").unwrap();
        skills::install_skill_folder(&root, "sniper-operator", "# updated skill\n").unwrap();
        let skill_md = fs::read_to_string(skill_dir.join("SKILL.md")).unwrap();
        assert_eq!(skill_md, "# updated skill\n");
        assert_eq!(
            fs::read_to_string(skill_dir.join("notes.md")).unwrap(),
            "keep me"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn skills_install_all_rejects_same_destination() {
        let root = std::env::temp_dir().join(format!("sniper-skill-same-{}", Uuid::new_v4()));
        let error = install_skills(SkillsInstallArgs {
            all: true,
            codex_dir: Some(root.clone()),
            claude_dir: Some(root.clone()),
            ..SkillsInstallArgs::default()
        })
        .unwrap_err();

        assert!(error.to_string().contains("same SKILL.md path"));
        assert!(!root.join(skills::SKILL_NAME).join("SKILL.md").exists());
        let _ = fs::remove_dir_all(root);
    }
}
