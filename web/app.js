function createDefaultFilterSettings() {
  return {
    inScopeOnly: false,
    hideWithoutResponses: false,
    onlyParameterized: false,
    onlyNotes: false,
    searchTerm: "",
    regex: false,
    caseSensitive: false,
    negativeSearch: false,
    mime: {
      html: true,
      script: true,
      json: true,
      css: true,
      image: true,
      other: true,
    },
    status: {
      success: true,
      redirect: true,
      clientError: true,
      serverError: true,
      other: true,
    },
    hiddenExtensions: "png,ico,css,woff,woff2,ttf,svg,jpg,jpeg,gif",
    port: "",
    colorTags: new Set(),
  };
}

function createDefaultDisplaySettings() {
  return {
    sizePx: 12,
    theme: "charcoal",
    uiFont: "plex",
    monoFont: "jetbrains",
  };
}

function createDefaultHistoryColumnWidths() {
  return Object.fromEntries(
    Object.entries(HISTORY_COLUMN_RULES).map(([key, limits]) => [key, limits.default]),
  );
}

function createDefaultWsColumnWidths() {
  return Object.fromEntries(
    Object.entries(WS_COLUMN_RULES).filter(([, r]) => r.max > 0).map(([key, r]) => [key, r.default]),
  );
}

const DISPLAY_THEME_OPTIONS = new Set([
  "charcoal",
  "black",
  "graphite",
  "midnight",
  "slate",
  "obsidian",
  "dusk",
  "white",
  "paper",
  "snow",
  "ivory",
  "frost",
]);
const DISPLAY_UI_FONT_OPTIONS = new Set(["plex", "system", "pretendard", "notokr", "applekr", "nanumgothic"]);
const DISPLAY_MONO_FONT_OPTIONS = new Set([
  "jetbrains",
  "sfmono",
  "plexmono",
  "d2coding",
  "nanumgothiccoding",
  "notomonokr",
]);
const OAST_TOKEN_REDACTION = "********";
const HISTORY_COLUMN_RULES = {
  index: { default: 48, min: 40, max: 88 },
  host: { default: 320, min: 160, max: 720 },
  method: { default: 110, min: 90, max: 180 },
  path: { default: 420, min: 180, max: 1200 },
  status: { default: 110, min: 94, max: 180 },
  length: { default: 104, min: 82, max: 180 },
  mime: { default: 128, min: 100, max: 260 },
  notes: { default: 90, min: 74, max: 140 },
  tls: { default: 92, min: 72, max: 140 },
  started_at: { default: 176, min: 132, max: 260 },
};
const HISTORY_COLUMN_DEFS = {
  index: { label: "#", cssClass: "col-index", sortKey: "index" },
  host: { label: "Host", cssClass: "col-host", sortKey: "host" },
  method: { label: "Method", cssClass: "col-method", sortKey: "method" },
  path: { label: "URL", cssClass: "col-url", sortKey: "path" },
  status: { label: "Status", cssClass: "col-status", sortKey: "status" },
  length: { label: "Length", cssClass: "col-length col-center", sortKey: "length" },
  mime: { label: "MIME", cssClass: "col-type col-center", sortKey: "mime" },
  notes: { label: "Notes", cssClass: "col-notes", sortKey: "notes" },
  tls: { label: "TLS", cssClass: "col-tls", sortKey: "tls" },
  started_at: { label: "Time", cssClass: "col-time", sortKey: "started_at" },
};
const DEFAULT_HISTORY_COLUMN_ORDER = ["index", "host", "method", "path", "status", "length", "mime", "notes", "tls", "started_at"];
const HISTORY_TIME_FORMATTER = new Intl.DateTimeFormat("en-US", {
  month: "short",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false,
});
const HISTORY_SORT_COLLATOR = new Intl.Collator(undefined, { numeric: true, sensitivity: "base" });
const HTTP_HISTORY_PAGE_SIZE = 5000;
const HTTP_HISTORY_MAX_LOADED_ITEMS = HTTP_HISTORY_PAGE_SIZE;
const HTTP_HISTORY_BACKFILL_DELAY_MS = 80;
const HTTP_HISTORY_SCROLL_PREFETCH_ROWS = 120;
const HTTP_HISTORY_POLL_FALLBACK_MS = 30000;
const WS_REPLAY_MAX_LOADED_FRAMES = 10000;
const WS_REPLAY_MAX_RENDERED_FRAMES = 1000;
const WS_REPLAY_MAX_PERSISTED_FRAMES = 1000;
const WS_REPLAY_MAX_PERSISTED_FRAME_BODY_BYTES = 16 * 1024;
const WS_REPLAY_MAX_PERSISTED_TOTAL_FRAMES = 2000;
const WS_REPLAY_MAX_PERSISTED_TOTAL_BODY_BYTES = 24 * 1024 * 1024;
const WS_REPLAY_TRANSCRIPT_SAVE_DELAY_MS = 2000;
const WS_REPLAY_TRANSCRIPT_SAVE_MAX_WAIT_MS = 5000;
const WORKSPACE_UNLOAD_KEEPALIVE_MAX_BYTES = 60 * 1024;
const WORKSPACE_UNLOAD_WS_FRAME_BUDGET = 32;
const WORKSPACE_UNLOAD_WS_BODY_BUDGET = 32 * 1024;
const WS_REPLAY_FINAL_POLL_INTERVAL_MS = 100;
const WS_REPLAY_FINAL_POLL_TIMEOUT_MS = 2200;
const HTTP_METHOD_TOKEN_RE = /^[A-Za-z0-9!#$%&'*+.^_`|~-]+$/;
const WS_COLUMN_RULES = {
  index:       { default: 48,  min: 36,  max: 80 },
  host:        { default: 260, min: 120, max: 600 },
  path:        { default: 0,   min: 0,   max: 0 },   // flex column, not resizable
  status:      { default: 62,  min: 50,  max: 120 },
  frame_count: { default: 72,  min: 50,  max: 140 },
  duration_ms: { default: 90,  min: 60,  max: 180 },
  started_at:  { default: 150, min: 110, max: 260 },
};

const FINDINGS_COL_RULES = {
  severity: { default: 88, min: 60, max: 150 },
  category: { default: 96, min: 60, max: 180 },
  title:    { default: 200, min: 100, max: 600 },
  host:     { default: 180, min: 80, max: 500 },
  path:     { default: 260, min: 80, max: 700 },
  time:     { default: 120, min: 80, max: 260 },
};
let findingsColWidths = Object.fromEntries(
  Object.entries(FINDINGS_COL_RULES).map(([k, v]) => [k, v.default])
);
const WORKBENCH_STACK_MIN_HEIGHTS = {
  history: 140,
  messages: 180,
};
const REPEATER_HISTORY_LIMIT = 30;
const HISTORY_ROW_HEIGHT = 27;
let measuredHistoryRowHeight = HISTORY_ROW_HEIGHT;
const HISTORY_BUFFER_ROWS = 30;
const FINDINGS_ROW_HEIGHT = 27;
const FINDINGS_BUFFER_ROWS = 20;
const IMPLEMENTED_TOOLS = new Set(["dashboard", "target", "proxy", "fuzzer", "sequence", "replay", "tools", "logger"]);
const DECODER_SCRIPT_SOURCES = [
  "/decoder/lib/jquery-1.7.2.min.js",
  "/decoder/lib/cryptojs/components/core-min.js",
  "/decoder/lib/cryptojs/components/enc-base64-min.js",
  "/decoder/lib/cryptojs/components/enc-utf16-min.js",
  "/decoder/lib/cryptojs/rollups/md5.js",
  "/decoder/lib/cryptojs/rollups/sha1.js",
  "/decoder/lib/cryptojs/rollups/sha224.js",
  "/decoder/lib/cryptojs/rollups/sha256.js",
  "/decoder/lib/cryptojs/rollups/sha384.js",
  "/decoder/lib/cryptojs/rollups/sha512.js",
  "/decoder/lib/cryptojs/rollups/hmac-md5.js",
  "/decoder/lib/cryptojs/rollups/hmac-sha1.js",
  "/decoder/lib/cryptojs/rollups/hmac-sha224.js",
  "/decoder/lib/cryptojs/rollups/hmac-sha256.js",
  "/decoder/lib/cryptojs/rollups/hmac-sha384.js",
  "/decoder/lib/cryptojs/rollups/hmac-sha512.js",
  "/decoder/lib/cryptojs/rollups/aes.js",
  "/decoder/lib/cryptojs/rollups/tripledes.js",
  "/decoder/lib/cryptojs/rollups/rabbit.js",
  "/decoder/lib/cryptojs/rollups/rc4.js",
  "/decoder/lib/hash/md4.js",
  "/decoder/lib/hash/ripemd.js",
  "/decoder/lib/hash/whirpool.js",
  "/decoder/lib/hash/crc.js",
  "/decoder/lib/snov/numbers.js",
  "/decoder/lib/snov/romanconverter.js",
  "/decoder/lib/snov/rot13.js",
  "/decoder/lib/snov/ipcalc.js",
  "/decoder/lib/xmorse.min.js",
  "/decoder/lib/custom-jwt.js",
  "/decoder/lib/custom-json.js",
  "/decoder/lib/textarea.js",
  "/decoder/hasher.js",
];

function showToast(message, type = "success", durationMs = 2000) {
  const container = document.getElementById("toastContainer");
  if (!container) return;
  const toast = document.createElement("div");
  toast.className = `toast toast-${type}`;
  toast.textContent = message;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = "0";
    setTimeout(() => toast.remove(), 300);
  }, durationMs);
}

function safeDecodeBase64(value, fallback = "") {
  if (!value) return "";
  try {
    return atob(value);
  } catch (_error) {
    return fallback || value;
  }
}

function safeEncodeBase64(value) {
  try {
    return btoa(value);
  } catch (_error) {
    const bytes = new TextEncoder().encode(value || "");
    let binary = "";
    for (const byte of bytes) {
      binary += String.fromCharCode(byte);
    }
    return btoa(binary);
  }
}

function decodedBase64Length(value) {
  return atob(value || "").length;
}

function editableRequestBodyLength(body, bodyEncoding) {
  if (bodyEncoding === "base64") {
    return decodedBase64Length(body);
  }
  return new TextEncoder().encode(body || "").length;
}

function editableResponseBodyLength(bodyText, bodyEncoding) {
  if (bodyEncoding === "base64") {
    return decodedBase64Length(safeEncodeBase64(bodyText || ""));
  }
  return new TextEncoder().encode(bodyText || "").length;
}

function isBase64Text(value) {
  const normalized = String(value || "").replace(/\s+/g, "");
  if (!normalized || normalized.length % 4 !== 0) return false;
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(normalized)) return false;
  try {
    atob(normalized);
    return true;
  } catch (_error) {
    return false;
  }
}

function wsReplayBodyForSend(body, kind, bodyIsEncoded = false) {
  const messageKind = normalizeWsMessageType(kind);
  if (messageKind === "text") return body;
  return bodyIsEncoded ? String(body || "").replace(/\s+/g, "") : safeEncodeBase64(body);
}

function defaultWsPortForScheme(scheme) {
  return scheme === "ws" ? 80 : 443;
}

function jsonArray(value) {
  return Array.isArray(value) ? value : [];
}

function websocketPagePayload(value) {
  if (Array.isArray(value)) {
    return {
      items: value,
      total: value.length,
      limit: value.length,
      has_more: false,
    };
  }
  const payload = value && typeof value === "object" ? value : {};
  const items = jsonArray(payload.items);
  return {
    items,
    total: Number.isFinite(Number(payload.total)) ? Number(payload.total) : items.length,
    limit: Number.isFinite(Number(payload.limit)) ? Number(payload.limit) : items.length,
    has_more: Boolean(payload.has_more),
  };
}

function createHistoryPagingState() {
  return {
    generation: 0,
    pageSize: HTTP_HISTORY_PAGE_SIZE,
    offset: 0,
    beforeSequence: null,
    total: 0,
    filteredTotal: null,
    hasMore: true,
    loading: false,
    fullyLoaded: false,
    backfillScheduled: false,
    trimmedHeadCount: 0,
    trimmedTailCount: 0,
    hiddenConnectTotal: null,
  };
}

function createWebsocketPagingState() {
  return {
    total: 0,
    limit: 5000,
    hasMore: false,
  };
}

const state = {
  items: [],
  selectedId: null,
  selectedRecord: null,
  historyPaging: createHistoryPagingState(),
  historyDirty: false,
  historyResetScrollOnNextLoad: false,
  sessions: [],
  activeSession: null,
  selectedSessionId: null,
  sessionSortKey: "created_at",
  sessionSortDir: "desc",
  activeTool: "proxy",
  activeProxyTab: "http-history",
  activeInspectorTab: "inspector",
  inspectorCollapsed: true,
  query: "",
  method: "",
  sortKey: "index",
  sortDirection: "desc",
  settings: null,
  appVersion: null,
  runtime: null,
  _settingsLoadPending: false,
  messageViews: {
    request: "pretty",
    response: "pretty",
  },
  showOriginal: {
    request: false,
    response: false,
  },
  messageSearch: {
    request: "",
    response: "",
  },
  replayMessageSearch: {
    request: "",
    response: "",
  },
  activeMessagePane: null,
  displaySettings: createDefaultDisplaySettings(),
  historyColumnWidths: createDefaultHistoryColumnWidths(),
  historyColumnOrder: [...DEFAULT_HISTORY_COLUMN_ORDER],
  wsColumnWidths: createDefaultWsColumnWidths(),
  filterSettings: createDefaultFilterSettings(),
  targetScopeDraft: "",
  targetScopeDirty: false,
  targetScopeEditorSessionId: null,
  targetExpandedHosts: new Set(),
  intercepts: [],
  responseIntercepts: [],
  interceptRules: [],
  interceptQueueTab: "request",
  selectedInterceptId: null,
  selectedInterceptRecord: null,
  selectedResponseInterceptId: null,
  selectedResponseInterceptRecord: null,
  responseInterceptEditorSeedId: null,
  websocketSessions: [],
  websocketPaging: createWebsocketPagingState(),
  websocketQuery: "",
  websocketSortKey: "started_at",
  websocketSortDirection: "desc",
  selectedWebsocketId: null,
  selectedWebsocketRecord: null,
  selectedFrameIdx: null,
  wsKeyboardFocus: "sessions",
  replayTabs: [],
  workspaceRevision: 0,
  activeReplayTabId: null,
  replayTabSequence: 0,
  replayRenamingTabId: null,
  replayMessageViews: { request: "pretty", response: "pretty" },
  interceptEditorSeedId: null,
  interceptInScopeOnly: false,
  eventLog: [],
  matchReplaceRules: [],
  selectedMatchReplaceRuleId: null,
  targetSiteMap: [],
  oastCallbacks: [],
  selectedOastId: null,
  sequenceDefinitions: [],
  selectedSequenceId: null,
  editingSequence: null,
  sequenceSelectionGeneration: 0,
  sequenceRunGeneration: 0,
  sequenceDirty: false,
  sequenceDraftVersion: 0,
  sequenceRunResult: null,
  sequencePastRuns: [],
  fuzzerBaseRequest: null,
  fuzzerSourceTransactionId: null,
  fuzzerTarget: null,
  fuzzerTargetRequestText: null,
  fuzzerNotice: "",
  fuzzerRequestText: "",
  fuzzerPayloadsText: "",
  fuzzerAttackRecord: null,
  fuzzerRunning: false,
  fuzzerDraftVersion: 0,
  fuzzerRunToken: 0,
  oastTokenClearPending: false,
  _cachedVisibleEntries: null,
  _cachedVisibleEntriesKey: "",
  _visibleEntriesSearchCache: null,
  _historyEntries: null,
  _itemById: new Map(),
  _itemIndexById: new Map(),
  _itemsVersion: 0,
  toolsReady: false,
  workbenchHeight: null,
};

let _historyPagingGeneration = 0;
let _websocketLoadGeneration = 0;
let _websocketDetailGeneration = 0;
let _websocketDetailPendingId = null;
let _websocketDetailPendingPromise = null;
let _lastHttpHistoryFallbackPoll = Date.now();
let _interceptToggleRequestSeq = 0;

const els = {
  dashboardShell: document.getElementById("dashboardShell"),
  dashboardCurrentSessionName: document.getElementById("dashboardCurrentSessionName"),
  dashboardCurrentSessionStatus: document.getElementById("dashboardCurrentSessionStatus"),
  dashboardCurrentSessionPath: document.getElementById("dashboardCurrentSessionPath"),
  dashboardOpenStorageBtn: document.getElementById("dashboardOpenStorageBtn"),
  dashboardCurrentSessionRequests: document.getElementById("dashboardCurrentSessionRequests"),
  dashboardCurrentSessionWebsockets: document.getElementById("dashboardCurrentSessionWebsockets"),
  dashboardCurrentSessionEvents: document.getElementById("dashboardCurrentSessionEvents"),
  dashboardCurrentSessionFuzzer: document.getElementById("dashboardCurrentSessionFuzzer"),
  dashboardCurrentSessionRules: document.getElementById("dashboardCurrentSessionRules"),
  dashboardCurrentSessionCreated: document.getElementById("dashboardCurrentSessionCreated"),
  dashboardCurrentSessionOpened: document.getElementById("dashboardCurrentSessionOpened"),
  dashboardCreateSessionName: document.getElementById("dashboardCreateSessionName"),
  dashboardCreateSessionButton: document.getElementById("dashboardCreateSessionButton"),
  dashboardReloadSessionsButton: document.getElementById("dashboardReloadSessionsButton"),
  dashboardSessionsBody: document.getElementById("dashboardSessionsBody"),
  proxyStatusIndicator: document.getElementById("proxyStatusIndicator"),
  proxyStatusLabel: document.getElementById("proxyStatusLabel"),
  appVersionLabel: document.getElementById("appVersionLabel"),
  openUpdateButton: document.getElementById("openUpdateButton"),
  proxyAddr: document.getElementById("proxyAddr"),
  uiAddr: document.getElementById("uiAddr"),
  liveStatus: document.getElementById("liveStatus"),
  historyMeta: document.getElementById("historyMeta"),
  historyTable: document.getElementById("historyTable"),
  historyTableBody: document.getElementById("historyTableBody"),
  searchInput: document.getElementById("searchInput"),
  methodFilter: document.getElementById("methodFilter"),
  proxyShell: document.getElementById("proxyShell"),
  replayShell: document.getElementById("replayShell"),
  toolsShell: document.getElementById("toolsShell"),
  toolsActiveToolTitle: document.getElementById("toolsActiveToolTitle"),
  replayTabStrip: document.getElementById("replayTabStrip"),
  newReplayTabButton: document.getElementById("newReplayTabButton"),
  fuzzerShell: document.getElementById("fuzzerShell"),
  sequenceShell: document.getElementById("sequenceShell"),
  targetShell: document.getElementById("targetShell"),
  loggerShell: document.getElementById("loggerShell"),
  filterBar: document.getElementById("filterBar"),
  trafficRegion: document.getElementById("trafficRegion"),
  historyWorkbenchResizer: document.getElementById("historyWorkbenchResizer"),
  lowerWorkbench: document.getElementById("lowerWorkbench"),
  requestColumn: document.getElementById("requestColumn"),
  responseColumn: document.getElementById("responseColumn"),
  inspectorColumn: document.querySelector(".inspector-column"),
  proxySubPlaceholder: document.getElementById("proxySubPlaceholder"),
  proxySubPath: document.getElementById("proxySubPath"),
  proxySubTitle: document.getElementById("proxySubTitle"),
  proxySubDescription: document.getElementById("proxySubDescription"),
  interceptPanel: document.getElementById("interceptPanel"),
  websocketPanel: document.getElementById("websocketPanel"),
  matchReplacePanel: document.getElementById("matchReplacePanel"),
  findingsPanel: document.getElementById("findingsPanel"),
  findingsBody: document.getElementById("findingsBody"),
  findingsBadge: document.getElementById("findingsBadge"),
  findingsDetailResizer: document.getElementById("findingsDetailResizer"),
  findingsDetailPanel: document.getElementById("findingsDetailPanel"),
  findingsDetailContent: document.getElementById("findingsDetailContent"),
  findingsDetailPlaceholder: document.getElementById("findingsDetailPlaceholder"),
  findingsDetailTitle: document.getElementById("findingsDetailTitle"),
  findingsDetailSeverity: document.getElementById("findingsDetailSeverity"),
  findingsDetailCategory: document.getElementById("findingsDetailCategory"),
  findingsDetailDesc: document.getElementById("findingsDetailDesc"),
  findingsDetailJump: document.getElementById("findingsDetailJump"),
  findingsDetailClose: document.getElementById("findingsDetailClose"),
  findingsReqView: document.getElementById("findingsReqView"),
  findingsReqLines: document.getElementById("findingsReqLines"),
  findingsResView: document.getElementById("findingsResView"),
  findingsResLines: document.getElementById("findingsResLines"),
  findingsReqSearchInput: document.getElementById("findingsReqSearchInput"),
  findingsReqSearchMeta: document.getElementById("findingsReqSearchMeta"),
  findingsResSearchInput: document.getElementById("findingsResSearchInput"),
  findingsResSearchMeta: document.getElementById("findingsResSearchMeta"),
  findingsClearButton: document.getElementById("findingsClearButton"),
  findingsSettingsButton: document.getElementById("findingsSettingsButton"),
  findingsFilterSeverity: document.getElementById("findingsFilterSeverity"),
  findingsFilterCategory: document.getElementById("findingsFilterCategory"),
  findingsFilterSearch: document.getElementById("findingsFilterSearch"),
  scannerSettingsBackdrop: document.getElementById("scannerSettingsBackdrop"),
  scannerSettingsClose: document.getElementById("scannerSettingsClose"),
  scannerSettingsCancel: document.getElementById("scannerSettingsCancel"),
  scannerSettingsSave: document.getElementById("scannerSettingsSave"),
  scannerEnabledToggle: document.getElementById("scannerEnabledToggle"),
  scannerBuiltinRules: document.getElementById("scannerBuiltinRules"),
  scannerCustomRules: document.getElementById("scannerCustomRules"),
  scannerAddCustomRule: document.getElementById("scannerAddCustomRule"),
  scannerQuickToggle: document.getElementById("scannerQuickToggle"),
  findingsInScopeOnly: document.getElementById("findingsInScopeOnly"),
  oastPanel: document.getElementById("oastPanel"),
  oastTableBody: document.getElementById("oastTableBody"),
  oastBadge: document.getElementById("oastBadge"),
  oastGenerateButton: document.getElementById("oastGenerateButton"),
  oastClearButton: document.getElementById("oastClearButton"),
  oastPayloadDisplay: document.getElementById("oastPayloadDisplay"),
  oastPayloadText: document.getElementById("oastPayloadText"),
  oastCopyPayloadButton: document.getElementById("oastCopyPayloadButton"),
  oastDetailTitle: document.getElementById("oastDetailTitle"),
  oastDetailView: document.getElementById("oastDetailView"),
  proxySettingsPanel: document.getElementById("proxySettingsPanel"),
  requestView: document.getElementById("requestView"),
  requestLines: document.getElementById("requestLines"),
  responseView: document.getElementById("responseView"),
  responseLines: document.getElementById("responseLines"),
  requestViewCM: document.getElementById("requestViewCM"),
  responseViewCM: document.getElementById("responseViewCM"),
  requestSearchInput: document.getElementById("requestSearchInput"),
  responseSearchInput: document.getElementById("responseSearchInput"),
  requestSearchMeta: document.getElementById("requestSearchMeta"),
  responseSearchMeta: document.getElementById("responseSearchMeta"),
  requestMrToggle: document.getElementById("requestMrToggle"),
  responseMrToggle: document.getElementById("responseMrToggle"),
  requestResponseResizer: document.getElementById("requestResponseResizer"),
  responseInspectorResizer: document.getElementById("responseInspectorResizer"),
  detailTitle: document.getElementById("detailTitle"),
  detailTags: document.getElementById("detailTags"),
  protocolStrip: document.getElementById("protocolStrip"),
  summaryList: document.getElementById("summaryList"),
  attributesCount: document.getElementById("attributesCount"),
  requestHeaderCount: document.getElementById("requestHeaderCount"),
  responseHeaderCount: document.getElementById("responseHeaderCount"),
  requestHeadersBody: document.getElementById("requestHeadersBody"),
  responseHeadersBody: document.getElementById("responseHeadersBody"),
  inspectorContent: document.getElementById("inspectorContent"),
  notesPanel: document.getElementById("notesPanel"),
  notesCard: document.getElementById("notesCard"),
  captureMode: document.getElementById("captureMode"),
  footerMode: document.getElementById("footerMode"),
  openEventLogButton: document.getElementById("openEventLogButton"),
  eventLogStatus: document.getElementById("eventLogStatus"),
  displaySettingsModal: document.getElementById("displaySettingsModal"),
  openDisplaySettingsButton: document.getElementById("openDisplaySettingsButton"),
  closeDisplaySettingsButton: document.getElementById("closeDisplaySettingsButton"),
  applyDisplaySettingsButton: document.getElementById("applyDisplaySettingsButton"),
  resetDisplaySettingsButton: document.getElementById("resetDisplaySettingsButton"),
  displayThemeSelect: document.getElementById("displayThemeSelect"),
  displaySizeInput: document.getElementById("displaySizeInput"),
  displayUiFontSelect: document.getElementById("displayUiFontSelect"),
  displayMonoFontSelect: document.getElementById("displayMonoFontSelect"),
  settingsSpecialHostHttp: document.getElementById("settingsSpecialHostHttp"),
  certificateName: document.getElementById("certificateName"),
  certificateExpiry: document.getElementById("certificateExpiry"),
  certificatePemPath: document.getElementById("certificatePemPath"),
  certificateDerPath: document.getElementById("certificateDerPath"),
  specialHostHttps: document.getElementById("specialHostHttps"),
  dataDir: document.getElementById("dataDir"),
  certificateNote: document.getElementById("certificateNote"),
  downloadPemButton: document.getElementById("downloadPemButton"),
  downloadDerButton: document.getElementById("downloadDerButton"),
  closeInspectorButton: document.getElementById("closeInspectorButton"),
  interceptStatus: document.getElementById("interceptStatus"),
  openFilterSettingsButton: document.getElementById("openFilterSettingsButton"),
  filterModal: document.getElementById("filterModal"),
  closeFilterModalButton: document.getElementById("closeFilterModalButton"),
  applyFilterSettingsButton: document.getElementById("applyFilterSettingsButton"),
  resetFilterSettingsButton: document.getElementById("resetFilterSettingsButton"),
  filterInScopeOnly: document.getElementById("filterInScopeOnly"),
  filterHideWithoutResponses: document.getElementById("filterHideWithoutResponses"),
  filterOnlyParameterized: document.getElementById("filterOnlyParameterized"),
  filterOnlyNotes: document.getElementById("filterOnlyNotes"),
  filterSearchTerm: document.getElementById("filterSearchTerm"),
  filterRegex: document.getElementById("filterRegex"),
  filterCaseSensitive: document.getElementById("filterCaseSensitive"),
  filterNegativeSearch: document.getElementById("filterNegativeSearch"),
  filterMimeHtml: document.getElementById("filterMimeHtml"),
  filterMimeScript: document.getElementById("filterMimeScript"),
  filterMimeJson: document.getElementById("filterMimeJson"),
  filterMimeCss: document.getElementById("filterMimeCss"),
  filterMimeImage: document.getElementById("filterMimeImage"),
  filterMimeOther: document.getElementById("filterMimeOther"),
  filterStatus2xx: document.getElementById("filterStatus2xx"),
  filterStatus3xx: document.getElementById("filterStatus3xx"),
  filterStatus4xx: document.getElementById("filterStatus4xx"),
  filterStatus5xx: document.getElementById("filterStatus5xx"),
  filterStatusOther: document.getElementById("filterStatusOther"),
  filterHiddenExtensions: document.getElementById("filterHiddenExtensions"),
  filterPort: document.getElementById("filterPort"),
  colorTagFilter: document.getElementById("colorTagFilter"),
  interceptTableBody: document.getElementById("interceptTableBody"),
  interceptDetailPath: document.getElementById("interceptDetailPath"),
  interceptDetailTitle: document.getElementById("interceptDetailTitle"),
  interceptRequestHighlight: document.getElementById("interceptRequestHighlight"),
  interceptRequestEditor: document.getElementById("interceptRequestEditor"),
  interceptMeta: document.getElementById("interceptMeta"),
  forwardInterceptButton: document.getElementById("forwardInterceptButton"),
  dropInterceptButton: document.getElementById("dropInterceptButton"),
  interceptRequestTable: document.getElementById("interceptRequestTable"),
  responseInterceptTable: document.getElementById("responseInterceptTable"),
  responseInterceptTableBody: document.getElementById("responseInterceptTableBody"),
  interceptRequestEditorPanel: document.getElementById("interceptRequestEditorPanel"),
  interceptResponseEditorPanel: document.getElementById("interceptResponseEditorPanel"),
  interceptResponseHighlight: document.getElementById("interceptResponseHighlight"),
  interceptResponseEditor: document.getElementById("interceptResponseEditor"),
  interceptRequestActions: document.getElementById("interceptRequestActions"),
  responseInterceptActions: document.getElementById("responseInterceptActions"),
  forwardResponseInterceptButton: document.getElementById("forwardResponseInterceptButton"),
  dropResponseInterceptButton: document.getElementById("dropResponseInterceptButton"),
  interceptQueueTabRequest: document.getElementById("interceptQueueTabRequest"),
  interceptQueueTabResponse: document.getElementById("interceptQueueTabResponse"),
  websocketMeta: document.getElementById("websocketMeta"),
  websocketSearchInput: document.getElementById("websocketSearchInput"),
  websocketTableBody: document.getElementById("websocketTableBody"),
  websocketDetailTitle: document.getElementById("websocketDetailTitle"),
  websocketRequestView: document.getElementById("websocketRequestView"),
  websocketResponseView: document.getElementById("websocketResponseView"),
  websocketFramesBody: document.getElementById("websocketFramesBody"),
  frameDetailPanel: document.getElementById("frameDetailPanel"),
  frameDetailResizer: document.getElementById("frameDetailResizer"),
  frameDetailMeta: document.getElementById("frameDetailMeta"),
  frameDetailBody: document.getElementById("frameDetailBody"),
  frameDetailClose: document.getElementById("frameDetailClose"),
  refreshWebsocketsButton: document.getElementById("refreshWebsocketsButton"),
  websocketWorkbench: document.getElementById("websocketWorkbench"),
  websocketHandshakeColumn: document.getElementById("websocketHandshakeColumn"),
  websocketFramesColumn: document.getElementById("websocketFramesColumn"),
  websocketSplitResizer: document.getElementById("websocketSplitResizer"),
  websocketStackResizer: document.getElementById("websocketStackResizer"),
  proxySettingIntercept: document.getElementById("proxySettingIntercept"),
  proxySettingWebsocketCapture: document.getElementById("proxySettingWebsocketCapture"),
  proxySettingUpstreamInsecure: document.getElementById("proxySettingUpstreamInsecure"),
  proxySettingScopePatterns: document.getElementById("proxySettingScopePatterns"),
  proxySettingPassthroughHosts: document.getElementById("proxySettingPassthroughHosts"),
  proxySettingOastClearToken: document.getElementById("proxySettingOastClearToken"),
  proxySettingOastTokenHint: document.getElementById("proxySettingOastTokenHint"),
  proxySettingBindHost: document.getElementById("proxySettingBindHost"),
  proxySettingPort: document.getElementById("proxySettingPort"),
  proxySettingListenerHelp: document.getElementById("proxySettingListenerHelp"),
  saveProxySettingsButton: document.getElementById("saveProxySettingsButton"),
  reloadProxySettingsButton: document.getElementById("reloadProxySettingsButton"),
  openCertFolderButton: document.getElementById("openCertFolderButton"),
  proxySettingsProxyAddr: document.getElementById("proxySettingsProxyAddr"),
  proxySettingsNextProxyAddr: document.getElementById("proxySettingsNextProxyAddr"),
  proxySettingsUiAddr: document.getElementById("proxySettingsUiAddr"),
  proxySettingsCaptureCap: document.getElementById("proxySettingsCaptureCap"),
  proxySettingsBootstrap: document.getElementById("proxySettingsBootstrap"),
  proxySettingsDataDir: document.getElementById("proxySettingsDataDir"),
  proxySettingsStartupPath: document.getElementById("proxySettingsStartupPath"),
  proxySettingsCertificateName: document.getElementById("proxySettingsCertificateName"),
  replaySchemeSelect: document.getElementById("replaySchemeSelect"),
  replayHostInput: document.getElementById("replayHostInput"),
  replayPortInput: document.getElementById("replayPortInput"),
  replayRequestHighlight: document.getElementById("replayRequestHighlight"),
  replayRequestEditor: document.getElementById("replayRequestEditor"),
  replayRequestSearchInput: document.getElementById("replayRequestSearchInput"),
  replayRequestSearchMeta: document.getElementById("replayRequestSearchMeta"),
  replayResponseMeta: document.getElementById("replayResponseMeta"),
  replayResponseView: document.getElementById("replayResponseView"), // legacy, may be null
  replayResponseCM: document.getElementById("replayResponseCM"),
  replayResponseSearchInput: document.getElementById("replayResponseSearchInput"),
  curlImportModal: document.getElementById("curlImportModal"),
  replayResponseSearchMeta: document.getElementById("replayResponseSearchMeta"),
  sendReplayButton: document.getElementById("sendReplayButton"),
  cancelReplayButton: document.getElementById("cancelReplayButton"),
  replayBackButton: document.getElementById("replayBackButton"),
  replayForwardButton: document.getElementById("replayForwardButton"),
  replayFollowRedirectButton: document.getElementById("replayFollowRedirectButton"),
  eventLogTableBody: document.getElementById("eventLogTableBody"),
  clearEventLogButton: document.getElementById("clearEventLogButton"),
  matchReplaceTableBody: document.getElementById("matchReplaceTableBody"),
  matchReplaceEditorPath: document.getElementById("matchReplaceEditorPath"),
  matchReplaceEditorTitle: document.getElementById("matchReplaceEditorTitle"),
  matchReplaceDescription: document.getElementById("matchReplaceDescription"),
  matchReplaceScope: document.getElementById("matchReplaceScope"),
  matchReplaceTarget: document.getElementById("matchReplaceTarget"),
  matchReplaceSearch: document.getElementById("matchReplaceSearch"),
  matchReplaceReplace: document.getElementById("matchReplaceReplace"),
  matchReplaceRegex: document.getElementById("matchReplaceRegex"),
  matchReplaceCaseSensitive: document.getElementById("matchReplaceCaseSensitive"),
  saveMatchReplaceRuleButton: document.getElementById("saveMatchReplaceRuleButton"),
  addMatchReplaceRuleButton: document.getElementById("addMatchReplaceRuleButton"),
  deleteMatchReplaceRuleButton: document.getElementById("deleteMatchReplaceRuleButton"),
  targetScopeEditor: document.getElementById("targetScopeEditor"),
  saveTargetScopeButton: document.getElementById("saveTargetScopeButton"),
  reloadTargetButton: document.getElementById("reloadTargetButton"),
  targetTree: document.getElementById("targetTree"),
  fuzzerRequestHighlight: document.getElementById("fuzzerRequestHighlight"),
  fuzzerRequestEditor: document.getElementById("fuzzerRequestEditor"),
  fuzzerPayloadsEditor: document.getElementById("fuzzerPayloadsEditor"),
  fuzzerMeta: document.getElementById("fuzzerMeta"),
  fuzzerResultsBody: document.getElementById("fuzzerResultsBody"),
  fuzzerDetailPanel: document.getElementById("fuzzerDetailPanel"),
  fuzzerDetailReqCM: document.getElementById("fuzzerDetailReqCM"),
  fuzzerDetailResCM: document.getElementById("fuzzerDetailResCM"),
  fuzzerDetailResponseMeta: document.getElementById("fuzzerDetailResponseMeta"),
  startFuzzerButton: document.getElementById("startFuzzerButton"),
  resetFuzzerButton: document.getElementById("resetFuzzerButton"),
  contextMenu: document.getElementById("contextMenu"),
  contextMenuNote: document.getElementById("contextMenuNote"),
  wsFrameContextMenu: document.getElementById("wsFrameContextMenu"),
  httpReplayToolbar: document.getElementById("httpReplayToolbar"),
  httpReplayWorkbench: document.getElementById("httpReplayWorkbench"),
  wsReplayPanel: document.getElementById("wsReplayPanel"),
  wsSchemeSelect: document.getElementById("wsSchemeSelect"),
  wsHostInput: document.getElementById("wsHostInput"),
  wsPortInput: document.getElementById("wsPortInput"),
  wsPathInput: document.getElementById("wsPathInput"),
  wsConnectButton: document.getElementById("wsConnectButton"),
  wsDisconnectButton: document.getElementById("wsDisconnectButton"),
  wsStatusIndicator: document.getElementById("wsStatusIndicator"),
  wsStatusText: document.getElementById("wsStatusText"),
  wsMessageEditor: document.getElementById("wsMessageEditor"),
  wsSendButton: document.getElementById("wsSendButton"),
  wsMessageType: document.getElementById("wsMessageType"),
  wsHandshakeHeaders: document.getElementById("wsHandshakeHeaders"),
  wsFrameList: document.getElementById("wsFrameList"),
  wsFrameCount: document.getElementById("wsFrameCount"),
  wsFrameDetailPath: document.getElementById("wsFrameDetailPath"),
  wsFrameDetailTitle: document.getElementById("wsFrameDetailTitle"),
  wsFrameDetailView: document.getElementById("wsFrameDetailView"),
  wsReplayPaneResizer: document.getElementById("wsReplayPaneResizer"),
  wsReplayFrameResizer: document.getElementById("wsReplayFrameResizer"),
  wsHandshakeLines: document.getElementById("wsHandshakeLines"),
  wsHandshakeSearchInput: document.getElementById("wsHandshakeSearchInput"),
  wsHandshakeSearchMeta: document.getElementById("wsHandshakeSearchMeta"),
  wsMessageHighlight: document.getElementById("wsMessageHighlight"),
  // CodeMirror containers
  findingsReqCM: document.getElementById("findingsReqCM"),
  findingsResCM: document.getElementById("findingsResCM"),
  websocketHandshakeCM: document.getElementById("websocketHandshakeCM"),
  interceptRequestCM: document.getElementById("interceptRequestCM"),
  interceptResponseCM: document.getElementById("interceptResponseCM"),
  replayRequestCM: document.getElementById("replayRequestCM"),
  fuzzerRequestCM: document.getElementById("fuzzerRequestCM"),
};

const mainTabs = Array.from(document.querySelectorAll(".main-tab"));
const proxyTabs = Array.from(document.querySelectorAll(".sub-tab"));
const viewTabs = Array.from(document.querySelectorAll(".view-tab"));
const railTabs = Array.from(document.querySelectorAll(".rail-tab"));
const sectionToggles = Array.from(document.querySelectorAll(".section-toggle"));
let sortHeaders = Array.from(document.querySelectorAll(".sort-header"));
let historyColumnHandles = Array.from(document.querySelectorAll(".column-resize-handle"));

let refreshTimer = null;
let auxTimer = null;
let eventSource = null;
let workspaceSaveTimer = null;
let wsTranscriptSaveTimer = null;
let wsTranscriptFirstDirtyAt = 0;
let workspaceSaveInFlight = false;
let workspaceSaveDirty = false;
let workspaceSaveVersion = 0;
let workspaceSaveLastSnapshot = null;
const workspaceClientId = createWorkspaceClientId();
let workspaceSaveLoopPromise = null;
let workspaceSaveConflictPending = false;
let uiSettingsSaveTimer = null;
let toolsBootPromise = null;
let displaySettingsPreviewActive = false;

const WORKBENCH_STACK_BREAKPOINT = "(max-width: 1260px)";
const WORKBENCH_MIN_WIDTHS = {
  request: 320,
  response: 320,
  inspector: 300,
};
const WEBSOCKET_WORKBENCH_BREAKPOINT = "(max-width: 980px)";
const WEBSOCKET_WORKBENCH_MIN_WIDTHS = {
  handshake: 360,
  frames: 320,
};

const WEBSOCKET_STACK_MIN_HEIGHTS = {
  sessions: 160,
  workbench: 220,
};

const LAYOUT_TEXTAREA_IDS = [
  "interceptRequestEditor",
  "proxySettingScopePatterns",
  "proxySettingPassthroughHosts",
  "fuzzerPayloadsEditor",
  "targetScopeEditor",
  "wsMessageEditor",
  "wsHandshakeHeaders",
];

init().catch((error) => {
  console.error(error);
  els.historyMeta.textContent = "Failed to load Sniper.";
  els.liveStatus.textContent = "Error";
  els.liveStatus.classList.remove("online");
});

async function init() {
  loadDisplaySettings();
  loadHistoryColumnWidths();
  loadWorkbenchLayout();
  renderHistoryHeader();
  bindEvents();
  resetLayoutTextareas();
  hydrateFilterForm();
  syncHttpInScopePill();
  const aclInit = document.getElementById("proxySettingAutoContentLength");
  if (aclInit) aclInit.checked = localStorage.getItem("sniper_auto_content_length") !== "false";
  await loadUiSettings();
  hydrateDisplaySettingsForm();
  await loadSessions();
  await loadSettings();
  const loads = [
    loadWorkspaceState(),
    loadTransactions(false),
    loadIntercepts(false),
    loadResponseIntercepts(false),
    loadInterceptRules(),
    loadWebsockets(false),
    loadEventLog(),
    loadMatchReplaceRules(),
    loadSequences(),
    loadTargetSiteMap(),
  ];
  loadAppVersionInfo().catch((error) => console.error(error));
  const results = await Promise.allSettled(loads);
  for (const result of results) {
    if (result.status === "rejected") {
      console.error("init load failed:", result.reason);
    }
  }
  connectEvents();
  auxTimer = window.setInterval(() => {
    pollAuxiliaryData().catch((error) => console.error(error));
  }, 1200);
  // Sync active tabs from DOM in case WKWebView restored a cached page state
  const domActiveTool = document.querySelector(".main-tab.active");
  if (domActiveTool?.dataset?.tool && domActiveTool.dataset.tool !== state.activeTool) {
    state.activeTool = domActiveTool.dataset.tool;
  }
  const domActiveProxyTab = document.querySelector(".sub-tab.active");
  if (domActiveProxyTab?.dataset?.proxyTab && domActiveProxyTab.dataset.proxyTab !== state.activeProxyTab) {
    state.activeProxyTab = domActiveProxyTab.dataset.proxyTab;
  }
  renderToolPanels();
  renderProxyPanels();
  renderInspectorPanels();
  renderViewTabs();
  renderSortHeaders();
  renderProxySettings();
  // Ensure Settings tab data loads on startup if it's the active tab
  if (state.activeProxyTab === "proxy-settings") {
    loadRuntimeSettings().catch((error) => console.error(error));
  }
  renderIntercepts();
  renderWebsocketSessions();
  renderReplay();
  renderDashboard();
  renderEventLog();
  renderMatchReplaceRules();
  renderTarget();
  renderFuzzer();
  normalizeWorkbenchStackHeight();
  // Safety: re-render settings after a short delay to cover WKWebView timing issues
  setTimeout(() => {
    if (state.settings && state.runtime) {
      renderProxySettings();
    }
  }, 800);
}

function resetLayoutTextareas() {
  for (const key of LAYOUT_TEXTAREA_IDS) {
    const element = els[key];
    if (!(element instanceof HTMLTextAreaElement)) {
      continue;
    }

    element.style.height = "";
    element.style.overflowY = "";
  }
}

function bindEvents() {
  window.addEventListener("resize", resetLayoutTextareas);
  window.addEventListener("pagehide", flushWorkspaceStateOnUnload);
  window.addEventListener("beforeunload", flushWorkspaceStateOnUnload);

  mainTabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      state.activeTool = tab.dataset.tool;
      renderToolPanels();
      if (state.activeTool === "dashboard") {
        loadSessions().catch((error) => console.error(error));
      }
      if (state.activeTool === "target") {
        loadTargetSiteMap(true).catch((error) => console.error(error));
      }
      if (state.activeTool === "logger") {
        loadEventLog().catch((error) => console.error(error));
      }
      if (state.activeTool === "proxy" && state.activeProxyTab === "http-history") {
        if (state.historyDirty) loadTransactions(true, consumeHistoryLoadOptions()).catch((error) => console.error(error));
      }
    });
  });

  proxyTabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      state.activeProxyTab = tab.dataset.proxyTab;
      renderProxyPanels();
      if (state.activeProxyTab === "intercept") {
        loadIntercepts(true).catch((error) => console.error(error));
        loadResponseIntercepts(true).catch((error) => console.error(error));
        loadInterceptRules().catch((error) => console.error(error));
      }
      if (state.activeProxyTab === "websockets-history") {
        loadWebsockets(true).catch((error) => console.error(error));
      }
      if (state.activeProxyTab === "http-history") {
        if (state.historyDirty) loadTransactions(true, consumeHistoryLoadOptions()).catch((error) => console.error(error));
      }
      if (state.activeProxyTab === "proxy-settings") {
        loadRuntimeSettings().catch((error) => console.error(error));
      }
      if (state.activeProxyTab === "replace") {
        loadMatchReplaceRules().catch((error) => console.error(error));
      }
      if (state.activeProxyTab === "oast") {
        loadOastCallbacks().catch((error) => console.error(error));
      }
    });
  });

  viewTabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      const target = tab.dataset.target;
      state.messageViews[target] = tab.dataset.view;
      renderViewTabs();
      renderMessagePanes();
    });
  });

  document.querySelectorAll(".mr-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const target = btn.dataset.target;
      state.showOriginal[target] = btn.dataset.mr === "original";
      renderViewTabs();
      renderMessagePanes();
    });
  });

  railTabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      state.activeInspectorTab = tab.dataset.inspectorTab;
      state.inspectorCollapsed = false;
      renderInspectorPanels();
    });
  });

  sectionToggles.forEach((toggle) => {
    toggle.addEventListener("click", () => {
      toggle.parentElement.classList.toggle("collapsed");
    });
  });

  // Virtual scroll for HTTP history table
  const historyShell = els.historyTable.closest(".history-table-shell");
  if (historyShell) {
    let historyScrollRaf = 0;
    historyShell.addEventListener("scroll", () => {
      if (historyScrollRaf) return;
      historyScrollRaf = requestAnimationFrame(() => {
        historyScrollRaf = 0;
        renderHistoryVirtual();
      });
    });
  }

  // Event delegation for HTTP history table rows (click & contextmenu)
  els.historyTableBody.addEventListener("click", (event) => {
    const row = event.target.closest(".history-row");
    if (!row) return;
    state.selectedId = row.dataset.id;
    state.selectedRecord = null;
    updateHistorySelection(state.selectedId);
    renderEmptyDetail();
    scrollSelectedHistoryRowIntoView();
    loadTransactionDetail(state.selectedId).catch((error) => console.error(error));
    // Keep focus on the table so arrow keys navigate rows, not code-view lines
    els.trafficRegion.focus({ preventScroll: true });
  });
  els.historyTableBody.addEventListener("contextmenu", (event) => {
    const row = event.target.closest(".history-row");
    if (!row) return;
    event.preventDefault();
    state.selectedId = row.dataset.id;
    state.selectedRecord = null;
    updateHistorySelection(state.selectedId);
    renderEmptyDetail();
    loadTransactionDetail(state.selectedId).catch((error) => console.error(error));
    openContextMenu(event.clientX, event.clientY, row.dataset.id);
  });

  let _searchDebounce = 0;
  els.searchInput.addEventListener("input", () => {
    // Pause incremental refresh while user is actively typing
    _searchActiveUntil = Date.now() + 800;
    clearTimeout(_searchDebounce);
    _searchDebounce = setTimeout(() => {
      state.query = els.searchInput.value.trim();
      scheduleRefresh({ resetScroll: true });
    }, 60);
  });
  els.searchInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      clearTimeout(_searchDebounce);
      state.query = els.searchInput.value.trim();
      scheduleRefresh({ resetScroll: true });
    }
  });
  els.searchInput.addEventListener("search", () => {
    // Triggered when user clears the search field via the X button
    clearTimeout(_searchDebounce);
    state.query = els.searchInput.value.trim();
    scheduleRefresh({ resetScroll: true });
  });

  els.requestSearchInput.addEventListener("input", () => {
    state.messageSearch.request = els.requestSearchInput.value;
    updateMessagePaneSearch("request");
  });

  els.responseSearchInput.addEventListener("input", () => {
    state.messageSearch.response = els.responseSearchInput.value;
    updateMessagePaneSearch("response");
  });

  els.replayRequestSearchInput.addEventListener("input", () => {
    state.replayMessageSearch.request = els.replayRequestSearchInput.value;
    const cv = getCMView("replayReq");
    const reqText = cv ? cv.getContent() : (els.replayRequestEditor ? els.replayRequestEditor.value : "") || "";
      updateReplaySearchPane("request", reqText);
  });

  els.replayResponseSearchInput.addEventListener("input", () => {
    state.replayMessageSearch.response = els.replayResponseSearchInput.value;
    const resText = _replayResponseCMView
      ? _replayResponseCMView.view.state.doc.toString()
      : (els.replayResponseView ? els.replayResponseView.textContent : "") || "";
    updateReplaySearchPane("response", resText);
  });

  // Search hit navigation: click counter to cycle through matches
  initSearchHitNavigation(els.requestSearchMeta, () => els.requestView);
  initSearchHitNavigation(els.responseSearchMeta, () => els.responseView);
  // CM search navigation: click counter cycles through CM matches
  initCMSearchNavigation(els.requestSearchMeta, "request");
  initCMSearchNavigation(els.responseSearchMeta, "response");
  initSearchHitNavigation(els.replayRequestSearchMeta, () => els.replayRequestHighlight);
  initSearchHitNavigation(els.replayResponseSearchMeta, () => els.replayResponseView);
  initCMSearchNavigation(els.replayRequestSearchMeta, "replayReq");
  initReplayResponseCMSearchNavigation();

  els.websocketSearchInput.addEventListener("input", () => {
    state.websocketQuery = els.websocketSearchInput.value.trim();
    syncVisibleWebsocketSelection(true).catch((error) => console.error(error));
  });
  document.getElementById("wsInScopeOnly")?.addEventListener("click", (e) => {
    e.currentTarget.classList.toggle("active");
    syncVisibleWebsocketSelection(true).catch((error) => console.error(error));
  });
  document.getElementById("wsHideClosed")?.addEventListener("click", (e) => {
    e.currentTarget.classList.toggle("active");
    syncVisibleWebsocketSelection(true).catch((error) => console.error(error));
  });
  document.getElementById("httpInScopeToggle")?.addEventListener("click", (e) => {
    e.currentTarget.classList.toggle("active");
    state.filterSettings.inScopeOnly = e.currentTarget.classList.contains("active");
    scheduleRefresh();
  });
  document.getElementById("interceptInScopeToggle")?.addEventListener("click", async (e) => {
    const toggle = e.currentTarget;
    const sessionId = currentSessionId();
    const previousScopeOnly = Boolean(state.interceptInScopeOnly);
    const nextScopeOnly = !toggle.classList.contains("active");
    toggle.classList.toggle("active", nextScopeOnly);
    toggle.disabled = true;
    state.interceptInScopeOnly = nextScopeOnly;
    try {
      await applyInterceptScopeFilterLocally();
      const response = await fetch("/api/runtime", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ session_id: sessionId, intercept_scope_only: nextScopeOnly }),
      });
      await requireOkResponse(response, "Failed to update intercept scope.");
      const runtime = await response.json();
      if (sessionId !== currentSessionId()) {
        return;
      }
      state.runtime = runtime;
      const savedScopeOnly = state.runtime?.intercept_scope_only ?? nextScopeOnly;
      state.interceptInScopeOnly = savedScopeOnly;
      toggle.classList.toggle("active", savedScopeOnly);
      await applyInterceptScopeFilterLocally();
    } catch (err) {
      if (sessionId !== currentSessionId()) {
        return;
      }
      console.error("Failed to update intercept scope:", err);
      showToast(err?.message || "Failed to update intercept scope.", "error");
      state.interceptInScopeOnly = previousScopeOnly;
      toggle.classList.toggle("active", previousScopeOnly);
      await applyInterceptScopeFilterLocally();
    } finally {
      toggle.disabled = false;
    }
  });

  els.methodFilter.addEventListener("change", () => {
    state.method = els.methodFilter.value;
    scheduleRefresh();
  });

  els.colorTagFilter.addEventListener("click", (event) => {
    const btn = event.target.closest(".color-dot-btn");
    if (!btn) return;
    const color = btn.dataset.color;
    if (state.filterSettings.colorTags.has(color)) {
      state.filterSettings.colorTags.delete(color);
      btn.classList.remove("active");
    } else {
      state.filterSettings.colorTags.add(color);
      btn.classList.add("active");
    }
    scheduleRefresh();
  });

  els.openDisplaySettingsButton.addEventListener("click", openDisplaySettingsModal);
  els.openUpdateButton.addEventListener("click", performSelfUpdate);
  if (els.toolsClearButton) els.toolsClearButton.addEventListener("click", clearToolsInputs);
  els.closeDisplaySettingsButton.addEventListener("click", closeDisplaySettingsModal);
  els.displaySettingsModal.addEventListener("click", (event) => {
    if (event.target === els.displaySettingsModal) {
      closeDisplaySettingsModal();
    }
  });

  els.openFilterSettingsButton.addEventListener("click", openFilterModal);
  els.historyMeta.addEventListener("click", openFilterModal);
  els.closeFilterModalButton.addEventListener("click", closeFilterModal);
  els.filterModal.addEventListener("click", (event) => {
    if (event.target === els.filterModal) {
      closeFilterModal();
    }
  });
  els.applyFilterSettingsButton.addEventListener("click", applyFilterSettings);
  els.resetFilterSettingsButton.addEventListener("click", () => {
    state.filterSettings = createDefaultFilterSettings();
    hydrateFilterForm();
    syncHttpInScopePill();
    scheduleRefresh({ resetScroll: true });
  });
  document.getElementById("closeCompareButton").addEventListener("click", closeCompareModal);
  document.getElementById("compareModal").addEventListener("click", (event) => {
    if (event.target.id === "compareModal") closeCompareModal();
  });
  document.querySelectorAll("[data-compare-tab]").forEach((btn) => {
    btn.addEventListener("click", () => {
      compareActiveTab = btn.dataset.compareTab;
      renderCompareModal();
    });
  });

  document.getElementById("closeCurlImportButton").addEventListener("click", closeCurlImportModal);
  document.getElementById("applyCurlImportButton").addEventListener("click", applyCurlImport);
  document.getElementById("curlImportModal").addEventListener("click", (event) => {
    if (event.target.id === "curlImportModal") closeCurlImportModal();
  });

  els.applyDisplaySettingsButton.addEventListener("click", saveDisplaySettingsFromForm);
  els.resetDisplaySettingsButton.addEventListener("click", () => {
    const defaults = createDefaultDisplaySettings();
    els.displayThemeSelect.value = defaults.theme;
    els.displaySizeInput.value = String(defaults.sizePx);
    els.displayUiFontSelect.value = defaults.uiFont;
    els.displayMonoFontSelect.value = defaults.monoFont;
    previewDisplaySettingsFromForm();
  });
  [els.displayThemeSelect, els.displayUiFontSelect, els.displayMonoFontSelect].forEach((element) => {
    element.addEventListener("change", previewDisplaySettingsFromForm);
  });
  els.displaySizeInput.addEventListener("input", previewDisplaySettingsFromForm);
  els.displaySizeInput.addEventListener("change", previewDisplaySettingsFromForm);

  els.openCertFolderButton.addEventListener("click", () => openCertificateFolder());
  els.openEventLogButton.addEventListener("click", async () => {
    state.activeTool = "logger";
    await loadEventLog();
    renderToolPanels();
  });
  els.dashboardReloadSessionsButton?.addEventListener("click", () => {
    loadSessions().catch((error) => console.error(error));
  });
  els.dashboardCreateSessionButton?.addEventListener("click", () => {
    createSession().catch(handleWorkspaceActionError);
  });
  els.dashboardOpenStorageBtn?.addEventListener("click", () => {
    const sessionId = state.selectedSessionId || state.activeSession?.id || state.sessions.find((s) => s.active)?.id;
    if (sessionId) {
      fetch(`/api/sessions/${encodeURIComponent(sessionId)}/reveal`, { method: "POST" }).catch(console.error);
    }
  });

  // Session table sort headers
  document.querySelectorAll("#dashboardSessionsTable thead th[data-sort-key]").forEach((th) => {
    th.addEventListener("click", () => {
      const key = th.dataset.sortKey;
      if (state.sessionSortKey === key) {
        state.sessionSortDir = state.sessionSortDir === "asc" ? "desc" : "asc";
      } else {
        state.sessionSortKey = key;
        state.sessionSortDir = key === "name" ? "asc" : "desc";
      }
      renderDashboard();
    });
  });

  els.clearEventLogButton.addEventListener("click", () => {
    clearEventLog().catch((error) => {
      console.error(error);
      showToast(error?.message || "Failed to clear event log.", "error");
    });
  });

  els.closeInspectorButton?.addEventListener("click", () => {
    state.inspectorCollapsed = true;
    renderInspectorPanels();
  });

  document.getElementById("addInterceptRuleButton")?.addEventListener("click", () => {
    addInterceptRule().catch(handleInterceptRuleError);
  });
  document.getElementById("interceptRulesList").addEventListener("click", (event) => {
    const deleteBtn = event.target.closest("[data-rule-delete]");
    if (deleteBtn) { deleteInterceptRule(deleteBtn.dataset.ruleDelete).catch(handleInterceptRuleError); return; }
    const saveBtn = event.target.closest("[data-rule-save]");
    if (saveBtn) { saveInterceptRuleFromRow(saveBtn.dataset.ruleSave).catch(handleInterceptRuleError); return; }
    const row = event.target.closest("[data-rule-id]");
    if (row && !event.target.closest("input") && !event.target.closest("button")) { editInterceptRule(row.dataset.ruleId); }
  });
  document.getElementById("interceptRulesList").addEventListener("change", (event) => {
    const toggle = event.target.closest("[data-rule-toggle]");
    if (toggle) { toggleInterceptRuleEnabled(toggle.dataset.ruleToggle, toggle.checked).catch(handleInterceptRuleError); }
  });
  document.getElementById("interceptRulesList").addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      const row = event.target.closest("[data-rule-id]");
      if (row) { saveInterceptRuleFromRow(row.dataset.ruleId).catch(handleInterceptRuleError); }
    }
  });
  if (els.refreshWebsocketsButton) {
    els.refreshWebsocketsButton.addEventListener("click", () => {
      loadWebsockets(true).catch((error) => console.error(error));
    });
  }
  els.frameDetailClose.addEventListener("click", hideFrameDetail);
  initFrameDetailResizer();
  document.querySelectorAll(".ws-sort").forEach((btn) => {
    btn.addEventListener("click", () => toggleWebsocketSort(btn.dataset.wsSortKey));
  });
  els.forwardInterceptButton.addEventListener("click", () => {
    forwardSelectedIntercept().catch((error) => {
      console.error(error);
      showToast(error?.message || "Failed to forward request.", "error");
    });
  });
  els.dropInterceptButton.addEventListener("click", () => {
    dropSelectedIntercept().catch((error) => {
      console.error(error);
      showToast(error?.message || "Failed to drop request.", "error");
    });
  });
  els.forwardResponseInterceptButton.addEventListener("click", () => {
    forwardSelectedResponseIntercept().catch((error) => {
      console.error(error);
      showToast(error?.message || "Failed to forward response.", "error");
    });
  });
  els.dropResponseInterceptButton.addEventListener("click", () => {
    dropSelectedResponseIntercept().catch((error) => {
      console.error(error);
      showToast(error?.message || "Failed to drop response.", "error");
    });
  });
  els.interceptQueueTabRequest.addEventListener("click", () => switchInterceptQueueTab("request"));
  els.interceptQueueTabResponse.addEventListener("click", () => switchInterceptQueueTab("response"));

  els.interceptStatus.addEventListener("click", () => {
    toggleIntercept().catch((error) => console.error(error));
  });
  els.saveProxySettingsButton.addEventListener("click", () => {
    saveProxySettings()
      .then((result) => {
        if (result?.rebound === true) {
          showToast(`Proxy listener moved to ${result.active_proxy_addr}`);
        } else if (result?.rebound === false && result?.rebind_error) {
          showToast(result.rebind_error, "error");
        } else {
          showToast("Proxy settings saved");
        }
      })
      .catch((error) => { console.error(error); showToast("Failed to save proxy settings", "error"); });
  });
  els.reloadProxySettingsButton.addEventListener("click", () => {
    loadSettings().catch((error) => console.error(error));
  });
  document.getElementById("proxySettingAutoContentLength")?.addEventListener("change", (e) => {
    localStorage.setItem("sniper_auto_content_length", e.target.checked);
  });

  // Pane context menu (right-click on Request/Response code-view)
  const paneCtx = document.getElementById("paneContextMenu");
  if (paneCtx) {
    [els.requestView, els.responseView, els.requestViewCM, els.responseViewCM].forEach((view) => {
      if (!view) return;
      view.addEventListener("contextmenu", (e) => {
        if (!state.selectedId) return;
        e.preventDefault();
        paneCtx.classList.remove("hidden");
        const mw = paneCtx.offsetWidth, mh = paneCtx.offsetHeight;
        paneCtx.style.left = `${Math.min(e.clientX, window.innerWidth - mw - 8)}px`;
        paneCtx.style.top = `${Math.min(e.clientY, window.innerHeight - mh - 8)}px`;
      });
    });
    document.addEventListener("click", () => paneCtx.classList.add("hidden"));
    paneCtx.addEventListener("click", (e) => {
      const btn = e.target.closest("[data-pane-action]");
      if (!btn || !state.selectedId) return;
      const action = btn.dataset.paneAction;
      paneCtx.classList.add("hidden");
      if (action === "copy-url") copySelectedTransactionUrl();
      else if (action === "send-to-replay") openReplayFromSelection().catch(handleSendActionError);
      else if (action === "send-to-fuzzer") openFuzzerFromSelection().catch(handleSendActionError);
      else if (action.startsWith("copy-response-")) copyResponseContent(action.replace("copy-", ""));
      else if (action.startsWith("copy-as-")) {
        const fmt = action.replace("copy-as-", "");
        const text = selectedRecordToFormat(fmt);
        if (text) {
          copyTextToClipboard(text)
            .then(() => showToast(`Copied as ${fmt}`))
            .catch(() => showToast("Failed to copy", "error"));
        }
      }
    });
  }

  els.sendReplayButton.addEventListener("click", () => {
    sendReplay().catch(handleReplayActionError);
  });
  els.newReplayTabButton.addEventListener("click", () => {
    openBlankReplayTab();
  });
  els.cancelReplayButton.addEventListener("click", cancelReplaySend);
  els.replayBackButton.addEventListener("click", () => {
    navigateReplayHistory(-1);
  });
  els.replayForwardButton.addEventListener("click", () => {
    navigateReplayHistory(1);
  });
  els.replayFollowRedirectButton.addEventListener("click", () => {
    followRedirect().catch(handleReplayActionError);
  });
  els.saveMatchReplaceRuleButton.addEventListener("click", () => {
    if (!state.selectedMatchReplaceRuleId) {
      createNewMatchReplaceRule();
    }
    syncMatchReplaceEditor();
    saveMatchReplaceRules()
      .then(() => showToast("Rule saved"))
      .catch((error) => { console.error(error); showToast("Failed to save rule", "error"); });
  });
  els.addMatchReplaceRuleButton.addEventListener("click", () => {
    syncMatchReplaceEditor();
    createNewMatchReplaceRule();
    // Don't save immediately — let user fill in fields first
    renderMatchReplaceRules();
  });
  els.deleteMatchReplaceRuleButton.addEventListener("click", () => {
    deleteSelectedMatchReplaceRule().catch((error) => {
      console.error(error);
      showToast(error?.message || "Failed to delete rule", "error");
      loadMatchReplaceRules().catch(console.error);
    });
  });
  [
    els.matchReplaceScope,
    els.matchReplaceTarget,
    els.matchReplaceSearch,
    els.matchReplaceReplace,
    els.matchReplaceRegex,
    els.matchReplaceCaseSensitive,
  ].forEach((element) => {
    element.addEventListener("input", syncMatchReplaceEditor);
    element.addEventListener("change", syncMatchReplaceEditor);
  });
  els.saveTargetScopeButton.addEventListener("click", () => {
    saveTargetScope()
      .then(() => showToast("Scope saved"))
      .catch((error) => { console.error(error); showToast(error?.message || "Failed to save scope", "error"); });
  });
  els.targetScopeEditor.addEventListener("input", () => {
    state.targetScopeDraft = els.targetScopeEditor.value;
    state.targetScopeDirty = true;
    state.targetScopeEditorSessionId = currentSessionId();
  });
  els.reloadTargetButton.addEventListener("click", () => {
    loadTargetSiteMap(true).catch((error) => console.error(error));
  });
  els.startFuzzerButton.addEventListener("click", () => {
    runFuzzerAttack().catch((error) => {
      console.error("Fuzzer start error:", error);
    });
  });
  els.resetFuzzerButton.addEventListener("click", resetFuzzer);

  // Fuzzer layout resizers
  initFuzzerResizers();

  // Fuzzer result row selection helper
  function selectFuzzerRow(row) {
    if (!row) return;
    els.fuzzerResultsBody.querySelectorAll(".fuzzer-result-selected").forEach((r) => r.classList.remove("fuzzer-result-selected"));
    row.classList.add("fuzzer-result-selected");
    row.scrollIntoView({ block: "nearest" });
    const txId = row.dataset.transactionId;
    const rowIndex = Number.isFinite(Number(row.dataset.rowIndex))
      ? Number(row.dataset.rowIndex)
      : Number(row.dataset.resultIndex);
    const selectionKey = txId ? `tx:${txId}` : `row:${rowIndex}`;
    state._selectedFuzzerResultKey = selectionKey;
    if (txId) {
      showFuzzerResultDetail(txId, selectionKey).catch((err) => console.error(err));
    } else {
      const result = state.fuzzerAttackRecord?.results?.[rowIndex];
      state._fuzzerDetailRecord = null;
      if (els.fuzzerDetailPanel) els.fuzzerDetailPanel.classList.remove("hidden");
      const _dr = document.getElementById("fuzzerDetailResizer");
      if (_dr) _dr.classList.remove("hidden");
      if (els.fuzzerDetailReqCM) updateCodePaneCM("fuzzerDetailReq", els.fuzzerDetailReqCM, result?.note || "No transaction was captured for this payload.", { mode: "http" });
      if (els.fuzzerDetailResCM) updateCodePaneCM("fuzzerDetailRes", els.fuzzerDetailResCM, "", { mode: "http" });
      if (els.fuzzerDetailResponseMeta) els.fuzzerDetailResponseMeta.textContent = "";
    }
  }

  // Fuzzer results shell (for keyboard navigation + focus)
  const fuzzerResultsShell = els.fuzzerResultsBody.closest(".history-table-shell");

  // Fuzzer result row click → show detail
  els.fuzzerResultsBody.addEventListener("click", (e) => {
    const row = e.target.closest(".fuzzer-result-row");
    if (row) {
      selectFuzzerRow(row);
      if (fuzzerResultsShell) fuzzerResultsShell.focus({ preventScroll: true });
    }
  });

  // Fuzzer results keyboard navigation (↑↓)
  if (fuzzerResultsShell) {
    fuzzerResultsShell.setAttribute("tabindex", "0");
    fuzzerResultsShell.addEventListener("keydown", (e) => {
      if (e.key !== "ArrowUp" && e.key !== "ArrowDown") return;
      e.preventDefault();
      const selected = els.fuzzerResultsBody.querySelector(".fuzzer-result-selected");
      const rows = Array.from(els.fuzzerResultsBody.querySelectorAll(".fuzzer-result-row"));
      if (!rows.length) return;
      let idx = selected ? rows.indexOf(selected) : -1;
      if (e.key === "ArrowDown") idx = Math.min(idx + 1, rows.length - 1);
      else idx = Math.max(idx - 1, 0);
      selectFuzzerRow(rows[idx]);
    });
  }

  // Fuzzer detail view mode tabs (Pretty/Raw/Hex)
  document.querySelectorAll(".fuzzer-detail-view-tab").forEach((btn) => {
    btn.addEventListener("click", () => {
      const target = btn.dataset.fuzzerDetailTarget;
      const view = btn.dataset.fuzzerDetailView;
      _fuzzerDetailViewModes[target] = view;
      // Update tab active state
      document.querySelectorAll(`.fuzzer-detail-view-tab[data-fuzzer-detail-target="${target}"]`).forEach((b) => {
        b.classList.toggle("active", b.dataset.fuzzerDetailView === view);
      });
      // Re-render with current record
      if (state._fuzzerDetailRecord) {
        renderFuzzerDetailPanes(state._fuzzerDetailRecord);
      }
    });
  });

  document.getElementById("newSequenceButton").addEventListener("click", () => {
    createNewSequence().catch(handleSequenceActionError);
  });
  document.getElementById("addSequenceStepButton").addEventListener("click", addSequenceStep);
  document.getElementById("saveSequenceButton").addEventListener("click", () => {
    saveCurrentSequence().catch(handleSequenceActionError);
  });
  document.getElementById("runSequenceButton").addEventListener("click", () => {
    runCurrentSequence().catch(handleSequenceActionError);
  });

  // The replay request editor uses a contenteditable <pre> for editing so that
  // native text selection works over syntax-highlighted text (WKWebView renders
  // textarea selection in an opaque native layer that cannot be hidden).
  // The hidden <textarea> is kept as a data store only.
  state._replayUndoStack = [];
  state._replayRedoStack = [];
  state._replayLastSnapshot = null;

  els.replayRequestHighlight?.addEventListener("input", () => {
    if (els.replayRequestCM) return; // CM handles editing
    if (state.replayMessageViews.request === "hex") return;
    const tab = getActiveReplayTab();
    if (!tab) return;
    const text = els.replayRequestHighlight.innerText || "";
    if (state._replayLastSnapshot !== null && state._replayLastSnapshot !== text) {
      state._replayUndoStack.push(state._replayLastSnapshot);
      if (state._replayUndoStack.length > 200) state._replayUndoStack.shift();
      state._replayRedoStack.length = 0;
    }
    state._replayLastSnapshot = text;
    els.replayRequestEditor.value = text;
    tab.requestText = text;
    // Debounce re-render so syntax highlighting refreshes without losing cursor
    clearTimeout(els.replayRequestHighlight._renderTimer);
    els.replayRequestHighlight._renderTimer = setTimeout(() => {
      replayHighlightRerender(text);
    }, 400);
    updateReplaySearchPane("request", text);
    syncReplayToolbar(tab);
    renderReplayTabs();
    scheduleWorkspaceStateSave();
  });
  els.replayRequestHighlight?.addEventListener("keydown", (e) => {
    if (els.replayRequestCM) return; // CM handles editing
    if (state.replayMessageViews.request === "hex") return;
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "z" && !e.altKey) {
      e.preventDefault();
      const stack = e.shiftKey ? state._replayRedoStack : state._replayUndoStack;
      const opposite = e.shiftKey ? state._replayUndoStack : state._replayRedoStack;
      if (!stack.length) return;
      opposite.push(state._replayLastSnapshot || els.replayRequestHighlight.innerText || "");
      const restored = stack.pop();
      state._replayLastSnapshot = restored;
      let undoHtml = renderCodeHtml(restored, state.replayMessageViews.request, "request");
      els.replayRequestHighlight.innerHTML = undoHtml;
      // Clamp caret to beginning of text after undo — avoids jumping to trailing whitespace
      const maxOffset = restored.length;
      const savedCaret = saveContentEditableCaret(els.replayRequestHighlight);
      const clampedPos = savedCaret
        ? { start: Math.min(savedCaret.start, maxOffset), end: Math.min(savedCaret.end, maxOffset) }
        : { start: 0, end: 0 };
      restoreContentEditableCaret(els.replayRequestHighlight, clampedPos);
      els.replayRequestEditor.value = restored;
      const tab = getActiveReplayTab();
      if (tab) tab.requestText = restored;
      updateReplaySearchPane("request", restored);
      syncReplayToolbar(tab);
      renderReplayTabs();
      scheduleWorkspaceStateSave();
    }
  });
  els.replayRequestHighlight?.addEventListener("paste", (e) => {
    if (els.replayRequestCM) return; // CM handles paste
    e.preventDefault();
    const text = e.clipboardData.getData("text/plain");
    document.execCommand("insertText", false, text);
  });
  els.replayRequestHighlight?.addEventListener("contextmenu", showReplayContextMenu);
  els.replayRequestCM?.addEventListener("contextmenu", showReplayContextMenu);
  initReplayContextMenu();
  // Replay Pretty/Raw/Hex view tabs
  document.querySelectorAll(".replay-view-tab").forEach((btn) => {
    btn.addEventListener("click", () => {
      const target = btn.dataset.replayTarget;
      const view = btn.dataset.replayView;
      state.replayMessageViews[target] = view;
      renderReplayViewTabs();
      renderReplayViewContent(target);
    });
  });

  bindWsReplayEvents();
  bindFindingsEvents();

  // OAST
  const oastProviderSelect = document.getElementById("proxySettingOastProvider");
  if (oastProviderSelect) {
    oastProviderSelect.addEventListener("change", () => renderProxySettings());
  }
  if (els.proxySettingOastClearToken) {
    els.proxySettingOastClearToken.addEventListener("click", () => {
      state.oastTokenClearPending = true;
      const oastToken = document.getElementById("proxySettingOastToken");
      if (oastToken) {
        oastToken.value = "";
      }
      renderProxySettings();
    });
  }
  const oastTokenInput = document.getElementById("proxySettingOastToken");
  if (oastTokenInput) {
    oastTokenInput.addEventListener("input", () => {
      if (oastTokenInput.value.trim()) {
        state.oastTokenClearPending = false;
        renderProxySettings();
      }
    });
  }
  if (els.oastGenerateButton) {
    els.oastGenerateButton.addEventListener("click", () => {
      generateOastPayload().catch(handleOastActionError);
    });
  }
  if (els.oastClearButton) {
    els.oastClearButton.addEventListener("click", () => {
      clearOastCallbacks().catch((error) => {
        console.error(error);
        showToast(error?.message || "Failed to clear OAST callbacks.", "error");
      });
    });
  }
  if (els.oastCopyPayloadButton) {
    els.oastCopyPayloadButton.addEventListener("click", () => {
      const text = els.oastPayloadText?.value;
      if (text) { copyTextToClipboard(text); showToast("Copied OAST payload"); }
    });
  }
  if (els.oastTableBody) {
    els.oastTableBody.addEventListener("click", (event) => {
      const row = event.target.closest("tr[data-oast-id]");
      if (!row) return;
      state.selectedOastId = row.dataset.oastId;
      loadOastDetail(row.dataset.oastId).catch(handleOastActionError);
      renderOastCallbacks();
    });
  }
  els.replaySchemeSelect.addEventListener("change", () => {
    applyReplayTargetFields().catch((error) => console.error(error));
  });
  document.getElementById("replayHttpVersionSelect")?.addEventListener("change", (e) => {
    const ver = e.target.value;
    const tab = getActiveReplayTab();
    if (!tab || tab.type === "websocket") return;
    tab.httpVersionMode = ver || "";
    const cv = getCMView("replayReq");
    const text = tab.requestBytes
      ? new TextDecoder().decode(tab.requestBytes)
      : (tab.requestText || "");
    const lines = text.split("\n");
    if (lines.length > 0) {
      lines[0] = ver
        ? lines[0].replace(/\s+HTTP\/[0-9.]+\s*$/i, ` ${ver}`)
        : lines[0].replace(/\s+HTTP\/[0-9.]+\s*$/i, "");
      if (ver && !lines[0].match(/HTTP\//i)) lines[0] += ` ${ver}`;
      const newText = lines.join("\n");
      tab.requestText = newText;
      tab.requestBytes = null;
      tab.requestOriginalBytes = null;
      syncReplayToolbar(tab);
      renderReplayTabs();
      scheduleWorkspaceStateSave();
      if (cv && state.replayMessageViews.request !== "hex") {
        cv.setContent(newText);
        updateReplaySearchPane("request", newText);
        return;
      }
      renderReplayViewContent("request");
      return;
    }
    if (cv) {
      return;
    }
    // Legacy path
    const hl = els.replayRequestHighlight;
    if (!hl) return;
    const legacyText = hl.innerText || "";
    const legacyLines = legacyText.split("\n");
    if (legacyLines.length > 0) {
      legacyLines[0] = ver
        ? legacyLines[0].replace(/\s+HTTP\/[0-9.]+\s*$/i, ` ${ver}`)
        : legacyLines[0].replace(/\s+HTTP\/[0-9.]+\s*$/i, "");
      if (ver && !legacyLines[0].match(/HTTP\//i)) legacyLines[0] += ` ${ver}`;
      const newText = legacyLines.join("\n");
      hl.innerText = newText;
      hl.dispatchEvent(new Event("input"));
      tab.requestText = newText;
      updateReplaySearchPane("request", newText);
      syncReplayToolbar(tab);
      renderReplayTabs();
      scheduleWorkspaceStateSave();
    }
  });
  els.replayHostInput.addEventListener("input", () => {
    applyReplayTargetFields().catch((error) => console.error(error));
  });
  els.replayPortInput.addEventListener("input", () => {
    applyReplayTargetFields().catch((error) => console.error(error));
  });
  if (els.fuzzerRequestEditor) {
    els.fuzzerRequestEditor.addEventListener("input", () => {
      if (els.fuzzerRequestCM) return; // CM handles it
      updateFuzzerRequestText(els.fuzzerRequestEditor.value, { userEdit: true });
      renderFuzzerRequestHighlight(state.fuzzerRequestText);
      scheduleWorkspaceStateSave();
    });
    els.fuzzerRequestEditor.addEventListener("scroll", syncFuzzerRequestHighlightScroll);
  }
  els.fuzzerPayloadsEditor.addEventListener("input", () => {
    updateFuzzerPayloadsText(els.fuzzerPayloadsEditor.value, { userEdit: true });
    scheduleWorkspaceStateSave();
  });
  if (els.interceptRequestEditor) {
    els.interceptRequestEditor.addEventListener("input", () => {
      if (els.interceptRequestCM) return; // CM handles it
      if (state.selectedInterceptRecord) {
        state.interceptEditorSeedId = state.selectedInterceptRecord.id;
      }
      renderInterceptRequestHighlight(els.interceptRequestEditor.value);
    });
    els.interceptRequestEditor.addEventListener("scroll", syncInterceptRequestHighlightScroll);
  }
  if (els.interceptResponseEditor) {
    els.interceptResponseEditor.addEventListener("input", () => {
      if (els.interceptResponseCM) return; // CM handles it
      if (state.selectedResponseInterceptRecord) {
        state.responseInterceptEditorSeedId = state.selectedResponseInterceptRecord.id;
      }
      renderInterceptResponseHighlight(els.interceptResponseEditor.value);
    });
    els.interceptResponseEditor.addEventListener("scroll", () => {
      if (els.interceptResponseHighlight) {
        els.interceptResponseHighlight.scrollTop = els.interceptResponseEditor.scrollTop;
        els.interceptResponseHighlight.scrollLeft = els.interceptResponseEditor.scrollLeft;
      }
    });
  }

  document.addEventListener("keydown", (event) => {
    const activeModalAction = getActiveModalAction();
    if (activeModalAction) {
      if (event.key === "Escape") {
        event.preventDefault();
        activeModalAction.close();
        return;
      }

      if (
        event.key === "Enter" &&
        typeof activeModalAction.apply === "function" &&
        !event.metaKey &&
        !event.ctrlKey &&
        !event.altKey &&
        !event.shiftKey &&
        !event.isComposing
      ) {
        event.preventDefault();
        activeModalAction.apply();
        return;
      }
    } else if (event.key === "Escape") {
      closeDisplaySettingsModal();
      closeCertificateModal();
      closeFilterModal();
      return;
    }

    if (
      !event.defaultPrevented &&
      (event.metaKey || event.ctrlKey) &&
      !event.shiftKey &&
      !event.altKey &&
      event.key.toLowerCase() === "a" &&
      isSelectableTextTarget(event.target) &&
      !event.target.closest?.(".cm-editor")
    ) {
      event.preventDefault();
      selectEditableTargetContents(event.target);
      return;
    }

    if (
      (event.metaKey || event.ctrlKey) &&
      !event.shiftKey &&
      !event.altKey &&
      event.key.toLowerCase() === "c" &&
      !isEditableTarget(event.target)
    ) {
      const selectedText = getSelectedCodePaneText();
      if (selectedText) {
        event.preventDefault();
        copyTextToClipboard(selectedText).catch((error) => console.error(error));
        return;
      }
    }

    if (
      (event.metaKey || event.ctrlKey) &&
      !event.shiftKey &&
      !event.altKey &&
      event.key.toLowerCase() === "a" &&
      state.activeTool === "proxy" &&
      state.activeProxyTab === "http-history" &&
      !isEditableTarget(event.target)
    ) {
      const targetPane = getActiveMessagePane();
      if (targetPane) {
        event.preventDefault();
        selectCodePaneContents(targetPane);
        return;
      }
    }

    if (
      (event.metaKey || event.ctrlKey) &&
      !event.altKey &&
      event.key === "Enter" &&
      state.activeTool === "proxy" &&
      state.activeProxyTab === "intercept" &&
      state.selectedInterceptRecord
    ) {
      event.preventDefault();
      if (event.shiftKey) {
        dropSelectedIntercept().catch((error) => console.error(error));
      } else {
        forwardSelectedIntercept().catch((error) => console.error(error));
      }
      return;
    }

    // Cmd+1~6: color tag selected HTTP item
    if (
      (event.metaKey || event.ctrlKey) &&
      !event.shiftKey &&
      !event.altKey &&
      state.activeTool === "proxy" &&
      state.activeProxyTab === "http-history" &&
      state.selectedId &&
      event.key >= "1" && event.key <= "6"
    ) {
      event.preventDefault();
      const colors = ["red", "orange", "yellow", "green", "blue", "purple"];
      const color = colors[parseInt(event.key) - 1];
      const item = getHistoryItem(state.selectedId);
      const newColor = item?.color_tag === color ? null : color;
      if (item) item.color_tag = newColor;
      invalidateVisibleEntriesCache();
      renderHistory();
      updateAnnotations(state.selectedId, { color_tag: newColor });
      return;
    }

    if (
      !event.metaKey &&
      !event.ctrlKey &&
      !event.altKey &&
      !event.shiftKey &&
      state.activeTool === "proxy" &&
      !isEditableTarget(event.target)
    ) {
      if (state.activeProxyTab === "http-history") {
        if (event.key === "ArrowUp") {
          event.preventDefault();
          moveHistorySelection(-1).catch((error) => console.error(error));
          return;
        }

        if (event.key === "ArrowDown") {
          event.preventDefault();
          moveHistorySelection(1).catch((error) => console.error(error));
          return;
        }
      }

      if (state.activeProxyTab === "websockets-history") {
        if (event.key === "Escape" && state.wsKeyboardFocus === "frames") {
          event.preventDefault();
          state.wsKeyboardFocus = "sessions";
          hideFrameDetail();
          return;
        }

        if (event.key === "ArrowUp") {
          event.preventDefault();
          if (state.wsKeyboardFocus === "frames") {
            moveFrameSelection(-1);
          } else {
            moveWebsocketSelection(-1).catch((error) => console.error(error));
          }
          return;
        }

        if (event.key === "ArrowDown") {
          event.preventDefault();
          if (state.wsKeyboardFocus === "frames") {
            moveFrameSelection(1);
          } else {
            moveWebsocketSelection(1).catch((error) => console.error(error));
          }
          return;
        }
      }
    }

    // Arrow keys in Dashboard: navigate session rows
    if (
      !event.metaKey &&
      !event.ctrlKey &&
      !event.altKey &&
      !event.shiftKey &&
      state.activeTool === "dashboard" &&
      !isEditableTarget(event.target)
    ) {
      if (event.key === "ArrowUp") {
        event.preventDefault();
        moveSessionSelection(-1);
        return;
      }
      if (event.key === "ArrowDown") {
        event.preventDefault();
        moveSessionSelection(1);
        return;
      }
    }

    // Arrow keys in WS Replay: navigate frames
    if (
      (event.key === "ArrowUp" || event.key === "ArrowDown") &&
      !event.metaKey && !event.ctrlKey && !event.altKey && !event.shiftKey &&
      state.activeTool === "replay" &&
      !isEditableTarget(event.target)
    ) {
      const tab = state.replayTabs.find(t => t.id === state.activeReplayTabId);
      const frames = getWsReplayFrames(tab);
      if (tab && tab.type === "websocket" && frames.length > 0) {
        event.preventDefault();
        const currentPosition = frames.findIndex((frame) => frame.index === tab.wsSelectedFrameIndex);
        const nextPosition = currentPosition === -1
          ? (event.key === "ArrowDown" ? 0 : frames.length - 1)
          : event.key === "ArrowDown"
            ? Math.min(currentPosition + 1, frames.length - 1)
            : Math.max(currentPosition - 1, 0);
        const nextFrameIndex = frames[nextPosition].index;
        tab.wsSelectedFrameIndex = nextFrameIndex;
        renderWsFrameList();
        const target = els.wsFrameList.querySelector(`[data-frame-index="${nextFrameIndex}"]`);
        if (target) { target.scrollIntoView({ block: "nearest" }); }
        return;
      }
    }

    // Ctrl+Tab / Ctrl+Shift+Tab: cycle through Replay tabs
    if (
      event.ctrlKey &&
      !event.metaKey &&
      !event.altKey &&
      event.key === "Tab" &&
      state.activeTool === "replay" &&
      state.replayTabs.length > 1 &&
      !(event.target instanceof Element && event.target.closest(".replay-tab-name-input"))
    ) {
      event.preventDefault();
      const visualOrder = getReplayTabVisualOrder();
      const idx = visualOrder.findIndex((t) => t.id === state.activeReplayTabId);
      const len = visualOrder.length;
      const next = event.shiftKey ? (idx - 1 + len) % len : (idx + 1) % len;
      state.activeReplayTabId = visualOrder[next].id;
      scheduleWorkspaceStateSave();
      renderReplay();
      return;
    }

    if (
      (event.metaKey || event.ctrlKey) &&
      !event.shiftKey &&
      !event.altKey &&
      event.key.toLowerCase() === "r" &&
      state.activeTool === "replay"
    ) {
      event.preventDefault();
      duplicateActiveReplayTab();
      return;
    }

    if (
      (event.metaKey || event.ctrlKey) &&
      !event.shiftKey &&
      !event.altKey &&
      event.key.toLowerCase() === "r" &&
      state.activeTool === "proxy" &&
      state.activeProxyTab === "http-history" &&
      state.selectedId
    ) {
      event.preventDefault();
      openReplayFromSelection().catch(handleSendActionError);
    }

    // Cmd+R on WebSocket tab — send selected frame to WS Replay
    if (
      (event.metaKey || event.ctrlKey) &&
      !event.shiftKey &&
      !event.altKey &&
      event.key.toLowerCase() === "r" &&
      state.activeTool === "proxy" &&
      state.activeProxyTab === "websockets-history" &&
      state.selectedWebsocketRecord &&
      state.selectedFrameIdx != null
    ) {
      event.preventDefault();
      sendWsFrameToReplay(state.selectedFrameIdx);
    }

    // Cmd+R on Findings tab — send selected finding to Replay
    if (
      (event.metaKey || event.ctrlKey) &&
      !event.shiftKey &&
      !event.altKey &&
      event.key.toLowerCase() === "r" &&
      state.activeTool === "proxy" &&
      state.activeProxyTab === "findings"
    ) {
      const recordId = els.findingsDetailJump?.dataset.recordId;
      if (recordId) {
        event.preventDefault();
        sendFindingToReplay(recordId).catch(handleFindingActionError);
      }
    }

    if (
      event.metaKey &&
      !event.shiftKey &&
      !event.altKey &&
      event.key.toLowerCase() === "i"
    ) {
      if (state.activeTool === "proxy" && state.activeProxyTab === "http-history" && state.selectedId) {
        event.preventDefault();
        openFuzzerFromSelection().catch(handleSendActionError);
      } else if (state.activeTool === "replay" && state.activeReplayTabId) {
        event.preventDefault();
        openFuzzerFromReplay().catch(handleSendActionError);
      }
    }

    // Cmd+Shift+F: send to Fuzzer (with content if in HTTP history or Replay)
    if (
      (event.metaKey || event.ctrlKey) &&
      event.shiftKey &&
      !event.altKey &&
      event.key.toLowerCase() === "f"
    ) {
      event.preventDefault();
      if (state.activeTool === "proxy" && state.activeProxyTab === "http-history" && state.selectedId) {
        openFuzzerFromSelection().catch(handleSendActionError);
      } else if (state.activeTool === "replay" && state.activeReplayTabId) {
        openFuzzerFromReplay().catch(handleSendActionError);
      } else {
        state.activeTool = "fuzzer";
        renderToolPanels();
      }
    }
  });

  document.addEventListener("copy", (event) => {
    if (isEditableTarget(event.target)) {
      return;
    }

    const selectedText = getSelectedCodePaneText();
    if (!selectedText || !event.clipboardData) {
      return;
    }

    event.preventDefault();
    event.clipboardData.setData("text/plain", selectedText);
  });

  bindCodePaneScroll(els.requestView, els.requestLines);
  bindCodePaneScroll(els.responseView, els.responseLines);
  // WS Handshake scroll sync
  if (els.wsHandshakeLines) {
    bindCodePaneScroll(els.websocketRequestView, els.wsHandshakeLines);
    bindCodePaneScroll(els.websocketResponseView, els.wsHandshakeLines);
  }
  // WS Handshake search
  if (els.wsHandshakeSearchInput) {
    els.wsHandshakeSearchInput.addEventListener("input", () => {
      // CM path
      const cv = getCMView("wsHandshake");
      if (cv) {
        const query = (els.wsHandshakeSearchInput.value || "").trim();
        const result = cv.applySearch(query);
        if (els.wsHandshakeSearchMeta) {
          els.wsHandshakeSearchMeta.innerHTML = buildSearchMeta(cv.view.state.doc.lines, "raw", result.matchCount);
        }
        return;
      }
      updateWsHandshakeSearch();
    });
    initSearchHitNavigation(els.wsHandshakeSearchMeta, () => {
      const resBtn = document.getElementById("wsHandshakeResBtn");
      return resBtn?.classList.contains("active") ? els.websocketResponseView : els.websocketRequestView;
    });
    initCMSearchNavigation(els.wsHandshakeSearchMeta, "wsHandshake");
  }
  bindMessagePaneActivation();
  bindPaneResizer(els.requestResponseResizer, "request-response");
  bindPaneResizer(els.responseInspectorResizer, "response-inspector");
  bindWorkbenchStackResizer(els.historyWorkbenchResizer);
  bindWebsocketPaneResizer(els.websocketSplitResizer);
  bindWebsocketStackResizer(els.websocketStackResizer);
  bindHistoryColumnResizers();
  applyWsColumnWidths();
  bindWsColumnResizers();

  // WS Handshake Request/Response tab toggle
  const wsReqBtn = document.getElementById("wsHandshakeReqBtn");
  const wsResBtn = document.getElementById("wsHandshakeResBtn");
  if (wsReqBtn && wsResBtn) {
    wsReqBtn.addEventListener("click", () => {
      wsReqBtn.classList.add("active");
      wsResBtn.classList.remove("active");
      if (els.websocketHandshakeCM && state.selectedWebsocketRecord) {
        const text = buildRawWebsocketRequest(state.selectedWebsocketRecord);
        updateCodePaneCM("wsHandshake", els.websocketHandshakeCM, text, { mode: "http" });
      } else {
        els.websocketRequestView?.classList.remove("hidden");
        els.websocketResponseView?.classList.add("hidden");
      }
      updateWsHandshakeLineNumbers();
      updateWsHandshakeSearch();
    });
    wsResBtn.addEventListener("click", () => {
      wsResBtn.classList.add("active");
      wsReqBtn.classList.remove("active");
      if (els.websocketHandshakeCM && state.selectedWebsocketRecord) {
        const text = buildRawWebsocketResponse(state.selectedWebsocketRecord);
        updateCodePaneCM("wsHandshake", els.websocketHandshakeCM, text, { mode: "http" });
      } else {
        els.websocketResponseView?.classList.remove("hidden");
        els.websocketRequestView?.classList.add("hidden");
      }
      updateWsHandshakeLineNumbers();
      updateWsHandshakeSearch();
    });
  }

  // WS pane swap button
  const wsSwapBtn = document.getElementById("wsSwapPanes");
  if (wsSwapBtn && els.websocketWorkbench) {
    wsSwapBtn.addEventListener("click", () => {
      els.websocketWorkbench.classList.toggle("ws-swapped");
    });
  }

  window.addEventListener("resize", () => {
    normalizeWorkbenchPaneWidths();
    normalizeWebsocketPaneWidth();
    normalizeWorkbenchStackHeight();
  });

}

async function loadSettings(retries = 5) {
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const response = await fetch("/api/settings");
      if (!response.ok) {
        throw new Error(`loadSettings failed: ${response.status}`);
      }
      return await _applySettings(response);
    } catch (err) {
      if (attempt < retries) {
        await new Promise((r) => setTimeout(r, 300 * (attempt + 1)));
        continue;
      }
      throw err;
    }
  }
}

async function _applySettings(response) {
  state.settings = await response.json();
  state.runtime = state.settings.runtime;
  state.activeSession = state.settings.active_session;
  // Sync intercept scope pill with server state
  const interceptScopePill = document.getElementById("interceptInScopeToggle");
  if (interceptScopePill) {
    const scopeOnly = state.runtime?.intercept_scope_only ?? true;
    interceptScopePill.classList.toggle("active", scopeOnly);
    state.interceptInScopeOnly = scopeOnly;
  }

  els.proxyAddr.textContent = state.settings.proxy_addr;
  els.uiAddr.textContent = state.settings.ui_addr;
  els.captureMode.textContent = `${formatSize(state.settings.body_preview_bytes)} preview cap / ${state.settings.max_entries} entries`;
  els.settingsSpecialHostHttp.textContent = state.settings.certificate.special_host_http;

  updateProxyStatusIndicator(state.settings.proxy_online);

  const certificate = state.settings.certificate;
  els.certificateName.textContent = certificate.common_name;
  els.certificateExpiry.textContent = formatTimestamp(certificate.expires_at);
  els.certificatePemPath.textContent = certificate.pem_path;
  els.certificateDerPath.textContent = certificate.der_path;
  els.specialHostHttps.textContent = certificate.special_host_https;
  els.dataDir.textContent = state.settings.data_dir;
  els.certificateNote.innerHTML = `
    Download the local root certificate here, or visit <code>${escapeHtml(certificate.special_host_https)}</code>
    from a proxied client. Trust the CA before expecting clean HTTPS flows.
  `;

  renderInterceptStatus();
  renderProxySettings();
  renderDashboard();
}

async function loadAppVersionInfo() {
  const response = await fetch("/api/app-version");
  if (!response.ok) {
    throw new Error(await response.text());
  }

  state.appVersion = await response.json();
  els.appVersionLabel.textContent = `v${state.appVersion.current_version}`;
  els.appVersionLabel.title = `Current version ${state.appVersion.current_version}`;

  if (state.appVersion.update_available) {
    els.openUpdateButton.title = state.appVersion.latest_version
      ? `Update to ${state.appVersion.latest_version}`
      : "Update available";
    els.openUpdateButton.classList.remove("hidden");
  } else {
    els.openUpdateButton.classList.add("hidden");
  }
}

async function performSelfUpdate() {
  if (els.openUpdateButton.disabled) return;
  els.openUpdateButton.disabled = true;

  // Show inline progress bar
  els.openUpdateButton.innerHTML =
    '<span class="update-label">Updating...</span>' +
    '<span class="update-bar"><span class="update-bar-fill"></span></span>';

  const fill = els.openUpdateButton.querySelector(".update-bar-fill");
  const label = els.openUpdateButton.querySelector(".update-label");

  const handleProgress = (data) => {
    if (data.step?.startsWith("error:")) {
      label.textContent = "Update failed";
      fill.style.width = "0%";
      els.openUpdateButton.disabled = false;
      setTimeout(() => {
        els.openUpdateButton.textContent = "Update";
      }, 3000);
      console.error("Self-update failed:", data.step);
      return false;
    }
    if (data.percent != null) {
      fill.style.width = data.percent + "%";
      const mb = (data.downloaded / 1048576).toFixed(1);
      const totalMb = (data.total / 1048576).toFixed(1);
      label.textContent = `${mb} / ${totalMb} MB`;
    } else {
      label.textContent = data.step;
      if (data.step === "Installing update...") fill.style.width = "90%";
      if (data.step === "Restarting...") fill.style.width = "100%";
    }
    return true;
  };

  const markRestarting = () => {
    label.textContent = "Restarting...";
    fill.style.width = "100%";
  };

  try {
    const response = await fetch("/api/self-update", { method: "POST" });
    await requireOkResponse(response, "Failed to start update.");
    if (!response.body) {
      markRestarting();
      return;
    }
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const events = buffer.split("\n\n");
      buffer = events.pop() || "";
      for (const eventText of events) {
        const dataText = eventText
          .split("\n")
          .filter((line) => line.startsWith("data:"))
          .map((line) => line.slice(5).trimStart())
          .join("\n");
        if (!dataText) continue;
        try {
          if (!handleProgress(JSON.parse(dataText))) return;
        } catch (_error) {
          // Ignore malformed progress frames.
        }
      }
    }
    markRestarting();
  } catch (error) {
    // Connection loss usually means the app is restarting after replacement.
    if (label.textContent === "Restarting..." || fill.style.width === "100%") {
      markRestarting();
      return;
    }
    label.textContent = "Update failed";
    fill.style.width = "0%";
    els.openUpdateButton.disabled = false;
    setTimeout(() => {
      els.openUpdateButton.textContent = "Update";
    }, 3000);
    console.error("Self-update failed:", error);
  }
}

async function loadSessions() {
  const response = await fetch("/api/sessions");
  await requireOkResponse(response, "Failed to load sessions.");
  state.sessions = jsonArray(await response.json());
  state.activeSession = state.sessions.find((session) => session.active) || state.sessions[0] || null;
  renderDashboard();
}

async function loadWorkspaceState() {
  const response = await fetch("/api/workspace-state");
  if (!response.ok) {
    throw new Error(await response.text());
  }
  const snapshot = await response.json();
  if (!workspaceSnapshotMatchesActiveSession(snapshot)) {
    await loadSessions();
    if (!workspaceSnapshotMatchesActiveSession(snapshot)) {
      throw new WorkspaceSessionMismatchError(snapshot?.session_id || null);
    }
  }
  applyWorkspaceState(snapshot);
}

class WorkspaceSessionMismatchError extends Error {
  constructor(sessionId) {
    super("Workspace state belongs to a different active session.");
    this.name = "WorkspaceSessionMismatchError";
    this.sessionId = sessionId;
  }
}

function applyWorkspaceState(snapshot) {
  if (!workspaceSnapshotMatchesActiveSession(snapshot)) {
    console.warn("Ignoring workspace state for a non-active session", snapshot?.session_id);
    return;
  }
  for (const tab of state.replayTabs || []) {
    if (tab?.type === "websocket") {
      cleanupWsReplayTab(tab).catch((error) => console.error(error));
    }
  }
  state.workspaceRevision = Number.isFinite(snapshot?.revision) ? snapshot.revision : 0;
  const replayWS = snapshot?.replay || {};
  const tabs = Array.isArray(replayWS.tabs)
    ? replayWS.tabs.map((tab) => hydrateReplayTab(tab)).filter(Boolean)
    : [];

  state.replayTabs = tabs;
  state.replayTabSequence = Math.max(
    Number.isFinite(replayWS.tab_sequence) ? replayWS.tab_sequence : 0,
    ...tabs.map((tab) => tab.sequence || 0),
    0,
  );
  state.activeReplayTabId = tabs.some((tab) => tab.id === replayWS.active_tab_id)
    ? replayWS.active_tab_id
    : tabs[0]?.id ?? null;
  state.replayRenamingTabId = null;

  const fuzzerWS = snapshot?.fuzzer || {};
  state.fuzzerBaseRequest = fuzzerWS.base_request ? cloneEditableRequest(fuzzerWS.base_request) : null;
  state.fuzzerSourceTransactionId = fuzzerWS.source_transaction_id || null;
  state.fuzzerTarget = normalizeFuzzerTargetOverride(fuzzerWS.target);
  state.fuzzerTargetRequestText = state.fuzzerTarget ? normalizeFuzzerTargetAuthority(fuzzerWS.target_request_authority) : null;
  if (state.fuzzerTarget && !state.fuzzerTargetRequestText) {
    state.fuzzerTarget = null;
  }
  state.fuzzerNotice = fuzzerWS.notice || "";
  state.fuzzerRequestText = fuzzerWS.request_text || "";
  state.fuzzerPayloadsText = fuzzerWS.payloads_text || "";
  state.fuzzerAttackRecord = normalizeFuzzerAttackRecord(fuzzerWS.attack_record);
}

function workspaceSnapshotMatchesActiveSession(snapshot) {
  const snapshotSessionId = snapshot?.session_id || null;
  const activeSessionId = state.activeSession?.id || null;
  if (!snapshotSessionId) return true;
  if (!activeSessionId) return false;
  return snapshotSessionId === activeSessionId;
}

function hydrateReplayTab(tab) {
  if (!tab || typeof tab !== "object") {
    return null;
  }

  if (tab.type === "websocket") {
    const wsScheme = tab.ws_scheme || "wss";
    return {
      id: typeof tab.id === "string" && tab.id ? tab.id : crypto.randomUUID(),
      type: "websocket",
      sequence: Number.isFinite(tab.sequence) ? tab.sequence : state.replayTabSequence + 1,
      customLabel: normalizeReplayTabCustomLabel(tab.custom_label || ""),
      pinned: !!tab.pinned,
      label: `WS ${tab.ws_host || "draft"}`,
      wsScheme,
      wsHost: tab.ws_host || "",
      wsPort: tab.ws_port || defaultWsPortForScheme(wsScheme),
      wsPath: tab.ws_path || "/",
      wsHeaders: normalizedHeaders(tab.ws_headers),
      wsHandshakeText: tab.ws_handshake_text || "",
      wsHandshakeEdited: !!tab.ws_handshake_edited,
      wsEditorText: tab.ws_editor_text || "",
      wsMessageType: normalizeWsMessageType(tab.ws_message_type),
      wsEditorBodyEncoded: !!tab.ws_editor_body_encoded,
      wsSetupQueue: Array.isArray(tab.ws_setup_queue)
        ? tab.ws_setup_queue.map((item) => normalizeWsSetupItem(item))
        : [],
      wsStatus: "disconnected",
      wsFrames: normalizeWebsocketFrames(tab.ws_frames),
      wsSelectedFrameIndex: -1,
      wsError: null,
      wsSessionId: null,
      wsPollTimer: null,
      wsLifecycleToken: 0,
      wsSetupPending: false,
      wsSetupRunning: false,
    };
  }

  const fallbackRequest = tab.base_request ? cloneEditableRequest(tab.base_request) : createDefaultEditableRequest();
  const fallbackTarget = authorityToTargetState(fallbackRequest.host, fallbackRequest.scheme);
  const historyEntries = Array.isArray(tab.history_entries)
    ? tab.history_entries.map((entry) => hydrateRepeaterHistoryEntry(entry, fallbackRequest)).filter(Boolean)
    : [];
  const historyIndex = normalizeRepeaterHistoryIndex(tab.history_index, historyEntries.length);
  const normalizedTarget = normalizeRepeaterTargetInput(
    tab.target_host ?? fallbackTarget.host,
    tab.target_port ?? fallbackTarget.port,
    tab.target_scheme || fallbackTarget.scheme,
  );
  return {
    id: typeof tab.id === "string" && tab.id ? tab.id : crypto.randomUUID(),
    sequence: Number.isFinite(tab.sequence) ? tab.sequence : state.replayTabSequence + 1,
    customLabel: normalizeReplayTabCustomLabel(tab.custom_label || ""),
    pinned: !!tab.pinned,
    baseRequest: fallbackRequest,
    sourceTransactionId: tab.source_transaction_id || null,
    notice: tab.notice || "",
    requestText: tab.request_text ?? buildEditableRawRequest(fallbackRequest),
    httpVersionMode: normalizeReplayHttpVersion(tab.http_version_mode || ""),
    responseRecord: tab.response_record || null,
    targetScheme: normalizedTarget.scheme,
    targetHost: normalizedTarget.host,
    targetPort: normalizedTarget.port,
    targetManuallyEdited: !!tab.target_manually_edited,
    historyEntries,
    historyIndex,
  };
}

function hydrateRepeaterHistoryEntry(entry, fallbackRequest) {
  if (!entry || typeof entry !== "object") {
    return null;
  }

  const request = entry.request ? cloneEditableRequest(entry.request) : cloneEditableRequest(fallbackRequest);
  const fallbackTarget = authorityToTargetState(request.host, request.scheme);
  const normalizedTarget = normalizeRepeaterTargetInput(
    entry.target_host ?? fallbackTarget.host,
    entry.target_port ?? fallbackTarget.port,
    entry.target_scheme || fallbackTarget.scheme,
  );
  return {
    request,
    requestText: entry.request_text ?? buildEditableRawRequest(request),
    httpVersionMode: normalizeReplayHttpVersion(entry.http_version_mode || "")
      || replayHttpVersionFromText(entry.request_text || ""),
    responseRecord: entry.response_record || null,
    notice: entry.notice || "",
    targetScheme: normalizedTarget.scheme,
    targetHost: normalizedTarget.host,
    targetPort: normalizedTarget.port,
  };
}

function normalizeFuzzerTargetOverride(target) {
  if (!target || typeof target !== "object") return null;
  const normalized = normalizeRepeaterTargetInput(target.host, target.port, target.scheme || "https");
  if (!normalized.host) return null;
  return {
    scheme: normalized.scheme || "https",
    host: normalized.host,
    port: normalizePortValue(normalized.port) || (normalized.scheme === "http" ? "80" : "443"),
  };
}

function createWorkspaceClientId() {
  if (window.crypto?.randomUUID) {
    return window.crypto.randomUUID();
  }
  return `client-${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`;
}

function snapshotWorkspaceState(options = {}) {
  const wsFrameBudget = {
    frames: Number.isFinite(options.wsFrameLimit)
      ? Math.max(0, options.wsFrameLimit)
      : WS_REPLAY_MAX_PERSISTED_TOTAL_FRAMES,
    bytes: Number.isFinite(options.wsBodyByteLimit)
      ? Math.max(0, options.wsBodyByteLimit)
      : WS_REPLAY_MAX_PERSISTED_TOTAL_BODY_BYTES,
  };
  return {
    revision: state.workspaceRevision || 0,
    session_id: state.activeSession?.id || null,
    client_id: workspaceClientId,
    client_version: workspaceSaveVersion,
    replay: {
      tabs: state.replayTabs.map((tab) => {
        if (tab.type === "websocket") {
          return {
            id: tab.id,
            type: "websocket",
            sequence: tab.sequence,
            custom_label: tab.customLabel || "",
            pinned: !!tab.pinned,
            ws_scheme: tab.wsScheme || "wss",
            ws_host: tab.wsHost || "",
            ws_port: tab.wsPort || defaultWsPortForScheme(tab.wsScheme),
            ws_path: tab.wsPath || "/",
            ws_headers: normalizedHeaders(tab.wsHeaders),
            ws_handshake_text: tab.wsHandshakeText || "",
            ws_handshake_edited: !!tab.wsHandshakeEdited,
            ws_editor_text: tab.wsEditorText || "",
            ws_message_type: normalizeWsMessageType(tab.wsMessageType),
            ws_editor_body_encoded: !!tab.wsEditorBodyEncoded,
            ws_setup_queue: (Array.isArray(tab.wsSetupQueue) ? tab.wsSetupQueue : []).map((item) => ({
              label: item.label || "",
              body: item.body || "",
              kind: normalizeWsMessageType(item.kind),
              body_encoded: !!item.bodyEncoded,
              autoSend: !!item.autoSend,
              sent: !!item.sent,
            })),
            ws_frames: snapshotWsReplayFrames(tab, wsFrameBudget),
          };
        }
        const historyEntries = Array.isArray(tab.historyEntries)
          ? tab.historyEntries.filter((entry) => entry && typeof entry === "object")
          : [];
        return {
          id: tab.id,
          sequence: tab.sequence,
          custom_label: tab.customLabel || "",
          pinned: !!tab.pinned,
          base_request: tab.baseRequest ? cloneEditableRequest(tab.baseRequest) : null,
          source_transaction_id: tab.sourceTransactionId || null,
          notice: tab.notice || "",
          request_text: tab.requestText || "",
          http_version_mode: normalizeReplayHttpVersion(tab.httpVersionMode || ""),
          response_record: tab.responseRecord || null,
          target_scheme: tab.targetScheme || "https",
          target_host: tab.targetHost || "",
          target_port: normalizePortValue(tab.targetPort),
          target_manually_edited: !!tab.targetManuallyEdited,
          history_entries: historyEntries.map((entry) => ({
            request: cloneEditableRequest(entry.request),
            request_text: entry.requestText || "",
            http_version_mode: normalizeReplayHttpVersion(entry.httpVersionMode || "")
              || replayHttpVersionFromText(entry.requestText || ""),
            response_record: entry.responseRecord || null,
            notice: entry.notice || "",
            target_scheme: entry.targetScheme || "https",
            target_host: entry.targetHost || "",
            target_port: normalizePortValue(entry.targetPort),
          })),
          history_index: normalizeRepeaterHistoryIndex(tab.historyIndex, historyEntries.length),
        };
      }),
      active_tab_id: state.activeReplayTabId,
      tab_sequence: state.replayTabSequence,
    },
    fuzzer: {
      base_request: state.fuzzerBaseRequest ? cloneEditableRequest(state.fuzzerBaseRequest) : null,
      source_transaction_id: state.fuzzerSourceTransactionId || null,
      target: normalizeFuzzerTargetOverride(state.fuzzerTarget),
      target_request_authority: state.fuzzerTarget ? normalizeFuzzerTargetAuthority(state.fuzzerTargetRequestText) : null,
      notice: state.fuzzerNotice || "",
      request_text: state.fuzzerRequestText || "",
      payloads_text: state.fuzzerPayloadsText || "",
      attack_record: normalizeFuzzerAttackRecord(state.fuzzerAttackRecord),
    },
  };
}

function scheduleWorkspaceStateSave() {
  if (!state.activeSession) {
    return;
  }

  window.clearTimeout(wsTranscriptSaveTimer);
  wsTranscriptSaveTimer = null;
  wsTranscriptFirstDirtyAt = 0;
  workspaceSaveDirty = true;
  workspaceSaveVersion += 1;
  window.clearTimeout(workspaceSaveTimer);
  workspaceSaveTimer = window.setTimeout(() => {
    workspaceSaveTimer = null;
    flushQueuedWorkspaceStateSave().catch((error) => console.error(error));
  }, 250);
}

function scheduleWsTranscriptWorkspaceSave() {
  if (!state.activeSession) {
    return;
  }
  workspaceSaveDirty = true;
  workspaceSaveVersion += 1;
  const now = Date.now();
  if (!wsTranscriptFirstDirtyAt) {
    wsTranscriptFirstDirtyAt = now;
  }
  const elapsed = now - wsTranscriptFirstDirtyAt;
  const delay = elapsed >= WS_REPLAY_TRANSCRIPT_SAVE_MAX_WAIT_MS
    ? 0
    : Math.min(
        WS_REPLAY_TRANSCRIPT_SAVE_DELAY_MS,
        WS_REPLAY_TRANSCRIPT_SAVE_MAX_WAIT_MS - elapsed,
      );
  window.clearTimeout(wsTranscriptSaveTimer);
  wsTranscriptSaveTimer = window.setTimeout(() => {
    wsTranscriptSaveTimer = null;
    wsTranscriptFirstDirtyAt = 0;
    window.clearTimeout(workspaceSaveTimer);
    workspaceSaveTimer = window.setTimeout(() => {
      workspaceSaveTimer = null;
      flushQueuedWorkspaceStateSave().catch((error) => console.error(error));
    }, 0);
  }, delay);
}

async function flushQueuedWorkspaceStateSave() {
  if (!state.activeSession) {
    return;
  }
  if (workspaceSaveLoopPromise) {
    return workspaceSaveLoopPromise;
  }

  workspaceSaveLoopPromise = runQueuedWorkspaceStateSaves()
    .finally(() => {
      workspaceSaveLoopPromise = null;
    });
  return workspaceSaveLoopPromise;
}

async function runQueuedWorkspaceStateSaves() {
  while (state.activeSession && workspaceSaveDirty) {
    workspaceSaveDirty = false;
    const version = workspaceSaveVersion;
    const snapshot = snapshotWorkspaceState();
    workspaceSaveLastSnapshot = snapshot;
    workspaceSaveInFlight = true;
    try {
      await saveWorkspaceState(snapshot);
    } catch (error) {
      if (!(error instanceof WorkspaceStateConflictError)) {
        workspaceSaveDirty = true;
        window.clearTimeout(workspaceSaveTimer);
        workspaceSaveTimer = window.setTimeout(() => {
          workspaceSaveTimer = null;
          flushQueuedWorkspaceStateSave().catch((error) => console.error(error));
        }, 1000);
        throw error;
      }
      workspaceSaveConflictPending = true;
      workspaceSaveDirty = false;
      showToast(
        "Workspace changed elsewhere; local workspace edits were not saved. Reload the workspace to reconcile.",
        "error",
        6000,
      );
      return;
    } finally {
      workspaceSaveInFlight = false;
    }
    if (workspaceSaveVersion !== version) {
      workspaceSaveDirty = true;
    }
    workspaceSaveConflictPending = false;
  }
}

async function saveWorkspaceState(snapshot = snapshotWorkspaceState()) {
  if (!state.activeSession) {
    return;
  }

  const response = await fetch("/api/workspace-state", {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify(snapshot),
  });

  if (!response.ok) {
    if (response.status === 409) {
      const latest = await response.json().catch(() => null);
      throw new WorkspaceStateConflictError(latest);
    }
    throw new Error(await response.text());
  }
  const saved = await response.json();
  const currentSessionId = state.activeSession?.id || null;
  if (
    (snapshot?.session_id && snapshot.session_id !== currentSessionId)
    || (saved?.session_id && saved.session_id !== currentSessionId)
  ) {
    return;
  }
  state.workspaceRevision = Number.isFinite(saved?.revision) ? saved.revision : state.workspaceRevision;
  workspaceSaveConflictPending = false;
}

class WorkspaceStateConflictError extends Error {
  constructor(latest) {
    super("Workspace state revision conflict");
    this.name = "WorkspaceStateConflictError";
    this.latest = latest;
  }
}

function handleWorkspaceActionError(error) {
  console.error(error);
  if (error instanceof WorkspaceStateConflictError) {
    showToast(
      "Workspace changed elsewhere. Reload the workspace before switching sessions.",
      "error",
      7000,
    );
    return;
  }
  showToast(error?.message || "Workspace action failed.", "error", 6000);
}

async function flushWorkspaceState() {
  const hasQueuedChanges = !!(workspaceSaveDirty || workspaceSaveTimer || wsTranscriptSaveTimer);
  const hasInFlightSave = !!(workspaceSaveInFlight || workspaceSaveLoopPromise);
  window.clearTimeout(wsTranscriptSaveTimer);
  wsTranscriptSaveTimer = null;
  wsTranscriptFirstDirtyAt = 0;
  window.clearTimeout(workspaceSaveTimer);
  workspaceSaveTimer = null;
  if (!state.activeSession || (!hasQueuedChanges && !hasInFlightSave)) {
    return;
  }
  if (hasQueuedChanges) {
    workspaceSaveDirty = true;
    workspaceSaveVersion += 1;
  }
  await flushQueuedWorkspaceStateSave();
  if (workspaceSaveConflictPending) {
    throw new WorkspaceStateConflictError(null);
  }
}

function flushWorkspaceStateOnUnload() {
  const hadTranscriptSaveTimer = !!wsTranscriptSaveTimer;
  window.clearTimeout(wsTranscriptSaveTimer);
  wsTranscriptSaveTimer = null;
  wsTranscriptFirstDirtyAt = 0;
  disconnectWsReplayTabsOnUnload();
  if (!state.activeSession || (!workspaceSaveDirty && !workspaceSaveTimer && !workspaceSaveInFlight && !hadTranscriptSaveTimer)) {
    return;
  }
  window.clearTimeout(workspaceSaveTimer);
  workspaceSaveTimer = null;
  const snapshot = workspaceSaveDirty || hadTranscriptSaveTimer
    ? snapshotWorkspaceState()
    : (workspaceSaveInFlight && workspaceSaveLastSnapshot
      ? workspaceSaveLastSnapshot
      : snapshotWorkspaceState());
  const payload = workspaceUnloadPayload(snapshot);
  if (!payload) {
    workspaceSaveDirty = true;
    console.warn("Skipping unload workspace keepalive save because even the bounded snapshot is too large.");
    return;
  }
  const blob = new Blob([payload], { type: "application/json" });
  if (navigator.sendBeacon && navigator.sendBeacon("/api/workspace-state", blob)) {
    return;
  }
  fetch("/api/workspace-state", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: payload,
    keepalive: true,
  }).catch(() => {});
}

function workspaceUnloadPayload(primarySnapshot) {
  const candidates = [
    primarySnapshot,
    snapshotWorkspaceState({
      wsFrameLimit: WORKSPACE_UNLOAD_WS_FRAME_BUDGET,
      wsBodyByteLimit: WORKSPACE_UNLOAD_WS_BODY_BUDGET,
    }),
    snapshotWorkspaceState({ wsFrameLimit: 0, wsBodyByteLimit: 0 }),
  ];
  for (const candidate of candidates) {
    const payload = JSON.stringify(candidate);
    if (utf8ByteLength(payload) <= WORKSPACE_UNLOAD_KEEPALIVE_MAX_BYTES) {
      return payload;
    }
  }
  return null;
}

function disconnectWsReplayTabsOnUnload() {
  const activeSessionId = state.activeSession?.id || null;
  if (!activeSessionId) return;
  for (const tab of state.replayTabs || []) {
    if (!tab || tab.type !== "websocket") continue;
    if (tab.wsStatus !== "connected" && tab.wsStatus !== "connecting") continue;
    const sessionId = tab.wsSessionId || activeSessionId;
    const payload = JSON.stringify({ session_id: sessionId, id: tab.id, remove: false });
    if (utf8ByteLength(payload) > WORKSPACE_UNLOAD_KEEPALIVE_MAX_BYTES) continue;
    fetch("/api/replay/ws-disconnect", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: payload,
      keepalive: true,
    }).catch(() => {});
    tab.wsStatus = "disconnected";
    tab.wsError = null;
  }
}

function hasPendingWorkspaceStateSave() {
  return !!(workspaceSaveDirty || workspaceSaveTimer || wsTranscriptSaveTimer || workspaceSaveInFlight || workspaceSaveLoopPromise);
}

function resetSessionScopedUiState() {
  clearReplaySendInFlight();
  closeContextMenu();
  window.clearTimeout(refreshTimer);
  refreshTimer = null;
  window.clearTimeout(workspaceSaveTimer);
  workspaceSaveTimer = null;
  window.clearTimeout(wsTranscriptSaveTimer);
  wsTranscriptSaveTimer = null;
  wsTranscriptFirstDirtyAt = 0;
  workspaceSaveDirty = false;
  workspaceSaveConflictPending = false;
  clearHistoryBackfill();
  window.clearTimeout(_incrementalTimer);
  _incrementalTimer = 0;
  window.clearTimeout(_transactionDeltaTimer);
  _transactionDeltaTimer = 0;
  _pendingTransactionSummaries.length = 0;
  state.items = [];
  state.historyPaging = createHistoryPagingState();
  state.selectedId = null;
  state.selectedRecord = null;
  state._connectCount = 0;
  state._itemById = new Map();
  state._itemIndexById = new Map();
  state._itemsVersion += 1;
  invalidateVisibleEntriesCache();
  state.intercepts = [];
  state.responseIntercepts = [];
  state.interceptRules = [];
  state.selectedInterceptId = null;
  state.selectedInterceptRecord = null;
  state.selectedResponseInterceptId = null;
  state.selectedResponseInterceptRecord = null;
  state.responseInterceptEditorSeedId = null;
  renderIntercepts();
  renderResponseIntercepts();
  renderInterceptRules();
  updateInterceptQueueBadges();
  state.websocketSessions = [];
  state.websocketPaging = createWebsocketPagingState();
  state.selectedWebsocketId = null;
  state.selectedWebsocketRecord = null;
  _websocketLoadGeneration += 1;
  _websocketDetailGeneration += 1;
  state.eventLog = [];
  state.matchReplaceRules = [];
  state.selectedMatchReplaceRuleId = null;
  state.targetSiteMap = [];
  resetOastUiState();
  state.targetScopeDraft = "";
  state.targetScopeDirty = false;
  state.targetScopeEditorSessionId = null;
  state.targetExpandedHosts = new Set();
  scannerConfigCache = null;
  scannerSettingsSessionId = null;
  if (els.scannerSettingsBackdrop) {
    closeScannerSettings();
  }
  resetFindingsUiState();
  state.replayTabs.forEach((tab) => {
    if (tab.type === "websocket") cleanupWsReplayTab(tab);
  });
  state.replayTabs = [];
  state.activeReplayTabId = null;
  state.replayTabSequence = 0;
  state.replayRenamingTabId = null;
  state.fuzzerRunToken = (state.fuzzerRunToken || 0) + 1;
  state.fuzzerRunning = false;
  state.fuzzerBaseRequest = null;
  state.fuzzerSourceTransactionId = null;
  state.fuzzerTarget = null;
  state.fuzzerTargetRequestText = null;
  state.fuzzerNotice = "";
  state.fuzzerRequestText = "";
  state.fuzzerPayloadsText = "";
  state.fuzzerAttackRecord = null;
  state._selectedFuzzerResultKey = null;
  state._fuzzerDetailRecord = null;
  state.sequenceDefinitions = [];
  state.selectedSequenceId = null;
  state.editingSequence = null;
  state.sequenceDirty = false;
  state.sequenceRunResult = null;
  state.sequencePastRuns = [];
  clearCompareState();
  renderHistory();
  renderEmptyDetail();
  renderWebsocketSessions();
  hideFrameDetail();
  renderEventLog();
  renderMatchReplaceRules();
  renderTarget();
  renderFindings();
  renderReplayClearedState();
  renderFuzzer();
  renderSequencePanel();
}

function renderReplayClearedState() {
  if (els.replayTabStrip) {
    els.replayTabStrip.innerHTML = "";
  }
  if (els.replayRequestCM) {
    updateCodePaneCM("replayReq", els.replayRequestCM, "", {
      mode: "http", readOnly: false,
      placeholder: "Loading session...",
      onChange: syncReplayRequestTextFromEditor,
    });
  } else {
    if (els.replayRequestEditor) els.replayRequestEditor.value = "";
    renderReplayRequestHighlight("");
  }
  if (els.replayHostInput) els.replayHostInput.value = "";
  if (els.replayPortInput) els.replayPortInput.value = "";
  if (els.replaySchemeSelect) els.replaySchemeSelect.value = "https";
  if (els.replayResponseMeta) els.replayResponseMeta.textContent = "Loading session...";
  renderReplayResponseView("Loading session...");
  updateReplaySearchPane("request", "");
  updateReplaySearchPane("response", "Loading session...");
  if (els.replayBackButton) els.replayBackButton.disabled = true;
  if (els.replayForwardButton) els.replayForwardButton.disabled = true;
  if (els.replayFollowRedirectButton) els.replayFollowRedirectButton.classList.add("hidden");
}

async function reloadSessionWorkspace() {
  resetSessionScopedUiState();
  for (let attempt = 0; attempt < 2; attempt += 1) {
    await loadSessions();
    await loadSettings();
    try {
      await loadWorkspaceState();
      break;
    } catch (error) {
      if (error instanceof WorkspaceSessionMismatchError && attempt === 0) {
        continue;
      }
      throw error;
    }
  }
  await loadTransactions(false);
  await loadIntercepts(false);
  await loadResponseIntercepts(false);
  await loadInterceptRules();
  await loadWebsockets(false);
  await loadEventLog();
  await loadMatchReplaceRules();
  await loadSequences();
  await loadTargetSiteMap(true);
  if (state.activeTool === "proxy" && state.activeProxyTab === "oast") {
    await loadOastCallbacks();
  }
  await refreshScannerQuickToggle();
  connectEvents();
  renderToolPanels();
}

async function handleExternalSessionChanged() {
  try {
    if (!(await flushSequenceDraft())) {
      return;
    }
  } catch (error) {
    handleSequenceActionError(error);
    return;
  }
  if (hasPendingWorkspaceStateSave()) {
    try {
      await flushWorkspaceState();
    } catch (error) {
      handleWorkspaceActionError(error);
      return;
    }
  }
  await reloadSessionWorkspace();
}

async function createSession() {
  if (!(await flushSequenceDraft())) {
    return;
  }
  await flushWorkspaceState();
  const name = els.dashboardCreateSessionName.value.trim();
  const response = await fetch("/api/sessions", {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify({ name: name || null }),
  });
  if (!response.ok) {
    throw new Error(await response.text());
  }
  els.dashboardCreateSessionName.value = "";
  await reloadSessionWorkspace();
}

async function activateSessionById(id) {
  if (!(await flushSequenceDraft())) {
    return;
  }
  await flushWorkspaceState();
  const response = await fetch(`/api/sessions/${id}/activate`, {
    method: "POST",
  });
  if (!response.ok) {
    throw new Error(await response.text());
  }
  await reloadSessionWorkspace();
}

async function loadRuntimeSettings() {
  const sessionId = currentSessionId();
  const response = await fetch(sessionQueryPath("/api/runtime", sessionId));
  await requireOkResponse(response, "Failed to load runtime settings.");
  const runtime = await response.json();
  if (sessionId !== currentSessionId()) {
    return;
  }
  state.runtime = runtime;
  renderInterceptStatus();
  renderProxySettings();
}

function currentSessionId() {
  return state.activeSession?.id || null;
}

function sessionQueryPath(path, sessionId = currentSessionId()) {
  if (!sessionId) return path;
  const separator = path.includes("?") ? "&" : "?";
  return `${path}${separator}session_id=${encodeURIComponent(sessionId)}`;
}

function transactionPath(id, sessionId = currentSessionId()) {
  return sessionQueryPath(`/api/transactions/${encodeURIComponent(id)}`, sessionId);
}

function buildTransactionsPageUrl({ limit, offset = 0, beforeSequence = null } = {}) {
  const params = new URLSearchParams();
  const sessionId = currentSessionId();
  const filters = state.filterSettings;
  const statusClasses = selectedStatusClasses(filters);
  const mimeTypes = selectedMimeTypes(filters);
  params.set("limit", String(limit ?? HTTP_HISTORY_PAGE_SIZE));
  if (beforeSequence != null) {
    params.set("before_sequence", String(beforeSequence));
  } else {
    params.set("offset", String(offset));
  }
  params.set("sort_key", state.sortKey || "index");
  params.set("sort_direction", state.sortDirection || "desc");
  if (sessionId) params.set("session_id", sessionId);
  params.set("hide_connect", "true");
  if (state.query) params.set("q", state.query);
  if (state.method) params.set("method", state.method);
  if (filters.inScopeOnly) params.set("in_scope_only", "true");
  if (filters.hideWithoutResponses) params.set("hide_without_responses", "true");
  if (filters.onlyParameterized) params.set("only_parameterized", "true");
  if (filters.onlyNotes) params.set("only_notes", "true");
  params.set("status_classes", statusClasses.join(","));
  params.set("mime_types", mimeTypes.join(","));
  if (filters.hiddenExtensions) params.set("hidden_extensions", filters.hiddenExtensions);
  if (filters.port) params.set("port", filters.port);
  if (filters.colorTags?.size) params.set("color_tags", [...filters.colorTags].join(","));
  if (filters.searchTerm) {
    params.set("advanced_search", filters.searchTerm);
    if (filters.regex) params.set("advanced_regex", "true");
    if (filters.caseSensitive) params.set("advanced_case_sensitive", "true");
    if (filters.negativeSearch) params.set("advanced_negative", "true");
  }
  return `/api/transactions-page?${params.toString()}`;
}

function selectedStatusClasses(filters) {
  const status = filters.status || {};
  const selected = [];
  if (status.success) selected.push("success");
  if (status.redirect) selected.push("redirect");
  if (status.clientError) selected.push("client_error");
  if (status.serverError) selected.push("server_error");
  if (status.other) selected.push("other");
  return selected;
}

function selectedMimeTypes(filters) {
  const mime = filters.mime || {};
  const selected = [];
  if (mime.html) selected.push("html");
  if (mime.script) selected.push("script");
  if (mime.json) selected.push("json");
  if (mime.css) selected.push("css");
  if (mime.image) selected.push("image");
  if (mime.other) selected.push("other");
  return selected;
}

async function fetchTransactionPage(offsetOrOptions = 0) {
  const sessionId = currentSessionId();
  const options = typeof offsetOrOptions === "object"
    ? offsetOrOptions
    : { offset: offsetOrOptions };
  const response = await fetch(buildTransactionsPageUrl({
    limit: state.historyPaging.pageSize,
    offset: options.offset ?? 0,
    beforeSequence: options.beforeSequence ?? null,
  }));
  if (!response.ok) {
    const message = await response.text();
    if (els.historyMeta) els.historyMeta.textContent = `HTTP History filter error: ${message}`;
    if (els.liveStatus) {
      els.liveStatus.textContent = "Filter error";
      els.liveStatus.classList.remove("online");
    }
    throw new Error(message);
  }
  const page = await response.json();
  if (sessionId !== currentSessionId()) {
    return null;
  }
  return page;
}

function applyPendingAnnotationsToItems(items) {
  if (!state._pendingAnnotations) return;
  const sessionId = currentSessionId();
  const freshById = new Map(items.map((item) => [item.id, item]));
  for (const [id, entry] of state._pendingAnnotations) {
    if (entry?.sessionId !== sessionId) continue;
    const item = freshById.get(id);
    if (item) Object.assign(item, entry.payload || {});
  }
}

function updateHistoryPagingCursor(items) {
  if (!canUseSequenceCursorForHistoryPaging()) {
    state.historyPaging.beforeSequence = null;
    return;
  }
  if (!items.length) return;
  let oldest = state.historyPaging.beforeSequence;
  for (const item of items) {
    if (item.sequence == null) continue;
    oldest = oldest == null ? item.sequence : Math.min(oldest, item.sequence);
  }
  state.historyPaging.beforeSequence = oldest;
}

function refreshHistoryPagingCursorFromItems() {
  if (!canUseSequenceCursorForHistoryPaging() || !state.historyPaging) {
    if (state.historyPaging) state.historyPaging.beforeSequence = null;
    return;
  }
  let oldest = null;
  for (const item of state.items) {
    if (item.sequence == null) continue;
    oldest = oldest == null ? item.sequence : Math.min(oldest, item.sequence);
  }
  state.historyPaging.beforeSequence = oldest;
  state.historyPaging.offset = state.items.length;
}

function isKnownCount(value) {
  return Number.isFinite(value);
}

async function loadTransactions(preserveSelection = true, options = {}) {
  _historyFullLoadInFlight += 1;
  try {
    clearHistoryBackfill();
    state.historyPaging = createHistoryPagingState();
    state.historyPaging.generation = ++_historyPagingGeneration;
    const generation = state.historyPaging.generation;
    const page = await fetchTransactionPage(0);
    if (!page) {
      return;
    }
    if (state.historyPaging.generation !== generation) {
      return;
    }
    const freshItems = jsonArray(page.items);

    // Preserve in-flight annotation changes (optimistic updates)
    applyPendingAnnotationsToItems(freshItems);
    state.items = freshItems;
    state._itemsVersion += 1;
    // Pre-compute search haystacks and CONNECT count to avoid first-search latency
    precomputeItemIndexes();
    updateHistoryPagingCursor(freshItems);
    state.historyPaging.offset = freshItems.length;
    state.historyPaging.total = page.total ?? freshItems.length;
    state.historyPaging.filteredTotal = page.filtered_total ?? null;
    state.historyPaging.hiddenConnectTotal = page.hidden_connect_total ?? null;
    state.historyPaging.hasMore = Boolean(page.has_more);
    state.historyPaging.fullyLoaded = !state.historyPaging.hasMore;
    state.historyDirty = false;
    invalidateVisibleEntriesCache();
    if (options.resetScroll) {
      resetHistoryScrollPosition();
    }

    const visibleEntries = getVisibleEntries();
    if (!preserveSelection || !visibleEntries.some((entry) => entry.item.id === state.selectedId)) {
      state.selectedId = visibleEntries[0]?.item.id ?? null;
    }

    renderHistory();
    if (state.selectedId) {
      if (preserveSelection && state.selectedRecord && state.selectedRecord.id === state.selectedId) {
        return;
      }
      await loadTransactionDetail(state.selectedId);
    } else {
      renderEmptyDetail();
    }
  } finally {
    _historyFullLoadInFlight = Math.max(0, _historyFullLoadInFlight - 1);
    if (!_historyFullLoadInFlight && _pendingTransactionSummaries.length) {
      scheduleTransactionDeltaFlush();
    }
  }
}

async function loadTransactionDetail(id) {
  const sessionId = currentSessionId();
  const response = await fetch(transactionPath(id, sessionId));
  if (sessionId !== currentSessionId()) {
    return;
  }
  if (!response.ok) {
    if (state.selectedId === id) {
      renderEmptyDetail();
    }
    return;
  }

  const record = await response.json();
  if (state.selectedId !== id || sessionId !== currentSessionId()) {
    return;
  }
  state.selectedRecord = record;
  renderDetail(state.selectedRecord);
}

async function loadSelectedTransactionRecord() {
  const id = state.selectedId;
  if (!id) {
    return null;
  }
  if (state.selectedRecord?.id === id) {
    return state.selectedRecord;
  }

  const sessionId = currentSessionId();
  const response = await fetch(transactionPath(id, sessionId));
  if (sessionId !== currentSessionId()) {
    return null;
  }
  if (!response.ok) {
    if (state.selectedId === id) {
      renderEmptyDetail();
    }
    return null;
  }

  const record = await response.json();
  if (state.selectedId === id && sessionId === currentSessionId()) {
    state.selectedRecord = record;
    renderDetail(record);
    return record;
  }
  return null;
}

async function loadIntercepts(preserveSelection = true) {
  const sessionId = currentSessionId();
  const response = await fetch(sessionQueryPath("/api/intercepts", sessionId));
  await requireOkResponse(response, "Failed to load intercepted requests.");
  const intercepts = jsonArray(await response.json());
  if (sessionId !== currentSessionId()) {
    return;
  }
  state.intercepts = intercepts;

  const visibleIntercepts = getVisibleRequestInterceptSummaries();
  if (!preserveSelection || !visibleIntercepts.some((item) => item.id === state.selectedInterceptId)) {
    state.selectedInterceptId = visibleIntercepts[0]?.id ?? null;
    state.selectedInterceptRecord = null;
    state.interceptEditorSeedId = null;
  }

  renderIntercepts();
  updateInterceptQueueBadges();
  // Auto-switch to Request Queue when requests arrive and Response Queue is empty
  if (visibleIntercepts.length > 0 && getVisibleResponseInterceptSummaries().length === 0 && state.interceptQueueTab === "response") {
    switchInterceptQueueTab("request");
  }
  if (state.selectedInterceptId) {
    await loadInterceptDetail(state.selectedInterceptId);
  } else {
    state.selectedInterceptRecord = null;
    renderIntercepts();
  }
}

async function loadInterceptDetail(id) {
  const sessionId = currentSessionId();
  const response = await fetch(sessionQueryPath(`/api/intercepts/${id}`, sessionId));
  if (sessionId !== currentSessionId() || state.selectedInterceptId !== id) {
    return;
  }
  if (!response.ok) {
    state.selectedInterceptRecord = null;
    renderIntercepts();
    return;
  }

  const record = await response.json();
  if (sessionId !== currentSessionId() || state.selectedInterceptId !== id) {
    return;
  }
  state.selectedInterceptRecord = record;
  renderIntercepts();
}

/* ─── Intercept Rules ─── */

async function loadInterceptRules() {
  const sessionId = currentSessionId();
  const response = await fetch(sessionQueryPath("/api/intercept-rules", sessionId));
  await requireOkResponse(response, "Failed to load intercept rules.");
  const rules = jsonArray(await response.json());
  if (sessionId !== currentSessionId()) {
    return;
  }
  state.interceptRules = rules;
  renderInterceptRules();
}

function handleInterceptRuleError(error) {
  console.error(error);
  showToast(error?.message || "Intercept rule action failed.", "error", 6000);
  loadInterceptRules().catch(console.error);
}

function renderInterceptRules() {
  const container = document.getElementById("interceptRulesList");
  if (!container) return;
  const rules = state.interceptRules || [];
  if (!rules.length) {
    container.innerHTML = `<div class="intercept-rules-empty">No rules: all in-scope requests will be intercepted. Add a response or Req+Res rule to intercept responses.</div>`;
    return;
  }
  container.innerHTML = rules.map((rule) => {
    const methods = rule.method_filter?.length ? rule.method_filter.join(", ") : "Any";
    const host = rule.host_pattern || "*";
    const path = rule.path_pattern || "*";
    const scope = rule.scope || "request";
    const scopeLabel = scope === "both" ? "Req+Res" : scope === "response" ? "Res" : "Req";
    return `<div class="intercept-rule-row${rule.enabled ? "" : " disabled"}" data-rule-id="${rule.id}">
      <label class="intercept-rule-toggle" title="Enable/disable">
        <input type="checkbox" ${rule.enabled ? "checked" : ""} data-rule-toggle="${rule.id}" />
      </label>
      <span class="intercept-rule-scope">${escapeHtml(scopeLabel)}</span>
      <span class="intercept-rule-methods">${escapeHtml(methods)}</span>
      <span class="intercept-rule-host">${escapeHtml(host)}</span>
      <span class="intercept-rule-path">${escapeHtml(path)}</span>
      <button class="intercept-rule-delete" data-rule-delete="${rule.id}" title="Delete rule">&times;</button>
    </div>`;
  }).join("");
}

async function addInterceptRule() {
  const sessionId = currentSessionId();
  const rule = {
    id: crypto.randomUUID(),
    enabled: true,
    scope: "request",
    host_pattern: "",
    path_pattern: "",
    method_filter: [],
  };
  const response = await fetch(sessionQueryPath("/api/intercept-rules", sessionId), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(rule),
  });
  await requireOkResponse(response, "Failed to add intercept rule.");
  if (sessionId !== currentSessionId()) {
    return;
  }
  await loadInterceptRules();
  editInterceptRule(rule.id);
}

function editInterceptRule(ruleId) {
  const rule = (state.interceptRules || []).find((r) => r.id === ruleId);
  if (!rule) return;
  const container = document.getElementById("interceptRulesList");
  const row = container.querySelector(`[data-rule-id="${ruleId}"]`);
  if (!row) return;
  const scope = rule.scope || "request";
  row.innerHTML = `
    <label class="intercept-rule-toggle"><input type="checkbox" ${rule.enabled ? "checked" : ""} data-rule-toggle="${rule.id}" /></label>
    <select class="intercept-rule-input intercept-rule-scope-select" data-field="scope">
      <option value="request"${scope === "request" ? " selected" : ""}>Request</option>
      <option value="response"${scope === "response" ? " selected" : ""}>Response</option>
      <option value="both"${scope === "both" ? " selected" : ""}>Both</option>
    </select>
    <input class="intercept-rule-input" data-field="method_filter" placeholder="Methods (e.g. GET,POST)" value="${escapeHtml((rule.method_filter || []).join(", "))}" />
    <input class="intercept-rule-input" data-field="host_pattern" placeholder="Host (e.g. *.example.com)" value="${escapeHtml(rule.host_pattern || "")}" />
    <input class="intercept-rule-input" data-field="path_pattern" placeholder="Path contains (e.g. /api/)" value="${escapeHtml(rule.path_pattern || "")}" />
    <button class="intercept-rule-save" data-rule-save="${rule.id}">&#10003;</button>
    <button class="intercept-rule-delete" data-rule-delete="${rule.id}">&times;</button>
  `;
}

async function saveInterceptRuleFromRow(ruleId) {
  const sessionId = currentSessionId();
  const container = document.getElementById("interceptRulesList");
  const row = container.querySelector(`[data-rule-id="${ruleId}"]`);
  if (!row) return;
  const rule = (state.interceptRules || []).find((r) => r.id === ruleId);
  if (!rule) return;
  const methodInput = row.querySelector('[data-field="method_filter"]');
  const hostInput = row.querySelector('[data-field="host_pattern"]');
  const pathInput = row.querySelector('[data-field="path_pattern"]');
  const scopeInput = row.querySelector('[data-field="scope"]');
  const toggleInput = row.querySelector(`[data-rule-toggle="${ruleId}"]`);
  const updated = {
    id: ruleId,
    enabled: toggleInput?.checked ?? rule.enabled,
    scope: scopeInput?.value || rule.scope || "request",
    host_pattern: hostInput?.value?.trim() || "",
    path_pattern: pathInput?.value?.trim() || "",
    method_filter: (methodInput?.value || "").split(",").map((m) => m.trim().toUpperCase()).filter(Boolean),
  };
  const response = await fetch(sessionQueryPath("/api/intercept-rules", sessionId), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(updated),
  });
  await requireOkResponse(response, "Failed to save intercept rule.");
  if (sessionId !== currentSessionId()) {
    return;
  }
  await loadInterceptRules();
}

async function deleteInterceptRule(ruleId) {
  const sessionId = currentSessionId();
  const response = await fetch(sessionQueryPath(`/api/intercept-rules/${ruleId}`, sessionId), { method: "DELETE" });
  await requireOkResponse(response, "Failed to delete intercept rule.");
  if (sessionId !== currentSessionId()) {
    return;
  }
  await loadInterceptRules();
}

async function toggleInterceptRuleEnabled(ruleId, enabled) {
  const sessionId = currentSessionId();
  const rule = (state.interceptRules || []).find((r) => r.id === ruleId);
  if (!rule) return;
  rule.enabled = enabled;
  const response = await fetch(sessionQueryPath("/api/intercept-rules", sessionId), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(rule),
  });
  await requireOkResponse(response, "Failed to update intercept rule.");
  if (sessionId !== currentSessionId()) {
    return;
  }
  await loadInterceptRules();
}

async function loadWebsockets(preserveSelection = true) {
  const generation = ++_websocketLoadGeneration;
  const sessionId = currentSessionId();
  const response = await fetch(sessionQueryPath("/api/websockets?limit=5000", sessionId));
  await requireOkResponse(response, "Failed to load WebSocket history.");
  const page = websocketPagePayload(await response.json());
  if (generation !== _websocketLoadGeneration || sessionId !== currentSessionId()) {
    return;
  }
  state.websocketSessions = page.items;
  state.websocketPaging = {
    total: page.total,
    limit: page.limit,
    hasMore: page.has_more,
  };
  await syncVisibleWebsocketSelection(preserveSelection);
}

async function loadWebsocketDetail(id) {
  if (_websocketDetailPendingId === id && _websocketDetailPendingPromise) {
    return _websocketDetailPendingPromise;
  }
  const generation = ++_websocketDetailGeneration;
  if (state.selectedWebsocketId !== id) {
    hideFrameDetail();
  }

  const pending = (async () => {
    const sessionId = currentSessionId();
    const response = await fetch(sessionQueryPath(`/api/websockets/${encodeURIComponent(id)}`, sessionId));
    if (generation !== _websocketDetailGeneration || sessionId !== currentSessionId()) {
      return;
    }
    if (!response.ok) {
      if (state.selectedWebsocketId !== id) {
        return;
      }
      state.selectedWebsocketRecord = null;
      renderWebsocketSessions();
      return;
    }

    const detail = await response.json();
    if (generation !== _websocketDetailGeneration || sessionId !== currentSessionId() || state.selectedWebsocketId !== id) {
      return;
    }
    state.selectedWebsocketRecord = detail;
    renderWebsocketSessions();
  })();
  _websocketDetailPendingId = id;
  _websocketDetailPendingPromise = pending;
  try {
    return await pending;
  } finally {
    if (_websocketDetailPendingId === id && _websocketDetailPendingPromise === pending) {
      _websocketDetailPendingId = null;
      _websocketDetailPendingPromise = null;
    }
  }
}

async function loadEventLog() {
  const sessionId = currentSessionId();
  const response = await fetch(sessionQueryPath("/api/event-log?limit=200", sessionId));
  await requireOkResponse(response, "Failed to load event log.");
  const entries = jsonArray(await response.json());
  if (sessionId !== currentSessionId()) {
    return;
  }
  state.eventLog = entries;
  renderEventLog();
}

async function clearEventLog() {
  const sessionId = currentSessionId();
  const response = await fetch(sessionQueryPath("/api/event-log", sessionId), { method: "DELETE" });
  await requireOkResponse(response, "Failed to clear event log.");
  if (sessionId !== currentSessionId()) {
    return;
  }
  state.eventLog = [];
  renderEventLog();
}

async function loadMatchReplaceRules() {
  const sessionId = currentSessionId();
  const response = await fetch(sessionQueryPath("/api/match-replace", sessionId));
  await requireOkResponse(response, "Failed to load match-replace rules.");
  const rules = jsonArray(await response.json());
  if (sessionId !== currentSessionId()) {
    return;
  }
  state.matchReplaceRules = rules;
  if (!state.matchReplaceRules.some((rule) => rule.id === state.selectedMatchReplaceRuleId)) {
    state.selectedMatchReplaceRuleId = state.matchReplaceRules[0]?.id ?? null;
  }
  renderMatchReplaceRules();
}

async function saveMatchReplaceRules() {
  const sessionId = currentSessionId();
  const response = await fetch(sessionQueryPath("/api/match-replace", sessionId), {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify({ rules: state.matchReplaceRules }),
  });
  await requireOkResponse(response, "Failed to save match-replace rules.");
  const rules = jsonArray(await response.json());
  if (sessionId !== currentSessionId()) {
    return;
  }
  state.matchReplaceRules = rules;
  if (!state.matchReplaceRules.some((rule) => rule.id === state.selectedMatchReplaceRuleId)) {
    state.selectedMatchReplaceRuleId = state.matchReplaceRules[0]?.id ?? null;
  }
  renderMatchReplaceRules();
}

function formatScopePatternsText(patterns) {
  return (patterns || []).join("\n");
}

function syncTargetScopeDraft(force = false) {
  const runtimeText = formatScopePatternsText(state.runtime?.scope_patterns);
  if (force || !state.targetScopeDirty) {
    state.targetScopeDraft = runtimeText;
    state.targetScopeDirty = false;
    if (force) {
      state.targetScopeEditorSessionId = null;
    }
  }
}

async function loadTargetSiteMap(forceScopeSync = false) {
  const sessionId = currentSessionId();
  const [runtimeResponse, siteMapResponse] = await Promise.all([
    fetch(sessionQueryPath("/api/runtime", sessionId)),
    fetch(sessionQueryPath("/api/target/site-map", sessionId)),
  ]);
  await requireOkResponse(runtimeResponse, "Failed to load runtime settings.");
  await requireOkResponse(siteMapResponse, "Failed to load target site map.");
  const runtime = await runtimeResponse.json();
  const siteMap = jsonArray(await siteMapResponse.json());
  if (sessionId !== currentSessionId()) {
    return;
  }
  state.runtime = runtime;
  state.targetSiteMap = siteMap;
  syncTargetScopeDraft(forceScopeSync);
  renderInterceptStatus();
  renderProxySettings();
  renderTarget();
}

async function pollAuxiliaryData() {
  const tasks = [];

  if (state.activeTool === "proxy" && state.activeProxyTab === "intercept") {
    tasks.push(loadIntercepts(true));
    tasks.push(loadResponseIntercepts(true));
  }

  if (state.activeTool === "proxy" && state.activeProxyTab === "websockets-history") {
    tasks.push(loadWebsockets(true));
  }

  if (state.activeTool === "proxy" && state.activeProxyTab === "http-history") {
    const now = Date.now();
    if (now - _lastHttpHistoryFallbackPoll >= HTTP_HISTORY_POLL_FALLBACK_MS) {
      _lastHttpHistoryFallbackPoll = now;
      scheduleIncrementalRefresh();
    }
  }

  if (state.activeTool === "logger") {
    tasks.push(loadEventLog());
  }

  if (state.activeTool === "target") {
    tasks.push(loadTargetSiteMap());
  }

  if (state.activeTool === "proxy" && state.activeProxyTab === "findings") {
    tasks.push(loadFindings());
  } else {
    // Always update badge count even when not on Findings tab
    tasks.push(updateFindingsBadgeOnly());
  }

  if (state.activeTool === "proxy" && state.activeProxyTab === "oast") {
    tasks.push(loadOastCallbacks());
  }

  if (!tasks.length) {
    return;
  }

  await Promise.allSettled(tasks);
}

function connectEvents() {
  if (eventSource) {
    eventSource.close();
  }
  const eventSessionId = currentSessionId();
  eventSource = new EventSource(sessionQueryPath("/api/events", eventSessionId));

  eventSource.addEventListener("transaction", (event) => {
    if (eventSessionId !== currentSessionId()) {
      return;
    }
    els.liveStatus.textContent = "Proxy live";
    els.liveStatus.classList.add("online");
    if (!applyTransactionDeltaEvent(event, eventSessionId)) {
      scheduleIncrementalRefresh();
    }
  });

  eventSource.addEventListener("transactions_gap", () => {
    if (eventSessionId !== currentSessionId()) {
      return;
    }
    scheduleRefresh();
  });

  eventSource.addEventListener("event_log", () => {
    if (eventSessionId !== currentSessionId()) {
      return;
    }
    if (state.activeTool === "logger") {
      loadEventLog().catch((error) => console.error(error));
    } else {
      els.eventLogStatus.textContent = "New activity";
    }
  });

  eventSource.addEventListener("event_log_gap", () => {
    if (eventSessionId !== currentSessionId()) {
      return;
    }
    loadEventLog().catch((error) => console.error(error));
  });

  eventSource.addEventListener("session_changed", () => {
    handleExternalSessionChanged().catch((error) => console.error(error));
  });

  eventSource.onerror = () => {
    els.liveStatus.textContent = "Retrying";
    els.liveStatus.classList.remove("online");
  };
}

function resetHistoryScrollPosition() {
  const shell = els.historyTable?.closest(".history-table-shell");
  if (shell) {
    shell.scrollTop = 0;
  }
}

function consumeHistoryLoadOptions() {
  const resetScroll = !!state.historyResetScrollOnNextLoad;
  state.historyResetScrollOnNextLoad = false;
  return { resetScroll };
}

function scheduleRefresh(options = {}) {
  invalidateVisibleEntriesCache();
  if (!isHttpHistoryVisible()) {
    state.historyDirty = true;
    if (options.resetScroll) {
      state.historyResetScrollOnNextLoad = true;
    }
    return;
  }
  if (options.resetScroll) {
    state.historyResetScrollOnNextLoad = true;
  }
  if (refreshTimer) {
    return;
  }
  refreshTimer = window.setTimeout(() => {
    refreshTimer = null;
    loadTransactions(true, consumeHistoryLoadOptions()).catch((error) => console.error(error));
  }, 160);
}

function mergeHistoryItems(items, { prepend = false } = {}) {
  applyPendingAnnotationsToItems(items);
  const newItems = [];
  let connectCount = 0;
  for (const item of items) {
    if (getHistoryItem(item.id)) continue;
    prepareHistoryItem(item);
    if (item.method === "CONNECT") connectCount++;
    newItems.push(item);
  }
  if (!newItems.length) return 0;

  if (prepend) {
    state.items = newItems.concat(state.items);
  } else {
    state.items.push(...newItems);
  }
  state._connectCount = (state._connectCount || 0) + connectCount;
  if (state.historyPaging) {
    state.historyPaging._trimmedTailOnLastMerge = false;
  }
  trimHistoryCache(prepend ? "recent" : "older");
  rebuildHistoryItemIndex();
  state._itemsVersion += 1;
  invalidateVisibleEntriesCache();
  return newItems.length;
}

function replaceHistoryItemsForGap(items) {
  applyPendingAnnotationsToItems(items);
  const seen = new Set();
  const freshItems = [];
  let connectCount = 0;
  for (const item of items) {
    if (!item?.id || seen.has(item.id)) continue;
    seen.add(item.id);
    prepareHistoryItem(item);
    if (item.method === "CONNECT") connectCount++;
    freshItems.push(item);
  }

  state.items = freshItems;
  state._connectCount = connectCount;
  rebuildHistoryItemIndex();
  state._itemsVersion += 1;
  invalidateVisibleEntriesCache();
  if (state.selectedId && !getHistoryItem(state.selectedId)) {
    state.selectedId = null;
    state.selectedRecord = null;
    renderEmptyDetail();
  }
  refreshHistoryPagingCursorFromItems();
  return freshItems.length;
}

function trimHistoryCache(prefer = "recent") {
  if (!canUseSequenceCursorForHistoryPaging()) return 0;
  const overflow = state.items.length - HTTP_HISTORY_MAX_LOADED_ITEMS;
  if (overflow <= 0) {
    refreshHistoryPagingCursorFromItems();
    return 0;
  }

  let removed;
  if (prefer === "older") {
    removed = state.items.splice(0, overflow);
    state.historyPaging.trimmedHeadCount += removed.length;
    adjustHistoryScrollAfterHeadTrim(removed.length);
  } else {
    removed = state.items.splice(state.items.length - overflow, overflow);
    state.historyPaging.trimmedTailCount += removed.length;
    state.historyPaging._trimmedTailOnLastMerge = true;
    state.historyPaging.hasMore = true;
    state.historyPaging.fullyLoaded = false;
  }

  if (removed.some((item) => item.id === state.selectedId)) {
    state.selectedId = null;
    state.selectedRecord = null;
    renderEmptyDetail();
  }
  state._connectCount = state.items.reduce((count, item) => count + (item.method === "CONNECT" ? 1 : 0), 0);
  refreshHistoryPagingCursorFromItems();
  return removed.length;
}

function adjustHistoryScrollAfterHeadTrim(removedCount) {
  const shell = els.historyTable?.closest(".history-table-shell");
  if (!shell || removedCount <= 0) return;
  shell.scrollTop = Math.max(0, shell.scrollTop - removedCount * (measuredHistoryRowHeight || HISTORY_ROW_HEIGHT));
}

async function loadMoreTransactions({ background = false } = {}) {
  const paging = state.historyPaging || (state.historyPaging = createHistoryPagingState());
  if (paging.loading || !paging.hasMore) {
    return 0;
  }

  let shouldRenderAfterLoad = !background;
  let shouldBackfillAfterLoad = false;
  const generation = paging.generation;
  const offset = paging.offset ?? state.items.length;
  paging.loading = true;
  if (!background) renderHistory();
  try {
    const page = paging.beforeSequence == null
      ? await fetchTransactionPage(offset)
      : await fetchTransactionPage({ beforeSequence: paging.beforeSequence });
    if (!page) {
      return 0;
    }
    if (state.historyPaging !== paging || state.historyPaging.generation !== generation) {
      return 0;
    }
    const pageItems = jsonArray(page.items);
    updateHistoryPagingCursor(pageItems);
    const added = mergeHistoryItems(pageItems);
    const hadMore = paging.hasMore;
    paging.offset = canUseSequenceCursorForHistoryPaging()
      ? state.items.length
      : offset + pageItems.length;
    paging.total = page.total ?? paging.total;
    paging.filteredTotal = page.filtered_total ?? paging.filteredTotal;
    if (page.hidden_connect_total != null) paging.hiddenConnectTotal = page.hidden_connect_total;
    paging.hasMore = Boolean(page.has_more);
    paging.fullyLoaded = !paging.hasMore;
    if (added || hadMore !== paging.hasMore || !background) {
      shouldRenderAfterLoad = true;
    }
    shouldBackfillAfterLoad = background && !added && paging.hasMore;
    return added;
  } catch (error) {
    console.error("Failed to load older transactions:", error);
    return 0;
  } finally {
    paging.loading = false;
    if (shouldRenderAfterLoad) renderHistory();
    if (shouldBackfillAfterLoad) scheduleHistoryBackfill();
  }
}

let _historyBackfillTimer = 0;
function scheduleHistoryBackfill(delayMs = HTTP_HISTORY_BACKFILL_DELAY_MS) {
  const paging = state.historyPaging;
  if (!paging || paging.loading || paging.backfillScheduled || !paging.hasMore || paging.fullyLoaded) {
    return;
  }
  if (state.items.length >= HTTP_HISTORY_MAX_LOADED_ITEMS) {
    return;
  }
  paging.backfillScheduled = true;
  const generation = paging.generation;
  _historyBackfillTimer = window.setTimeout(async () => {
    _historyBackfillTimer = 0;
    const currentPaging = state.historyPaging;
    if (!currentPaging) return;
    if (currentPaging.generation !== generation) return;
    currentPaging.backfillScheduled = false;
    if (_searchActiveUntil > Date.now()) {
      scheduleHistoryBackfill(HTTP_HISTORY_BACKFILL_DELAY_MS);
      return;
    }
    await loadMoreTransactions({ background: true });
  }, delayMs);
}

function clearHistoryBackfill() {
  if (_historyBackfillTimer) {
    clearTimeout(_historyBackfillTimer);
    _historyBackfillTimer = 0;
  }
  if (state.historyPaging) {
    state.historyPaging.backfillScheduled = false;
  }
}

function canMergeRecentTransactions() {
  const filters = state.filterSettings || {};
  return state.sortKey === "index"
    && state.sortDirection === "desc"
    && !(filters.searchTerm && filters.regex);
}

function canUseSequenceCursorForHistoryPaging() {
  return state.sortKey === "index" && state.sortDirection === "desc";
}

function isHttpHistoryVisible() {
  return state.activeTool === "proxy" && state.activeProxyTab === "http-history";
}

/** Incremental refresh: fetch only recent transactions and merge into cache. */
let _incrementalTimer = 0;
let _transactionDeltaTimer = 0;
let _historyFullLoadInFlight = 0;
const _pendingTransactionSummaries = [];

function applyTransactionDeltaEvent(event, sessionId = currentSessionId()) {
  if (sessionId !== currentSessionId()) {
    return true;
  }
  if (!isHttpHistoryVisible()) {
    state.historyDirty = true;
    return true;
  }
  if (!canMergeRecentTransactions() || _searchActiveUntil > Date.now()) {
    return false;
  }

  try {
    const summary = JSON.parse(event.data || "null");
    if (!summary || !summary.id) return false;
    _pendingTransactionSummaries.push({ sessionId, summary });
    scheduleTransactionDeltaFlush();
    return true;
  } catch (error) {
    console.error("Failed to parse transaction event:", error);
    return false;
  }
}

function scheduleTransactionDeltaFlush() {
  if (_transactionDeltaTimer) return;
  _transactionDeltaTimer = window.setTimeout(() => {
    _transactionDeltaTimer = 0;
    flushTransactionDeltas();
  }, 120);
}

function flushTransactionDeltas() {
  if (!_pendingTransactionSummaries.length) return;
  const activeSessionId = currentSessionId();
  for (let i = _pendingTransactionSummaries.length - 1; i >= 0; i -= 1) {
    if (_pendingTransactionSummaries[i]?.sessionId !== activeSessionId) {
      _pendingTransactionSummaries.splice(i, 1);
    }
  }
  if (!_pendingTransactionSummaries.length) return;
  if (_historyFullLoadInFlight) {
    scheduleTransactionDeltaFlush();
    return;
  }
  const pending = _pendingTransactionSummaries.splice(0);
  if (!isHttpHistoryVisible()) {
    state.historyDirty = true;
    return;
  }
  if (!canMergeRecentTransactions() || _searchActiveUntil > Date.now()) {
    scheduleIncrementalRefresh();
    return;
  }

  const fresh = [];
  let totalAdded = 0;
  let hiddenConnectAdded = 0;
  for (const { summary } of pending) {
    if (!summary?.id || getHistoryItem(summary.id)) continue;
    totalAdded += 1;
    if (String(summary.method || "").toUpperCase() === "CONNECT") {
      if (summaryMatchesActiveHistoryFilters(summary, { includeConnect: true })) hiddenConnectAdded += 1;
      continue;
    }
    if (!summaryMatchesActiveHistoryFilters(summary)) continue;
    fresh.push(summary);
  }

  if (fresh.length && state.historyPaging?.trimmedHeadCount > 0 && canUseSequenceCursorForHistoryPaging()) {
    scheduleIncrementalRefresh();
    return;
  }

  fresh.sort((a, b) => Number(b.sequence ?? 0) - Number(a.sequence ?? 0));
  const added = mergeHistoryItems(fresh, { prepend: true });
  if (state.historyPaging) {
    state.historyPaging.total += totalAdded;
    if (isKnownCount(state.historyPaging.filteredTotal)) {
      state.historyPaging.filteredTotal += added;
    }
    if (isKnownCount(state.historyPaging.hiddenConnectTotal)) {
      state.historyPaging.hiddenConnectTotal += hiddenConnectAdded;
    }
    state.historyPaging.offset = state.items.length;
  }
  if (totalAdded || added) {
    state.historyDirty = false;
    renderHistory();
  }
}

function summaryMatchesActiveHistoryFilters(item, options = {}) {
  const method = String(item.method || "").toUpperCase();
  if (!options.includeConnect && method === "CONNECT") return false;
  if (state.method && String(item.method || "").toLowerCase() !== state.method.toLowerCase()) return false;

  const filters = state.filterSettings;
  if (filters.inScopeOnly && !isInScopeHost(item.host || "")) return false;
  if (filters.hideWithoutResponses && !item.has_response) return false;
  if (filters.onlyParameterized && !String(item.path || "").includes("?")) return false;
  if (filters.onlyNotes && !item.note_count && !item.has_user_note) return false;
  if (!summaryMatchesStatusFilter(item, filters)) return false;
  if (!summaryMatchesMimeFilter(item, filters)) return false;
  if (!summaryMatchesHiddenExtensions(item, filters)) return false;
  if (!summaryMatchesPortFilter(item, filters)) return false;
  if (!summaryMatchesColorTags(item, filters)) return false;
  if (!summaryMatchesAdvancedSearch(item, filters)) return false;
  if (state.query && !summaryQuickSearchHaystack(item).includes(state.query.toLowerCase())) return false;
  return true;
}

function summaryMatchesStatusFilter(item, filters) {
  const selected = selectedStatusClasses(filters);
  if (!selected.length) return false;
  const status = Number(item.status);
  const statusClass = Number.isFinite(status) && status >= 200 && status < 300
    ? "success"
    : Number.isFinite(status) && status >= 300 && status < 400
      ? "redirect"
      : Number.isFinite(status) && status >= 400 && status < 500
        ? "client_error"
        : Number.isFinite(status) && status >= 500 && status < 600
          ? "server_error"
          : "other";
  return selected.includes(statusClass);
}

function summaryMatchesMimeFilter(item, filters) {
  const selected = selectedMimeTypes(filters);
  return selected.length > 0 && selected.includes(inferMimeType(item));
}

function summaryMatchesHiddenExtensions(item, filters) {
  const hidden = String(filters.hiddenExtensions || "")
    .split(",")
    .map((value) => value.trim().toLowerCase())
    .filter(Boolean);
  if (!hidden.length) return true;
  const extension = extractSummaryPathExtension(item.path || "");
  return !extension || !hidden.includes(extension);
}

function extractSummaryPathExtension(path) {
  const clean = String(path || "").split("?")[0];
  const index = clean.lastIndexOf(".");
  if (index < 0) return "";
  const extension = clean.slice(index + 1).toLowerCase();
  return /^[a-z0-9]+$/.test(extension) ? extension : "";
}

function summaryMatchesPortFilter(item, filters) {
  const expected = String(filters.port || "").trim();
  if (!expected) return true;
  return extractHostPort(item.host || "") === expected;
}

function summaryMatchesColorTags(item, filters) {
  const tags = filters.colorTags;
  if (!tags?.size) return true;
  return tags.has(item.color_tag || "");
}

function summaryMatchesAdvancedSearch(item, filters) {
  const term = String(filters.searchTerm || "").trim();
  if (!term) return true;
  const haystack = `${item.host || ""} ${item.method || ""} ${item.path || ""} ${item.content_type || ""}`;
  let matched = false;
  if (filters.regex) {
    try {
      matched = new RegExp(term, filters.caseSensitive ? "" : "i").test(haystack);
    } catch (_) {
      return !filters.negativeSearch;
    }
  } else {
    matched = filters.caseSensitive
      ? haystack.includes(term)
      : haystack.toLowerCase().includes(term.toLowerCase());
  }
  return filters.negativeSearch ? !matched : matched;
}

function summaryQuickSearchHaystack(item) {
  const totalBytes = (item.request_bytes ?? 0) + (item.response_bytes ?? 0);
  const startedAt = item.started_at || "";
  let formattedTime = "";
  try {
    formattedTime = startedAt ? formatTimestamp(startedAt) : "";
  } catch (_) {
    formattedTime = "";
  }
  return [
    item.id || "",
    item.sequence ?? "",
    item.method || "",
    item.host || "",
    item.path || "",
    item.status ?? "",
    item.content_type || "",
    inferMimeType(item),
    totalBytes,
    formatSize(totalBytes),
    startedAt,
    formattedTime,
  ].join(" ").toLowerCase();
}

function scheduleIncrementalRefresh() {
  if (_incrementalTimer) return;
  _incrementalTimer = window.setTimeout(async () => {
    _incrementalTimer = 0;
    // Skip incremental refresh while user is actively typing in search
    if (_searchActiveUntil > Date.now()) {
      // Reschedule a tick later instead of dropping
      scheduleIncrementalRefresh();
      return;
    }
    try {
      if (!canMergeRecentTransactions()) {
        scheduleRefresh();
        return;
      }
      const refreshSessionId = state.activeSession?.id || null;
      const refreshItemsVersion = state._itemsVersion;
      const resp = await fetch(buildTransactionsPageUrl({ limit: 50, offset: 0 }));
      if (refreshSessionId !== (state.activeSession?.id || null) || refreshItemsVersion !== state._itemsVersion) {
        return;
      }
      if (!resp.ok) {
        const message = await resp.text().catch(() => "");
        if (els.historyMeta) els.historyMeta.textContent = `HTTP History refresh error: ${message || resp.status}`;
        if (els.liveStatus) {
          els.liveStatus.textContent = "Refresh error";
          els.liveStatus.classList.remove("online");
        }
        throw new Error(message || `HTTP History refresh failed: ${resp.status}`);
      }
      const page = await resp.json();
      if (refreshSessionId !== (state.activeSession?.id || null) || refreshItemsVersion !== state._itemsVersion) {
        return;
      }
      const recent = jsonArray(page.items);
      const previousTotal = state.historyPaging?.total;
      const previousFilteredTotal = state.historyPaging?.filteredTotal;
      const previousHasMore = state.historyPaging?.hasMore;
      const wasFullyLoaded = state.historyPaging?.fullyLoaded === true;
      const hasOverlap = recent.some((item) => item?.id && getHistoryItem(item.id));
      const hasGapBeforeLoadedWindow = Boolean(page.has_more)
        && state.items.length > 0
        && recent.length > 0
        && !hasOverlap
        && canUseSequenceCursorForHistoryPaging();
      if (state.historyPaging) {
        state.historyPaging._trimmedTailOnLastMerge = false;
      }
      const added = hasGapBeforeLoadedWindow
        ? replaceHistoryItemsForGap(recent)
        : mergeHistoryItems(recent, { prepend: true });
      if (state.historyPaging) {
        if (page.total != null) state.historyPaging.total = page.total;
        if (page.filtered_total != null) state.historyPaging.filteredTotal = page.filtered_total;
        if (page.hidden_connect_total != null) state.historyPaging.hiddenConnectTotal = page.hidden_connect_total;
        state.historyPaging.hasMore = wasFullyLoaded
          && !hasGapBeforeLoadedWindow
          && !state.historyPaging._trimmedTailOnLastMerge
          ? false
          : Boolean(page.has_more) || state.historyPaging._trimmedTailOnLastMerge;
        state.historyPaging.fullyLoaded = !state.historyPaging.hasMore;
      }
      if (added > 0 && state.historyPaging) state.historyPaging.offset = state.items.length;
      if (hasGapBeforeLoadedWindow) {
        scheduleHistoryBackfill(0);
      }
      if (
        added > 0
        || previousTotal !== state.historyPaging?.total
        || previousFilteredTotal !== state.historyPaging?.filteredTotal
        || previousHasMore !== state.historyPaging?.hasMore
      ) {
        renderHistory();
      }
    } catch (err) {
      console.error("Incremental refresh failed:", err);
    }
  }, 300);
}

// Search activity guard: incremental refresh pauses while user is typing
let _searchActiveUntil = 0;

function renderToolPanels() {
  if (!IMPLEMENTED_TOOLS.has(state.activeTool)) {
    state.activeTool = "proxy";
  }

  mainTabs.forEach((tab) => {
    tab.classList.toggle("active", tab.dataset.tool === state.activeTool);
  });

  const dashboardVisible = state.activeTool === "dashboard";
  const proxyVisible = state.activeTool === "proxy";
  const replayVisible = state.activeTool === "replay";
  const decoderVisible = state.activeTool === "tools";
  const fuzzerVisible = state.activeTool === "fuzzer";
  const sequenceVisible = state.activeTool === "sequence";
  const targetVisible = state.activeTool === "target";
  const loggerVisible = state.activeTool === "logger";
  els.dashboardShell.classList.toggle("hidden", !dashboardVisible);
  els.proxyShell.classList.toggle("hidden", !proxyVisible);
  els.replayShell.classList.toggle("hidden", !replayVisible);
  els.toolsShell.classList.toggle("hidden", !decoderVisible);
  els.fuzzerShell.classList.toggle("hidden", !fuzzerVisible);
  els.sequenceShell.classList.toggle("hidden", !sequenceVisible);
  els.targetShell.classList.toggle("hidden", !targetVisible);
  els.loggerShell.classList.toggle("hidden", !loggerVisible);

  if (dashboardVisible) {
    renderDashboard();
    els.footerMode.textContent = "Session active";
    return;
  }

  if (proxyVisible) {
    renderProxyPanels();
    return;
  }

  if (replayVisible) {
    renderReplay();
    els.footerMode.textContent = "Replay active";
    return;
  }

  if (decoderVisible) {
    ensureDecoderWorkbench().catch((error) => {
      console.error(error);
      // Tools load failed
    });
    els.footerMode.textContent = "Tools active";
    return;
  }

  if (fuzzerVisible) {
    renderFuzzer();
    els.footerMode.textContent = "Fuzzer active";
    return;
  }

  if (sequenceVisible) {
    renderSequencePanel();
    els.footerMode.textContent = "Sequence active";
    return;
  }

  if (targetVisible) {
    renderTarget();
    els.footerMode.textContent = "Scope active";
    return;
  }

  if (loggerVisible) {
    renderEventLog();
    els.footerMode.textContent = "Event log active";
    return;
  }
}

async function ensureDecoderWorkbench() {
  if (state.toolsReady) {
    syncDecoderToolMeta();
    return;
  }

  if (!toolsBootPromise) {
    toolsBootPromise = bootToolsWorkbench();
  }

  await toolsBootPromise;
}

async function bootToolsWorkbench() {
  for (const source of DECODER_SCRIPT_SOURCES) {
    await loadScriptOnce(source);
  }

  if (!window.hasher || !window.tabs || !window.jQuery) {
    throw new Error("Decoder assets did not initialize correctly.");
  }

  const $ = window.jQuery;
  const refreshOutputs = () => {
    window.hasher.update();
    syncDecoderToolMeta();
    if (typeof window.autoScroll === "function") {
      window.autoScroll(els.toolsShell);
    }
  };

  $("#input-value, #input-password, #input-url").on("input", refreshOutputs);

  $("#tabs li").on("click", function () {
    const nextTab = window.tabs[this.id];
    if (nextTab == null) {
      return;
    }

    window.hasher.tab = nextTab;
    window.hasher.updateUI();
    syncDecoderToolMeta();
    document.getElementById("input-value")?.focus();
  });

  window.hasher.updateUI();
  syncDecoderToolMeta();
  if (typeof window.autoScroll === "function") {
    window.autoScroll(els.toolsShell);
  }
  state.toolsReady = true;
}

function syncDecoderToolMeta() {
  const activeTab = document.querySelector("#tabs li.on");
  const activeLabel = activeTab?.textContent?.trim() || "Decoder";
  els.toolsActiveToolTitle.textContent = `${activeLabel} output`;
}

function clearToolsInputs() {
  const input = document.getElementById("input-value");
  const password = document.getElementById("input-password");
  const url = document.getElementById("input-url");

  if (input) input.value = "";
  if (password) password.value = "";
  if (url) url.value = "";

  if (typeof window.resizeTextarea === "function" && input) {
    window.resizeTextarea(input);
  }

  if (state.toolsReady && window.hasher) {
    window.hasher.update();
    syncDecoderToolMeta();
  }
}

async function pasteIntoDecoder() {
  try {
    const text = await navigator.clipboard.readText();
    const input = document.getElementById("input-value");
    if (!input) {
      return;
    }

    input.value = text;
    input.focus();
    if (typeof window.resizeTextarea === "function") {
      window.resizeTextarea(input);
    }

    if (state.toolsReady && window.hasher) {
      window.hasher.update();
      syncDecoderToolMeta();
    }
  } catch (error) {
    console.error(error);
    console.warn("Clipboard paste failed. Paste directly into the input field.");
  }
}

function loadScriptOnce(source) {
  const existing = document.querySelector(`script[data-dynamic-src="${source}"]`);
  if (existing) {
    if (existing.dataset.loaded === "true") {
      return Promise.resolve();
    }

    return new Promise((resolve, reject) => {
      existing.addEventListener("load", () => resolve(), { once: true });
      existing.addEventListener("error", () => reject(new Error(`Failed to load ${source}`)), { once: true });
    });
  }

  return new Promise((resolve, reject) => {
    const script = document.createElement("script");
    script.src = source;
    script.async = false;
    script.defer = true;
    script.dataset.dynamicSrc = source;
    script.addEventListener(
      "load",
      () => {
        script.dataset.loaded = "true";
        resolve();
      },
      { once: true },
    );
    script.addEventListener("error", () => reject(new Error(`Failed to load ${source}`)), { once: true });
    document.head.appendChild(script);
  });
}

function renderDashboard() {
  // Ensure selectedSessionId defaults to active session
  const activeSession = state.activeSession || state.sessions.find((session) => session.active) || null;
  if (!state.selectedSessionId && activeSession) {
    state.selectedSessionId = activeSession.id;
  }
  const current = state.sessions.find((s) => s.id === state.selectedSessionId) || activeSession;
  els.dashboardCurrentSessionName.textContent = current?.name || "No active session";
  const isActive = current?.active || current?.id === activeSession?.id;
  els.dashboardCurrentSessionStatus.textContent = isActive ? "Active" : "Stored";
  els.dashboardCurrentSessionStatus.className = `detail-chip ${isActive ? "active-badge" : "none"}`;
  els.dashboardCurrentSessionPath.textContent = current?.storage_path || "No storage path";
  els.dashboardCurrentSessionRequests.textContent = String(current?.request_count ?? 0);
  els.dashboardCurrentSessionWebsockets.textContent = String(current?.websocket_count ?? 0);
  els.dashboardCurrentSessionEvents.textContent = String(current?.event_count ?? 0);
  els.dashboardCurrentSessionFuzzer.textContent = String(current?.fuzzer_count ?? 0);
  els.dashboardCurrentSessionRules.textContent = String(current?.rule_count ?? 0);
  els.dashboardCurrentSessionCreated.textContent = current ? formatTimestamp(current.created_at) : "-";
  els.dashboardCurrentSessionOpened.textContent = current ? formatTimestamp(current.last_opened_at) : "-";

  // Sort sessions
  const sortedSessions = getSortedSessions();

  // Render sort arrows in headers
  const sessTable = document.getElementById("dashboardSessionsTable");
  if (sessTable) {
    sessTable.querySelectorAll("thead th[data-sort-key]").forEach((th) => {
      const existing = th.querySelector(".sort-arrow");
      if (existing) existing.remove();
      if (th.dataset.sortKey === state.sessionSortKey) {
        const arrow = document.createElement("span");
        arrow.className = "sort-arrow";
        arrow.textContent = state.sessionSortDir === "asc" ? "\u25B2" : "\u25BC";
        th.appendChild(arrow);
      }
    });
  }

  els.dashboardSessionsBody.innerHTML = sortedSessions.length
    ? sortedSessions
        .map((session) => `
          <tr class="history-row ${session.id === state.selectedSessionId ? "selected" : ""}" data-id="${session.id}">
            <td>${escapeHtml(session.name)}</td>
            <td>${session.request_count}</td>
            <td>${session.websocket_count}</td>
            <td>${session.event_count}</td>
            <td>${session.rule_count}</td>
            <td>${escapeHtml(formatTimestamp(session.created_at))}</td>
            <td>${escapeHtml(formatTimestamp(session.last_opened_at))}</td>
            <td>
              <div class="session-actions">
                ${session.active
                  ? `<button class="session-active-badge" type="button" disabled>Active</button>`
                  : `<button class="secondary-action session-open-button" type="button">Open</button>`}
                <button class="session-delete-button" type="button" ${session.active ? "disabled" : ""}>Delete</button>
              </div>
            </td>
          </tr>
        `)
        .join("")
    : `
        <tr class="empty-row">
          <td colspan="8">No sessions are available yet.</td>
        </tr>
      `;

  // Row click = select (update workspace info panel)
  Array.from(els.dashboardSessionsBody.querySelectorAll("tr[data-id]")).forEach((row) => {
    row.addEventListener("click", () => {
      const { id } = row.dataset;
      if (!id) return;
      state.selectedSessionId = id;
      renderDashboard();
    });
  });

  // Activate button = switch session
  Array.from(els.dashboardSessionsBody.querySelectorAll(".session-open-button")).forEach((btn) => {
    btn.addEventListener("click", (event) => {
      event.stopPropagation();
      const row = btn.closest("tr[data-id]");
      if (!row) return;
      const { id } = row.dataset;
      if (!id) return;
      activateSessionById(id).catch(handleWorkspaceActionError);
    });
  });

  // Right-click context menu on session rows
  Array.from(els.dashboardSessionsBody.querySelectorAll("tr[data-id]")).forEach((row) => {
    row.addEventListener("contextmenu", (event) => {
      event.preventDefault();
      event.stopPropagation();
      const { id } = row.dataset;
      if (!id) return;
      state.selectedSessionId = id;
      renderDashboard();
      showSessionContextMenu(event, id);
    });
  });

  // Delete button
  Array.from(els.dashboardSessionsBody.querySelectorAll(".session-delete-button")).forEach((btn) => {
    btn.addEventListener("click", (event) => {
      event.stopPropagation();
      const row = btn.closest("tr[data-id]");
      if (!row) return;
      const { id } = row.dataset;
      if (!id) return;
      deleteSessionById(id);
    });
  });
}

// ── Session context menu ──
let sessionContextMenuEl = null;

function showSessionContextMenu(event, sessionId) {
  closeSessionContextMenu();
  const session = state.sessions.find((s) => s.id === sessionId);
  if (!session) return;

  const menu = document.createElement("div");
  menu.className = "context-menu session-context-menu";
  menu.innerHTML = `
    <button class="context-menu-item" data-action="folder">Open session folder</button>
    ${session.active ? "" : `<button class="context-menu-item danger" data-action="delete">Delete session</button>`}
  `;
  document.body.appendChild(menu);

  const rect = menu.getBoundingClientRect();
  let x = event.clientX;
  let y = event.clientY;
  if (x + rect.width > window.innerWidth) x = window.innerWidth - rect.width - 4;
  if (y + rect.height > window.innerHeight) y = window.innerHeight - rect.height - 4;
  menu.style.left = `${x}px`;
  menu.style.top = `${y}px`;
  sessionContextMenuEl = menu;

  menu.addEventListener("click", (e) => {
    const btn = e.target.closest("[data-action]");
    if (!btn) return;
    const action = btn.dataset.action;
    if (action === "folder") {
      fetch(`/api/sessions/${encodeURIComponent(sessionId)}/reveal`, { method: "POST" }).catch(console.error);
    } else if (action === "delete") {
      deleteSessionById(sessionId);
    }
    closeSessionContextMenu();
  });
}

function closeSessionContextMenu() {
  if (sessionContextMenuEl) {
    sessionContextMenuEl.remove();
    sessionContextMenuEl = null;
  }
}

document.addEventListener("click", () => closeSessionContextMenu());
document.addEventListener("contextmenu", () => closeSessionContextMenu());

function showConfirmDialog(message, onConfirm) {
  const backdrop = document.createElement("div");
  backdrop.className = "modal-backdrop confirm-dialog-backdrop";
  backdrop.innerHTML = `
    <div class="modal-card" style="width: min(400px, 90%);">
      <div class="modal-header" style="padding: 16px 20px;">
        <h3 style="margin:0; font-size: var(--font-md);">Confirm</h3>
      </div>
      <div class="modal-body" style="padding: 16px 20px;">
        <p style="margin:0; white-space: pre-line; color: var(--text-dim);">${escapeHtml(message)}</p>
      </div>
      <div style="display:flex; justify-content:flex-end; gap:8px; padding: 12px 20px; border-top: 1px solid var(--line);">
        <button class="secondary-action confirm-dialog-cancel" type="button" style="min-height:34px; padding:0 14px; font-size:var(--font-xs);">Cancel</button>
        <button class="danger-action confirm-dialog-ok" type="button" style="min-height:34px; padding:0 14px; font-size:var(--font-xs);">Delete</button>
      </div>
    </div>
  `;
  document.body.appendChild(backdrop);
  const close = () => backdrop.remove();
  backdrop.querySelector(".confirm-dialog-cancel").addEventListener("click", close);
  backdrop.querySelector(".confirm-dialog-ok").addEventListener("click", () => { close(); onConfirm(); });
  backdrop.addEventListener("click", (e) => { if (e.target === backdrop) close(); });
}

async function deleteSessionById(id) {
  const session = state.sessions.find((s) => s.id === id);
  const name = session ? session.name : id;
  showConfirmDialog(`Delete session "${name}"?\nThis will permanently remove all session data.`, async () => {
    try {
      const res = await fetch(`/api/sessions/${encodeURIComponent(id)}`, { method: "DELETE" });
      if (!res.ok) throw new Error(await res.text());
      state.sessions = state.sessions.filter((s) => s.id !== id);
      if (state.selectedSessionId === id) state.selectedSessionId = null;
      renderDashboard();
    } catch (error) {
      console.error("Failed to delete session:", error);
      showToast(error?.message || "Failed to delete session.", "error");
    }
  });
}

function moveSessionSelection(offset) {
  const sortedSessions = getSortedSessions();
  if (!sortedSessions.length) return;
  const currentIndex = sortedSessions.findIndex((s) => s.id === state.selectedSessionId);
  const fallbackIndex = offset > 0 ? 0 : sortedSessions.length - 1;
  const nextIndex = clamp(
    currentIndex === -1 ? fallbackIndex : currentIndex + offset,
    0,
    sortedSessions.length - 1,
  );
  state.selectedSessionId = sortedSessions[nextIndex].id;
  renderDashboard();
  const selectedRow = els.dashboardSessionsBody.querySelector(`tr[data-id="${state.selectedSessionId}"]`);
  if (selectedRow) selectedRow.scrollIntoView({ block: "nearest" });
}

function getSortedSessions() {
  return [...state.sessions].sort((a, b) => {
    const key = state.sessionSortKey || "created_at";
    const dir = state.sessionSortDir || "desc";
    let va = a[key], vb = b[key];
    if (key === "name") {
      va = (va || "").toLowerCase();
      vb = (vb || "").toLowerCase();
      const cmp = va < vb ? -1 : va > vb ? 1 : 0;
      return dir === "asc" ? cmp : -cmp;
    }
    if (key === "last_opened_at" || key === "created_at") {
      va = va ? new Date(va).getTime() : 0;
      vb = vb ? new Date(vb).getTime() : 0;
    }
    if (key === "active") {
      va = va ? 1 : 0;
      vb = vb ? 1 : 0;
    }
    const diff = (va ?? 0) - (vb ?? 0);
    return dir === "asc" ? diff : -diff;
  });
}

// ── Findings (Passive Scanner) ──

let findingsData = [];
let scannerConfigCache = null;
let scannerSettingsSessionId = null;
let findingsSortKey = "found_at";
let findingsSortDir = "desc";

const BUILTIN_RULE_LABELS = {
  jwt: "JWT Analysis",
  header: "Security Headers",
  cookie: "Cookie Flags",
  disclosure: "Sensitive Data Exposure",
  cors: "CORS Misconfiguration",
  server: "Server Disclosure",
  error: "Error Messages",
};

let selectedFindingId = null;

async function loadFindings() {
  const sessionId = currentSessionId();
  try {
    const response = await fetch(sessionQueryPath("/api/findings?limit=5000", sessionId));
    if (!response.ok) return;
    const findings = jsonArray(await response.json());
    if (sessionId !== currentSessionId()) return;
    findingsData = findings;
    renderFindings();
    updateFindingsBadge();
  } catch (error) {
    console.error("Failed to load findings:", error);
  }
}

async function updateFindingsBadgeOnly() {
  const sessionId = currentSessionId();
  try {
    const response = await fetch(sessionQueryPath("/api/findings?limit=5000", sessionId));
    if (!response.ok) return;
    const findings = jsonArray(await response.json());
    if (sessionId !== currentSessionId()) return;
    findingsData = findings;
    updateFindingsBadge();
  } catch (e) { /* silent */ }
}

function updateFindingsBadge() {
  if (!els.findingsBadge) return;
  const count = findingsData.length;
  els.findingsBadge.textContent = count > 0 ? String(count) : "";
  els.findingsBadge.classList.toggle("hidden", count === 0);
}

function clearFindingDetail() {
  selectedFindingId = null;
  if (els.findingsDetailJump) {
    delete els.findingsDetailJump.dataset.recordId;
  }
  if (els.findingsDetailContent) {
    els.findingsDetailContent.classList.add("hidden");
  }
  if (els.findingsDetailPlaceholder) {
    els.findingsDetailPlaceholder.classList.remove("hidden");
  }
  if (els.findingsDetailTitle) els.findingsDetailTitle.textContent = "";
  if (els.findingsDetailCategory) els.findingsDetailCategory.textContent = "";
  if (els.findingsDetailDesc) els.findingsDetailDesc.textContent = "";
  if (getCMView("findingsReq")) updateCodePaneCM("findingsReq", els.findingsReqCM, "", { mode: "http" });
  if (getCMView("findingsRes")) updateCodePaneCM("findingsRes", els.findingsResCM, "", { mode: "http" });
  if (els.findingsReqView) els.findingsReqView.innerHTML = "";
  if (els.findingsResView) els.findingsResView.innerHTML = "";
}

function resetFindingsUiState() {
  findingsData = [];
  state._findingsEntries = [];
  clearFindingDetail();
  renderFindings();
  updateFindingsBadge();
}

function severityClass(severity) {
  switch (severity) {
    case "critical": return "severity-critical";
    case "high": return "severity-high";
    case "medium": return "severity-medium";
    case "low": return "severity-low";
    default: return "severity-info";
  }
}

function severityLabel(severity) {
  switch (severity) {
    case "critical": return "Critical";
    case "high": return "High";
    case "medium": return "Medium";
    case "low": return "Low";
    default: return "Info";
  }
}

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function getFilteredFindings() {
  const sevFilter = els.findingsFilterSeverity ? els.findingsFilterSeverity.value : "";
  const catFilter = els.findingsFilterCategory ? els.findingsFilterCategory.value : "";
  const searchTerm = els.findingsFilterSearch ? els.findingsFilterSearch.value.toLowerCase().trim() : "";
  const inScopeOnly = els.findingsInScopeOnly ? els.findingsInScopeOnly.checked : false;

  let filtered = findingsData.filter((f) => {
    if (inScopeOnly && !isInScopeHost(f.host)) return false;
    if (sevFilter) {
      const threshold = SEVERITY_ORDER[sevFilter] ?? 5;
      const fLevel = SEVERITY_ORDER[f.severity] ?? 5;
      if (fLevel > threshold) return false;
    }
    if (catFilter && f.category !== catFilter) return false;
    if (searchTerm) {
      const haystack = `${f.title} ${f.host} ${f.path} ${f.category}`.toLowerCase();
      if (!haystack.includes(searchTerm)) return false;
    }
    return true;
  });

  // Sort
  const dir = findingsSortDir === "asc" ? 1 : -1;
  filtered.sort((a, b) => {
    let va, vb;
    if (findingsSortKey === "severity") {
      va = SEVERITY_ORDER[a.severity] ?? 5;
      vb = SEVERITY_ORDER[b.severity] ?? 5;
    } else if (findingsSortKey === "found_at") {
      va = a.found_at || "";
      vb = b.found_at || "";
    } else {
      va = (a[findingsSortKey] || "").toLowerCase();
      vb = (b[findingsSortKey] || "").toLowerCase();
    }
    if (va < vb) return -1 * dir;
    if (va > vb) return 1 * dir;
    return 0;
  });

  return filtered;
}

function toggleFindingsSort(key) {
  if (findingsSortKey === key) {
    findingsSortDir = findingsSortDir === "asc" ? "desc" : "asc";
  } else {
    findingsSortKey = key;
    findingsSortDir = key === "severity" ? "asc" : (key === "found_at" ? "desc" : "asc");
  }
  updateFindingsSortHeaders();
  renderFindings();
}

function updateFindingsSortHeaders() {
  document.querySelectorAll(".findings-sortable").forEach((th) => {
    const key = th.dataset.findingsSort;
    const active = key === findingsSortKey;
    th.classList.toggle("active", active);
    const indicator = th.querySelector(".findings-sort-indicator");
    if (indicator) {
      indicator.textContent = active ? (findingsSortDir === "asc" ? "↑" : "↓") : "↕";
    }
  });
}

function updateCategoryFilter() {
  if (!els.findingsFilterCategory) return;
  const current = els.findingsFilterCategory.value;
  const builtinCats = new Set(["jwt", "header", "cookie", "disclosure", "cors", "error"]);
  const extraCats = new Set();
  for (const f of findingsData) {
    if (!builtinCats.has(f.category)) extraCats.add(f.category);
  }
  // Remove old custom options
  Array.from(els.findingsFilterCategory.options).forEach((opt) => {
    if (opt.dataset.custom) opt.remove();
  });
  for (const cat of extraCats) {
    const opt = document.createElement("option");
    opt.value = cat;
    opt.textContent = cat;
    opt.dataset.custom = "1";
    els.findingsFilterCategory.appendChild(opt);
  }
  els.findingsFilterCategory.value = current;
}

function renderFindings() {
  if (!els.findingsBody) return;
  updateCategoryFilter();
  state._findingsEntries = getFilteredFindings();

  if (!state._findingsEntries.length) {
    els.findingsBody.innerHTML = `<tr class="empty-row"><td colspan="6">No findings yet. Browse with the proxy to start scanning.</td></tr>`;
    return;
  }

  renderFindingsVirtual();
}

function renderFindingsVirtual() {
  const entries = state._findingsEntries;
  if (!entries || !entries.length) return;

  const shell = els.findingsBody.closest(".history-table-shell");
  if (!shell) return;

  const viewportHeight = shell.clientHeight;
  const totalCount = entries.length;
  const maxScrollTop = Math.max(0, totalCount * FINDINGS_ROW_HEIGHT - viewportHeight);
  const scrollTop = Math.min(shell.scrollTop, maxScrollTop);
  if (shell.scrollTop !== scrollTop) {
    shell.scrollTop = scrollTop;
  }

  const startIdx = Math.max(0, Math.floor(scrollTop / FINDINGS_ROW_HEIGHT) - FINDINGS_BUFFER_ROWS);
  const endIdx = Math.min(totalCount, Math.ceil((scrollTop + viewportHeight) / FINDINGS_ROW_HEIGHT) + FINDINGS_BUFFER_ROWS);

  const topPadding = startIdx * FINDINGS_ROW_HEIGHT;
  const bottomPadding = Math.max(0, (totalCount - endIdx) * FINDINGS_ROW_HEIGHT);

  const rows = [];
  for (let i = startIdx; i < endIdx; i++) {
    const f = entries[i];
    const selected = f.id === selectedFindingId ? " selected" : "";
    rows.push(`<tr class="history-row${selected}" data-finding-id="${f.id}" data-record-id="${f.record_id}">
      <td class="findings-col-severity"><span class="severity-badge ${severityClass(f.severity)}">${severityLabel(f.severity)}</span></td>
      <td class="findings-col-category"><span class="detail-chip">${escapeHtml(f.category)}</span></td>
      <td class="findings-col-title">${escapeHtml(f.title)}</td>
      <td class="findings-col-host">${escapeHtml(f.host)}</td>
      <td class="findings-col-path">${escapeHtml(f.path)}</td>
      <td class="findings-col-time">${escapeHtml(formatTimestamp(f.found_at))}</td>
    </tr>`);
  }

  els.findingsBody.innerHTML =
    (topPadding > 0 ? `<tr class="virtual-spacer"><td colspan="6" style="height:${topPadding}px;padding:0;border:none"></td></tr>` : "") +
    rows.join("") +
    (bottomPadding > 0 ? `<tr class="virtual-spacer"><td colspan="6" style="height:${bottomPadding}px;padding:0;border:none"></td></tr>` : "");
}

async function loadFindingDetail(id) {
  const sessionId = currentSessionId();
  try {
    const res = await fetch(sessionQueryPath(`/api/findings/${encodeURIComponent(id)}`, sessionId));
    if (selectedFindingId !== id) return;
    if (!res.ok) return;
    const finding = await res.json();
    if (currentSessionId() !== sessionId) return;
    if (selectedFindingId !== id) return;
    // Also fetch the transaction record for request/response
    let record = null;
    try {
      const tRes = await fetch(transactionPath(finding.record_id, sessionId));
      if (tRes.ok) record = await tRes.json();
    } catch (_) { /* silent */ }
    if (currentSessionId() !== sessionId) return;
    if (selectedFindingId !== id) return;
    showFindingDetail(finding, record);
  } catch (error) {
    console.error("Failed to load finding detail:", error);
  }
}

function showFindingDetail(finding, record) {
  if (!els.findingsDetailPanel) return;
  if (els.findingsDetailPlaceholder) els.findingsDetailPlaceholder.classList.add("hidden");
  if (els.findingsDetailContent) els.findingsDetailContent.classList.remove("hidden");

  // Header info
  els.findingsDetailSeverity.className = `severity-badge ${severityClass(finding.severity)}`;
  els.findingsDetailSeverity.textContent = severityLabel(finding.severity);
  els.findingsDetailCategory.textContent = finding.category;
  els.findingsDetailTitle.textContent = finding.title;

  // Description + evidence
  els.findingsDetailDesc.innerHTML = `<span class="findings-desc-text">${escapeHtml(finding.detail)}</span>`;

  // Jump button — store record_id
  els.findingsDetailJump.dataset.recordId = finding.record_id;

  // Render request/response with highlight
  const evidence = finding.evidence || "";
  if (record) {
    const reqText = buildFindingsRawMessage(record, "request");
    const resText = buildFindingsRawMessage(record, "response");
    // CM path
    if (els.findingsReqCM) {
      updateCodePaneCM("findingsReq", els.findingsReqCM, reqText, { mode: "http" });
      const reqSearchMeta = els.findingsReqSearchMeta;
      if (reqSearchMeta) reqSearchMeta.innerHTML = buildSearchMeta(countLines(reqText), "raw", 0);
      if (els.findingsReqSearchInput) els.findingsReqSearchInput.value = "";
    }
    if (els.findingsResCM) {
      updateCodePaneCM("findingsRes", els.findingsResCM, resText, { mode: "http" });
      const resSearchMeta = els.findingsResSearchMeta;
      if (resSearchMeta) resSearchMeta.innerHTML = buildSearchMeta(countLines(resText), "raw", 0);
      if (els.findingsResSearchInput) els.findingsResSearchInput.value = "";
    }
    // Legacy fallback
    if (!els.findingsReqCM) {
      renderFindingsCodePane(els.findingsReqView, els.findingsReqLines, reqText, evidence, "request", finding);
    }
    if (!els.findingsResCM) {
      renderFindingsCodePane(els.findingsResView, els.findingsResLines, resText, evidence, "response", finding);
    }
  } else {
    if (els.findingsReqCM) {
      updateCodePaneCM("findingsReq", els.findingsReqCM, "Transaction not available.", { mode: "http" });
    } else if (els.findingsReqView) {
      els.findingsReqView.innerHTML = '<span class="code-line code-line-empty">Transaction not available.</span>';
      if (els.findingsReqLines) els.findingsReqLines.textContent = "";
    }
    if (els.findingsResCM) {
      updateCodePaneCM("findingsRes", els.findingsResCM, "Transaction not available.", { mode: "http" });
    } else if (els.findingsResView) {
      els.findingsResView.innerHTML = '<span class="code-line code-line-empty">Transaction not available.</span>';
      if (els.findingsResLines) els.findingsResLines.textContent = "";
    }
  }
}

function renderFindingsCodePane(viewEl, lineEl, text, evidence, target, finding) {
  if (!viewEl || !lineEl) return;
  if (!text) {
    viewEl.innerHTML = '<span class="code-line code-line-empty">&nbsp;</span>';
    lineEl.textContent = "";
    return;
  }
  const html = renderHttpHtml(text, target);
  viewEl.innerHTML = html;
  lineEl.textContent = buildLineNumbers(countLines(text));
  if (window._enableReadonlyCaret) window._enableReadonlyCaret(viewEl);

  // Highlight evidence — line background + inline mark
  highlightFindingLines(viewEl, evidence, finding);

  // Clear search when new finding is loaded
  const isReq = (viewEl === els.findingsReqView);
  const searchInput = isReq ? els.findingsReqSearchInput : els.findingsResSearchInput;
  const searchMeta = isReq ? els.findingsReqSearchMeta : els.findingsResSearchMeta;
  if (searchInput) searchInput.value = "";
  if (searchMeta) searchMeta.innerHTML = buildSearchMeta(countLines(text), "raw", 0);

  // Scroll sync
  viewEl.addEventListener("scroll", () => { lineEl.scrollTop = viewEl.scrollTop; });
}

function highlightFindingLines(container, evidence, finding) {
  const codeLines = container.querySelectorAll(".code-line");
  let scrollTarget = null;

  // 1) If evidence exists, highlight lines containing the evidence text
  if (evidence && evidence.length >= 3) {
    const escapedEvidence = evidence.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    let pattern;
    try { pattern = new RegExp(`(${escapedEvidence})`, "gi"); } catch (_) { pattern = null; }

    if (pattern) {
      codeLines.forEach((line) => {
        pattern.lastIndex = 0;
        if (pattern.test(line.textContent)) {
          line.classList.add("findings-line-hit");
          if (!scrollTarget) scrollTarget = line;

          // Also inline-mark the exact text
          const walker = document.createTreeWalker(line, NodeFilter.SHOW_TEXT, null);
          const textNodes = [];
          while (walker.nextNode()) textNodes.push(walker.currentNode);
          textNodes.forEach((node) => {
            const txt = node.nodeValue;
            pattern.lastIndex = 0;
            if (!pattern.test(txt)) return;
            pattern.lastIndex = 0;
            const frag = document.createDocumentFragment();
            let lastIdx = 0;
            let m;
            while ((m = pattern.exec(txt)) !== null) {
              if (m.index > lastIdx) frag.appendChild(document.createTextNode(txt.slice(lastIdx, m.index)));
              const mark = document.createElement("mark");
              mark.className = "findings-highlight";
              mark.textContent = m[1];
              frag.appendChild(mark);
              lastIdx = pattern.lastIndex;
            }
            if (lastIdx < txt.length) frag.appendChild(document.createTextNode(txt.slice(lastIdx)));
            node.parentNode.replaceChild(frag, node);
          });
        }
      });
    }
  }

  // 2) For "missing" findings (no evidence), highlight related header lines
  if (!scrollTarget && finding) {
    const keywords = extractFindingKeywords(finding);
    if (keywords.length) {
      codeLines.forEach((line) => {
        const text = line.textContent.toLowerCase();
        if (keywords.some((kw) => text.includes(kw))) {
          line.classList.add("findings-line-related");
          if (!scrollTarget) scrollTarget = line;
        }
      });
    }
  }

  // Scroll to first highlighted line
  if (scrollTarget) {
    setTimeout(() => scrollTarget.scrollIntoView({ block: "center", behavior: "smooth" }), 50);
  }
}

function extractFindingKeywords(finding) {
  const title = (finding.title || "").toLowerCase();
  const keywords = [];

  // Missing header findings → highlight related headers
  if (title.includes("content-security-policy")) keywords.push("content-security-policy");
  if (title.includes("strict-transport-security")) keywords.push("strict-transport-security");
  if (title.includes("x-content-type-options")) keywords.push("x-content-type-options");
  if (title.includes("x-frame-options")) keywords.push("x-frame-options", "frame-ancestors");
  if (title.includes("httponly")) keywords.push("set-cookie", "httponly");
  if (title.includes("secure flag")) keywords.push("set-cookie", "secure");
  if (title.includes("samesite")) keywords.push("set-cookie", "samesite");
  if (title.includes("cors")) keywords.push("access-control-allow-origin", "access-control-allow-credentials");
  if (title.includes("server version")) keywords.push("server:", "x-powered-by:");
  if (title.includes("jwt")) keywords.push("authorization:", "bearer");
  if (title.includes("cookie") && !keywords.length) keywords.push("set-cookie", "cookie");

  return keywords;
}

function jumpToTransaction(recordId) {
  state.activeProxyTab = "http-history";
  state.selectedId = recordId;
  renderProxyPanels();
  loadTransactionDetail(recordId).then(() => {
    const row = document.querySelector(`.history-row[data-id="${recordId}"]`);
    if (row) {
      updateHistorySelection(recordId);
      row.scrollIntoView({ block: "center", behavior: "smooth" });
    }
  }).catch((error) => console.error(error));
}

async function sendFindingToReplay(recordId) {
  const sessionId = currentSessionId();
  const response = await fetch(transactionPath(recordId, sessionId));
  if (currentSessionId() !== sessionId) return;
  await requireOkResponse(response, "Failed to load finding transaction.");
  const record = await response.json();
  if (currentSessionId() !== sessionId) return;
  openTransactionRecordInReplay(record);
}

function openTransactionRecordInReplay(record) {
  if (!record || record.kind === "tunnel") {
    throw new Error("Tunnel records cannot be sent to Replay.");
  }
  if (isWebSocketUpgradeRecord(record)) {
    const scheme = record.scheme === "https" ? "wss" : record.scheme === "http" ? "ws" : record.scheme || "wss";
    const target = authorityToTargetState(record.host || "", record.scheme || "https");
    createWsReplayTab({
      scheme,
      host: target.host,
      port: normalizePortValue(target.port) || (scheme === "wss" ? 443 : 80),
      path: record.path || "/",
      headers: normalizedHeaders(record.request?.headers),
    });
    state.activeTool = "replay";
    scheduleWorkspaceStateSave();
    renderToolPanels();
    return;
  }
  const request = editableRequestFromRecord(record);
  const tab = createReplayTab({
    baseRequest: request,
    sourceTransactionId: record.id,
    notice: isRequestPreviewTruncated(record) ? buildTruncatedBodyNotice(record, "Replay") : "",
    requestText: buildEditableRawRequest(request),
  });
  state.replayTabs.push(tab);
  state.activeReplayTabId = tab.id;
  state.activeTool = "replay";
  scheduleWorkspaceStateSave();
  renderToolPanels();
}

function isWebSocketUpgradeRecord(record) {
  return Number(record?.status) === 101 || normalizedHeaders(record?.request?.headers).some(
    (h) => headerNameEquals(h, "upgrade") && String(h.value || "").toLowerCase() === "websocket"
  );
}

async function sendFindingToFuzzer(recordId) {
  const sessionId = currentSessionId();
  const response = await fetch(transactionPath(recordId, sessionId));
  if (currentSessionId() !== sessionId) return;
  await requireOkResponse(response, "Failed to load finding transaction.");
  const record = await response.json();
  if (currentSessionId() !== sessionId) return;
  if (!record || record.kind === "tunnel") {
    throw new Error("Tunnel records cannot be sent to Fuzzer.");
  }
  const request = editableRequestFromRecord(record);
  invalidateFuzzerRun();
  state.fuzzerBaseRequest = request;
  state.fuzzerSourceTransactionId = record.id;
  state.fuzzerTarget = null;
  state.fuzzerTargetRequestText = null;
  updateFuzzerRequestText(buildEditableRawRequest(request), { userEdit: true });
  state.fuzzerNotice = isRequestPreviewTruncated(record) ? buildTruncatedBodyNotice(record, "Fuzzer") : "";
  updateFuzzerPayloadsText("", { userEdit: true });
  state.fuzzerAttackRecord = null;
  state._selectedFuzzerResultKey = null;
  hideFuzzerDetailPanel();
  state.activeTool = "fuzzer";
  scheduleWorkspaceStateSave();
  renderToolPanels();
}

function handleFindingActionError(error) {
  console.error(error);
  showToast(error?.message || "Finding action failed.", "error");
}

// ── Scanner Settings Modal ──

async function loadScannerConfig(sessionId = currentSessionId()) {
  try {
    const res = await fetch(sessionQueryPath("/api/scanner-config", sessionId));
    await requireOkResponse(res, "Failed to load scanner settings.");
    const config = await res.json();
    if (sessionId !== currentSessionId()) {
      return null;
    }
    scannerConfigCache = config;
    return scannerConfigCache;
  } catch (e) {
    console.error("Failed to load scanner config:", e);
    showToast(e?.message || "Failed to load scanner settings.", "error");
    return null;
  }
}

async function saveScannerConfig(config, sessionId = currentSessionId()) {
  if (sessionId !== currentSessionId()) {
    return false;
  }
  const res = await fetch(sessionQueryPath("/api/scanner-config", sessionId), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(config),
  });
  await requireOkResponse(res, "Failed to save scanner settings.");
  if (sessionId !== currentSessionId()) {
    return false;
  }
  scannerConfigCache = config;
  return true;
}

async function openScannerSettings() {
  const sessionId = currentSessionId();
  const config = await loadScannerConfig(sessionId);
  if (!config || sessionId !== currentSessionId()) return;
  scannerSettingsSessionId = sessionId;

  // Render built-in rules
  els.scannerBuiltinRules.innerHTML = Object.entries(BUILTIN_RULE_LABELS)
    .map(([id, label]) => {
      const checked = config.rules[id] !== false ? "checked" : "";
      return `<div class="scanner-rule-item">
        <label><input type="checkbox" data-rule-id="${id}" ${checked} /> ${escapeHtml(label)}</label>
      </div>`;
    })
    .join("");

  // Render custom rules
  renderCustomRulesEditor(config.custom_rules || []);

  els.scannerSettingsBackdrop.classList.remove("hidden");
}

function renderCustomRulesEditor(customRules) {
  els.scannerCustomRules.innerHTML = customRules
    .map((rule, idx) => `
      <div class="scanner-custom-rule-card" data-custom-idx="${idx}">
        <div class="scanner-custom-rule-header">
          <label><input type="checkbox" class="custom-rule-enabled" ${rule.enabled ? "checked" : ""} /></label>
          <input type="text" class="custom-rule-name" value="${escapeHtml(rule.name)}" placeholder="Rule name" style="margin: 0 6px;" />
          <button class="secondary-action scanner-custom-rule-delete" type="button" data-del-idx="${idx}">&times;</button>
        </div>
        <div class="scanner-custom-rule-fields">
          <select class="custom-rule-target">
            <option value="response_body" ${rule.target === "response_body" ? "selected" : ""}>Response Body</option>
            <option value="response_header" ${rule.target === "response_header" ? "selected" : ""}>Response Header</option>
            <option value="request_header" ${rule.target === "request_header" ? "selected" : ""}>Request Header</option>
          </select>
          <input type="text" class="custom-rule-header-name" value="${escapeHtml(rule.header_name || "")}" placeholder="Header name (optional)" />
          <input type="text" class="custom-rule-pattern scanner-custom-rule-fullrow" value="${escapeHtml(rule.pattern)}" placeholder="Regex pattern" />
          <select class="custom-rule-severity">
            <option value="critical" ${rule.severity === "critical" ? "selected" : ""}>Critical</option>
            <option value="high" ${rule.severity === "high" ? "selected" : ""}>High</option>
            <option value="medium" ${rule.severity === "medium" ? "selected" : ""}>Medium</option>
            <option value="low" ${rule.severity === "low" ? "selected" : ""}>Low</option>
            <option value="info" ${rule.severity === "info" ? "selected" : ""}>Info</option>
          </select>
          <input type="text" class="custom-rule-category" value="${escapeHtml(rule.category)}" placeholder="Category" />
          <input type="text" class="custom-rule-description scanner-custom-rule-fullrow" value="${escapeHtml(rule.description)}" placeholder="Description" />
        </div>
      </div>
    `)
    .join("");

  // Delete button events
  els.scannerCustomRules.querySelectorAll(".scanner-custom-rule-delete").forEach((btn) => {
    btn.addEventListener("click", () => {
      const rules = collectCustomRulesFromEditor();
      rules.splice(parseInt(btn.dataset.delIdx, 10), 1);
      renderCustomRulesEditor(rules);
    });
  });
}

function collectCustomRulesFromEditor() {
  const cards = els.scannerCustomRules.querySelectorAll(".scanner-custom-rule-card");
  return Array.from(cards).map((card, idx) => ({
    id: `custom_${idx}_${Date.now()}`,
    enabled: card.querySelector(".custom-rule-enabled").checked,
    name: card.querySelector(".custom-rule-name").value.trim() || `Custom Rule ${idx + 1}`,
    target: card.querySelector(".custom-rule-target").value,
    header_name: card.querySelector(".custom-rule-header-name").value.trim(),
    pattern: card.querySelector(".custom-rule-pattern").value,
    severity: card.querySelector(".custom-rule-severity").value,
    category: card.querySelector(".custom-rule-category").value.trim() || "custom",
    description: card.querySelector(".custom-rule-description").value.trim(),
  }));
}

function collectScannerConfig() {
  const rules = {};
  els.scannerBuiltinRules.querySelectorAll("input[data-rule-id]").forEach((input) => {
    rules[input.dataset.ruleId] = input.checked;
  });
  return {
    enabled: els.scannerQuickToggle ? els.scannerQuickToggle.checked : true,
    rules,
    custom_rules: collectCustomRulesFromEditor(),
  };
}

function closeScannerSettings() {
  scannerSettingsSessionId = null;
  if (els.scannerSettingsBackdrop) {
    els.scannerSettingsBackdrop.classList.add("hidden");
  }
}

async function saveScannerSettingsFromModal() {
  const sessionId = scannerSettingsSessionId;
  if (!sessionId || sessionId !== currentSessionId()) {
    closeScannerSettings();
    showToast("Scanner settings changed sessions. Reopen settings and save again.", "error");
    return;
  }
  const config = collectScannerConfig();
  if (!(await saveScannerConfig(config, sessionId))) {
    return;
  }
  syncQuickToggle(config.enabled);
  closeScannerSettings();
  showToast("Scanner settings saved");
}

async function refreshScannerQuickToggle() {
  if (!els.scannerQuickToggle) return;
  const sessionId = currentSessionId();
  const config = await loadScannerConfig(sessionId);
  if (config && sessionId === currentSessionId()) {
    syncQuickToggle(config.enabled);
  }
}

function syncQuickToggle(enabled) {
  if (els.scannerQuickToggle) {
    els.scannerQuickToggle.checked = enabled;
  }
}

function updateFindingsSelection(newId) {
  const prev = els.findingsBody.querySelector(".history-row.selected");
  if (prev) prev.classList.remove("selected");
  if (newId) {
    const next = els.findingsBody.querySelector(`tr[data-finding-id="${newId}"]`);
    if (next) {
      next.classList.add("selected");
    } else {
      scrollFindingsToId(newId);
    }
  }
}

function scrollFindingsToId(targetId) {
  const entries = state._findingsEntries;
  if (!entries) return;
  const idx = entries.findIndex((f) => f.id === targetId);
  if (idx === -1) return;
  const shell = els.findingsBody.closest(".history-table-shell");
  if (!shell) return;
  shell.scrollTop = Math.max(0, idx * FINDINGS_ROW_HEIGHT - shell.clientHeight / 2);
}

function findingsArrowNav(direction) {
  const entries = state._findingsEntries;
  if (!entries || !entries.length) return;
  const currentIdx = entries.findIndex((f) => f.id === selectedFindingId);
  let nextIdx;
  if (currentIdx < 0) {
    nextIdx = 0;
  } else {
    nextIdx = currentIdx + direction;
    if (nextIdx < 0) nextIdx = 0;
    if (nextIdx >= entries.length) nextIdx = entries.length - 1;
  }
  const f = entries[nextIdx];
  selectedFindingId = f.id;
  updateFindingsSelection(f.id);

  // Scroll into view
  const shell = els.findingsBody.closest(".history-table-shell");
  if (shell) {
    const rowTop = nextIdx * FINDINGS_ROW_HEIGHT;
    const rowBottom = rowTop + FINDINGS_ROW_HEIGHT;
    const viewTop = shell.scrollTop;
    const viewBottom = viewTop + shell.clientHeight;
    if (rowTop < viewTop) {
      shell.scrollTop = rowTop;
    } else if (rowBottom > viewBottom) {
      shell.scrollTop = rowBottom - shell.clientHeight;
    }
  }
  loadFindingDetail(f.id);
}

async function loadOastCallbacks() {
  const sessionId = currentSessionId();
  const [cbRes, statusRes] = await Promise.all([
    fetch(sessionQueryPath("/api/oast/callbacks", sessionId)),
    fetch(sessionQueryPath("/api/oast/status", sessionId)),
  ]);
  await requireOkResponse(cbRes, "Failed to load OAST callbacks.");
  const callbacks = jsonArray(await cbRes.json());
  if (sessionId !== currentSessionId()) {
    return;
  }
  state.oastCallbacks = callbacks;
  if (state.selectedOastId && !state.oastCallbacks.some((cb) => cb.id === state.selectedOastId)) {
    state.selectedOastId = null;
    clearOastDetail();
  }
  renderOastCallbacks();
  updateOastBadge();
  // Update registration status display
  try {
    await requireOkResponse(statusRes, "Failed to load OAST status.");
    const status = await statusRes.json() || {};
    if (sessionId !== currentSessionId()) {
      return;
    }
    const el = document.getElementById("oastStatusText");
    if (el) {
      if (status.registered) {
        el.textContent = `${status.provider} · Registered (${status.payload_domain || status.correlation_id || ""})`;
        el.className = "oast-status-text registered";
      } else if (status.provider && status.provider !== "custom") {
        el.textContent = `${status.provider} · Not registered`;
        el.className = "oast-status-text not-registered";
      } else {
        el.textContent = status.provider || "Not configured";
        el.className = "oast-status-text not-registered";
      }
    }
  } catch (_) { /* ignore status fetch errors */ }
}

function renderOastCallbacks() {
  if (!els.oastTableBody) return;
  els.oastTableBody.innerHTML = state.oastCallbacks.length
    ? state.oastCallbacks.map((cb) => {
        const selected = cb.id === state.selectedOastId ? "selected" : "";
        return `<tr class="history-row ${selected}" data-oast-id="${cb.id}">
          <td>${escapeHtml(formatTimestamp(cb.received_at))}</td>
          <td>${escapeHtml(cb.protocol)}</td>
          <td>${escapeHtml(cb.remote_addr)}</td>
          <td>${escapeHtml(cb.correlation_id)}</td>
        </tr>`;
      }).join("")
    : '<tr class="empty-row"><td colspan="4">No OAST callbacks received yet. Generate a payload and use it in your tests.</td></tr>';
}

function updateOastBadge() {
  if (!els.oastBadge) return;
  const count = state.oastCallbacks.length;
  els.oastBadge.textContent = count > 0 ? String(count) : "";
  els.oastBadge.classList.toggle("hidden", count === 0);
}

function clearOastDetail() {
  if (els.oastDetailView) els.oastDetailView.textContent = "Select an OAST callback to view details.";
  if (els.oastDetailTitle) els.oastDetailTitle.textContent = "Select a callback";
}

function resetOastUiState() {
  state.oastCallbacks = [];
  state.selectedOastId = null;
  state.oastTokenClearPending = false;
  if (els.oastPayloadText) els.oastPayloadText.value = "";
  renderOastCallbacks();
  updateOastBadge();
  clearOastDetail();
  const status = document.getElementById("oastStatusText");
  if (status) {
    status.textContent = "Not configured";
    status.className = "oast-status-text not-registered";
  }
}

function handleOastActionError(error) {
  console.error(error);
  showToast(error?.message || "OAST action failed.", "error");
}

async function loadOastDetail(id) {
  const sessionId = currentSessionId();
  const response = await fetch(sessionQueryPath(`/api/oast/callbacks/${id}`, sessionId));
  if (sessionId !== currentSessionId() || state.selectedOastId !== id) {
    return;
  }
  if (!response.ok) {
    state.selectedOastId = null;
    clearOastDetail();
    renderOastCallbacks();
    return;
  }
  const cb = await response.json();
  if (sessionId !== currentSessionId() || state.selectedOastId !== id) {
    return;
  }
  if (els.oastDetailTitle) els.oastDetailTitle.textContent = `${cb.protocol} from ${cb.remote_addr}`;
  if (els.oastDetailView) {
    els.oastDetailView.textContent = [
      `Protocol: ${cb.protocol}`,
      `Remote: ${cb.remote_addr}`,
      `Correlation ID: ${cb.correlation_id}`,
      `Received: ${cb.received_at}`,
      '',
      '--- Raw Data ---',
      cb.raw_data || '(empty)',
    ].join('\n');
  }
}

async function generateOastPayload() {
  const serverUrl = (state.runtime.oast_server_url || "").trim();
  if (!state.runtime.oast_enabled) {
    showToast("Enable OAST in Settings before generating a payload", "error");
    return;
  }
  if (!serverUrl) {
    showToast("Set an OAST server URL in Settings first", "error");
    return;
  }
  const sessionId = currentSessionId();
  const response = await fetch(sessionQueryPath("/api/oast/generate", sessionId), { method: "POST" });
  if (!response.ok) {
    showToast(await response.text(), "error");
    return;
  }
  const data = await response.json();
  if (sessionId !== currentSessionId()) {
    return;
  }
  if (els.oastPayloadText) els.oastPayloadText.value = data.payload;
  showToast(`OAST payload: ${data.payload}`);
}

async function clearOastCallbacks() {
  const sessionId = currentSessionId();
  const response = await fetch(sessionQueryPath("/api/oast/callbacks/clear", sessionId), { method: "POST" });
  await requireOkResponse(response, "Failed to clear OAST callbacks.");
  if (sessionId !== currentSessionId()) {
    return;
  }
  state.oastCallbacks = [];
  state.selectedOastId = null;
  renderOastCallbacks();
  updateOastBadge();
  clearOastDetail();
}

function bindFindingsEvents() {
  // Sort headers
  document.querySelectorAll(".findings-sortable").forEach((th) => {
    th.addEventListener("click", () => toggleFindingsSort(th.dataset.findingsSort));
  });

  // Virtual scroll for findings table
  const findingsShell = els.findingsBody ? els.findingsBody.closest(".history-table-shell") : null;
  if (findingsShell) {
    let findingsScrollRaf = 0;
    findingsShell.addEventListener("scroll", () => {
      if (findingsScrollRaf) return;
      findingsScrollRaf = requestAnimationFrame(() => {
        findingsScrollRaf = 0;
        renderFindingsVirtual();
      });
    });
  }

  // Event delegation for findings table rows
  if (els.findingsBody) {
    els.findingsBody.addEventListener("click", (event) => {
      const row = event.target.closest("tr[data-finding-id]");
      if (!row) return;
      const id = row.dataset.findingId;
      selectedFindingId = id;
      updateFindingsSelection(id);
      loadFindingDetail(id);
    });
    els.findingsBody.addEventListener("dblclick", (event) => {
      const row = event.target.closest("tr[data-finding-id]");
      if (!row) return;
      const recordId = row.dataset.recordId;
      if (recordId) jumpToTransaction(recordId);
    });
  }

  if (els.findingsDetailClose) {
    els.findingsDetailClose.addEventListener("click", () => {
      clearFindingDetail();
    });
  }
  if (els.findingsDetailJump) {
    els.findingsDetailJump.addEventListener("click", () => {
      const recordId = els.findingsDetailJump.dataset.recordId;
      if (recordId) jumpToTransaction(recordId);
    });
  }
  const findingsReplayBtn = document.getElementById("findingsDetailSendReplay");
  if (findingsReplayBtn) {
    findingsReplayBtn.addEventListener("click", () => {
      const recordId = els.findingsDetailJump?.dataset.recordId;
      if (recordId) sendFindingToReplay(recordId).catch(handleFindingActionError);
    });
  }
  const findingsFuzzerBtn = document.getElementById("findingsDetailSendFuzzer");
  if (findingsFuzzerBtn) {
    findingsFuzzerBtn.addEventListener("click", () => {
      const recordId = els.findingsDetailJump?.dataset.recordId;
      if (recordId) sendFindingToFuzzer(recordId).catch(handleFindingActionError);
    });
  }
  if (els.findingsClearButton) {
    els.findingsClearButton.addEventListener("click", async () => {
      const sessionId = currentSessionId();
      try {
        const response = await fetch(sessionQueryPath("/api/findings/clear", sessionId), { method: "POST" });
        await requireOkResponse(response, "Failed to clear findings.");
        if (sessionId !== currentSessionId()) return;
        resetFindingsUiState();
      } catch (error) {
        console.error(error);
        showToast(error?.message || "Failed to clear findings.", "error");
      }
    });
  }

  // Filters
  if (els.findingsFilterSeverity) {
    els.findingsFilterSeverity.addEventListener("change", () => renderFindings());
  }
  if (els.findingsFilterCategory) {
    els.findingsFilterCategory.addEventListener("change", () => renderFindings());
  }
  if (els.findingsFilterSearch) {
    let debounce = null;
    els.findingsFilterSearch.addEventListener("input", () => {
      clearTimeout(debounce);
      debounce = setTimeout(() => renderFindings(), 200);
    });
  }
  if (els.findingsInScopeOnly) {
    els.findingsInScopeOnly.addEventListener("change", () => renderFindings());
  }

  // Arrow key navigation
  document.addEventListener("keydown", (e) => {
    // Skip if scanner settings modal is open
    if (els.scannerSettingsBackdrop && !els.scannerSettingsBackdrop.classList.contains("hidden")) {
      if (e.key === "Escape") { e.preventDefault(); closeScannerSettings(); }
      if (e.key === "Enter" && !e.target.matches("input, textarea, select")) { e.preventDefault(); saveScannerSettingsFromModal(); }
      return;
    }
    // Only handle when findings tab is active and not focused on input
    if (state.activeTool !== "proxy" || state.activeProxyTab !== "findings") return;
    if (e.target.matches("input, textarea, select")) return;
    if (e.key === "ArrowDown") { e.preventDefault(); findingsArrowNav(1); }
    if (e.key === "ArrowUp") { e.preventDefault(); findingsArrowNav(-1); }
  });

  // Findings detail search
  if (els.findingsReqSearchInput) {
    els.findingsReqSearchInput.addEventListener("input", () => {
      const query = els.findingsReqSearchInput.value;
      // CM path
      const cv = getCMView("findingsReq");
      if (cv) {
        const result = cv.applySearch(query);
        const lineCount = cv.view.state.doc.lines;
        els.findingsReqSearchMeta.innerHTML = buildSearchMeta(lineCount, "raw", result.matchCount);
        return;
      }
      // Legacy fallback
      if (!els.findingsReqView) return;
      const { count } = applyCodeSearch(els.findingsReqView, query);
      const lines = els.findingsReqView.querySelectorAll(".code-line").length;
      els.findingsReqSearchMeta.innerHTML = buildSearchMeta(lines, "raw", count);
    });
  }
  if (els.findingsResSearchInput) {
    els.findingsResSearchInput.addEventListener("input", () => {
      const query = els.findingsResSearchInput.value;
      // CM path
      const cv = getCMView("findingsRes");
      if (cv) {
        const result = cv.applySearch(query);
        const lineCount = cv.view.state.doc.lines;
        els.findingsResSearchMeta.innerHTML = buildSearchMeta(lineCount, "raw", result.matchCount);
        return;
      }
      // Legacy fallback
      if (!els.findingsResView) return;
      const { count } = applyCodeSearch(els.findingsResView, query);
      const lines = els.findingsResView.querySelectorAll(".code-line").length;
      els.findingsResSearchMeta.innerHTML = buildSearchMeta(lines, "raw", count);
    });
  }
  initSearchHitNavigation(els.findingsReqSearchMeta, () => els.findingsReqView);
  initSearchHitNavigation(els.findingsResSearchMeta, () => els.findingsResView);
  initCMSearchNavigation(els.findingsReqSearchMeta, "findingsReq");
  initCMSearchNavigation(els.findingsResSearchMeta, "findingsRes");

  // Quick toggle (on/off in toolbar)
  if (els.scannerQuickToggle) {
    els.scannerQuickToggle.addEventListener("change", async () => {
      const enabled = els.scannerQuickToggle.checked;
      const sessionId = currentSessionId();
      els.scannerQuickToggle.disabled = true;
      try {
        const config = await loadScannerConfig(sessionId);
        if (sessionId !== currentSessionId()) {
          return;
        }
        if (!config) {
          syncQuickToggle(!enabled);
          return;
        }
        config.enabled = enabled;
        if (!(await saveScannerConfig(config, sessionId))) {
          return;
        }
        syncQuickToggle(enabled);
      } catch (error) {
        console.error(error);
        showToast(error?.message || "Failed to save scanner settings.", "error");
        syncQuickToggle(!enabled);
      } finally {
        els.scannerQuickToggle.disabled = false;
      }
    });
    // Sync initial state from server
    refreshScannerQuickToggle();
  }

  // Scanner settings modal
  if (els.findingsSettingsButton) {
    els.findingsSettingsButton.addEventListener("click", () => openScannerSettings());
  }
  if (els.scannerSettingsClose) {
    els.scannerSettingsClose.addEventListener("click", () => closeScannerSettings());
  }
  if (els.scannerSettingsCancel) {
    els.scannerSettingsCancel.addEventListener("click", () => closeScannerSettings());
  }
  if (els.scannerSettingsSave) {
    els.scannerSettingsSave.addEventListener("click", () => {
      saveScannerSettingsFromModal().catch((error) => {
        console.error(error);
        showToast(error?.message || "Failed to save scanner settings.", "error");
      });
    });
  }
  if (els.scannerAddCustomRule) {
    els.scannerAddCustomRule.addEventListener("click", () => {
      const rules = collectCustomRulesFromEditor();
      rules.push({
        id: `custom_${Date.now()}`,
        enabled: true,
        name: "",
        target: "response_body",
        header_name: "",
        pattern: "",
        severity: "medium",
        category: "custom",
        description: "",
      });
      renderCustomRulesEditor(rules);
    });
  }
  if (els.scannerSettingsBackdrop) {
    els.scannerSettingsBackdrop.addEventListener("click", (e) => {
      if (e.target === els.scannerSettingsBackdrop) closeScannerSettings();
    });
  }

  initFindingsResizer();
  applyFindingsColumnWidths();
  bindFindingsColumnResizers();
}

function applyFindingsColumnWidths() {
  const table = document.getElementById("findingsTable");
  if (!table) return;
  let total = 0;
  for (const [key, w] of Object.entries(findingsColWidths)) {
    table.style.setProperty(`--fc-${key}`, `${w}px`);
    total += w;
  }
  table.style.setProperty("--findings-table-width", `${Math.max(total, 800)}px`);
}

function bindFindingsColumnResizers() {
  document.querySelectorAll(".findings-col-resize").forEach((handle) => {
    handle.addEventListener("mousedown", (event) => {
      const key = handle.dataset.findingsCol;
      const limits = FINDINGS_COL_RULES[key];
      if (!key || !limits) return;

      event.preventDefault();
      event.stopPropagation();

      const header = handle.closest("th");
      const startWidth = header?.getBoundingClientRect().width ?? limits.default;
      document.body.classList.add("pane-resizing-x");
      handle.classList.add("active");

      const onMove = (moveEvent) => {
        const delta = moveEvent.clientX - event.clientX;
        findingsColWidths[key] = Math.max(limits.min, Math.min(Math.round(startWidth + delta), limits.max));
        applyFindingsColumnWidths();
      };

      const onUp = () => {
        document.body.classList.remove("pane-resizing-x");
        handle.classList.remove("active");
        document.removeEventListener("mousemove", onMove);
        document.removeEventListener("mouseup", onUp);
      };

      document.addEventListener("mousemove", onMove);
      document.addEventListener("mouseup", onUp);
    });
  });
}

function initFindingsResizer() {
  const resizer = els.findingsDetailResizer;
  if (!resizer) return;

  resizer.addEventListener("mousedown", (event) => {
    if (!els.findingsPanel || !els.findingsDetailPanel || resizer.classList.contains("hidden")) {
      return;
    }

    event.preventDefault();
    const tableShell = els.findingsPanel.querySelector(".history-table-shell");
    const start = {
      table: tableShell.getBoundingClientRect().height,
      detail: els.findingsDetailPanel.getBoundingClientRect().height,
    };
    const combinedHeight = start.table + start.detail;

    document.body.classList.add("pane-resizing-y");
    resizer.classList.add("active");

    const onMove = (moveEvent) => {
      const delta = moveEvent.clientY - event.clientY;
      const nextDetail = Math.max(120, Math.min(start.detail - delta, combinedHeight - 60));
      const nextTable = combinedHeight - nextDetail;
      tableShell.style.flex = "0 0 " + Math.round(nextTable) + "px";
      els.findingsDetailPanel.style.flex = "0 0 " + Math.round(nextDetail) + "px";
    };

    const onUp = () => {
      document.body.classList.remove("pane-resizing-y");
      resizer.classList.remove("active");
      document.removeEventListener("mousemove", onMove);
      document.removeEventListener("mouseup", onUp);
    };

    document.addEventListener("mousemove", onMove);
    document.addEventListener("mouseup", onUp);
  });
}

function renderProxyPanels() {
  proxyTabs.forEach((tab) => {
    tab.classList.toggle("active", tab.dataset.proxyTab === state.activeProxyTab);
  });

  const showHistory = state.activeProxyTab === "http-history";
  const showIntercept = state.activeProxyTab === "intercept";
  const showWebsockets = state.activeProxyTab === "websockets-history";
  const showMatchReplace = state.activeProxyTab === "replace";
  const showFindings = state.activeProxyTab === "findings";
  const showOast = state.activeProxyTab === "oast";
  const showProxySettings = state.activeProxyTab === "proxy-settings";
  const showPlaceholder = !showHistory && !showIntercept && !showWebsockets && !showMatchReplace && !showFindings && !showOast && !showProxySettings;

  els.colorTagFilter.classList.toggle("hidden", !showHistory);
  els.filterBar.classList.toggle("hidden", !showHistory);
  els.trafficRegion.classList.toggle("hidden", !showHistory);
  els.historyWorkbenchResizer.classList.toggle("hidden", !showHistory);
  els.lowerWorkbench.classList.toggle("hidden", !showHistory);
  els.interceptPanel.classList.toggle("hidden", !showIntercept);
  els.websocketPanel.classList.toggle("hidden", !showWebsockets);
  els.matchReplacePanel.classList.toggle("hidden", !showMatchReplace);
  els.findingsPanel.classList.toggle("hidden", !showFindings);
  if (els.oastPanel) els.oastPanel.classList.toggle("hidden", state.activeProxyTab !== "oast");
  els.proxySettingsPanel.classList.toggle("hidden", !showProxySettings);
  els.proxySubPlaceholder.classList.toggle("hidden", !showPlaceholder);

  if (showHistory) {
    els.footerMode.textContent = "HTTP active";
    return;
  }

  if (showIntercept) {
    els.footerMode.textContent = "Intercept active";
    return;
  }

  if (showWebsockets) {
    els.footerMode.textContent = "Web Socket active";
    return;
  }

  if (showMatchReplace) {
    renderMatchReplaceRules();
    els.footerMode.textContent = "Replace active";
    return;
  }

  if (showFindings) {
    loadFindings();
    els.footerMode.textContent = "Findings active";
    return;
  }

  if (showProxySettings) {
    els.footerMode.textContent = "Settings active";
    return;
  }

  const label = humanizeProxyTab(state.activeProxyTab);
  els.proxySubPath.textContent = `Proxy / ${label}`;
  els.proxySubTitle.textContent = `${label} is planned next`;
  els.proxySubDescription.textContent = `${label} will plug into the same capture store and message workbench.`;
  els.footerMode.textContent = `${label} placeholder active`;
}

function renderInspectorPanels() {
  if (!els.lowerWorkbench) {
    return;
  }
  els.lowerWorkbench.classList.toggle("inspector-collapsed", state.inspectorCollapsed);
}

function renderInterceptStatus() {
  const enabled = Boolean(state.runtime?.intercept_enabled);
  els.interceptStatus.textContent = enabled ? "On" : "Off";
  els.interceptStatus.classList.toggle("online", enabled);
}

function updateProxyStatusIndicator(online) {
  if (!els.proxyStatusIndicator) return;
  const isOnline = Boolean(online);
  els.proxyStatusIndicator.classList.toggle("online", isOnline);
  els.proxyStatusIndicator.classList.toggle("offline", !isOnline);
  els.proxyStatusLabel.textContent = isOnline ? "Proxy" : "Offline";
  els.proxyStatusIndicator.title = isOnline
    ? `Proxy listening on ${state.settings?.proxy_addr || "..."}`
    : `Proxy failed to bind on ${state.settings?.proxy_addr || "..."}. Restart the app after freeing the port.`;
}

function renderHistory() {
  const visibleEntries = getVisibleEntries();
  const hiddenConnectCount = countHiddenConnectItems();
  const paging = state.historyPaging || createHistoryPagingState();
  const hiddenConnectExact = isKnownCount(paging.hiddenConnectTotal);
  const summary = [];
  const totalCount = visibleEntries.length;
  summary.push(`${totalCount} loaded item(s) visible`);
  if (hiddenConnectCount) summary.push(`${hiddenConnectCount}${hiddenConnectExact || paging.fullyLoaded ? "" : " loaded"} CONNECT tunnel(s) hidden`);
  if (isKnownCount(paging.filteredTotal)) {
    summary.push(`${state.items.length}/${paging.filteredTotal} server-matched summaries loaded`);
  }
  if (paging.total && (!isKnownCount(paging.filteredTotal) || paging.total !== paging.filteredTotal)) {
    summary.push(`${paging.total} total captured`);
  }
  if (!paging.fullyLoaded) {
    summary.push(paging.loading ? "loading older history" : "scroll for older history");
  }
  if (state.query) summary.push(`search: "${state.query}"`);
  if (state.method) summary.push(`method: ${state.method}`);
  if (state.filterSettings.inScopeOnly) summary.push("scope only");
  if (state.filterSettings.hideWithoutResponses) summary.push("responses only");
  if (state.filterSettings.onlyParameterized) summary.push("parameterized only");
  if (state.filterSettings.onlyNotes) summary.push("notes only");
  if (state.filterSettings.searchTerm) summary.push(`advanced: ${state.filterSettings.searchTerm}`);
  if (state.filterSettings.colorTags?.size) summary.push(`color: ${[...state.filterSettings.colorTags].join(", ")}`);
  summary.push(`sort: ${humanizeSortKey(state.sortKey)} ${state.sortDirection}`);
  els.historyMeta.textContent = `Filter settings: ${summary.join(" | ")}`;
  renderSortHeaders();

  // Store entries for virtual scroll
  state._historyEntries = visibleEntries;

  if (!visibleEntries.length) {
    els.historyTableBody.innerHTML = `
      <tr class="empty-row">
        <td colspan="${state.historyColumnOrder.length}">${historyEmptyMessage(hiddenConnectCount, paging)}</td>
      </tr>
    `;
    if (paging.hasMore && !paging.loading && !paging.fullyLoaded) {
      scheduleHistoryBackfill(0);
    }
    return;
  }

  renderHistoryVirtual();
}

function renderHistoryVirtual() {
  const entries = state._historyEntries;
  if (!entries || !entries.length) return;

  const shell = els.historyTable.closest(".history-table-shell");
  if (!shell) return;

  const rowHeight = measuredHistoryRowHeight || HISTORY_ROW_HEIGHT;
  const viewportHeight = shell.clientHeight;
  const totalCount = entries.length;
  const colCount = state.historyColumnOrder.length;
  const maxScrollTop = Math.max(0, totalCount * rowHeight - viewportHeight);
  const scrollTop = Math.min(shell.scrollTop, maxScrollTop);
  if (shell.scrollTop !== scrollTop) {
    shell.scrollTop = scrollTop;
  }

  const startIdx = Math.max(0, Math.floor(scrollTop / rowHeight) - HISTORY_BUFFER_ROWS);
  const endIdx = Math.min(totalCount, Math.ceil((scrollTop + viewportHeight) / rowHeight) + HISTORY_BUFFER_ROWS);
  if (totalCount - endIdx <= HTTP_HISTORY_SCROLL_PREFETCH_ROWS) {
    scheduleHistoryBackfill(0);
  }

  const topPadding = startIdx * rowHeight;
  const bottomPadding = Math.max(0, (totalCount - endIdx) * rowHeight);

  const rows = [];
  for (let i = startIdx; i < endIdx; i++) {
    const entry = entries[i];
    const item = entry.item;
    const selected = item.id === state.selectedId ? "selected" : "";
    const tagClass = item.color_tag ? ` tagged-${escapeHtml(item.color_tag)}` : "";
    const cells = state.historyColumnOrder.map((colKey) => renderHistoryCell(colKey, item, entry)).join("");
    rows.push(`<tr class="history-row ${selected}${tagClass}" data-id="${item.id}">${cells}</tr>`);
  }

  els.historyTableBody.innerHTML =
    (topPadding > 0 ? `<tr class="virtual-spacer"><td colspan="${colCount}" style="height:${topPadding}px;padding:0;border:none"></td></tr>` : "") +
    rows.join("") +
    (bottomPadding > 0 ? `<tr class="virtual-spacer"><td colspan="${colCount}" style="height:${bottomPadding}px;padding:0;border:none"></td></tr>` : "");

  const measuredRow = els.historyTableBody.querySelector(".history-row");
  const measured = measuredRow?.getBoundingClientRect().height || 0;
  if (measured > 0 && Math.abs(measured - rowHeight) >= 1) {
    measuredHistoryRowHeight = measured;
    renderHistoryVirtual();
  }
}

function historyEmptyMessage(hiddenConnectCount, paging) {
  if (hiddenConnectCount) {
    return "Only CONNECT tunnels were captured, and they are hidden from HTTP history. Trust the Sniper Root CA and retry the HTTPS client if you expect decrypted traffic.";
  }
  if (!paging.fullyLoaded) {
    return paging.loading
      ? "No loaded traffic matches yet. Older history is still loading."
      : "No loaded traffic matches yet. Older history will load as needed.";
  }
  return "No traffic matches the current filter settings.";
}

function updateHistorySelection(newId) {
  const prev = els.historyTableBody.querySelector(".history-row.selected");
  if (prev) prev.classList.remove("selected");
  if (newId) {
    const next = els.historyTableBody.querySelector(`.history-row[data-id="${newId}"]`);
    if (next) {
      next.classList.add("selected");
    } else {
      // Row not in DOM (outside virtual scroll window) — scroll to it
      scrollHistoryToId(newId);
    }
  }
}

function scrollHistoryToId(targetId) {
  const entries = state._historyEntries;
  if (!entries) return;
  const idx = entries.findIndex((e) => e.item.id === targetId);
  if (idx === -1) return;

  const shell = els.historyTable.closest(".history-table-shell");
  if (!shell) return;

  // Scroll so that target row is near center of viewport
  const targetTop = idx * (measuredHistoryRowHeight || HISTORY_ROW_HEIGHT);
  shell.scrollTop = Math.max(0, targetTop - shell.clientHeight / 2);
  // renderHistoryVirtual will be called by scroll event
}

async function moveHistorySelection(offset) {
  const visibleEntries = getVisibleEntries();
  if (!visibleEntries.length) {
    return;
  }

  const currentIndex = visibleEntries.findIndex((entry) => entry.item.id === state.selectedId);
  const fallbackIndex = offset > 0 ? 0 : visibleEntries.length - 1;
  const nextIndex = clamp(
    currentIndex === -1 ? fallbackIndex : currentIndex + offset,
    0,
    visibleEntries.length - 1,
  );
  const nextId = visibleEntries[nextIndex]?.item.id;
  if (!nextId) {
    return;
  }

  state.selectedId = nextId;
  updateHistorySelection(nextId);
  scrollSelectedHistoryRowIntoView();
  await loadTransactionDetail(nextId);
}

function scrollSelectedHistoryRowIntoView() {
  const selectedRow = els.historyTableBody.querySelector(".history-row.selected");
  if (selectedRow) {
    selectedRow.scrollIntoView({ block: "nearest" });
    return;
  }
  // Row not in DOM — use virtual scroll position
  if (!state.selectedId || !state._historyEntries) return;
  const idx = state._historyEntries.findIndex((e) => e.item.id === state.selectedId);
  if (idx === -1) return;
  const shell = els.historyTable.closest(".history-table-shell");
  if (!shell) return;
  const rowHeight = measuredHistoryRowHeight || HISTORY_ROW_HEIGHT;
  const rowTop = idx * rowHeight;
  const rowBottom = rowTop + rowHeight;
  const viewTop = shell.scrollTop;
  const viewBottom = viewTop + shell.clientHeight;
  if (rowTop < viewTop) {
    shell.scrollTop = rowTop;
  } else if (rowBottom > viewBottom) {
    shell.scrollTop = rowBottom - shell.clientHeight;
  }
}

async function moveWebsocketSelection(offset) {
  const sortedEntries = getSortedWebsocketEntries();
  if (!sortedEntries.length) return;

  const currentIndex = sortedEntries.findIndex(({ session }) => session.id === state.selectedWebsocketId);
  const fallbackIndex = offset > 0 ? 0 : sortedEntries.length - 1;
  const nextIndex = clamp(
    currentIndex === -1 ? fallbackIndex : currentIndex + offset,
    0,
    sortedEntries.length - 1,
  );
  const nextId = sortedEntries[nextIndex]?.session?.id;
  if (!nextId) return;

  if (state.selectedWebsocketId !== nextId) {
    state.selectedFrameIdx = null;
    hideFrameDetail();
  }
  state.selectedWebsocketId = nextId;
  renderWebsocketSessions();
  scrollSelectedWebsocketRowIntoView();
  await loadWebsocketDetail(nextId);
}

function scrollSelectedWebsocketRowIntoView() {
  const selectedRow = els.websocketTableBody.querySelector(".history-row.selected");
  selectedRow?.scrollIntoView({ block: "nearest" });
}

function moveFrameSelection(offset) {
  const session = state.selectedWebsocketRecord;
  const frames = getWebsocketFrames(session);
  if (!frames.length) return;

  const current = state.selectedFrameIdx;
  const currentPosition = current == null
    ? -1
    : frames.findIndex((frame) => frame.index === current);
  const fallback = offset > 0 ? 0 : frames.length - 1;
  const nextPosition = clamp(
    currentPosition === -1 ? fallback : currentPosition + offset,
    0,
    frames.length - 1,
  );

  const frame = frames[nextPosition];
  if (!frame) return;
  state.selectedFrameIdx = frame.index;

  // Update selection highlight — find by data attribute, not DOM index
  els.websocketFramesBody.querySelectorAll(".frame-selected").forEach((r) => r.classList.remove("frame-selected"));
  const target = els.websocketFramesBody.querySelector(`.history-row[data-frame-index="${frame.index}"]`);
  if (target) {
    target.classList.add("frame-selected");
    target.scrollIntoView({ block: "nearest" });
  }

  showFrameDetail(frame);
}

function isEditableTarget(target) {
  if (!(target instanceof HTMLElement)) {
    return false;
  }

  // Truly editable elements (replay editor, ws message editor) block table nav.
  // Readonly code-view panels with data-readonly-editable also block table nav
  // when they have focus — arrow keys should navigate lines, not history rows.
  if (target.isContentEditable) {
    return true;
  }

  const tagName = target.tagName.toLowerCase();
  if (["input", "textarea", "select", "option", "button"].includes(tagName)) {
    return true;
  }

  const editableParent = target.closest("input, textarea, select, [contenteditable='true']");
  if (editableParent) {
    return true;
  }

  return false;
}

function isSelectableTextTarget(target) {
  if (!(target instanceof HTMLElement)) {
    return false;
  }

  if (target.isContentEditable) {
    return true;
  }

  const direct =
    target instanceof HTMLTextAreaElement
    || (
      target instanceof HTMLInputElement
      && ["text", "search", "password", "url", "email", "tel", "number", ""].includes(
        (target.type || "").toLowerCase(),
      )
    );

  if (direct) {
    return true;
  }

  return Boolean(
    target.closest(
      "textarea, input[type='text'], input[type='search'], input[type='password'], input[type='url'], input[type='email'], input[type='tel'], input[type='number'], input:not([type]), [contenteditable='true']",
    ),
  );
}

function selectEditableTargetContents(target) {
  if (!(target instanceof HTMLElement)) {
    return;
  }

  const element =
    target.closest(
      "textarea, input[type='text'], input[type='search'], input[type='password'], input[type='url'], input[type='email'], input[type='tel'], input[type='number'], input:not([type]), [contenteditable='true']",
    ) || target;

  if (element instanceof HTMLTextAreaElement || element instanceof HTMLInputElement) {
    element.focus();
    element.select();
    return;
  }

  if (element instanceof HTMLElement && element.isContentEditable) {
    const selection = window.getSelection();
    if (!selection) {
      return;
    }
    const range = document.createRange();
    range.selectNodeContents(element);
    selection.removeAllRanges();
    selection.addRange(range);
  }
}

function getActiveMessagePane() {
  if (document.activeElement === els.requestView) {
    return "request";
  }

  if (document.activeElement === els.responseView) {
    return "response";
  }

  if (document.activeElement instanceof Node) {
    if (els.requestViewCM?.contains(document.activeElement)) {
      return "request";
    }

    if (els.responseViewCM?.contains(document.activeElement)) {
      return "response";
    }
  }

  const selection = window.getSelection();
  const anchorNode = selection?.anchorNode;
  if (anchorNode instanceof Node) {
    if (els.requestView?.contains(anchorNode)) {
      return "request";
    }

    if (els.responseView?.contains(anchorNode)) {
      return "response";
    }

    if (els.requestViewCM?.contains(anchorNode)) {
      return "request";
    }

    if (els.responseViewCM?.contains(anchorNode)) {
      return "response";
    }
  }

  return state.activeMessagePane;
}

function getSelectedCodePaneText() {
  const activePane = getActiveMessagePane();
  if (activePane === "request" || activePane === "response") {
    const activeCMText = getSelectedCMText(activePane);
    if (activeCMText) return activeCMText;
  }

  const cmSelections = ["request", "response"]
    .filter((pane) => pane !== activePane)
    .map((pane) => getSelectedCMText(pane))
    .filter(Boolean);
  if (cmSelections.length === 1) return cmSelections[0];

  const selection = window.getSelection();
  if (!selection || selection.isCollapsed || !selection.toString()) {
    return "";
  }

  if (!selection.rangeCount) {
    return "";
  }

  const range = selection.getRangeAt(0);
  const container = range.commonAncestorContainer;
  if (
    els.requestView?.contains(container)
    || els.responseView?.contains(container)
    || els.requestViewCM?.contains(container)
    || els.responseViewCM?.contains(container)
  ) {
    return selection.toString();
  }

  const anchorNode = selection.anchorNode;
  const focusNode = selection.focusNode;
  if (
    (anchorNode instanceof Node && (els.requestView?.contains(anchorNode) || els.responseView?.contains(anchorNode)))
    || (focusNode instanceof Node && (els.requestView?.contains(focusNode) || els.responseView?.contains(focusNode)))
    || (anchorNode instanceof Node && (els.requestViewCM?.contains(anchorNode) || els.responseViewCM?.contains(anchorNode)))
    || (focusNode instanceof Node && (els.requestViewCM?.contains(focusNode) || els.responseViewCM?.contains(focusNode)))
  ) {
    return selection.toString();
  }

  return "";
}

function getSelectedCMText(targetPane) {
  const codeView = getCMView(targetPane);
  const view = codeView?.view;
  if (!view) return "";
  const ranges = view.state.selection.ranges
    .filter((range) => !range.empty)
    .map((range) => view.state.sliceDoc(range.from, range.to));
  return ranges.join("\n");
}

async function copyTextToClipboard(text) {
  if (text == null) {
    return;
  }
  const clipboardText = String(text);

  // Try modern Clipboard API first, fall back to textarea+execCommand
  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(clipboardText);
      return;
    } catch (_) {
      // Clipboard API rejected (common in WKWebView) — fall through to fallback
    }
  }

  const textarea = document.createElement("textarea");
  textarea.value = clipboardText;
  textarea.setAttribute("readonly", "true");
  textarea.style.position = "fixed";
  textarea.style.opacity = "0";
  textarea.style.pointerEvents = "none";
  document.body.appendChild(textarea);
  textarea.select();
  const copied = document.execCommand("copy");
  textarea.remove();
  if (!copied) {
    throw new Error("Clipboard copy failed");
  }
}

function selectCodePaneContents(targetPane) {
  const codeView = getCMView(targetPane);
  const cmView = codeView?.view;
  if (cmView) {
    cmView.focus();
    cmView.dispatch({
      selection: { anchor: 0, head: cmView.state.doc.length },
      scrollIntoView: true,
    });
    return;
  }

  const viewElement = targetPane === "response" ? els.responseView : els.requestView;
  if (!viewElement) {
    return;
  }

  viewElement.focus({ preventScroll: true });
  const range = document.createRange();
  range.selectNodeContents(viewElement);

  const selection = window.getSelection();
  selection?.removeAllRanges();
  selection?.addRange(range);
}

function renderDetail(record, options = {}) {
  if (!els.detailTitle) return;
  if (!options.preserveOriginalToggles) {
    state.showOriginal.request = false;
    state.showOriginal.response = false;
  }
  els.detailTitle.textContent = "Inspector";
  els.detailTags.innerHTML = "";

  const protocolState = inferProtocolState(record);
  const request = record.request || {};
  const response = record.response || null;
  const requestHeaders = normalizedHeaders(request.headers);
  const responseHeaders = normalizedHeaders(response?.headers);
  const notes = Array.isArray(record.notes) ? record.notes : [];

  const attributes = [
    { label: "Method", value: record.method },
    { label: "Path", value: record.path || "/" },
    ["Started", formatTimestamp(record.started_at)],
    ["Duration", `${record.duration_ms} ms`],
    ["Host", record.host],
    ["Request size", formatSize(request.body_size)],
    ["Response size", formatSize(response?.body_size ?? 0)],
    ["MIME type", response?.content_type || request.content_type || "n/a"],
    ["Notes", `${notes.length}`],
    ...(record.color_tag ? [["Color tag", record.color_tag]] : []),
    ...(record.user_note ? [["User note", record.user_note]] : []),
  ];

  els.attributesCount.textContent = String(attributes.length);
  els.protocolStrip.innerHTML = renderProtocolStrip(protocolState);
  els.summaryList.innerHTML = renderSummaryRows(attributes);

  els.requestHeaderCount.textContent = String(requestHeaders.length);
  els.responseHeaderCount.textContent = String(responseHeaders.length);
  els.requestHeadersBody.innerHTML = renderHeaderList(requestHeaders);
  els.responseHeadersBody.innerHTML = response
    ? renderHeaderList(responseHeaders)
    : "<p class=\"empty-copy\">No response headers were captured.</p>";

  const noteParts = [];
  if (record.user_note) {
    noteParts.push(`<p class="user-note-display"><strong>Note:</strong> ${escapeHtml(record.user_note)}</p>`);
  }
  if (notes.length) {
    noteParts.push(...notes.map((note) => `<p>${escapeHtml(note)}</p>`));
  }
  els.notesCard.innerHTML = noteParts.length
    ? noteParts.join("")
    : "<p>No anomalies were recorded for this transaction.</p>";

  renderViewTabs();
  renderMessagePanes();
}

function renderEmptyDetail() {
  state.selectedRecord = null;
  els.detailTitle.textContent = "Inspector";
  els.detailTags.innerHTML = "";
  els.protocolStrip.innerHTML = renderProtocolStrip({ current: "HTTP/1", supportsHttp2: false });
  els.attributesCount.textContent = "0";
  els.requestHeaderCount.textContent = "0";
  els.responseHeaderCount.textContent = "0";
  els.summaryList.innerHTML = renderSummaryRows([
    { label: "Status", value: "Select a transaction to inspect it." },
  ]);
  els.requestHeadersBody.innerHTML = "<p class=\"empty-copy\">Select a transaction from HTTP.</p>";
  els.responseHeadersBody.innerHTML = "<p class=\"empty-copy\">No response selected.</p>";
  els.notesCard.innerHTML = "<p>No anomalies were recorded for this transaction.</p>";
  renderViewTabs();
  renderMessagePanes();
}

function renderMessagePanes() {
  const record = state.selectedRecord;
  const requestRecord = record && state.showOriginal.request && record.original_request
    ? { ...record, request: record.original_request }
    : record;
  const responseRecord = record && state.showOriginal.response && record.original_response
    ? { ...record, response: record.original_response }
    : record;
  const requestText = requestRecord
    ? buildMessagePresentation("request", requestRecord)
    : "Select a transaction from HTTP.";
  const responseText = responseRecord
    ? buildMessagePresentation("response", responseRecord)
    : "No response selected.";

  const reqMode = state.messageViews.request;
  const resMode = state.messageViews.response;
  // Map view mode to CM highlight mode: pretty/raw → http, hex → hex, diff → diff
  const cmMode = (m) => (m === "hex" ? "hex" : m === "diff" ? "diff" : "http");
  const requestPane = els.requestViewCM
    ? updateCodePaneCM("request", els.requestViewCM, requestText, { mode: cmMode(reqMode), search: state.messageSearch.request })
    : (els.requestView && els.requestLines ? updateCodePane(els.requestView, els.requestLines, requestText, reqMode, "request") : null);
  const responsePane = els.responseViewCM
    ? updateCodePaneCM("response", els.responseViewCM, responseText, { mode: cmMode(resMode), search: state.messageSearch.response })
    : (els.responseView && els.responseLines ? updateCodePane(els.responseView, els.responseLines, responseText, resMode, "response") : null);
  if (els.requestSearchInput.value !== state.messageSearch.request) {
    els.requestSearchInput.value = state.messageSearch.request;
  }
  if (els.responseSearchInput.value !== state.messageSearch.response) {
    els.responseSearchInput.value = state.messageSearch.response;
  }
  els.requestSearchMeta.innerHTML = requestPane
    ? buildSearchMeta(requestPane.lineCount, state.messageViews.request, requestPane.matchCount)
    : buildSearchMeta(0, state.messageViews.request, 0);
  els.responseSearchMeta.innerHTML = responsePane
    ? buildSearchMeta(responsePane.lineCount, state.messageViews.response, responsePane.matchCount)
    : buildSearchMeta(0, state.messageViews.response, 0);
}

function updateMessagePaneSearch(target) {
  const query = state.messageSearch[target] || "";
  const mode = state.messageViews[target];
  const meta = target === "response" ? els.responseSearchMeta : els.requestSearchMeta;
  const cmView = getCMView(target);
  if (cmView) {
    const result = cmView.applySearch(query);
    if (meta) {
      meta.innerHTML = buildSearchMeta(cmView.view.state.doc.lines, mode, result.matchCount);
    }
    return;
  }

  const viewElement = target === "response" ? els.responseView : els.requestView;
  if (!viewElement) {
    if (meta) meta.innerHTML = buildSearchMeta(0, mode, 0);
    return;
  }
  const result = applyCodeSearch(viewElement, query);
  if (meta) {
    meta.innerHTML = buildSearchMeta(countLines(viewElement.textContent || ""), mode, result.count);
  }
}

function renderViewTabs() {
  const record = state.selectedRecord;
  const hasRequestDiff = Boolean(record?.original_request);
  const hasResponseDiff = Boolean(record?.original_response);
  viewTabs.forEach((tab) => {
    const target = tab.dataset.target;
    tab.classList.toggle("active", state.messageViews[target] === tab.dataset.view);
  });
  els.requestMrToggle.classList.toggle("hidden", !hasRequestDiff);
  els.responseMrToggle.classList.toggle("hidden", !hasResponseDiff);
  // sync active states on mr-toggle buttons
  document.querySelectorAll(".mr-btn").forEach((btn) => {
    const target = btn.dataset.target;
    const showOriginal = state.showOriginal?.[target] || false;
    const isOriginal = btn.dataset.mr === "original";
    btn.classList.toggle("active", isOriginal === showOriginal);
  });
  // reset showOriginal when no diff
  if (!hasRequestDiff && state.showOriginal) state.showOriginal.request = false;
  if (!hasResponseDiff && state.showOriginal) state.showOriginal.response = false;
}

function getVisibleRequestInterceptSummaries() {
  return state.interceptInScopeOnly
    ? state.intercepts.filter((item) => isInScopeHost(item.host))
    : state.intercepts;
}

function getVisibleResponseInterceptSummaries() {
  return state.interceptInScopeOnly
    ? state.responseIntercepts.filter((item) => isInScopeHost(item.host))
    : state.responseIntercepts;
}

function reconcileRequestInterceptSelection(visibleIntercepts = getVisibleRequestInterceptSummaries()) {
  const selectedIsVisible = visibleIntercepts.some((item) => item.id === state.selectedInterceptId);
  if (!selectedIsVisible) {
    state.selectedInterceptId = visibleIntercepts[0]?.id ?? null;
    state.selectedInterceptRecord = null;
    state.interceptEditorSeedId = null;
    return;
  }
  if (state.selectedInterceptRecord && state.selectedInterceptRecord.id !== state.selectedInterceptId) {
    state.selectedInterceptRecord = null;
    state.interceptEditorSeedId = null;
  }
}

function reconcileResponseInterceptSelection(visibleIntercepts = getVisibleResponseInterceptSummaries()) {
  const selectedIsVisible = visibleIntercepts.some((item) => item.id === state.selectedResponseInterceptId);
  if (!selectedIsVisible) {
    state.selectedResponseInterceptId = visibleIntercepts[0]?.id ?? null;
    state.selectedResponseInterceptRecord = null;
    state.responseInterceptEditorSeedId = null;
    return;
  }
  if (state.selectedResponseInterceptRecord && state.selectedResponseInterceptRecord.id !== state.selectedResponseInterceptId) {
    state.selectedResponseInterceptRecord = null;
    state.responseInterceptEditorSeedId = null;
  }
}

async function refreshInterceptDetailsForCurrentSelection() {
  const tasks = [];
  if (state.selectedInterceptId && (!state.selectedInterceptRecord || state.selectedInterceptRecord.id !== state.selectedInterceptId)) {
    tasks.push(loadInterceptDetail(state.selectedInterceptId));
  }
  if (state.selectedResponseInterceptId && (!state.selectedResponseInterceptRecord || state.selectedResponseInterceptRecord.id !== state.selectedResponseInterceptId)) {
    tasks.push(loadResponseInterceptDetail(state.selectedResponseInterceptId));
  }
  if (tasks.length) {
    await Promise.all(tasks);
  }
}

async function applyInterceptScopeFilterLocally() {
  reconcileRequestInterceptSelection();
  reconcileResponseInterceptSelection();
  renderIntercepts();
  renderResponseIntercepts();
  updateInterceptQueueBadges();
  await refreshInterceptDetailsForCurrentSelection();
}

function renderIntercepts() {
  const filteredIntercepts = getVisibleRequestInterceptSummaries();
  reconcileRequestInterceptSelection(filteredIntercepts);
  els.interceptTableBody.innerHTML = filteredIntercepts.length
    ? filteredIntercepts
        .map((item) => {
          const selected = item.id === state.selectedInterceptId ? "selected" : "";
          return `
            <tr class="history-row ${selected}" data-id="${item.id}">
              <td class="iq-col-method">${escapeHtml(item.method)}</td>
              <td class="iq-col-host text-truncate">${escapeHtml(item.host)}</td>
              <td class="iq-col-path text-truncate">${escapeHtml(item.path || "/")}</td>
              <td class="iq-col-time">${escapeHtml(formatTimestamp(item.started_at))}</td>
            </tr>
          `;
        })
        .join("")
    : `
        <tr class="empty-row">
          <td colspan="4">Intercept queue is empty.</td>
        </tr>
      `;

  Array.from(els.interceptTableBody.querySelectorAll(".history-row")).forEach((row) => {
    row.addEventListener("click", () => {
      state.selectedInterceptId = row.dataset.id;
      loadInterceptDetail(row.dataset.id).catch((error) => console.error(error));
    });
  });

  if (!state.selectedInterceptRecord) {
    state.interceptEditorSeedId = null;
    els.interceptDetailPath.textContent = "Intercept";
    els.interceptDetailTitle.textContent = "No request selected";
    if (els.interceptRequestCM) {
      updateCodePaneCM("interceptReq", els.interceptRequestCM, "", {
        mode: "http", readOnly: false,
        placeholder: "Intercepted request will appear here...",
      });
    } else {
      els.interceptRequestEditor.value = "";
      renderInterceptRequestHighlight("");
    }
    els.interceptMeta.textContent = state.runtime?.intercept_enabled
      ? "Intercept is on. New requests will queue here."
      : "Intercept is off. Toggle it on to pause requests before forwarding.";
    els.forwardInterceptButton.disabled = true;
    els.dropInterceptButton.disabled = true;
    return;
  }

  els.interceptDetailPath.textContent = `${state.selectedInterceptRecord.request.scheme.toUpperCase()} / ${state.selectedInterceptRecord.peer_addr}`;
  els.interceptDetailTitle.textContent = `${state.selectedInterceptRecord.request.method} ${state.selectedInterceptRecord.request.host}`;
  if (els.interceptRequestCM) {
    const cv = getCMView("interceptReq");
    const isFocused = cv && cv.view.hasFocus;
    if (state.interceptEditorSeedId !== state.selectedInterceptRecord.id || !isFocused) {
      const rawText = buildEditableRawRequest(state.selectedInterceptRecord.request);
      updateCodePaneCM("interceptReq", els.interceptRequestCM, rawText, {
        mode: "http", readOnly: false,
      });
      state.interceptEditorSeedId = state.selectedInterceptRecord.id;
    }
  } else {
    if (state.interceptEditorSeedId !== state.selectedInterceptRecord.id || document.activeElement !== els.interceptRequestEditor) {
      els.interceptRequestEditor.value = buildEditableRawRequest(state.selectedInterceptRecord.request);
      state.interceptEditorSeedId = state.selectedInterceptRecord.id;
    }
    renderInterceptRequestHighlight(els.interceptRequestEditor.value);
  }
  els.interceptMeta.textContent = [
    state.selectedInterceptRecord.is_websocket ? "WebSocket upgrade" : "HTTP request",
    `queued at ${formatTimestamp(state.selectedInterceptRecord.started_at)}`,
    state.selectedInterceptRecord.request.preview_truncated ? "captured request body is preview-truncated" : "body captured in memory",
  ].join(" · ");
  els.forwardInterceptButton.disabled = false;
  els.dropInterceptButton.disabled = false;
}

function renderWebsocketSessions() {
  const sortedEntries = getSortedWebsocketEntries();
  if (els.websocketSearchInput.value !== state.websocketQuery) {
    els.websocketSearchInput.value = state.websocketQuery;
  }
  els.websocketMeta.textContent = buildWebsocketFilterSummary(
    sortedEntries.length,
    state.websocketSessions.length,
    state.websocketPaging?.total ?? state.websocketSessions.length,
    Boolean(state.websocketPaging?.hasMore),
    state.websocketQuery,
  );

  updateWebsocketSortIndicators();

  els.websocketTableBody.innerHTML = sortedEntries.length
    ? sortedEntries
        .map(({ session, index }) => {
          const selected = session.id === state.selectedWebsocketId ? "selected" : "";
          return `
            <tr class="history-row ${selected}" data-id="${session.id}">
              <td>${index + 1}</td>
              <td>${escapeHtml(session.host)}</td>
              <td>${escapeHtml(session.path)}</td>
              <td>${escapeHtml(formatStatus(session.status))}</td>
              <td>${session.frame_count}</td>
              <td>${session.duration_ms == null ? "live" : `${session.duration_ms} ms`}</td>
              <td>${escapeHtml(formatTimestamp(session.started_at))}</td>
            </tr>
          `;
        })
        .join("")
    : `
        <tr class="empty-row">
          <td colspan="7">${
            state.websocketSessions.length
              ? "No WebSocket sessions match the current filter."
              : "No WebSocket sessions have been captured yet."
          }</td>
        </tr>
      `;

	  Array.from(els.websocketTableBody.querySelectorAll(".history-row")).forEach((row) => {
	    row.addEventListener("click", () => {
	      state.wsKeyboardFocus = "sessions";
	      if (state.selectedWebsocketId !== row.dataset.id) {
	        state.selectedFrameIdx = null;
	        state.selectedWebsocketRecord = null;
	        hideFrameDetail();
	      }
	      state.selectedWebsocketId = row.dataset.id;
	      renderWebsocketSessions();
	      loadWebsocketDetail(row.dataset.id).catch((error) => console.error(error));
	    });
	  });

  if (!state.selectedWebsocketRecord) {
    const noSessionMsg = state.websocketSessions.length && !sortedEntries.length
      ? "No WebSocket session matches the current filter."
      : "Select a WebSocket session.";
    if (els.websocketHandshakeCM) {
      updateCodePaneCM("wsHandshake", els.websocketHandshakeCM, noSessionMsg, { mode: "http" });
    } else {
      if (els.websocketRequestView) els.websocketRequestView.textContent = noSessionMsg;
      if (els.websocketResponseView) els.websocketResponseView.textContent = "No response selected.";
    }
    els.websocketFramesBody.innerHTML = `
      <tr class="empty-row">
        <td colspan="5">${
        state.websocketSessions.length && !sortedEntries.length
          ? "Clear or adjust the filter to inspect captured frames."
          : "Frame capture will appear here after a WebSocket handshake completes."
        }</td>
      </tr>
    `;
    return;
  }

  const session = state.selectedWebsocketRecord;
  const reqText = buildRawWebsocketRequest(session);
  const resText = buildRawWebsocketResponse(session);
  // Preserve current handshake tab selection (default to Request)
  const resBtn = document.getElementById("wsHandshakeResBtn");
  const showingResponse = resBtn?.classList.contains("active");
  const activeHandshakeText = showingResponse ? resText : reqText;

  // CM path
  if (els.websocketHandshakeCM) {
    updateCodePaneCM("wsHandshake", els.websocketHandshakeCM, activeHandshakeText, { mode: "http" });
    // Hide legacy views
    if (els.websocketRequestView) els.websocketRequestView.classList.add("hidden");
    if (els.websocketResponseView) els.websocketResponseView.classList.add("hidden");
    // Apply handshake search via CM
    const query = (els.wsHandshakeSearchInput?.value || "").trim();
    if (query) {
      const cv = getCMView("wsHandshake");
      if (cv) cv.applySearch(query);
    }
  } else {
    // Legacy fallback
    const savedReqFocus = window._saveCodeViewFocus?.(els.websocketRequestView);
    const savedResFocus = window._saveCodeViewFocus?.(els.websocketResponseView);
    els.websocketRequestView.innerHTML = renderHttpHtml(reqText, "request");
    els.websocketResponseView.innerHTML = renderHttpHtml(resText, "response");
    window._restoreCodeViewFocus?.(els.websocketRequestView, savedReqFocus);
    window._restoreCodeViewFocus?.(els.websocketResponseView, savedResFocus);
    els.websocketRequestView.classList.toggle("hidden", !!showingResponse);
    els.websocketResponseView.classList.toggle("hidden", !showingResponse);
    updateWsHandshakeSearch();
  }
  // Update line numbers for active handshake view
  const hsLineCount = countLines(activeHandshakeText);
  if (els.wsHandshakeLines) {
    els.wsHandshakeLines.textContent = buildLineNumbers(hsLineCount);
  }
  const frames = getWebsocketFrames(session);
  if (
    state.selectedFrameIdx != null
    && !frames.some((frame) => frame.index === state.selectedFrameIdx)
  ) {
    state.selectedFrameIdx = null;
  }
  els.websocketFramesBody.innerHTML = frames.length
    ? frames
        .map((frame, idx) => {
          const dir = frame.direction === "client_to_server" ? "\u2192" : "\u2190";
          const dirClass = frame.direction === "client_to_server" ? "dir-client" : "dir-server";
          return `
          <tr class="history-row${frame.index === state.selectedFrameIdx ? ' frame-selected' : ''}" data-frame-index="${frame.index}">
            <td class="cell-narrow">${idx + 1}</td>
            <td class="cell-narrow ${dirClass}">${dir}</td>
            <td class="cell-narrow">${frame.kind}</td>
            <td class="cell-narrow">${escapeHtml(formatSize(frame.body_size))}</td>
            <td class="cell-url">${escapeHtml(renderFramePreview(frame))}</td>
          </tr>`;
        })
        .join("")
    : `
        <tr class="empty-row">
          <td colspan="5">No frames recorded yet.</td>
        </tr>
      `;

	  // Frame click + context menu handlers
	  Array.from(els.websocketFramesBody.querySelectorAll(".history-row[data-frame-index]")).forEach((row) => {
	    const selectFrameRow = () => {
	      const frameIndex = parseInt(row.dataset.frameIndex, 10);
	      const frame = frames.find((candidate) => candidate.index === frameIndex);
	      if (!frame) return false;

	      state.selectedFrameIdx = frame.index;
	      state.wsKeyboardFocus = "frames";

      // Highlight selected row
      els.websocketFramesBody.querySelectorAll(".frame-selected").forEach((r) => r.classList.remove("frame-selected"));
      row.classList.add("frame-selected");

	      // Show detail panel
	      showFrameDetail(frame);
	      return true;
	    };
	    row.addEventListener("click", () => {
	      selectFrameRow();
	    });

	    // Right-click on frame → show context menu
	    row.addEventListener("contextmenu", (e) => {
	      e.preventDefault();
	      if (!selectFrameRow()) return;
	      openWsFrameContextMenu(e.clientX, e.clientY);
	    });
	  });
}

function buildWebsocketFilterSummary(visibleCount, loadedCount, totalCount, hasMore, query) {
  const parts = [`${visibleCount} session(s) visible`];
  const filters = [];
  if (document.getElementById("wsInScopeOnly")?.classList.contains("active")) filters.push("in scope");
  if (document.getElementById("wsHideClosed")?.classList.contains("active")) filters.push("live only");
  if (query) filters.push(query);
  if (filters.length) parts.push(`filter: ${filters.join(", ")}`);
  if (totalCount) {
    parts.push(hasMore ? `${loadedCount}/${totalCount} sessions loaded` : `${totalCount} total captured`);
  } else {
    parts.push("No sessions captured yet");
  }
  return parts.join(" · ");
}

function getVisibleWebsocketSessions() {
  const normalizedQuery = String(state.websocketQuery || "").trim().toLowerCase();
  const inScopeOnly = document.getElementById("wsInScopeOnly")?.classList.contains("active") ?? false;
  const liveOnly = document.getElementById("wsHideClosed")?.classList.contains("active") ?? false;

  return state.websocketSessions.filter((session) => {
    if (inScopeOnly && !isInScopeHost(session.host)) return false;
    if (liveOnly && session.duration_ms != null) return false;
    if (normalizedQuery) {
      const haystack = [
        session.host,
        session.path,
        formatStatus(session.status),
        String(session.frame_count),
        session.duration_ms == null ? "live" : `${session.duration_ms} ms`,
        formatTimestamp(session.started_at),
      ]
        .filter(Boolean)
        .join("\n")
        .toLowerCase();
      if (!haystack.includes(normalizedQuery)) return false;
    }
    return true;
  });
}

function getSortedWebsocketEntries() {
  const filtered = getVisibleWebsocketSessions();
  const direction = state.websocketSortDirection === "asc" ? 1 : -1;

  return filtered
    .map((session, index) => ({ session, index }))
    .sort((a, b) => {
      if (state.websocketSortKey === "index") {
        return (a.index - b.index) * direction;
      }

      const av = getWebsocketSortValue(a.session, state.websocketSortKey);
      const bv = getWebsocketSortValue(b.session, state.websocketSortKey);
      const cmp = compareSortValues(av, bv);
      return cmp !== 0 ? cmp * direction : a.index - b.index;
    });
}

function getWebsocketSortValue(session, key) {
  switch (key) {
    case "host": return String(session?.host || "").toLowerCase();
    case "path": return String(session?.path || "").toLowerCase();
    case "status": return Number.isFinite(Number(session?.status)) ? Number(session.status) : -1;
    case "frame_count": return Number.isFinite(Number(session?.frame_count)) ? Number(session.frame_count) : 0;
    case "duration_ms": return Number.isFinite(Number(session?.duration_ms)) ? Number(session.duration_ms) : Infinity;
    case "started_at": return Date.parse(session?.started_at) || 0;
    default: return "";
  }
}

function toggleWebsocketSort(key) {
  if (state.websocketSortKey === key) {
    state.websocketSortDirection = state.websocketSortDirection === "asc" ? "desc" : "asc";
  } else {
    state.websocketSortKey = key;
    state.websocketSortDirection = key === "index" ? "asc" : "desc";
  }
  renderWebsocketSessions();
}

function updateWebsocketSortIndicators() {
  document.querySelectorAll(".ws-sort").forEach((btn) => {
    const key = btn.dataset.wsSortKey;
    const active = key === state.websocketSortKey;
    const indicator = btn.querySelector(".sort-indicator");
    if (indicator) {
      indicator.textContent = active ? (state.websocketSortDirection === "asc" ? "↑" : "↓") : "↕";
    }
    btn.closest("th")?.setAttribute("aria-sort", active ? (state.websocketSortDirection === "asc" ? "ascending" : "descending") : "none");
  });
}

async function syncVisibleWebsocketSelection(preserveSelection = true) {
  const previousSelectedId = state.selectedWebsocketId;
  const visibleSessions = getVisibleWebsocketSessions();
  if (!preserveSelection || !visibleSessions.some((item) => item.id === state.selectedWebsocketId)) {
    state.selectedWebsocketId = visibleSessions[0]?.id ?? null;
  }
  if (previousSelectedId !== state.selectedWebsocketId) {
    state.selectedFrameIdx = null;
    hideFrameDetail();
  }

  if (!state.selectedWebsocketId) {
    state.selectedWebsocketRecord = null;
    renderWebsocketSessions();
    return;
  }

  if (state.selectedWebsocketRecord?.id !== state.selectedWebsocketId) {
    state.selectedWebsocketRecord = null;
  }
  const selectedSummary = visibleSessions.find((item) => item.id === state.selectedWebsocketId);
  const selectedDetailIsStale = Boolean(
    selectedSummary
    && state.selectedWebsocketRecord
    && (
      Number(state.selectedWebsocketRecord.frame_count || 0) !== Number(selectedSummary.frame_count || 0)
      || state.selectedWebsocketRecord.status !== selectedSummary.status
      || (state.selectedWebsocketRecord.closed_at || null) !== (selectedSummary.closed_at || null)
      || (state.selectedWebsocketRecord.duration_ms ?? null) !== (selectedSummary.duration_ms ?? null)
    )
  );
  renderWebsocketSessions();
  if (!state.selectedWebsocketRecord || selectedDetailIsStale) {
    await loadWebsocketDetail(state.selectedWebsocketId);
  }
}

function renderProxySettings() {
  if (!state.settings || !state.runtime) {
    // Data not ready — schedule a background load to self-heal
    if (!state._settingsLoadPending) {
      state._settingsLoadPending = true;
      loadSettings()
        .then(() => { state._settingsLoadPending = false; renderProxySettings(); })
        .catch(() => { state._settingsLoadPending = false; });
    }
    return;
  }

  const startup = state.settings.startup;
  els.proxySettingIntercept.checked = Boolean(state.runtime.intercept_enabled);
  els.proxySettingWebsocketCapture.checked = Boolean(state.runtime.websocket_capture_enabled);
  els.proxySettingUpstreamInsecure.checked = state.runtime.upstream_insecure !== false;
  els.proxySettingScopePatterns.value = (state.runtime.scope_patterns || []).join("\n");
  els.proxySettingPassthroughHosts.value = (state.runtime.passthrough_hosts || []).join("\n");
  if (startup && document.activeElement !== els.proxySettingBindHost) {
    els.proxySettingBindHost.value = startup.proxy_bind_host;
  }
  if (startup && document.activeElement !== els.proxySettingPort) {
    els.proxySettingPort.value = String(startup.proxy_port);
  }
  els.proxySettingsProxyAddr.textContent = state.settings.proxy_addr;
  els.proxySettingsNextProxyAddr.textContent = startup?.proxy_addr || state.settings.proxy_addr;
  els.proxySettingsUiAddr.textContent = state.settings.ui_addr;
  els.proxySettingsCaptureCap.textContent = `${formatSize(state.settings.body_preview_bytes)} preview / ${state.settings.max_entries} entries`;
  els.proxySettingsBootstrap.textContent = state.settings.certificate.special_host_https;
  // Auto Content-Length (local UI setting, not server-side)
  const aclEl = document.getElementById("proxySettingAutoContentLength");
  if (aclEl) aclEl.checked = localStorage.getItem("sniper_auto_content_length") !== "false";

  const oastEnabled = document.getElementById("proxySettingOastEnabled");
  const oastProvider = document.getElementById("proxySettingOastProvider");
  const oastUrl = document.getElementById("proxySettingOastServerUrl");
  const oastToken = document.getElementById("proxySettingOastToken");
  const oastInterval = document.getElementById("proxySettingOastInterval");
  const oastUrlHint = document.getElementById("oastServerUrlHint");
  const oastTokenField = document.getElementById("oastTokenField");
  const tokenConfigured = state.runtime.oast_token === OAST_TOKEN_REDACTION;
  if (oastEnabled) oastEnabled.checked = Boolean(state.runtime.oast_enabled);
  if (oastProvider && document.activeElement !== oastProvider) oastProvider.value = state.runtime.oast_provider || "custom";
  if (oastUrl && document.activeElement !== oastUrl) oastUrl.value = state.runtime.oast_server_url || "";
  if (oastToken && document.activeElement !== oastToken) {
    oastToken.value = "";
    oastToken.placeholder = tokenConfigured
      ? "Token configured; leave blank to keep it"
      : "Optional token";
  }
  if (els.proxySettingOastClearToken) {
    els.proxySettingOastClearToken.disabled = !tokenConfigured || state.oastTokenClearPending;
    els.proxySettingOastClearToken.textContent = state.oastTokenClearPending ? "Clearing" : "Clear";
  }
  if (els.proxySettingOastTokenHint) {
    els.proxySettingOastTokenHint.textContent = state.oastTokenClearPending
      ? "Token will be cleared when settings are saved."
      : tokenConfigured
        ? "Leave blank to keep the saved token, or clear it explicitly."
        : "Enter a token only if your OAST server requires one.";
  }
  if (oastInterval && document.activeElement !== oastInterval) oastInterval.value = state.runtime.oast_polling_interval_secs || 5;
  // Update UI based on provider
  const prov = oastProvider?.value || "custom";
  if (oastUrl) {
    const placeholders = { interactsh: "https://oast.fun", boast: "https://your-boast:1337", custom: "https://your-server" };
    oastUrl.placeholder = placeholders[prov] || placeholders.custom;
  }
  if (oastUrlHint) {
    const hints = {
      interactsh: "Interactsh server. Sniper auto-registers with RSA encryption and polls for callbacks.",
      boast: "BOAST server. Sniper polls the /events endpoint for callbacks.",
      custom: "Custom OAST server. Sniper polls {url}/poll for JSON callbacks.",
    };
    oastUrlHint.textContent = hints[prov] || hints.custom;
  }
  if (oastTokenField) {
    oastTokenField.style.display = prov === "boast" ? "none" : "";
  }

  els.proxySettingsDataDir.textContent = state.settings.data_dir;
  els.proxySettingsStartupPath.textContent = startup?.file_path || state.settings.data_dir;
  els.proxySettingsCertificateName.textContent = `${state.settings.certificate.common_name} · expires ${formatTimestamp(state.settings.certificate.expires_at)}`;
  els.proxySettingListenerHelp.textContent = startup
    ? startup.rebound === true
      ? `Proxy listener is now running on ${startup.active_proxy_addr}.`
      : startup.rebind_error
        ? `${startup.rebind_error} Saved ${startup.proxy_addr} for the next launch.`
        : startup.restart_required
          ? `Saved ${startup.proxy_addr} for the next launch. Restart Sniper to replace the active listener ${startup.active_proxy_addr}.`
          : `Proxy listener is running on ${startup.active_proxy_addr}.`
    : "Changes are saved for the next app start.";
}

function renderReplay() {
  const tab = ensureRepeaterTab();
  renderReplayTabs();

  const isWsTab = tab && tab.type === "websocket";

  // Toggle HTTP vs WS panels
  if (els.httpReplayToolbar) els.httpReplayToolbar.classList.toggle("hidden", isWsTab);
  if (els.httpReplayWorkbench) els.httpReplayWorkbench.classList.toggle("hidden", isWsTab);
  if (els.wsReplayPanel) els.wsReplayPanel.classList.toggle("hidden", !isWsTab);

  if (isWsTab) {
    renderWsReplay();
    return;
  }

  if (!tab) {
    if (els.replayRequestCM) {
      updateCodePaneCM("replayReq", els.replayRequestCM, "", {
        mode: "http", readOnly: false,
        placeholder: "Paste or type an HTTP request here...",
        onChange: syncReplayRequestTextFromEditor,
      });
    } else {
      if (els.replayRequestEditor) els.replayRequestEditor.value = "";
      renderReplayRequestHighlight("");
    }
    els.replayHostInput.value = "";
    els.replayPortInput.value = "";
    els.replaySchemeSelect.value = "https";
    els.replayResponseMeta.textContent = "No response yet.";
    renderReplayResponseView("Send a request from Replay to capture the response here.");
    updateReplaySearchPane("request", "");
    updateReplaySearchPane("response", "Send a request from Replay to capture the response here.");
    els.replayBackButton.disabled = true;
    els.replayForwardButton.disabled = true;
    els.replayFollowRedirectButton.classList.add("hidden");
    return;
  }

  syncReplayToolbar(tab);
  const reqMode = state.replayMessageViews.request;
  if (els.replayRequestCM) {
    // CM path for all modes
    if (reqMode === "hex") {
      // Hex mode: read-only hex dump view
      if (!tab.requestBytes) {
        tab.requestBytes = new TextEncoder().encode(tab.requestText);
        tab.requestOriginalBytes = new Uint8Array(tab.requestBytes);
      }
      const hexText = toHexDumpFromBytes(tab.requestBytes);
      updateCodePaneCM("replayReq", els.replayRequestCM, hexText, {
        mode: "hex", readOnly: true,
      });
      updateReplaySearchPane("request", hexText);
    } else {
      // Pretty/Raw mode: editable
      if (tab.requestBytes) {
        tab.requestText = new TextDecoder().decode(tab.requestBytes);
        tab.requestBytes = null;
        tab.requestOriginalBytes = null;
      }
      updateCodePaneCM("replayReq", els.replayRequestCM, tab.requestText, {
        mode: "http", readOnly: false,
        onChange: syncReplayRequestTextFromEditor,
      });
      updateReplaySearchPane("request", tab.requestText);
    }
  } else if (reqMode === "hex") {
    if (els.replayRequestHighlight) els.replayRequestHighlight.removeAttribute("contenteditable");
    if (!tab.requestBytes) {
      tab.requestBytes = new TextEncoder().encode(tab.requestText);
      tab.requestOriginalBytes = new Uint8Array(tab.requestBytes);
    }
    if (els.replayRequestHighlight) {
      els.replayRequestHighlight.innerHTML = renderEditableHexHtml(tab.requestBytes, tab.requestOriginalBytes);
      bindHexByteHandlers(els.replayRequestHighlight, tab);
    }
    updateReplaySearchPane("request", toHexDumpFromBytes(tab.requestBytes));
  } else {
    // Legacy non-CM path
    if (tab.requestBytes) {
      tab.requestText = new TextDecoder().decode(tab.requestBytes);
      if (els.replayRequestEditor) els.replayRequestEditor.value = tab.requestText;
      tab.requestBytes = null;
      tab.requestOriginalBytes = null;
    }
    if (els.replayRequestHighlight && !els.replayRequestHighlight.isContentEditable) {
      els.replayRequestHighlight.setAttribute("contenteditable", "plaintext-only");
    }
    if (els.replayRequestEditor) els.replayRequestEditor.value = tab.requestText;
    renderReplayRequestHighlight(tab.requestText);
    updateReplaySearchPane("request", tab.requestText);
  }

  if (!tab.responseRecord) {
    renderReplayEmptyResponse(tab);
    return;
  }

  // Show/hide Follow button for redirect responses
  const isRedirect = [301, 302, 303, 307, 308].includes(tab.responseRecord.status);
  const hasLocation = normalizedHeaders(tab.responseRecord.response?.headers).some((h) => headerNameEquals(h, "location"));
  els.replayFollowRedirectButton.classList.toggle("hidden", !(isRedirect && hasLocation));

  els.replayResponseMeta.textContent = [
    `${formatStatus(tab.responseRecord.status)}`,
    `${tab.responseRecord.duration_ms} ms`,
    tab.responseRecord.response?.content_type || tab.responseRecord.request.content_type || "n/a",
  ].join(" · ");

  const rawResponseText = buildRawResponse(tab.responseRecord);
  const respMode = state.replayMessageViews.response;
  let responseText;
  if (respMode === "hex") {
    responseText = toHexDump(rawResponseText);
  } else if (respMode === "pretty") {
    responseText = prettyFormat(rawResponseText, tab.responseRecord.response);
  } else {
    responseText = rawResponseText;
  }
  renderReplayResponseView(responseText);
  updateReplaySearchPane("response", responseText);
  renderReplayViewTabs();
}

function renderReplayRequestHighlight(text) {
  if (!els.replayRequestHighlight) {
    return;
  }
  const mode = state.replayMessageViews.request;
  els.replayRequestHighlight.innerHTML = renderCodeHtml(text, mode, "request");
  // Reset undo history when switching tabs
  state._replayUndoStack = [];
  state._replayRedoStack = [];
  state._replayLastSnapshot = text;
}

// Re-render syntax highlighting while preserving cursor position in the
// contenteditable replay editor.
function replayHighlightRerender(text) {
  if (!els.replayRequestHighlight) return;
  const mode = state.replayMessageViews.request;
  const saved = saveContentEditableCaret(els.replayRequestHighlight);
  els.replayRequestHighlight.innerHTML = renderCodeHtml(text, mode, "request");
  restoreContentEditableCaret(els.replayRequestHighlight, saved);
}

function saveContentEditableCaret(el) {
  const sel = window.getSelection();
  if (!sel.rangeCount || !el.contains(sel.anchorNode)) return null;
  const range = sel.getRangeAt(0);
  const pre = document.createRange();
  pre.selectNodeContents(el);
  pre.setEnd(range.startContainer, range.startOffset);
  const start = pre.toString().length;
  pre.setEnd(range.endContainer, range.endOffset);
  const end = pre.toString().length;
  return { start, end };
}

function restoreContentEditableCaret(el, pos) {
  if (!pos) return;
  const sel = window.getSelection();
  const range = document.createRange();
  const walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT);
  let offset = 0;
  let startSet = false;
  while (walker.nextNode()) {
    const node = walker.currentNode;
    if (!startSet && offset + node.length >= pos.start) {
      range.setStart(node, pos.start - offset);
      startSet = true;
    }
    if (startSet && offset + node.length >= pos.end) {
      range.setEnd(node, pos.end - offset);
      break;
    }
    offset += node.length;
  }
  if (startSet) {
    sel.removeAllRanges();
    sel.addRange(range);
  }
}

function syncReplayRequestTextFromEditor(newText) {
  const activeTab = getActiveReplayTab();
  if (!activeTab || activeTab.type === "websocket") {
    return;
  }
  activeTab.requestText = newText;
  activeTab.requestBytes = null;
  activeTab.requestOriginalBytes = null;
  syncReplayToolbar(activeTab);
  refreshReplayTabLabel(activeTab.id);
  updateReplaySearchPane("request", newText, { scrollToFirst: false });
  scheduleWorkspaceStateSave();
}

function syncReplayRequestHighlightScroll() {
  // No longer needed — the contenteditable pre scrolls natively.
}

function renderInterceptRequestHighlight(text) {
  if (!els.interceptRequestHighlight) {
    return;
  }

  els.interceptRequestHighlight.innerHTML = renderCodeHtml(text, "pretty", "request");
  syncInterceptRequestHighlightScroll();
}

function syncInterceptRequestHighlightScroll() {
  if (!els.interceptRequestHighlight || !els.interceptRequestEditor) {
    return;
  }

  els.interceptRequestHighlight.scrollTop = els.interceptRequestEditor.scrollTop;
  els.interceptRequestHighlight.scrollLeft = els.interceptRequestEditor.scrollLeft;
}

function renderInterceptResponseHighlight(text) {
  if (!els.interceptResponseHighlight || !els.interceptResponseEditor) return;
  els.interceptResponseHighlight.innerHTML = renderCodeHtml(text, "pretty", "response");
  els.interceptResponseHighlight.scrollTop = els.interceptResponseEditor.scrollTop;
  els.interceptResponseHighlight.scrollLeft = els.interceptResponseEditor.scrollLeft;
}

function renderFuzzerRequestHighlight(text) {
  if (!els.fuzzerRequestHighlight) {
    return;
  }

  let html = renderCodeHtml(text, "pretty", "request");
  // Highlight $payload$ markers
  html = html.replace(/(\$payload\$)/gi, '<span class="hl-payload-placeholder">$1</span>');
  els.fuzzerRequestHighlight.innerHTML = html;
  syncFuzzerRequestHighlightScroll();
}

function syncFuzzerRequestHighlightScroll() {
  if (!els.fuzzerRequestHighlight || !els.fuzzerRequestEditor) {
    return;
  }

  els.fuzzerRequestHighlight.scrollTop = els.fuzzerRequestEditor.scrollTop;
  els.fuzzerRequestHighlight.scrollLeft = els.fuzzerRequestEditor.scrollLeft;
}

let _replayResponseCMView = null;
let _replayResponseCMMode = null;
function renderReplayResponseView(text) {
  // Use CodeMirror if container exists
  if (els.replayResponseCM) {
    const mode = state.replayMessageViews.response;
    const cmMode = mode === "hex" ? "hex" : mode === "diff" ? "diff" : "http";
    // Recreate if mode changed
    if (_replayResponseCMView && _replayResponseCMMode !== cmMode) {
      _replayResponseCMView.destroy();
      _replayResponseCMView = null;
    }
    if (!_replayResponseCMView) {
      const opts = { readOnly: true };
      if (cmMode === "http") opts.httpHighlight = true;
      else if (cmMode === "hex") opts.hexHighlight = true;
      else if (cmMode === "diff") opts.diffHighlight = true;
      _replayResponseCMView = new SniperCodeView(els.replayResponseCM, opts);
      _replayResponseCMMode = cmMode;
    }
    _replayResponseCMView.setContent(text || "");
    // Apply search
    const query = (state.replayMessageSearch?.response || "").trim();
    _replayResponseCMView.applySearch(query);
    return;
  }
  // Fallback to legacy
  const mode = state.replayMessageViews.response;
  if (els.replayResponseView) els.replayResponseView.innerHTML = renderCodeHtml(text, mode, "response");
}

function renderReplayEmptyResponse(tab) {
  const notice = tab?.notice || "Send a request from Replay to capture the response here.";
  els.replayResponseMeta.textContent = tab?.notice || "No response yet.";
  renderReplayResponseView(notice);
  updateReplaySearchPane("response", notice);
  els.replayFollowRedirectButton.classList.add("hidden");
  renderReplayViewTabs();
}

/** Update only the response pane + meta after a send — preserves request cursor/scroll. */
function renderReplayResponseOnly(tab) {
  if (!tab.responseRecord) {
    renderReplayEmptyResponse(tab);
    return;
  }
  const isRedirect = [301, 302, 303, 307, 308].includes(tab.responseRecord.status);
  const hasLocation = normalizedHeaders(tab.responseRecord.response?.headers).some((h) => headerNameEquals(h, "location"));
  els.replayFollowRedirectButton.classList.toggle("hidden", !(isRedirect && hasLocation));
  els.replayResponseMeta.textContent = [
    `${formatStatus(tab.responseRecord.status)}`,
    `${tab.responseRecord.duration_ms} ms`,
    tab.responseRecord.response?.content_type || tab.responseRecord.request.content_type || "n/a",
  ].join(" · ");
  const rawResponseText = buildRawResponse(tab.responseRecord);
  const respMode = state.replayMessageViews.response;
  let responseText;
  if (respMode === "hex") {
    responseText = toHexDump(rawResponseText);
  } else if (respMode === "pretty") {
    responseText = prettyFormat(rawResponseText, tab.responseRecord.response);
  } else {
    responseText = rawResponseText;
  }
  renderReplayResponseView(responseText);
  updateReplaySearchPane("response", responseText);
}

function renderReplayViewTabs() {
  document.querySelectorAll(".replay-view-tab").forEach((btn) => {
    const target = btn.dataset.replayTarget;
    const view = btn.dataset.replayView;
    btn.classList.toggle("active", state.replayMessageViews[target] === view);
  });
}

function renderReplayViewContent(target) {
  const tab = getActiveReplayTab();
  if (!tab || tab.type === "websocket") return;

  if (target === "request") {
    const mode = state.replayMessageViews.request;
    if (els.replayRequestCM) {
      // CM path for all modes
      if (mode === "hex") {
        if (!tab.requestBytes) {
          tab.requestBytes = new TextEncoder().encode(tab.requestText);
          tab.requestOriginalBytes = new Uint8Array(tab.requestBytes);
        }
        const hexText = toHexDumpFromBytes(tab.requestBytes);
        updateCodePaneCM("replayReq", els.replayRequestCM, hexText, { mode: "hex", readOnly: true });
        updateReplaySearchPane("request", hexText);
      } else {
        if (tab.requestBytes) {
          tab.requestText = new TextDecoder().decode(tab.requestBytes);
          tab.requestBytes = null;
          tab.requestOriginalBytes = null;
        }
        updateCodePaneCM("replayReq", els.replayRequestCM, tab.requestText, {
          mode: "http",
          readOnly: false,
          onChange: syncReplayRequestTextFromEditor,
        });
        updateReplaySearchPane("request", tab.requestText);
      }
    } else {
      // Legacy non-CM path
      if (mode === "hex") {
        if (els.replayRequestHighlight) els.replayRequestHighlight.removeAttribute("contenteditable");
        if (!tab.requestBytes) {
          tab.requestBytes = new TextEncoder().encode(tab.requestText);
          tab.requestOriginalBytes = new Uint8Array(tab.requestBytes);
        }
        if (els.replayRequestHighlight) {
          els.replayRequestHighlight.innerHTML = renderEditableHexHtml(tab.requestBytes, tab.requestOriginalBytes);
          bindHexByteHandlers(els.replayRequestHighlight, tab);
        }
        updateReplaySearchPane("request", toHexDumpFromBytes(tab.requestBytes));
      } else {
        if (tab.requestBytes) {
          tab.requestText = new TextDecoder().decode(tab.requestBytes);
          if (els.replayRequestEditor) els.replayRequestEditor.value = tab.requestText;
          tab.requestBytes = null;
          tab.requestOriginalBytes = null;
        }
        if (els.replayRequestHighlight && !els.replayRequestHighlight.isContentEditable) {
          els.replayRequestHighlight.setAttribute("contenteditable", "plaintext-only");
        }
        renderReplayRequestHighlight(tab.requestText);
        updateReplaySearchPane("request", tab.requestText);
      }
    }
  }

  if (target === "response") {
    if (!tab.responseRecord) {
      renderReplayEmptyResponse(tab);
      return;
    }
    const mode = state.replayMessageViews.response;
    const rawText = buildRawResponse(tab.responseRecord);
    let displayText;
    if (mode === "hex") {
      displayText = toHexDump(rawText);
    } else if (mode === "pretty") {
      displayText = prettyFormat(rawText, tab.responseRecord.response);
    } else {
      displayText = rawText;
    }
    renderReplayResponseView(displayText);
    updateReplaySearchPane("response", displayText);
  }
}

function updateReplaySearchPane(target, text, options = {}) {
  const isRequest = target === "request";
  const scrollToFirst = options.scrollToFirst !== false;
  const query = state.replayMessageSearch[target];
  const input = isRequest ? els.replayRequestSearchInput : els.replayResponseSearchInput;
  const meta = isRequest ? els.replayRequestSearchMeta : els.replayResponseSearchMeta;

  if (input && input.value !== query) {
    input.value = query;
  }

  if (!meta) return;

  // CM path for request
  if (isRequest) {
    const cv = getCMView("replayReq");
    if (cv) {
      const result = cv.applySearch(query || "", { scrollToFirst });
      const mode = state.replayMessageViews[target] || "pretty";
      meta.innerHTML = buildSearchMeta(cv.view.state.doc.lines, mode, result.matchCount);
      return;
    }
  }
  // CM path for response (via existing _replayResponseCMView)
  if (!isRequest && _replayResponseCMView) {
    const result = _replayResponseCMView.applySearch(query || "", { scrollToFirst });
    const mode = state.replayMessageViews[target] || "pretty";
    meta.innerHTML = buildSearchMeta(_replayResponseCMView.view.state.doc.lines, mode, result.matchCount);
    return;
  }

  const view = isRequest ? els.replayRequestHighlight : els.replayResponseView;
  if (!view) return;

  const searchResult = applyCodeSearch(view, query);
  const mode = state.replayMessageViews[target] || "pretty";
  meta.innerHTML = buildSearchMeta(countLines(text), mode, searchResult.count);
}

function syncReplayToolbar(tab) {
  const request = deriveRepeaterRequest(tab);
  const target = getRepeaterTargetConfig(tab, request);
  if (document.activeElement !== els.replayHostInput && els.replayHostInput.value !== target.host) {
    els.replayHostInput.value = target.host;
  }
  if (document.activeElement !== els.replayPortInput && els.replayPortInput.value !== target.port) {
    els.replayPortInput.value = target.port;
  }
  if (document.activeElement !== els.replaySchemeSelect && els.replaySchemeSelect.value !== target.scheme) {
    els.replaySchemeSelect.value = target.scheme;
  }
  setReplayTargetInputValidity(validateManualRepeaterTargetInput(
    els.replayHostInput.value,
    els.replayPortInput.value,
  ));
  const versionSelect = document.getElementById("replayHttpVersionSelect");
  if (versionSelect && document.activeElement !== versionSelect) {
    versionSelect.value = normalizeReplayHttpVersion(tab.httpVersionMode || "");
  }
  els.replayBackButton.disabled = !canNavigateReplayHistory(tab, -1);
  els.replayForwardButton.disabled = !canNavigateReplayHistory(tab, 1);
  return target;
}

function normalizeReplayHttpVersion(value) {
  const normalized = String(value || "").trim().toUpperCase();
  if (normalized === "HTTP/1.0" || normalized === "1.0") return "HTTP/1.0";
  if (normalized === "HTTP/1.1" || normalized === "1.1") return "HTTP/1.1";
  if (normalized === "HTTP/2" || normalized === "HTTP/2.0" || normalized === "2" || normalized === "2.0") return "HTTP/2";
  return "";
}

function replayHttpVersionFromText(text) {
  const firstLine = (text || "").split(/\r?\n/)[0] || "";
  const match = firstLine.match(/^[A-Z]+\s+\S+\s+(HTTP\/[0-9.]+)$/i);
  return normalizeReplayHttpVersion(match ? match[1] : "");
}

function parseReplayHttpVersionToken(token) {
  if (!token) return undefined;
  const normalized = normalizeReplayHttpVersion(token);
  if (!normalized) {
    throw new Error(`Unsupported HTTP version: ${token}`);
  }
  return normalized;
}

function renderEventLog() {
  els.eventLogStatus.textContent = `${state.eventLog.length} entr${state.eventLog.length === 1 ? "y" : "ies"}`;
  els.eventLogTableBody.innerHTML = state.eventLog.length
    ? state.eventLog
        .map((entry) => `
          <tr>
            <td>${escapeHtml(formatTimestamp(entry.captured_at))}</td>
            <td>${escapeHtml(entry.level)}</td>
            <td>${escapeHtml(entry.source)}</td>
            <td>${escapeHtml(entry.title)}</td>
            <td>${escapeHtml(entry.message)}</td>
          </tr>
        `)
        .join("")
    : `
        <tr class="empty-row">
          <td colspan="5">No runtime events have been recorded yet.</td>
        </tr>
      `;
}

function renderMatchReplaceRules() {
  const selected = getSelectedMatchReplaceRule();
  els.matchReplaceTableBody.innerHTML = state.matchReplaceRules.length
    ? state.matchReplaceRules
        .map((rule) => {
          const active = rule.id === state.selectedMatchReplaceRuleId ? "selected" : "";
          return `
            <tr class="history-row ${active}" data-id="${rule.id}">
              <td><label class="mini-toggle"><input type="checkbox" data-rule-toggle="${rule.id}" ${rule.enabled ? "checked" : ""} /><span class="mini-toggle-track"></span></label></td>
              <td>${escapeHtml(rule.scope)}</td>
              <td>${escapeHtml(rule.target)}</td>
              <td class="text-truncate">${escapeHtml(rule.search || "—")}</td>
              <td class="text-truncate">${escapeHtml(rule.replace || "—")}</td>
              <td>${rule.regex ? "✓" : ""}</td>
              <td>${rule.case_sensitive ? "✓" : ""}</td>
            </tr>
          `;
        })
        .join("")
    : `
        <tr class="empty-row">
          <td colspan="7">No replace rules are configured.</td>
        </tr>
      `;

  Array.from(els.matchReplaceTableBody.querySelectorAll(".history-row")).forEach((row) => {
    row.addEventListener("click", (event) => {
      if (event.target.closest(".mini-toggle")) return;
      state.selectedMatchReplaceRuleId = row.dataset.id;
      renderMatchReplaceRules();
    });
  });

  Array.from(els.matchReplaceTableBody.querySelectorAll("[data-rule-toggle]")).forEach((toggle) => {
    toggle.addEventListener("change", (event) => {
      event.stopPropagation();
      const rule = state.matchReplaceRules.find((r) => r.id === toggle.dataset.ruleToggle);
      if (rule) {
        rule.enabled = toggle.checked;
        saveMatchReplaceRules().catch((error) => {
          console.error(error);
          showToast(error?.message || "Failed to save rule", "error");
          loadMatchReplaceRules().catch(console.error);
        });
      }
    });
  });

  if (!selected) {
    els.matchReplaceEditorPath.textContent = "Rule";
    els.matchReplaceEditorTitle.textContent = "New rule";
    els.matchReplaceScope.value = "request";
    els.matchReplaceTarget.value = "any";
    els.matchReplaceSearch.value = "";
    els.matchReplaceReplace.value = "";
    els.matchReplaceRegex.checked = false;
    els.matchReplaceCaseSensitive.checked = false;
    els.deleteMatchReplaceRuleButton.disabled = true;
    els.saveMatchReplaceRuleButton.textContent = "Save";
    return;
  }

  els.matchReplaceEditorPath.textContent = `${selected.scope} / ${selected.target}`;
  els.matchReplaceEditorTitle.textContent = selected.search ? `${selected.search} → ${selected.replace || "∅"}` : "Edit rule";
  els.matchReplaceScope.value = selected.scope;
  els.matchReplaceTarget.value = selected.target;
  els.matchReplaceSearch.value = selected.search;
  els.matchReplaceReplace.value = selected.replace;
  els.matchReplaceRegex.checked = Boolean(selected.regex);
  els.matchReplaceCaseSensitive.checked = Boolean(selected.case_sensitive);
  els.deleteMatchReplaceRuleButton.disabled = false;
  els.saveMatchReplaceRuleButton.textContent = "Save";
}

function renderTarget() {
  const sessionId = currentSessionId();
  if (!state.targetScopeDirty) {
    state.targetScopeDraft = formatScopePatternsText(state.runtime?.scope_patterns);
  }

  const editorSessionMismatch = state.targetScopeEditorSessionId !== sessionId;
  if (
    (editorSessionMismatch || document.activeElement !== els.targetScopeEditor)
    && els.targetScopeEditor.value !== state.targetScopeDraft
  ) {
    els.targetScopeEditor.value = state.targetScopeDraft;
  }
  if (editorSessionMismatch || document.activeElement !== els.targetScopeEditor) {
    state.targetScopeEditorSessionId = sessionId;
  }

  const siteMap = Array.isArray(state.targetSiteMap) ? state.targetSiteMap : [];
  const liveHosts = new Set(siteMap.map((host) => String(host.host || "")));
  state.targetExpandedHosts = new Set(
    Array.from(state.targetExpandedHosts).filter((host) => liveHosts.has(host)),
  );

  els.targetTree.innerHTML = siteMap.length
    ? siteMap
        .map((host) => {
          const hostName = String(host.host || "");
          const paths = Array.isArray(host.paths) ? host.paths : [];
          const schemes = Array.isArray(host.schemes) ? host.schemes.map(String).filter(Boolean) : [];
          const requestCount = Number.isFinite(Number(host.request_count)) ? Number(host.request_count) : 0;
          const expanded = state.targetExpandedHosts.has(hostName);
          return `
            <section class="target-host-card">
              <button
                class="target-host-toggle ${expanded ? "expanded" : ""}"
                type="button"
                data-target-host="${escapeHtml(hostName)}"
                aria-expanded="${expanded ? "true" : "false"}"
              >
                <div class="target-host-copy">
                  <div class="target-host-title">${escapeHtml(hostName)}</div>
                  <div class="target-path-meta">${requestCount} request(s) · ${paths.length} path(s) · ${escapeHtml(schemes.join(", ") || "http")}</div>
                </div>
                <div class="target-host-actions">
                  <span class="detail-chip ${host.in_scope ? "ok" : "none"}">${host.in_scope ? "In scope" : "Out of scope"}</span>
                  <span class="target-host-chevron" aria-hidden="true">▾</span>
                </div>
              </button>
              <div class="target-path-list" ${expanded ? "" : "hidden"}>
                ${paths.map((path) => {
                  const methods = Array.isArray(path.methods) ? path.methods.map(String) : [];
                  const noteCount = Number.isFinite(Number(path.note_count)) ? Number(path.note_count) : 0;
                  return `
                    <div class="target-path-item">
                      <div class="target-path-title">${escapeHtml(path.path || "/")}</div>
                      <div class="target-path-meta">
                        ${escapeHtml(methods.join(", "))} · ${escapeHtml(formatStatus(path.status))} · ${escapeHtml(formatTimestamp(path.last_seen))}${path.is_websocket ? " · websocket" : ""}${noteCount ? ` · ${noteCount} note(s)` : ""}
                      </div>
                    </div>
                  `;
                }).join("")}
              </div>
            </section>
          `;
        })
        .join("")
    : "<p class=\"empty-copy\">No captured targets yet. Send traffic through the proxy to build a site map.</p>";

  Array.from(els.targetTree.querySelectorAll(".target-host-toggle")).forEach((button) => {
    button.addEventListener("click", () => {
      const host = button.dataset.targetHost;
      if (!host) {
        return;
      }

      if (state.targetExpandedHosts.has(host)) {
        state.targetExpandedHosts.delete(host);
      } else {
        state.targetExpandedHosts.add(host);
      }

      renderTarget();
    });
  });
}

function renderFuzzer() {
  if (els.fuzzerRequestCM) {
    // CM path
    const cv = getCMView("fuzzerReq");
    if (!cv || cv.getContent() !== state.fuzzerRequestText) {
      updateCodePaneCM("fuzzerReq", els.fuzzerRequestCM, state.fuzzerRequestText, {
        mode: "http", readOnly: false,
        payloadHighlight: true,
        placeholder: "Paste an HTTP request with $payload$ markers...",
      });
      // Wire onChange to sync state
      const newCv = getCMView("fuzzerReq");
      if (newCv && !newCv._fuzzerOnChangeWired) {
        newCv._fuzzerOnChangeWired = true;
        addCMUpdateListener(newCv.view, (newText) => {
          updateFuzzerRequestText(newText, { userEdit: true });
          scheduleWorkspaceStateSave();
        });
      }
    }
  } else if (els.fuzzerRequestEditor) {
    if (els.fuzzerRequestEditor.value !== state.fuzzerRequestText) {
      els.fuzzerRequestEditor.value = state.fuzzerRequestText;
    }
    renderFuzzerRequestHighlight(state.fuzzerRequestText);
  }
  if (els.fuzzerPayloadsEditor.value !== state.fuzzerPayloadsText) {
    els.fuzzerPayloadsEditor.value = state.fuzzerPayloadsText;
  }
  if (els.startFuzzerButton) {
    els.startFuzzerButton.disabled = !!state.fuzzerRunning;
  }
  if (els.resetFuzzerButton) {
    els.resetFuzzerButton.disabled = !!state.fuzzerRunning;
  }

  const attackRecord = normalizeFuzzerAttackRecord(state.fuzzerAttackRecord);
  state.fuzzerAttackRecord = attackRecord;
  if (!attackRecord) {
    els.fuzzerMeta.textContent = state.fuzzerNotice || "No fuzz run has been started yet.";
    els.fuzzerResultsBody.innerHTML = `
      <tr class="empty-row">
        <td colspan="6">${escapeHtml(state.fuzzerNotice || "Use $payload$ markers in the request template, then click Start.")}</td>
      </tr>
    `;
    // Hide detail panel and its resizer when no attack record
    if (els.fuzzerDetailPanel) els.fuzzerDetailPanel.classList.add("hidden");
    const _dr = document.getElementById("fuzzerDetailResizer");
    if (_dr) _dr.classList.add("hidden");
    state._fuzzerDetailRecord = null;
    return;
  }

  els.fuzzerMeta.textContent = [
    `${attackRecord.payload_count ?? attackRecord.results.length} payload(s)`,
    `${attackRecord.marker_count ?? 0} marker(s)`,
    attackRecord.status || "completed",
  ].join(" · ");
  els.fuzzerResultsBody.innerHTML = attackRecord.results
    .map((result, rowIndex) => {
      const resultIndex = Number.isFinite(Number(result.index)) ? Number(result.index) : rowIndex;
      const selectionKey = result.transaction_id ? `tx:${result.transaction_id}` : `row:${rowIndex}`;
      const selectedClass = state._selectedFuzzerResultKey === selectionKey ? " fuzzer-result-selected" : "";
      return `
      <tr class="fuzzer-result-row${selectedClass}" data-transaction-id="${result.transaction_id || ""}" data-result-index="${resultIndex}" data-row-index="${rowIndex}">
        <td>${resultIndex + 1}</td>
        <td class="cell-url">${escapeHtml(result.payload)}</td>
        <td>${escapeHtml(formatStatus(result.status))}</td>
        <td>${result.duration_ms == null ? "-" : `${result.duration_ms} ms`}</td>
        <td>${escapeHtml(formatSize(result.response_bytes))}</td>
        <td>${result.transaction_id ? escapeHtml(String(result.transaction_id).slice(0, 8)) : escapeHtml(result.note || "-")}</td>
      </tr>
    `;
    })
    .join("");
}

function normalizeFuzzerAttackRecord(record) {
  if (!record || typeof record !== "object") return null;
  return {
    ...record,
    payload_count: Number.isFinite(Number(record.payload_count)) ? Number(record.payload_count) : jsonArray(record.results).length,
    marker_count: Number.isFinite(Number(record.marker_count)) ? Number(record.marker_count) : 0,
    results: jsonArray(record.results),
  };
}

// ─── Fuzzer result detail panel ────────────────────────────────────────────

let _fuzzerDetailViewModes = { request: "pretty", response: "pretty" };

/** Show request/response detail for a fuzzer result. */
async function showFuzzerResultDetail(transactionId, selectionKey = `tx:${transactionId}`) {
  if (!transactionId || !els.fuzzerDetailPanel) return;

  els.fuzzerDetailPanel.classList.remove("hidden");
  const detailResizer = document.getElementById("fuzzerDetailResizer");
  if (detailResizer) detailResizer.classList.remove("hidden");
  state._fuzzerDetailRecord = null;
  if (els.fuzzerDetailResponseMeta) els.fuzzerDetailResponseMeta.textContent = "";
  updateCodePaneCM("fuzzerDetailReq", els.fuzzerDetailReqCM, "Loading transaction...", { mode: "http" });
  updateCodePaneCM("fuzzerDetailRes", els.fuzzerDetailResCM, "", { mode: "http" });

  try {
    const sessionId = currentSessionId();
    const resp = await fetch(transactionPath(transactionId, sessionId));
    if (sessionId !== currentSessionId()) return;
    if (!resp.ok) {
      if (state._selectedFuzzerResultKey !== selectionKey) return;
      updateCodePaneCM("fuzzerDetailReq", els.fuzzerDetailReqCM, `Failed to load transaction: ${resp.status}`, { mode: "http" });
      updateCodePaneCM("fuzzerDetailRes", els.fuzzerDetailResCM, "", { mode: "http" });
      if (els.fuzzerDetailResponseMeta) els.fuzzerDetailResponseMeta.textContent = "";
      return;
    }
    const record = await resp.json();
    if (state._selectedFuzzerResultKey !== selectionKey || sessionId !== currentSessionId()) return;

    // Store for mode switching
    state._fuzzerDetailRecord = record;

    renderFuzzerDetailPanes(record);
  } catch (err) {
    if (state._selectedFuzzerResultKey !== selectionKey) return;
    updateCodePaneCM("fuzzerDetailReq", els.fuzzerDetailReqCM, `Error: ${err.message}`, { mode: "http" });
    updateCodePaneCM("fuzzerDetailRes", els.fuzzerDetailResCM, "", { mode: "http" });
    if (els.fuzzerDetailResponseMeta) els.fuzzerDetailResponseMeta.textContent = "";
  }
}

function syncFuzzerDetailTabs() {
  document.querySelectorAll(".fuzzer-detail-view-tab").forEach((btn) => {
    const target = btn.dataset.fuzzerDetailTarget;
    const view = btn.dataset.fuzzerDetailView;
    btn.classList.toggle("active", view === _fuzzerDetailViewModes[target]);
  });
}

function renderFuzzerDetailPanes(record) {
  if (!record) return;

  syncFuzzerDetailTabs();

  const reqMode = _fuzzerDetailViewModes.request;
  const resMode = _fuzzerDetailViewModes.response;

  // Request
  const rawReq = buildRawRequest(record);
  let reqText = rawReq;
  if (reqMode === "pretty") {
    const fakeMsg = { content_type: record.request?.content_type };
    reqText = prettyFormat(rawReq, fakeMsg);
  } else if (reqMode === "hex") {
    reqText = toHexDump(rawReq);
  }
  const cmReqMode = reqMode === "hex" ? "hex" : "http";
  if (els.fuzzerDetailReqCM) {
    updateCodePaneCM("fuzzerDetailReq", els.fuzzerDetailReqCM, reqText, { mode: cmReqMode });
  }

  // Response
  if (record.response) {
    const rawRes = buildRawResponse(record);
    let resText = rawRes;
    if (resMode === "pretty") {
      resText = prettyFormat(rawRes, record.response);
    } else if (resMode === "hex") {
      resText = toHexDump(rawRes);
    }
    const cmResMode = resMode === "hex" ? "hex" : "http";
    if (els.fuzzerDetailResCM) {
      updateCodePaneCM("fuzzerDetailRes", els.fuzzerDetailResCM, resText, { mode: cmResMode });
    }
    if (els.fuzzerDetailResponseMeta) {
      els.fuzzerDetailResponseMeta.textContent = `${record.status ?? ""} · ${record.response?.content_type || ""}`;
    }
  } else {
    if (els.fuzzerDetailResCM) {
      updateCodePaneCM("fuzzerDetailRes", els.fuzzerDetailResCM, "No response captured.", { mode: "http" });
    }
    if (els.fuzzerDetailResponseMeta) {
      els.fuzzerDetailResponseMeta.textContent = "";
    }
  }
}

function hideFuzzerDetailPanel() {
  if (els.fuzzerDetailPanel) els.fuzzerDetailPanel.classList.add("hidden");
  const dr = document.getElementById("fuzzerDetailResizer");
  if (dr) dr.classList.add("hidden");
  state._fuzzerDetailRecord = null;
}

function createNewMatchReplaceRule() {
  const rule = {
    id: crypto.randomUUID(),
    enabled: true,
    description: "",
    scope: "request",
    target: "any",
    search: "",
    replace: "",
    regex: false,
    case_sensitive: false,
  };
  state.matchReplaceRules = [rule, ...state.matchReplaceRules];
  state.selectedMatchReplaceRuleId = rule.id;
  renderMatchReplaceRules();
}

function getSelectedMatchReplaceRule() {
  return state.matchReplaceRules.find((rule) => rule.id === state.selectedMatchReplaceRuleId) || null;
}

function syncMatchReplaceEditor() {
  const rule = getSelectedMatchReplaceRule();
  if (!rule) {
    return;
  }

  rule.description = "";
  rule.scope = els.matchReplaceScope.value;
  rule.target = els.matchReplaceTarget.value;
  rule.search = els.matchReplaceSearch.value;
  rule.replace = els.matchReplaceReplace.value;
  rule.regex = els.matchReplaceRegex.checked;
  rule.case_sensitive = els.matchReplaceCaseSensitive.checked;
}

async function deleteSelectedMatchReplaceRule() {
  if (!state.selectedMatchReplaceRuleId) {
    return;
  }

  state.matchReplaceRules = state.matchReplaceRules.filter((rule) => rule.id !== state.selectedMatchReplaceRuleId);
  state.selectedMatchReplaceRuleId = state.matchReplaceRules[0]?.id ?? null;
  renderMatchReplaceRules();
  await saveMatchReplaceRules();
  showToast("Rule deleted");
}

async function saveTargetScope() {
  const sessionId = currentSessionId();
  if (state.targetScopeEditorSessionId && state.targetScopeEditorSessionId !== sessionId) {
    await loadTargetSiteMap(true);
    throw new Error("Scope editor changed sessions. Review the scope and save again.");
  }
  const scopePatterns = els.targetScopeEditor.value
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
  const response = await fetch("/api/runtime", {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify({
      session_id: sessionId,
      scope_patterns: scopePatterns,
      intercept_enabled: state.runtime?.intercept_enabled,
      websocket_capture_enabled: state.runtime?.websocket_capture_enabled,
    }),
  });
  if (!response.ok) {
    throw new Error(`saveTargetScope failed: ${response.status}`);
  }
  const runtime = await response.json();
  if (sessionId !== currentSessionId()) {
    return;
  }
  state.runtime = runtime;
  state.targetScopeDraft = formatScopePatternsText(state.runtime?.scope_patterns);
  state.targetScopeDirty = false;
  state.targetScopeEditorSessionId = sessionId;
  if (els.targetScopeEditor.value !== state.targetScopeDraft) {
    els.targetScopeEditor.value = state.targetScopeDraft;
  }
  renderInterceptStatus();
  renderProxySettings();
  await loadTargetSiteMap();
  invalidateVisibleEntriesCache();
  scheduleRefresh();
}

async function openFuzzerFromReplay() {
  const tab = getActiveReplayTab();
  if (!tab || tab.type === "websocket") {
    throw new Error("Select an HTTP Replay tab before sending to Fuzzer.");
  }
  const request = parseEditableRawRequest(tab.requestText, tab.baseRequest);
  const target = getRepeaterTargetConfig(tab, request);
  invalidateFuzzerRun();
  state.fuzzerBaseRequest = request;
  state.fuzzerSourceTransactionId = tab.sourceTransactionId || null;
  state.fuzzerTarget = normalizeFuzzerTargetOverride(replayTargetOverridePayload(tab, request, target));
  state.fuzzerTargetRequestText = state.fuzzerTarget ? fuzzerTargetAuthorityFromRequestText(tab.requestText) : null;
  state.fuzzerNotice = "";
  state.fuzzerRequestText = tab.requestText;
  state.fuzzerPayloadsText = "";
  state.fuzzerAttackRecord = null;
  state._selectedFuzzerResultKey = null;
  hideFuzzerDetailPanel();
  state.activeTool = "fuzzer";
  scheduleWorkspaceStateSave();
  renderToolPanels();
}

async function openFuzzerFromSelection() {
  const record = await loadSelectedTransactionRecord();

  if (!record) {
    throw new Error("Selected transaction could not be loaded.");
  }
  if (record.kind === "tunnel") {
    throw new Error("Tunnel records cannot be sent to Fuzzer.");
  }

  const request = editableRequestFromRecord(record);
  invalidateFuzzerRun();
  state.fuzzerBaseRequest = request;
  state.fuzzerSourceTransactionId = record.id;
  state.fuzzerTarget = null;
  state.fuzzerTargetRequestText = null;
  state.fuzzerNotice = isRequestPreviewTruncated(record)
    ? buildTruncatedBodyNotice(record, "Fuzzer")
    : "";
  state.fuzzerRequestText = buildEditableRawRequest(request);
  state.fuzzerPayloadsText = "";
  state.fuzzerAttackRecord = null;
  state._selectedFuzzerResultKey = null;
  hideFuzzerDetailPanel();
  state.activeTool = "fuzzer";
  scheduleWorkspaceStateSave();
  renderToolPanels();
}

async function sendToSequenceFromSelection() {
  const record = await loadSelectedTransactionRecord();
  if (!record) {
    throw new Error("Selected transaction could not be loaded.");
  }
  if (record.kind === "tunnel") {
    throw new Error("Tunnel records cannot be sent to Sequence.");
  }

  const request = editableRequestFromRecord(record);
  if (!state.editingSequence) {
    if (!(await createNewSequence())) {
      return;
    }
  }
  if (!state.editingSequence) {
    return;
  }
  state.editingSequence.steps.push({
    id: crypto.randomUUID(),
    label: `${request.method} ${request.path}`,
    request,
    source_transaction_id: record.id,
    http_version: normalizeReplayHttpVersion(request.http_version || ""),
    target: null,
    extractions: [],
  });
  state.activeTool = "sequence";
  if (!(await saveCurrentSequence())) {
    return;
  }
  scheduleWorkspaceStateSave();
  renderToolPanels();
}

function handleSendActionError(error) {
  console.error(error);
  showToast(error?.message || "Failed to send selected item.", "error");
}

function handleReplayActionError(error) {
  console.error(error);
  showToast(error?.message || "Replay action failed.", "error");
}

function initFuzzerResizers() {
  const colHandle = document.getElementById("fuzzerColResizer");
  const rowHandle = document.getElementById("fuzzerRowResizer");
  const topRow = document.querySelector(".fuzzer-top-row");
  const templateCard = document.querySelector(".fuzzer-template-card");
  const payloadsCard = document.querySelector(".fuzzer-payloads-card");

  // Column resizer: template ↔ payloads
  if (colHandle && topRow && templateCard && payloadsCard) {
    colHandle.addEventListener("mousedown", (e) => {
      e.preventDefault();
      const startX = e.clientX;
      const startTemplateW = templateCard.offsetWidth;
      const startPayloadsW = payloadsCard.offsetWidth;
      const totalW = startTemplateW + startPayloadsW;
      document.body.classList.add("pane-resizing-x");
      colHandle.classList.add("active");
      const onMove = (me) => {
        const delta = me.clientX - startX;
        const newTemplateW = Math.max(200, Math.min(totalW - 120, startTemplateW + delta));
        const newPayloadsW = totalW - newTemplateW;
        templateCard.style.flex = `0 0 ${newTemplateW}px`;
        payloadsCard.style.flex = `0 0 ${newPayloadsW}px`;
      };
      const onUp = () => {
        document.body.classList.remove("pane-resizing-x");
        colHandle.classList.remove("active");
        document.removeEventListener("mousemove", onMove);
        document.removeEventListener("mouseup", onUp);
      };
      document.addEventListener("mousemove", onMove);
      document.addEventListener("mouseup", onUp);
    });
    colHandle.addEventListener("dblclick", () => {
      templateCard.style.flex = "";
      payloadsCard.style.flex = "";
    });
  }

  // Row resizer: top row ↔ results
  if (rowHandle && topRow) {
    rowHandle.addEventListener("mousedown", (e) => {
      e.preventDefault();
      const startY = e.clientY;
      const startH = topRow.offsetHeight;
      const layout = topRow.closest(".fuzzer-layout");
      const layoutH = layout ? layout.offsetHeight : 800;
      document.body.classList.add("pane-resizing-y");
      rowHandle.classList.add("active");
      const onMove = (me) => {
        const delta = me.clientY - startY;
        const newH = Math.max(120, Math.min(layoutH - 200, startH + delta));
        topRow.style.height = `${newH}px`;
      };
      const onUp = () => {
        document.body.classList.remove("pane-resizing-y");
        rowHandle.classList.remove("active");
        document.removeEventListener("mousemove", onMove);
        document.removeEventListener("mouseup", onUp);
      };
      document.addEventListener("mousemove", onMove);
      document.addEventListener("mouseup", onUp);
    });
    rowHandle.addEventListener("dblclick", () => {
      topRow.style.height = "";
    });
  }

  // Detail resizer: results table ↔ detail panel
  const detailHandle = document.getElementById("fuzzerDetailResizer");
  const detailPanel = els.fuzzerDetailPanel;
  if (detailHandle && detailPanel) {
    detailHandle.addEventListener("mousedown", (e) => {
      e.preventDefault();
      const startY = e.clientY;
      const startH = detailPanel.offsetHeight;
      const parentH = detailPanel.parentElement.offsetHeight;
      document.body.classList.add("pane-resizing-y");
      detailHandle.classList.add("active");
      const onMove = (me) => {
        const delta = startY - me.clientY; // drag up = bigger detail
        const newH = Math.max(100, Math.min(parentH - 100, startH + delta));
        detailPanel.style.flex = `0 0 ${newH}px`;
      };
      const onUp = () => {
        document.body.classList.remove("pane-resizing-y");
        detailHandle.classList.remove("active");
        document.removeEventListener("mousemove", onMove);
        document.removeEventListener("mouseup", onUp);
      };
      document.addEventListener("mousemove", onMove);
      document.addEventListener("mouseup", onUp);
    });
    detailHandle.addEventListener("dblclick", () => {
      detailPanel.style.flex = "";
    });
  }
}

function resetFuzzer() {
  invalidateFuzzerRun();
  updateFuzzerRequestText(
    state.fuzzerBaseRequest ? buildEditableRawRequest(state.fuzzerBaseRequest) : "",
    { userEdit: true },
  );
  state.fuzzerPayloadsText = "";
  state.fuzzerAttackRecord = null;
  state.fuzzerNotice = "";
  state._selectedFuzzerResultKey = null;
  hideFuzzerDetailPanel();
  scheduleWorkspaceStateSave();
  renderFuzzer();
}

function updateFuzzerRequestText(text, { userEdit = false } = {}) {
  const normalized = text || "";
  if (state.fuzzerRequestText !== normalized) {
    state.fuzzerRequestText = normalized;
    if (userEdit) markFuzzerDraftChanged();
  }
}

function updateFuzzerPayloadsText(text, { userEdit = false } = {}) {
  const normalized = text || "";
  if (state.fuzzerPayloadsText !== normalized) {
    state.fuzzerPayloadsText = normalized;
    if (userEdit) markFuzzerDraftChanged();
  }
}

function markFuzzerDraftChanged() {
  state.fuzzerDraftVersion = (state.fuzzerDraftVersion || 0) + 1;
  if (state.fuzzerAttackRecord) {
    state.fuzzerAttackRecord = null;
    state._selectedFuzzerResultKey = null;
    state.fuzzerNotice = "Fuzzer draft changed. Start a new run to see results for the current template.";
    hideFuzzerDetailPanel();
  }
}

function invalidateFuzzerRun() {
  state.fuzzerRunToken = (state.fuzzerRunToken || 0) + 1;
  state.fuzzerRunning = false;
}

function fuzzerRequestAuthorityFromText(requestText) {
  try {
    const request = parseEditableRawRequest(
      requestText,
      state.fuzzerBaseRequest || createDefaultEditableRequest(),
    );
    return { scheme: request.scheme || "https", host: request.host || "" };
  } catch (_error) {
    return null;
  }
}

function fuzzerAuthorityFromSavedValue(value) {
  const text = String(value || "").trim();
  if (!text) {
    return null;
  }
  if (/^https?:\/\//i.test(text)) {
    try {
      const parsed = new URL(text);
      const scheme = parsed.protocol.replace(":", "").toLowerCase();
      if ((scheme !== "http" && scheme !== "https") || !parsed.host) {
        return null;
      }
      return { scheme, host: parsed.host };
    } catch (_error) {
      return null;
    }
  }
  return fuzzerRequestAuthorityFromText(text);
}

function activeFuzzerTargetForRequest(requestText) {
  if (!state.fuzzerTarget) return null;
  if (!state.fuzzerTargetRequestText) return null;
  const original = fuzzerAuthorityFromSavedValue(state.fuzzerTargetRequestText);
  const current = fuzzerRequestAuthorityFromText(requestText);
  if (
    !original
    || !current
    || original.scheme !== current.scheme
    || !httpRequestAuthoritiesEquivalent(original.host, current.host, current.scheme)
  ) {
    return null;
  }
  return normalizeFuzzerTargetOverride(state.fuzzerTarget);
}

function fuzzerTargetAuthorityFromRequestText(requestText) {
  const authority = fuzzerRequestAuthorityFromText(requestText || "");
  if (!authority || !authority.host) {
    return null;
  }
  return `${authority.scheme}://${authority.host}`;
}

function normalizeFuzzerTargetAuthority(value) {
  const authority = fuzzerAuthorityFromSavedValue(value);
  if (!authority || !authority.host) {
    return null;
  }
  return `${authority.scheme}://${authority.host}`;
}

function isCurrentFuzzerRun(runToken, sessionId) {
  return state.fuzzerRunToken === runToken && state.activeSession?.id === sessionId;
}

async function runFuzzerAttack() {
  if (state.fuzzerRunning) {
    return;
  }
  const runToken = (state.fuzzerRunToken || 0) + 1;
  const sessionId = state.activeSession?.id || null;
  state.fuzzerRunToken = runToken;
  state.fuzzerRunning = true;
  state._selectedFuzzerResultKey = null;
  hideFuzzerDetailPanel();
  renderFuzzer();
  const draftVersion = state.fuzzerDraftVersion || 0;
  try {
    const fallback = state.fuzzerBaseRequest || {
      scheme: "https",
      host: "",
      method: "GET",
      path: "/",
      headers: [],
      body: "",
      body_encoding: "utf8",
      preview_truncated: false,
    };
    const fuzzerReqText = getCMView("fuzzerReq")
      ? getCMView("fuzzerReq").getContent()
      : (els.fuzzerRequestEditor ? els.fuzzerRequestEditor.value : "");
    if (!fuzzerReqText.trim()) {
      state.fuzzerAttackRecord = null;
      state.fuzzerNotice = "Request template is empty. Paste a raw HTTP request with $payload$ markers, or send one from HTTP History (Command+I).";
      scheduleWorkspaceStateSave();
      renderFuzzer();
      return;
    }

    let template;
    try {
      template = parseEditableRawRequest(fuzzerReqText, fallback);
    } catch (parseErr) {
      state.fuzzerAttackRecord = null;
      state.fuzzerNotice = parseErr.message || "Failed to parse the request template.";
      scheduleWorkspaceStateSave();
      renderFuzzer();
      return;
    }

    const payloadsText = els.fuzzerPayloadsEditor.value;
    const payloads = splitFuzzerPayloadLines(payloadsText);

    if (payloads.length === 0) {
      state.fuzzerAttackRecord = null;
      state.fuzzerNotice = "No payloads provided. Enter one payload per line in the Payloads panel.";
      scheduleWorkspaceStateSave();
      renderFuzzer();
      return;
    }

    const target = activeFuzzerTargetForRequest(fuzzerReqText);
    const httpVersion = replayHttpVersionFromText(fuzzerReqText) || undefined;
    const response = await fetch("/api/fuzzer/attacks", {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify({
        session_id: sessionId,
        template,
        payloads,
        source_transaction_id: state.fuzzerSourceTransactionId,
        http_version: httpVersion,
        target,
      }),
    });
    if (!isCurrentFuzzerRun(runToken, sessionId)) {
      return;
    }
    if (!response.ok) {
      const notice = await response.text();
      if (!isCurrentFuzzerRun(runToken, sessionId)) {
        return;
      }
      const draftUnchanged = (state.fuzzerDraftVersion || 0) === draftVersion;
      if (!draftUnchanged) {
        showToast(notice || "Fuzzer run failed after the draft changed.", "error", 4000);
        return;
      }
      state.fuzzerAttackRecord = null;
      state.fuzzerNotice = notice;
      scheduleWorkspaceStateSave();
      renderFuzzer();
      return;
    }
    const attackRecord = normalizeFuzzerAttackRecord(await response.json());
    if (!isCurrentFuzzerRun(runToken, sessionId)) {
      return;
    }
    const draftUnchanged = (state.fuzzerDraftVersion || 0) === draftVersion;
    if (!draftUnchanged) {
      state.fuzzerAttackRecord = null;
      state.fuzzerNotice = "Fuzzer run completed, but the draft changed while it was running. Start again to see current results.";
      state._selectedFuzzerResultKey = null;
      hideFuzzerDetailPanel();
      scheduleWorkspaceStateSave();
      renderFuzzer();
      scheduleRefresh();
      return;
    }
    state.fuzzerBaseRequest = template;
    state.fuzzerTarget = target;
    state.fuzzerTargetRequestText = target ? fuzzerTargetAuthorityFromRequestText(fuzzerReqText) : null;
    state.fuzzerRequestText = fuzzerReqText;
    state.fuzzerPayloadsText = payloadsText;
    state.fuzzerNotice = "";
    state._selectedFuzzerResultKey = null;
    hideFuzzerDetailPanel();
    state.fuzzerAttackRecord = attackRecord;
    scheduleWorkspaceStateSave();
    renderFuzzer();
    scheduleRefresh();
  } catch (error) {
    if (!isCurrentFuzzerRun(runToken, sessionId)) {
      return;
    }
    console.error("Fuzzer run error:", error);
    const draftUnchanged = (state.fuzzerDraftVersion || 0) === draftVersion;
    if (!draftUnchanged) {
      showToast(error?.message || "Fuzzer run failed after the draft changed.", "error", 4000);
      return;
    }
    state.fuzzerAttackRecord = null;
    state.fuzzerNotice = error?.message || "An unexpected error occurred while starting the fuzzer.";
    scheduleWorkspaceStateSave();
    renderFuzzer();
  } finally {
    if (isCurrentFuzzerRun(runToken, sessionId)) {
      state.fuzzerRunning = false;
      renderFuzzer();
    }
  }
}

function splitFuzzerPayloadLines(text) {
  const normalized = String(text ?? "").replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  if (normalized.length === 0) return [];
  const lines = normalized.split("\n");
  if (lines.length > 1 && lines[lines.length - 1] === "") {
    lines.pop();
  }
  return lines;
}

/* ─── Sequence/Macro ─── */

function currentSequenceSessionId() {
  return state.activeSession?.id || null;
}

function isCurrentSequenceSession(sessionId) {
  return (state.activeSession?.id || null) === sessionId;
}

function isCurrentSequenceRun(runGeneration, sequenceId, sessionId, draftVersion) {
  return Boolean(
    state.sequenceRunGeneration === runGeneration
    && state.selectedSequenceId === sequenceId
    && isCurrentSequenceSession(sessionId)
    && (state.sequenceDraftVersion || 0) === draftVersion
  );
}

function sequenceSessionPath(path, sessionId) {
  if (!sessionId) return path;
  const separator = path.includes("?") ? "&" : "?";
  return `${path}${separator}session_id=${encodeURIComponent(sessionId)}`;
}

async function loadSequences({ sessionId = currentSequenceSessionId() } = {}) {
  const [defsResp, runsResp] = await Promise.all([
    fetch(sequenceSessionPath("/api/sequences", sessionId)),
    fetch(sequenceSessionPath("/api/sequence-runs?limit=20", sessionId)),
  ]);
  await requireOkResponse(defsResp, "Failed to load sequences.");
  await requireOkResponse(runsResp, "Failed to load sequence runs.");
  const definitions = jsonArray(await defsResp.json());
  const pastRuns = jsonArray(await runsResp.json());
  if (!isCurrentSequenceSession(sessionId)) {
    return false;
  }
  state.sequenceDefinitions = definitions;
  state.sequencePastRuns = pastRuns;
  return true;
}

function handleSequenceActionError(error) {
  console.error(error);
  showToast(error?.message || "Sequence action failed.", "error", 6000);
}

async function createNewSequence() {
  if (!(await flushSequenceDraft())) {
    return false;
  }
  const sessionId = currentSequenceSessionId();
  const def = {
    id: crypto.randomUUID(),
    name: "New Sequence",
    steps: [],
  };
  const response = await fetch("/api/sequences", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ ...def, session_id: sessionId }),
  });
  if (!isCurrentSequenceSession(sessionId)) {
    return false;
  }
  await requireOkResponse(response, "Failed to create sequence.");
  if (!isCurrentSequenceSession(sessionId)) {
    return false;
  }
  const loaded = await loadSequences({ sessionId });
  if (!loaded) {
    return false;
  }
  state.selectedSequenceId = def.id;
  state.editingSequence = JSON.parse(JSON.stringify(def));
  state.sequenceDirty = false;
  bumpSequenceDraftVersion();
  renderSequencePanel();
  return true;
}

async function selectSequence(id) {
  if (state.selectedSequenceId === id) {
    syncSequenceStepFromDom({ allowInvalidRequests: true });
    return;
  }
  const selectionGeneration = (state.sequenceSelectionGeneration || 0) + 1;
  state.sequenceSelectionGeneration = selectionGeneration;
  if (!(await flushSequenceDraft())) {
    return;
  }
  if (state.sequenceSelectionGeneration !== selectionGeneration) {
    return;
  }
  state.selectedSequenceId = id;
  const def = state.sequenceDefinitions.find((d) => d.id === id);
  state.editingSequence = def ? JSON.parse(JSON.stringify(def)) : null;
  state.sequenceDirty = false;
  bumpSequenceDraftVersion();
  state.sequenceRunResult = null;
  renderSequencePanel();
}

function bumpSequenceDraftVersion() {
  state.sequenceDraftVersion = (state.sequenceDraftVersion || 0) + 1;
}

function markSequenceDraftDirty() {
  state.sequenceDirty = true;
  bumpSequenceDraftVersion();
}

function addSequenceStep() {
  if (!state.editingSequence) return;
  state.editingSequence.steps.push({
    id: crypto.randomUUID(),
    label: `Step ${state.editingSequence.steps.length + 1}`,
    request: {
      scheme: "https", host: "", method: "GET", path: "/",
      headers: [], body: "", body_encoding: "utf8", preview_truncated: false,
    },
    target: null,
    extractions: [],
  });
  markSequenceDraftDirty();
  renderSequencePanel();
}

function removeSequenceStep(index) {
  if (!state.editingSequence) return;
  state.editingSequence.steps.splice(index, 1);
  markSequenceDraftDirty();
  renderSequencePanel();
}

function addExtractionRule(stepIndex) {
  if (!state.editingSequence) return;
  const step = state.editingSequence.steps[stepIndex];
  if (!step) return;
  step.extractions.push({
    variable_name: "",
    source: "response_body",
    pattern: "",
    group: 1,
  });
  markSequenceDraftDirty();
  renderSequencePanel();
}

function removeExtractionRule(stepIndex, ruleIndex) {
  if (!state.editingSequence) return;
  const step = state.editingSequence.steps[stepIndex];
  if (!step) return;
  step.extractions.splice(ruleIndex, 1);
  markSequenceDraftDirty();
  renderSequencePanel();
}

function syncSequenceStepFromDom({ allowInvalidRequests = false } = {}) {
  if (!state.editingSequence) return;
  const container = document.getElementById("sequenceStepsContainer");
  if (!container) return;
  const cards = container.querySelectorAll(".sequence-step-card");
  cards.forEach((card, i) => {
    const step = state.editingSequence.steps[i];
    if (!step) return;
    const labelInput = card.querySelector(".step-label");
    if (labelInput) step.label = labelInput.value;
    const reqTextarea = card.querySelector(".step-request-text");
    if (reqTextarea) {
      step.request_text = reqTextarea.value;
      const httpVersion = replayHttpVersionFromText(reqTextarea.value);
      step.http_version = httpVersion || null;
      try {
        const parsed = parseEditableRawRequest(reqTextarea.value, step.request);
        parsed.http_version = httpVersion || undefined;
        Object.assign(step.request, parsed);
        delete step.request_parse_error;
      } catch (error) {
        step.request_parse_error = error?.message || "Invalid request";
        if (!allowInvalidRequests) {
          throw error;
        }
      }
    }
    card.querySelectorAll(".extraction-row").forEach((row, j) => {
      const rule = step.extractions[j];
      if (!rule) return;
      const varInput = row.querySelector(".ext-var");
      const sourceSelect = row.querySelector(".ext-source");
      const patternInput = row.querySelector(".ext-pattern");
      if (varInput) rule.variable_name = varInput.value;
      if (sourceSelect) rule.source = sourceSelect.value;
      if (patternInput) rule.pattern = patternInput.value;
    });
  });
}

async function saveCurrentSequence({ render = true, preserveSelection = false } = {}) {
  if (!state.editingSequence) return false;
  syncSequenceStepFromDom({ allowInvalidRequests: true });
  const sessionId = currentSequenceSessionId();
  const savedId = state.editingSequence.id;
  const selectedBeforeSave = state.selectedSequenceId;
  const draftVersion = state.sequenceDraftVersion || 0;
  const payload = JSON.parse(JSON.stringify(state.editingSequence));
  payload.session_id = sessionId;
  const response = await fetch("/api/sequences", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!isCurrentSequenceSession(sessionId)) {
    return false;
  }
  await requireOkResponse(response, "Failed to save sequence.");
  if (!isCurrentSequenceSession(sessionId)) {
    return false;
  }
  const loaded = await loadSequences({ sessionId });
  if (!loaded) {
    return false;
  }
  if (state.selectedSequenceId !== selectedBeforeSave) {
    return false;
  }
  if ((state.sequenceDraftVersion || 0) !== draftVersion) {
    state.sequenceDirty = true;
    return false;
  }
  const saved = state.sequenceDefinitions.find((def) => def.id === savedId);
  if (saved && (!preserveSelection || state.selectedSequenceId === savedId)) {
    state.editingSequence = JSON.parse(JSON.stringify(saved));
    state.selectedSequenceId = savedId;
  }
  state.sequenceDirty = false;
  if (render) {
    renderSequencePanel();
  }
  return true;
}

async function flushSequenceDraft() {
  if (!state.sequenceDirty || !state.editingSequence) return true;
  return saveCurrentSequence({ render: false, preserveSelection: true });
}

async function deleteSequence(id) {
  const sessionId = currentSequenceSessionId();
  const response = await fetch(sequenceSessionPath(`/api/sequences/${id}`, sessionId), { method: "DELETE" });
  if (!isCurrentSequenceSession(sessionId)) {
    return;
  }
  await requireOkResponse(response, "Failed to delete sequence.");
  if (!isCurrentSequenceSession(sessionId)) {
    return;
  }
  if (state.selectedSequenceId === id) {
    state.selectedSequenceId = null;
    state.editingSequence = null;
    bumpSequenceDraftVersion();
  }
  await loadSequences({ sessionId });
  renderSequencePanel();
}

async function runCurrentSequence() {
  if (!state.editingSequence) return;
  const runSequenceId = state.editingSequence.id;
  const sessionId = currentSequenceSessionId();
  const runGeneration = (state.sequenceRunGeneration || 0) + 1;
  state.sequenceRunGeneration = runGeneration;
  syncSequenceStepFromDom();
  const saved = await saveCurrentSequence();
  if (!saved) {
    return;
  }
  if (
    state.sequenceRunGeneration !== runGeneration
    || state.selectedSequenceId !== runSequenceId
    || !isCurrentSequenceSession(sessionId)
  ) {
    return;
  }
  const runDraftVersion = state.sequenceDraftVersion || 0;

  const runBtn = document.getElementById("runSequenceButton");
  runBtn.disabled = true;
  runBtn.textContent = "Running...";

  try {
    const response = await fetch(`/api/sequences/${runSequenceId}/run`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ session_id: sessionId }),
    });
    if (!isCurrentSequenceRun(runGeneration, runSequenceId, sessionId, runDraftVersion)) {
      return;
    }
    if (!response.ok) {
      const errText = await response.text();
      if (!isCurrentSequenceRun(runGeneration, runSequenceId, sessionId, runDraftVersion)) {
        return;
      }
      showToast(`Sequence failed: ${errText}`, "error");
      return;
    }
    const result = normalizeSequenceRunResult(await response.json());
    if (!isCurrentSequenceRun(runGeneration, runSequenceId, sessionId, runDraftVersion)) {
      return;
    }
    state.sequenceRunResult = result;
    await loadSequences({ sessionId });
    scheduleRefresh();
  } catch (err) {
    if (!isCurrentSequenceRun(runGeneration, runSequenceId, sessionId, runDraftVersion)) {
      return;
    }
    showToast(`Sequence error: ${err.message}`, "error");
  } finally {
    if (
      state.sequenceRunGeneration === runGeneration
      && state.selectedSequenceId === runSequenceId
      && isCurrentSequenceSession(sessionId)
    ) {
      runBtn.disabled = false;
      runBtn.textContent = "Run";
      renderSequencePanel();
    }
  }
}

function renderSequencePanel() {
  const listBody = document.getElementById("sequenceListBody");
  const editorTitle = document.getElementById("sequenceEditorTitle");
  const stepsContainer = document.getElementById("sequenceStepsContainer");
  const addStepBtn = document.getElementById("addSequenceStepButton");
  const saveBtn = document.getElementById("saveSequenceButton");
  const runBtn = document.getElementById("runSequenceButton");
  const runMeta = document.getElementById("sequenceRunMeta");
  const resultsBody = document.getElementById("sequenceRunResultsBody");
  const pastBody = document.getElementById("sequencePastRunsBody");

  // List
  listBody.innerHTML = state.sequenceDefinitions.length
    ? state.sequenceDefinitions.map((def) => {
        const selected = def.id === state.selectedSequenceId ? "selected" : "";
        return `<tr class="history-row ${selected}" data-seq-id="${def.id}">
          <td>${escapeHtml(def.name)}</td>
          <td>${def.steps.length}</td>
          <td><button class="secondary-action seq-delete" data-seq-delete="${def.id}" style="font-size:0.7rem;padding:2px 6px">&times;</button></td>
        </tr>`;
      }).join("")
    : `<tr class="empty-row"><td colspan="3">No sequences yet.</td></tr>`;

  listBody.querySelectorAll(".history-row").forEach((row) => {
    row.addEventListener("click", (e) => {
      if (e.target.closest(".seq-delete")) return;
      selectSequence(row.dataset.seqId).catch(handleSequenceActionError);
    });
  });
  listBody.querySelectorAll(".seq-delete").forEach((btn) => {
    btn.addEventListener("click", () => deleteSequence(btn.dataset.seqDelete).catch(handleSequenceActionError));
  });

  // Editor
  const editing = state.editingSequence;
  const hasSequence = !!editing;
  addStepBtn.disabled = !hasSequence;
  saveBtn.disabled = !hasSequence;
  runBtn.disabled = !hasSequence || !editing?.steps?.length;
  editorTitle.textContent = hasSequence ? editing.name : "No sequence selected";

  if (hasSequence) {
    stepsContainer.innerHTML = editing.steps.map((step, idx) => {
      const requestForRender = {
        ...(step.request || {}),
        http_version: normalizeReplayHttpVersion(step.http_version || step.request?.http_version || "")
          || step.request?.http_version,
      };
      const reqText = step.request_text ?? buildEditableRawRequest(requestForRender);
      const extractionsHtml = step.extractions.map((rule, rIdx) => `
        <div class="extraction-row">
          <input class="ext-var" placeholder="Variable name" value="${escapeHtml(rule.variable_name)}" />
          <select class="ext-source">
            <option value="response_body"${rule.source === "response_body" ? " selected" : ""}>Body</option>
            <option value="response_header"${rule.source === "response_header" ? " selected" : ""}>Header</option>
          </select>
          <input class="ext-pattern" placeholder="Regex / header name" value="${escapeHtml(rule.pattern)}" />
          <button class="ext-remove" data-step="${idx}" data-rule="${rIdx}" title="Remove">&times;</button>
        </div>
      `).join("");

      return `<div class="sequence-step-card" data-step-idx="${idx}">
        <div class="step-header">
          <span class="step-number">#${idx + 1}</span>
          <input class="step-label" value="${escapeHtml(step.label)}" placeholder="Step label" />
          <button class="step-remove" data-remove-step="${idx}" title="Remove step">&times;</button>
        </div>
        <textarea class="step-request-text" spellcheck="false">${escapeHtml(reqText)}</textarea>
        <details class="step-extractions">
          <summary>Extractions (${step.extractions.length}) <button class="ext-add" data-add-ext="${idx}" style="font-size:0.7rem;margin-left:8px">+ Extract</button></summary>
          ${extractionsHtml}
        </details>
      </div>`;
    }).join("");

    if (!stepsContainer._sequenceDraftSyncWired) {
      stepsContainer._sequenceDraftSyncWired = true;
      const markSequenceDirty = () => {
        syncSequenceStepFromDom({ allowInvalidRequests: true });
        markSequenceDraftDirty();
      };
      stepsContainer.addEventListener("input", markSequenceDirty);
      stepsContainer.addEventListener("change", markSequenceDirty);
    }

    stepsContainer.querySelectorAll(".step-remove").forEach((btn) => {
      btn.addEventListener("click", () => {
        syncSequenceStepFromDom({ allowInvalidRequests: true });
        removeSequenceStep(parseInt(btn.dataset.removeStep, 10));
      });
    });
    stepsContainer.querySelectorAll(".ext-add").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        e.preventDefault();
        syncSequenceStepFromDom({ allowInvalidRequests: true });
        addExtractionRule(parseInt(btn.dataset.addExt, 10));
      });
    });
    stepsContainer.querySelectorAll(".ext-remove").forEach((btn) => {
      btn.addEventListener("click", () => {
        syncSequenceStepFromDom({ allowInvalidRequests: true });
        removeExtractionRule(parseInt(btn.dataset.step, 10), parseInt(btn.dataset.rule, 10));
      });
    });
  } else {
    stepsContainer.innerHTML = `<div style="padding:20px;color:var(--text-muted);font-size:0.85rem">Select or create a sequence to start building steps.</div>`;
  }

  // Run results
  const run = normalizeSequenceRunResult(state.sequenceRunResult);
  state.sequenceRunResult = run;
  if (run) {
    const stepResults = jsonArray(run.step_results);
    runMeta.textContent = `${run.sequence_name || "Sequence"} — ${run.status || "unknown"} — ${stepResults.length} steps`;
    resultsBody.innerHTML = stepResults.map((sr, i) => {
      const extracted = Object.entries((sr && typeof sr.extracted === "object" && sr.extracted) || {}).map(([k, v]) => `${k}=${v}`).join(", ");
      return `<tr>
        <td>${i + 1}</td>
        <td>${escapeHtml(sr?.label || `Step ${i + 1}`)}</td>
        <td>${sr?.error ? `<span style="color:var(--danger)">${escapeHtml(sr.error)}</span>` : escapeHtml(String(sr?.status ?? "-"))}</td>
        <td>${sr?.duration_ms != null ? `${sr.duration_ms} ms` : "-"}</td>
        <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis">${escapeHtml(extracted || "-")}</td>
      </tr>`;
    }).join("");
  } else {
    runMeta.textContent = "No sequence run yet.";
    resultsBody.innerHTML = `<tr class="empty-row"><td colspan="5">Run a sequence to see results.</td></tr>`;
  }

  // Past runs
  pastBody.innerHTML = state.sequencePastRuns.length
    ? state.sequencePastRuns.map((r) => `<tr>
        <td>${escapeHtml(r.sequence_name)}</td>
        <td>${escapeHtml(r.status)}</td>
        <td>${r.step_count}</td>
        <td>${escapeHtml(formatTimestamp(r.started_at))}</td>
      </tr>`).join("")
    : `<tr class="empty-row"><td colspan="4">No past runs.</td></tr>`;
}

function normalizeSequenceRunResult(run) {
  if (!run || typeof run !== "object") return null;
  return {
    ...run,
    step_results: jsonArray(run.step_results),
  };
}

async function toggleIntercept() {
  if (!state.runtime) {
    return;
  }

  const sessionId = currentSessionId();
  const turningOff = state.runtime.intercept_enabled;
  // Optimistic UI update — render immediately, sync in background
  state.runtime.intercept_enabled = !state.runtime.intercept_enabled;
  const desiredInterceptEnabled = state.runtime.intercept_enabled;
  const requestSeq = ++_interceptToggleRequestSeq;
  renderInterceptStatus();

  fetch("/api/runtime", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ session_id: sessionId, intercept_enabled: desiredInterceptEnabled }),
  }).then(async (r) => {
    await requireOkResponse(r, "Failed to update intercept mode.");
    return r.json();
  }).then((rt) => {
    if (requestSeq === _interceptToggleRequestSeq && sessionId === currentSessionId()) {
      state.runtime = rt;
      renderInterceptStatus();
    }
  })
    .catch((error) => {
      if (requestSeq !== _interceptToggleRequestSeq || sessionId !== currentSessionId()) {
        return;
      }
      console.error(error);
      showToast(error?.message || "Failed to update intercept mode.", "error");
      loadRuntimeSettings().then(renderInterceptStatus).catch(console.error);
    });

  if (turningOff) {
    Promise.all([
      fetch(sessionQueryPath("/api/intercepts/forward-all", sessionId), { method: "POST" }),
      fetch(sessionQueryPath("/api/response-intercepts/forward-all", sessionId), { method: "POST" }),
    ]).then(async ([requestResponse, responseResponse]) => {
      await requireOkResponse(requestResponse, "Failed to forward queued requests.");
      await requireOkResponse(responseResponse, "Failed to forward queued responses.");
    }).then(() => {
      if (sessionId !== currentSessionId()) {
        return null;
      }
      return Promise.all([loadIntercepts(false), loadResponseIntercepts(false)]);
    })
      .then(() => {
        if (sessionId === currentSessionId()) {
          scheduleRefresh();
        }
      })
      .catch((error) => {
        if (sessionId !== currentSessionId()) {
          return;
        }
        console.error(error);
        showToast(error?.message || "Failed to forward queued intercepts.", "error");
        Promise.all([loadIntercepts(false), loadResponseIntercepts(false)]).catch(console.error);
      });
  }
}

async function saveProxySettings() {
  const sessionId = currentSessionId();
  const scopePatterns = els.proxySettingScopePatterns.value
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
  const passthroughHosts = els.proxySettingPassthroughHosts.value
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);

  const bindHost = els.proxySettingBindHost.value.trim();
  const proxyPortText = els.proxySettingPort.value.trim();
  const proxyPort = strictIntegerInRange(proxyPortText, 1, 65535);
  if (proxyPortText && proxyPort === null) {
    throw new Error("Proxy port must be an integer between 1 and 65535.");
  }
  if (bindHost && !isValidIpLiteral(bindHost)) {
    throw new Error("Proxy bind host must be an IPv4 or IPv6 address.");
  }
  const startupUpdate = {
    proxy_bind_host: bindHost || undefined,
    proxy_port: proxyPortText ? proxyPort : undefined,
  };
  const oastTokenValue = document.getElementById("proxySettingOastToken")?.value?.trim() || "";
  const oastIntervalText = document.getElementById("proxySettingOastInterval")?.value?.trim() || "";
  const oastInterval = oastIntervalText ? strictIntegerInRange(oastIntervalText, 1, 300) : 5;
  if (oastInterval === null) {
    throw new Error("OAST polling interval must be an integer between 1 and 300 seconds.");
  }
  const runtimeUpdate = {
    session_id: sessionId,
    intercept_enabled: els.proxySettingIntercept.checked,
    websocket_capture_enabled: els.proxySettingWebsocketCapture.checked,
    upstream_insecure: els.proxySettingUpstreamInsecure.checked,
    scope_patterns: scopePatterns,
    passthrough_hosts: passthroughHosts,
    oast_enabled: document.getElementById("proxySettingOastEnabled")?.checked ?? false,
    oast_provider: document.getElementById("proxySettingOastProvider")?.value || "custom",
    oast_server_url: document.getElementById("proxySettingOastServerUrl")?.value?.trim() || "",
    oast_polling_interval_secs: oastInterval,
  };
  if (state.oastTokenClearPending) {
    runtimeUpdate.oast_token = "";
  } else if (oastTokenValue && oastTokenValue !== OAST_TOKEN_REDACTION) {
    runtimeUpdate.oast_token = oastTokenValue;
  }

  const runtimeResponse = await fetch("/api/runtime", {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify(runtimeUpdate),
  });

  if (!runtimeResponse.ok) {
    throw new Error(await runtimeResponse.text());
  }
  const runtimeResult = await runtimeResponse.json();

  const startupResponse = await fetch("/api/startup-settings", {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify(startupUpdate),
  });

  if (!startupResponse.ok) {
    throw new Error(await startupResponse.text());
  }

  const startupResult = await startupResponse.json();
  if (sessionId !== currentSessionId()) {
    return startupResult;
  }
  state.runtime = runtimeResult;
  state.oastTokenClearPending = false;
  state.settings.startup = startupResult;

  // If proxy was rebound, update the main proxy_addr in settings too
  if (startupResult.rebound === true) {
    state.settings.proxy_addr = startupResult.active_proxy_addr;
  }

  renderInterceptStatus();
  renderProxySettings();
  invalidateVisibleEntriesCache();
  scheduleRefresh();
  return startupResult;
}

function isValidIpLiteral(value) {
  const host = String(value || "").trim();
  if (!host) return false;
  if (host.includes(":")) {
    const inner = host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
    if (!inner || inner.includes("[") || inner.includes("]")) return false;
    try {
      const parsed = new URL(`http://[${inner}]/`);
      return parsed.hostname.startsWith("[") && parsed.hostname.endsWith("]");
    } catch (_error) {
      return false;
    }
  }
  const octets = host.split(".");
  return octets.length === 4 && octets.every((octet) => {
    if (!/^\d{1,3}$/.test(octet)) return false;
    const value = Number(octet);
    return value >= 0 && value <= 255 && String(value) === octet;
  });
}

async function requireOkResponse(response, fallbackMessage) {
  if (response.ok) return;
  const message = await response.text().catch(() => "");
  throw new Error(message || fallbackMessage);
}

async function forwardSelectedIntercept() {
  if (!state.selectedInterceptRecord) {
    return;
  }

  const sessionId = currentSessionId();
  const id = state.selectedInterceptRecord.id;
  const interceptReqText = getCMView("interceptReq")
    ? getCMView("interceptReq").getContent()
    : (els.interceptRequestEditor ? els.interceptRequestEditor.value : "");
  const request = parseEditableRawRequest(
    interceptReqText,
    state.selectedInterceptRecord.request,
  );
  if (state.selectedInterceptRecord.is_websocket && request.body) {
    showToast("WebSocket upgrade requests must not include a request body.", "error");
    return;
  }

  // Optimistic: remove from UI immediately
  state.intercepts = state.intercepts.filter((i) => i.id !== id);
  state.selectedInterceptRecord = null;
  state.interceptEditorSeedId = null;
  state.selectedInterceptId = getVisibleRequestInterceptSummaries()[0]?.id ?? null;
  renderIntercepts();
  updateInterceptQueueBadges();

  try {
    const response = await fetch(sessionQueryPath(`/api/intercepts/${id}/forward`, sessionId), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ request }),
    });
    await requireOkResponse(response, "Failed to forward intercepted request.");
    if (sessionId !== currentSessionId()) {
      return;
    }
    await loadIntercepts(true);
    scheduleRefresh();
  } catch (e) {
    if (sessionId !== currentSessionId()) {
      return;
    }
    console.error(e);
    showToast(e?.message || "Failed to forward intercepted request.", "error");
    await loadIntercepts(false).catch(console.error);
  }
}

async function dropSelectedIntercept() {
  if (!state.selectedInterceptRecord) {
    return;
  }

  const sessionId = currentSessionId();
  const id = state.selectedInterceptRecord.id;

  // Optimistic: remove from UI immediately
  state.intercepts = state.intercepts.filter((i) => i.id !== id);
  state.selectedInterceptRecord = null;
  state.interceptEditorSeedId = null;
  state.selectedInterceptId = getVisibleRequestInterceptSummaries()[0]?.id ?? null;
  renderIntercepts();
  updateInterceptQueueBadges();

  try {
    const response = await fetch(sessionQueryPath(`/api/intercepts/${id}/drop`, sessionId), { method: "POST" });
    await requireOkResponse(response, "Failed to drop intercepted request.");
    if (sessionId !== currentSessionId()) {
      return;
    }
    await loadIntercepts(true);
    scheduleRefresh();
  } catch (e) {
    if (sessionId !== currentSessionId()) {
      return;
    }
    console.error(e);
    showToast(e?.message || "Failed to drop intercepted request.", "error");
    await loadIntercepts(false).catch(console.error);
  }
}

/* ─── Response Intercept ─── */

async function loadResponseIntercepts(preserveSelection = true) {
  const sessionId = currentSessionId();
  const response = await fetch(sessionQueryPath("/api/response-intercepts", sessionId));
  await requireOkResponse(response, "Failed to load intercepted responses.");
  const responseIntercepts = jsonArray(await response.json());
  if (sessionId !== currentSessionId()) {
    return;
  }
  state.responseIntercepts = responseIntercepts;

  const visibleResponseIntercepts = getVisibleResponseInterceptSummaries();
  if (!preserveSelection || !visibleResponseIntercepts.some((item) => item.id === state.selectedResponseInterceptId)) {
    state.selectedResponseInterceptId = visibleResponseIntercepts[0]?.id ?? null;
    state.selectedResponseInterceptRecord = null;
    state.responseInterceptEditorSeedId = null;
  }

  renderResponseIntercepts();
  updateInterceptQueueBadges();
  // Auto-switch to Response Queue when responses arrive and Request Queue is empty
  if (visibleResponseIntercepts.length > 0 && getVisibleRequestInterceptSummaries().length === 0 && state.interceptQueueTab === "request") {
    switchInterceptQueueTab("response");
  }
  if (state.selectedResponseInterceptId) {
    await loadResponseInterceptDetail(state.selectedResponseInterceptId);
  } else {
    state.selectedResponseInterceptRecord = null;
    renderResponseIntercepts();
  }
}

async function loadResponseInterceptDetail(id) {
  const sessionId = currentSessionId();
  const response = await fetch(sessionQueryPath(`/api/response-intercepts/${id}`, sessionId));
  if (sessionId !== currentSessionId() || state.selectedResponseInterceptId !== id) {
    return;
  }
  if (!response.ok) {
    state.selectedResponseInterceptRecord = null;
    renderResponseIntercepts();
    return;
  }

  const record = await response.json();
  if (sessionId !== currentSessionId() || state.selectedResponseInterceptId !== id) {
    return;
  }
  state.selectedResponseInterceptRecord = record;
  renderResponseIntercepts();
}

function buildEditableRawResponse(resp) {
  const source = resp || {};
  let text = `HTTP/1.1 ${source.status ?? 200}\r\n`;
  for (const h of normalizedHeaders(source.headers)) {
    text += `${h.name}: ${h.value}\r\n`;
  }
  text += "\r\n";
  if (source.body_encoding === "base64") {
    text += safeDecodeBase64(source.body);
  } else {
    text += source.body || "";
  }
  return text;
}

function parseEditableRawResponse(text, original) {
  const { head, body } = splitRawHttpMessage(text);
  const lines = head.split("\n").filter((line) => line.length > 0);
  const statusLine = lines[0] || "";
  const hasStatusLine = /^HTTP\//i.test(statusLine);
  const statusMatch = hasStatusLine ? statusLine.match(/^HTTP\/[0-9.]+\s+(\d{3})(?:\s+.*)?$/i) : null;
  if (hasStatusLine && !statusMatch) {
    throw new Error("Invalid response status line in editor");
  }
  const status = statusMatch ? parseInt(statusMatch[1], 10) : (original?.status || 200);

  const headers = [];
  for (let i = hasStatusLine ? 1 : 0; i < lines.length; i++) {
    const line = lines[i];
    const colonIdx = line.indexOf(":");
    if (colonIdx > 0) {
      headers.push({
        name: line.substring(0, colonIdx).trim(),
        value: line.substring(colonIdx + 1).trim(),
      });
    } else {
      throw new Error(`Invalid response header line: ${line}`);
    }
  }

  const bodyText = body;
  const isText = !original || original.body_encoding === "utf8";
  const bodyEncoding = isText ? "utf8" : "base64";
  const bodyLength = editableResponseBodyLength(bodyText, bodyEncoding);

  // Auto-update Content-Length if enabled
  if (document.getElementById("proxySettingAutoContentLength")?.checked) {
    for (const header of headers) {
      if (headerNameEquals(header, "content-length")) {
        header.value = String(bodyLength);
      }
    }
  }
  validateRawHttpBodyFraming(headers, bodyLength);

  return {
    status,
    headers,
    body: isText ? bodyText : safeEncodeBase64(bodyText),
    body_encoding: bodyEncoding,
  };
}

function renderResponseIntercepts() {
  const filteredResponseIntercepts = getVisibleResponseInterceptSummaries();
  reconcileResponseInterceptSelection(filteredResponseIntercepts);
  els.responseInterceptTableBody.innerHTML = filteredResponseIntercepts.length
    ? filteredResponseIntercepts
        .map((item) => {
          const selected = item.id === state.selectedResponseInterceptId ? "selected" : "";
          return `
            <tr class="history-row ${selected}" data-id="${item.id}">
              <td class="iq-col-status">${escapeHtml(String(item.status))}</td>
              <td class="iq-col-method">${escapeHtml(item.method)}</td>
              <td class="iq-col-host text-truncate">${escapeHtml(item.host)}</td>
              <td class="iq-col-path text-truncate">${escapeHtml(item.path || "/")}</td>
              <td class="iq-col-time">${escapeHtml(formatTimestamp(item.started_at))}</td>
            </tr>
          `;
        })
        .join("")
    : `
        <tr class="empty-row">
          <td colspan="5">Response intercept queue is empty.</td>
        </tr>
      `;

  Array.from(els.responseInterceptTableBody.querySelectorAll(".history-row")).forEach((row) => {
    row.addEventListener("click", () => {
      state.selectedResponseInterceptId = row.dataset.id;
      loadResponseInterceptDetail(row.dataset.id).catch((error) => console.error(error));
    });
  });

  if (!state.selectedResponseInterceptRecord) {
    state.responseInterceptEditorSeedId = null;
    if (state.interceptQueueTab === "response") {
      els.interceptDetailPath.textContent = "Response Intercept";
      els.interceptDetailTitle.textContent = "No response selected";
      if (els.interceptResponseCM) {
        updateCodePaneCM("interceptRes", els.interceptResponseCM, "", {
          mode: "http", readOnly: false,
          placeholder: "Intercepted response will appear here...",
        });
      } else {
        els.interceptResponseEditor.value = "";
        renderInterceptResponseHighlight("");
      }
      els.interceptMeta.textContent = state.runtime?.intercept_enabled
        ? "Intercept is on. Matched responses will queue here."
        : "Intercept is off. Toggle it on to pause responses before forwarding.";
    }
    els.forwardResponseInterceptButton.disabled = true;
    els.dropResponseInterceptButton.disabled = true;
    return;
  }

  const rec = state.selectedResponseInterceptRecord;
  if (state.interceptQueueTab === "response") {
    els.interceptDetailPath.textContent = `${rec.scheme.toUpperCase()} / ${rec.method} ${rec.host}${rec.path}`;
    els.interceptDetailTitle.textContent = `${rec.status} Response`;
    if (els.interceptResponseCM) {
      const cv = getCMView("interceptRes");
      const isFocused = cv && cv.view.hasFocus;
      if (state.responseInterceptEditorSeedId !== rec.id || !isFocused) {
        const rawText = buildEditableRawResponse(rec.response);
        updateCodePaneCM("interceptRes", els.interceptResponseCM, rawText, {
          mode: "http", readOnly: false,
        });
        state.responseInterceptEditorSeedId = rec.id;
      }
    } else {
      if (state.responseInterceptEditorSeedId !== rec.id || document.activeElement !== els.interceptResponseEditor) {
        els.interceptResponseEditor.value = buildEditableRawResponse(rec.response);
        state.responseInterceptEditorSeedId = rec.id;
      }
      renderInterceptResponseHighlight(els.interceptResponseEditor.value);
    }
    els.interceptMeta.textContent = `Response queued at ${formatTimestamp(rec.started_at)}`;
  }
  els.forwardResponseInterceptButton.disabled = false;
  els.dropResponseInterceptButton.disabled = false;
}

async function forwardSelectedResponseIntercept() {
  if (!state.selectedResponseInterceptRecord) return;

  const sessionId = currentSessionId();
  const id = state.selectedResponseInterceptRecord.id;
  const interceptResText = getCMView("interceptRes")
    ? getCMView("interceptRes").getContent()
    : (els.interceptResponseEditor ? els.interceptResponseEditor.value : "");
  const editedResponse = parseEditableRawResponse(
    interceptResText,
    state.selectedResponseInterceptRecord.response,
  );

  // Optimistic UI
  state.responseIntercepts = state.responseIntercepts.filter((i) => i.id !== id);
  state.selectedResponseInterceptRecord = null;
  state.responseInterceptEditorSeedId = null;
  state.selectedResponseInterceptId = getVisibleResponseInterceptSummaries()[0]?.id ?? null;
  renderResponseIntercepts();
  updateInterceptQueueBadges();

  try {
    const response = await fetch(sessionQueryPath(`/api/response-intercepts/${id}/forward`, sessionId), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ response: editedResponse }),
    });
    await requireOkResponse(response, "Failed to forward intercepted response.");
    if (sessionId !== currentSessionId()) {
      return;
    }
    await loadResponseIntercepts(true);
    scheduleRefresh();
  } catch (e) {
    if (sessionId !== currentSessionId()) {
      return;
    }
    console.error(e);
    showToast(e?.message || "Failed to forward intercepted response.", "error");
    await loadResponseIntercepts(false).catch(console.error);
  }
}

async function dropSelectedResponseIntercept() {
  if (!state.selectedResponseInterceptRecord) return;

  const sessionId = currentSessionId();
  const id = state.selectedResponseInterceptRecord.id;

  // Optimistic UI
  state.responseIntercepts = state.responseIntercepts.filter((i) => i.id !== id);
  state.selectedResponseInterceptRecord = null;
  state.responseInterceptEditorSeedId = null;
  state.selectedResponseInterceptId = getVisibleResponseInterceptSummaries()[0]?.id ?? null;
  renderResponseIntercepts();
  updateInterceptQueueBadges();

  try {
    const response = await fetch(sessionQueryPath(`/api/response-intercepts/${id}/drop`, sessionId), { method: "POST" });
    await requireOkResponse(response, "Failed to drop intercepted response.");
    if (sessionId !== currentSessionId()) {
      return;
    }
    await loadResponseIntercepts(true);
    scheduleRefresh();
  } catch (e) {
    if (sessionId !== currentSessionId()) {
      return;
    }
    console.error(e);
    showToast(e?.message || "Failed to drop intercepted response.", "error");
    await loadResponseIntercepts(false).catch(console.error);
  }
}

function updateInterceptQueueBadges() {
  const reqCount = state.intercepts.length;
  const resCount = state.responseIntercepts.length;
  els.interceptQueueTabRequest.textContent = reqCount > 0 ? `Request Queue (${reqCount})` : "Request Queue";
  els.interceptQueueTabResponse.textContent = resCount > 0 ? `Response Queue (${resCount})` : "Response Queue";
}

function switchInterceptQueueTab(tab) {
  state.interceptQueueTab = tab;
  els.interceptQueueTabRequest.classList.toggle("active", tab === "request");
  els.interceptQueueTabResponse.classList.toggle("active", tab === "response");

  els.interceptRequestTable.classList.toggle("hidden", tab !== "request");
  els.responseInterceptTable.classList.toggle("hidden", tab !== "response");

  els.interceptRequestEditorPanel.classList.toggle("hidden", tab !== "request");
  els.interceptResponseEditorPanel.classList.toggle("hidden", tab !== "response");

  els.interceptRequestActions.classList.toggle("hidden", tab !== "request");
  els.responseInterceptActions.classList.toggle("hidden", tab !== "response");

  if (tab === "request") {
    renderIntercepts();
  } else {
    renderResponseIntercepts();
  }
}

async function openReplayFromSelection() {
  const record = await loadSelectedTransactionRecord();

  if (!record) {
    throw new Error("Selected transaction could not be loaded.");
  }
  if (record.kind === "tunnel") {
    throw new Error("Tunnel records cannot be sent to Replay.");
  }

  openTransactionRecordInReplay(record);
}

function resetReplay() {
  const tab = getActiveReplayTab();
  if (!tab || tab.type === "websocket") {
    return;
  }

  const activeHistoryEntry = getActiveRepeaterHistoryEntry(tab);
  if (activeHistoryEntry) {
    restoreRepeaterHistoryEntry(tab, activeHistoryEntry);
  } else {
    const fallback = tab.baseRequest || createDefaultEditableRequest();
    const target = authorityToTargetState(fallback.host, fallback.scheme);
    tab.requestText = buildEditableRawRequest(fallback);
    tab.targetScheme = target.scheme;
    tab.targetHost = target.host;
    tab.targetPort = target.port;
    tab.notice = "";
  }
  tab.responseRecord = null;
  scheduleWorkspaceStateSave();
  renderReplay();
}

let _replayAbortController = null;
let _replaySendingTabId = null;

function setReplaySending(sending) {
  els.sendReplayButton.disabled = sending;
  els.cancelReplayButton.disabled = !sending;
  if (els.replayFollowRedirectButton) {
    els.replayFollowRedirectButton.disabled = sending;
  }
  if (sending) {
    els.replayBackButton.disabled = true;
    els.replayForwardButton.disabled = true;
  } else {
    const tab = getActiveReplayTab();
    if (tab && tab.type !== "websocket") {
      syncReplayToolbar(tab);
    } else {
      els.replayBackButton.disabled = true;
      els.replayForwardButton.disabled = true;
    }
  }
}

function cancelReplaySend() {
  const sendingTabId = _replaySendingTabId;
  if (_replayAbortController) {
    _replayAbortController.abort();
    _replayAbortController = null;
  }
  _replaySendingTabId = null;
  const tab = sendingTabId
    ? state.replayTabs.find((item) => item.id === sendingTabId)
    : getActiveReplayTab();
  if (tab && tab.type !== "websocket") {
    tab.responseRecord = null;
    tab.notice = "Cancelled.";
    scheduleWorkspaceStateSave();
    renderReplayTabs();
  }
  setReplaySending(false);
  if (!sendingTabId || state.activeReplayTabId === sendingTabId) {
    els.replayResponseMeta.textContent = "Cancelled.";
    renderReplayResponseView("");
  }
}

function clearReplaySendInFlight() {
  if (_replayAbortController) {
    _replayAbortController.abort();
    _replayAbortController = null;
  }
  _replaySendingTabId = null;
  setReplaySending(false);
}

function isReplayTabStillCurrent(tab, tabId, sessionId) {
  return Boolean(
    tab
    && state.replayTabs.includes(tab)
    && tab.id === tabId
    && (state.activeSession?.id || null) === sessionId
  );
}

async function sendReplay() {
  const tab = getActiveReplayTab();
  if (!tab || tab.type === "websocket") {
    return;
  }

  const targetValidation = validateManualRepeaterTargetInput(
    els.replayHostInput.value,
    els.replayPortInput.value,
  );
  setReplayTargetInputValidity(targetValidation);
  if (!targetValidation.valid) {
    els.replayHostInput.reportValidity();
    els.replayPortInput.reportValidity();
    return;
  }

  let request, requestText, target;
  try {
    const fallback = tab.baseRequest || createDefaultEditableRequest();
    const replayReqText = tab.requestText || "";
    request = parseEditableRawRequest(replayReqText, fallback);
    requestText = replayReqText;
    target = getRepeaterTargetConfig(tab, request);
  } catch (e) {
    els.replayResponseMeta.textContent = "Error";
    renderReplayResponseView(e.message || "Failed to parse request.");
    return;
  }

  // Enter sending state after validation so parse errors do not discard the last response.
  tab.responseRecord = null;
  tab.notice = "";
  els.replayResponseMeta.textContent = "";
  renderReplayResponseView("");
  setReplaySending(true);
  const sendingTabId = tab.id;
  const sendingSessionId = state.activeSession?.id || null;

  // HTTP version: prefer dropdown selection, fall back to request line
  const httpVersion = normalizeReplayHttpVersion(tab.httpVersionMode || "")
    || replayHttpVersionFromText(requestText)
    || undefined;

  const replayController = new AbortController();
  _replayAbortController = replayController;
  _replaySendingTabId = sendingTabId;

  let response;
  try {
    const targetPayload = replayTargetOverridePayload(tab, request, target);
    response = await fetch("/api/replay/send", {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify({
        session_id: sendingSessionId,
        request,
        target: targetPayload,
        source_transaction_id: tab.sourceTransactionId,
        http_version: httpVersion,
      }),
      signal: replayController.signal,
    });
  } catch (e) {
    if (e.name === "AbortError") return; // cancelled
    if (!isReplayTabStillCurrent(tab, sendingTabId, sendingSessionId)) return;
    const notice = e?.message || "Failed to send replay.";
    const draftUnchanged = replaySentDraftUnchanged(tab, requestText, target);
    if (draftUnchanged) {
      tab.responseRecord = null;
      tab.notice = notice;
      applyReplaySentDraftIfUnchanged(tab, request, requestText, target);
    }
    recordRepeaterHistory(tab, {
      request,
      requestText,
      responseRecord: null,
      notice,
      target,
    });
    scheduleWorkspaceStateSave();
    if (draftUnchanged && state.activeReplayTabId === sendingTabId) {
      renderReplayResponseOnly(tab);
      syncReplayToolbar(tab);
    }
    showToast(notice, "error");
    return;
  } finally {
    if (_replayAbortController === replayController && _replaySendingTabId === sendingTabId) {
      _replayAbortController = null;
      _replaySendingTabId = null;
      setReplaySending(false);
    }
  }

  if (!state.replayTabs.some((item) => item.id === sendingTabId)) {
    return;
  }
  if (!isReplayTabStillCurrent(tab, sendingTabId, sendingSessionId)) {
    return;
  }

  if (!response.ok) {
    const errorPayload = await readReplaySendError(response);
    if (!isReplayTabStillCurrent(tab, sendingTabId, sendingSessionId)) {
      return;
    }
    const notice = errorPayload.notice;
    const responseRecord = errorPayload.responseRecord;
    const draftUnchanged = replaySentDraftUnchanged(tab, requestText, target);
    if (draftUnchanged) {
      tab.responseRecord = responseRecord;
      tab.notice = notice;
      applyReplaySentDraftIfUnchanged(tab, request, requestText, target);
    }
    recordRepeaterHistory(tab, {
      request,
      requestText,
      responseRecord,
      notice,
      target,
    });
    scheduleWorkspaceStateSave();
    if (draftUnchanged && state.activeReplayTabId === sendingTabId) {
      renderReplayResponseOnly(tab);
      syncReplayToolbar(tab);
    }
    showToast(notice, "error");
    if (responseRecord) {
      scheduleRefresh();
    }
    return;
  }

  const responseRecord = await response.json();
  if (!isReplayTabStillCurrent(tab, sendingTabId, sendingSessionId)) {
    return;
  }
  const draftUnchanged = replaySentDraftUnchanged(tab, requestText, target);
  if (draftUnchanged) {
    applyReplaySentDraftIfUnchanged(tab, request, requestText, target);
    tab.notice = "";
    tab.responseRecord = responseRecord;
  }
  recordRepeaterHistory(tab, {
    request,
    requestText,
    responseRecord,
    notice: "",
    target,
  });
  scheduleWorkspaceStateSave();
  // Only update response side — don't re-render request to preserve cursor/scroll
  if (draftUnchanged && state.activeReplayTabId === sendingTabId) {
    renderReplayResponseOnly(tab);
    syncReplayToolbar(tab);
    renderReplayViewTabs();
  } else if (!draftUnchanged && state.activeReplayTabId === sendingTabId) {
    syncReplayToolbar(tab);
    showToast("Replay response was saved to history; current request changed while sending.", "info", 4000);
  }
  scheduleRefresh();
}

async function readReplaySendError(response) {
  const fallback = `Replay failed (${response.status})`;
  const contentType = response.headers.get("content-type") || "";
  if (contentType.toLowerCase().includes("application/json")) {
    try {
      const payload = await response.json();
      return {
        notice: String(payload?.error || fallback),
        responseRecord: payload?.record || payload?.response_record || null,
      };
    } catch (_error) {
      return { notice: fallback, responseRecord: null };
    }
  }
  const text = await response.text();
  return {
    notice: text || fallback,
    responseRecord: null,
  };
}

function replaySentDraftUnchanged(tab, requestText, target) {
  if (!tab || tab.type === "websocket") return false;
  if ((tab.requestText || "") !== requestText) {
    return false;
  }
  const effectiveTarget = getRepeaterTargetConfig(tab, requestText ? deriveRepeaterRequest(tab) : null);
  return targetStatesEquivalent(effectiveTarget, target);
}

function applyReplaySentDraftIfUnchanged(tab, request, requestText, target) {
  if (!replaySentDraftUnchanged(tab, requestText, target)) {
    return;
  }
  tab.baseRequest = cloneEditableRequest(request);
  tab.targetScheme = target.scheme;
  tab.targetHost = target.host;
  tab.targetPort = target.port;
  tab.targetManuallyEdited = !targetStatesEquivalent(
    target,
    authorityToTargetState(request.host, request.scheme),
  );
  tab.requestText = requestText;
}

async function followRedirect() {
  const tab = getActiveReplayTab();
  if (!tab || !tab.responseRecord) return;
  if (_replaySendingTabId) return;

  const resp = tab.responseRecord.response;
  if (!resp) return;

  const status = tab.responseRecord.status;
  const responseHeaders = normalizedHeaders(resp.headers);
  const locationHeader = responseHeaders.find((h) => headerNameEquals(h, "location"));
  if (!locationHeader) return;

  // Build new request from current request
  const fallback = tab.baseRequest || createDefaultEditableRequest();
  const replayReqText = tab.requestText || "";
  let currentRequest;
  let httpVersion;
  try {
    currentRequest = parseEditableRawRequest(replayReqText, fallback);
    httpVersion = normalizeReplayHttpVersion(tab.httpVersionMode || "")
      || replayHttpVersionFromText(replayReqText)
      || undefined;
  } catch (e) {
    const message = e?.message || "Failed to parse request.";
    els.replayResponseMeta.textContent = "Error";
    showToast(message, "error");
    return;
  }

  const location = String(locationHeader.value || "").trim();
  let redirectUrl;
  try {
    const currentTarget = getRepeaterTargetConfig(tab, currentRequest);
    const currentUrl = buildUrlFromTarget(
      currentTarget.scheme || currentRequest.scheme || "https",
      currentTarget.host || currentRequest.host || "localhost",
      currentTarget.port || "",
      currentRequest.path || "/",
    );
    redirectUrl = new URL(location, currentUrl);
  } catch (_error) {
    showToast("Invalid redirect Location header", "error");
    return;
  }
  const newScheme = redirectUrl.protocol.replace(":", "") || currentRequest.scheme || "https";
  const newHost = stripIpv6Brackets(redirectUrl.hostname);
  const newPort = redirectUrl.port || (newScheme === "https" ? "443" : "80");
  const newPath = `${redirectUrl.pathname || "/"}${redirectUrl.search || ""}`;

  // 301/302/303 → GET (drop body), 307/308 → keep method
  const useGet = status === 301 || status === 302 || status === 303;
  const newMethod = useGet ? "GET" : currentRequest.method;
  const newBody = useGet ? "" : currentRequest.body;
  const newBodyEncoding = useGet ? "utf8" : (currentRequest.body_encoding || "utf8");

  // Collect Set-Cookie from response
  const setCookies = responseHeaders
    .filter((h) => headerNameEquals(h, "set-cookie"))
    .map((h) => {
      // Extract just the cookie name=value (before ;)
      const raw = h.value.split(";")[0].trim();
      return raw;
    })
    .filter(Boolean);

  // Merge with existing cookies
  let existingCookies = [];
  const currentHeaders = normalizedHeaders(currentRequest.headers);
  const cookieHeader = currentHeaders.find((h) => headerNameEquals(h, "cookie"));
  if (cookieHeader) {
    existingCookies = cookieHeader.value.split(";").map((c) => c.trim()).filter(Boolean);
  }

  // Override existing cookies with new ones (by name)
  const cookieMap = new Map();
  for (const c of existingCookies) {
    const eqIdx = c.indexOf("=");
    const name = eqIdx > 0 ? c.substring(0, eqIdx) : c;
    cookieMap.set(name, c);
  }
  for (const c of setCookies) {
    const eqIdx = c.indexOf("=");
    const name = eqIdx > 0 ? c.substring(0, eqIdx) : c;
    cookieMap.set(name, c);
  }

  // Build new headers
  const newHeaders = currentHeaders
    .filter((h) => !headerNameEquals(h, "cookie") && !headerNameEquals(h, "host"))
    .map((h) => ({ name: h.name, value: h.value }));

  // Add updated host
  const newHostPort = isDefaultPortForScheme(newScheme, newPort) ? "" : newPort;
  newHeaders.unshift({ name: "host", value: joinAuthority(newHost, newHostPort) });

  // Add merged cookies
  if (cookieMap.size > 0) {
    newHeaders.push({ name: "cookie", value: Array.from(cookieMap.values()).join("; ") });
  }

  const newRequest = {
    scheme: newScheme,
    host: newHost,
    method: newMethod,
    path: newPath,
    headers: newHeaders,
    body: newBody,
    body_encoding: newBodyEncoding,
    preview_truncated: false,
  };

  // Update tab target
  tab.targetScheme = newScheme;
  tab.targetHost = newHost;
  tab.targetPort = newPort;

  // Build raw request text and set in editor
  const requestText = buildEditableRawRequest(newRequest);
  tab.requestText = requestText;
  tab.baseRequest = cloneEditableRequest(newRequest);
  if (getCMView("replayReq")) {
    getCMView("replayReq").setContent(requestText);
  } else if (els.replayRequestEditor) {
    els.replayRequestEditor.value = requestText;
    renderReplayRequestHighlight(requestText);
  }

  // Send the follow request
  const target = { scheme: newScheme, host: newHost, port: newPort };
  const followingTabId = tab.id;
  const followingSessionId = state.activeSession?.id || null;
  setReplaySending(true);
  const replayController = new AbortController();
  _replayAbortController = replayController;
  _replaySendingTabId = followingTabId;
  let response;
  try {
    response = await fetch("/api/replay/send", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        session_id: followingSessionId,
        request: newRequest,
        target,
        source_transaction_id: null,
        http_version: httpVersion,
      }),
      signal: replayController.signal,
    });
  } catch (e) {
    if (e.name === "AbortError") return;
    if (!isReplayTabStillCurrent(tab, followingTabId, followingSessionId)) return;
    const notice = e?.message || "Failed to follow redirect.";
    const draftUnchanged = replaySentDraftUnchanged(tab, requestText, target);
    if (draftUnchanged) {
      tab.responseRecord = null;
      tab.notice = notice;
      applyReplaySentDraftIfUnchanged(tab, newRequest, requestText, target);
    }
    recordRepeaterHistory(tab, { request: newRequest, requestText, responseRecord: null, notice, target });
    scheduleWorkspaceStateSave();
    if (draftUnchanged && state.activeReplayTabId === followingTabId) {
      renderReplayResponseOnly(tab);
      syncReplayToolbar(tab);
    }
    showToast(notice, "error");
    return;
  } finally {
    if (_replayAbortController === replayController && _replaySendingTabId === followingTabId) {
      _replayAbortController = null;
      _replaySendingTabId = null;
      setReplaySending(false);
    }
  }

  if (!isReplayTabStillCurrent(tab, followingTabId, followingSessionId)) return;

  if (!response.ok) {
    const errorPayload = await readReplaySendError(response);
    if (!isReplayTabStillCurrent(tab, followingTabId, followingSessionId)) return;
    const notice = errorPayload.notice;
    const responseRecord = errorPayload.responseRecord;
    const draftUnchanged = replaySentDraftUnchanged(tab, requestText, target);
    if (draftUnchanged) {
      tab.responseRecord = responseRecord;
      tab.notice = notice;
      applyReplaySentDraftIfUnchanged(tab, newRequest, requestText, target);
    }
    recordRepeaterHistory(tab, { request: newRequest, requestText, responseRecord, notice, target });
    scheduleWorkspaceStateSave();
    if (draftUnchanged && state.activeReplayTabId === followingTabId) {
      renderReplayResponseOnly(tab);
      syncReplayToolbar(tab);
    }
    if (responseRecord) {
      scheduleRefresh();
    }
    return;
  }

  const responseRecord = await response.json();
  if (!isReplayTabStillCurrent(tab, followingTabId, followingSessionId)) return;
  const draftUnchanged = replaySentDraftUnchanged(tab, requestText, target);
  if (draftUnchanged) {
    applyReplaySentDraftIfUnchanged(tab, newRequest, requestText, target);
    tab.notice = "";
    tab.responseRecord = responseRecord;
  }
  recordRepeaterHistory(tab, { request: newRequest, requestText, responseRecord, notice: "", target });
  scheduleWorkspaceStateSave();
  if (draftUnchanged && state.activeReplayTabId === followingTabId) {
    renderReplayResponseOnly(tab);
    syncReplayToolbar(tab);
    renderReplayViewTabs();
  } else if (!draftUnchanged && state.activeReplayTabId === followingTabId) {
    syncReplayToolbar(tab);
    showToast("Redirect response was saved to history; current request changed while sending.", "info", 4000);
  }
  scheduleRefresh();
}

function openBlankReplayTab() {
  const tab = createReplayTab();
  state.replayTabs.push(tab);
  state.activeReplayTabId = tab.id;
  state.activeTool = "replay";
  scheduleWorkspaceStateSave();
  renderToolPanels();
}

function duplicateActiveReplayTab() {
  const tab = getActiveReplayTab();
  if (!tab) {
    return;
  }

  if (tab.type === "websocket") {
    if (state.activeReplayTabId === tab.id && els.wsHandshakeHeaders) {
      tab.wsHandshakeText = els.wsHandshakeHeaders.value;
      tab.wsHandshakeEdited = true;
    }
    createWsReplayTab({
      scheme: tab.wsScheme,
      host: tab.wsHost,
      port: tab.wsPort,
      path: tab.wsPath,
      headers: normalizedHeaders(tab.wsHeaders),
      handshakeText: tab.wsHandshakeText || "",
      handshakeEdited: !!tab.wsHandshakeEdited,
      editorText: tab.wsEditorText || "",
      messageType: tab.wsMessageType || "text",
      editorBodyEncoded: !!tab.wsEditorBodyEncoded,
      setupQueue: Array.isArray(tab.wsSetupQueue)
        ? tab.wsSetupQueue.map((item) => ({ ...item }))
        : [],
      customLabel: tab.customLabel || "",
    });
    return;
  }

  const fallback = tab.baseRequest || createDefaultEditableRequest();
  const requestText = tab.requestText || buildEditableRawRequest(fallback);
  let request = cloneEditableRequest(fallback);
  try {
    request = parseEditableRawRequest(requestText, fallback);
  } catch (_error) {
    request = cloneEditableRequest(fallback);
  }

  const target = getRepeaterTargetConfig(tab, request);

  tab.baseRequest = cloneEditableRequest(request);
  tab.requestText = requestText;
  tab.targetScheme = target.scheme;
  tab.targetHost = target.host;
  tab.targetPort = target.port;

  const historyEntries = Array.isArray(tab.historyEntries)
    ? tab.historyEntries.map(cloneRepeaterHistoryEntry)
    : [];
  const duplicate = createReplayTab({
    baseRequest: request,
    sourceTransactionId: tab.sourceTransactionId,
    notice: tab.notice,
    requestText,
    httpVersionMode: tab.httpVersionMode || "",
    customLabel: tab.customLabel || "",
    responseRecord: cloneTransactionRecord(tab.responseRecord),
    targetScheme: target.scheme,
    targetHost: target.host,
    targetPort: target.port,
    targetManuallyEdited: !!tab.targetManuallyEdited,
    historyEntries,
    historyIndex: normalizeRepeaterHistoryIndex(tab.historyIndex, historyEntries.length),
  });

  state.replayTabs.push(duplicate);
  state.activeReplayTabId = duplicate.id;
  scheduleWorkspaceStateSave();
  renderReplay();
}

function createReplayTab(seed = {}) {
  state.replayTabSequence += 1;
  const baseRequest = seed.baseRequest ? cloneEditableRequest(seed.baseRequest) : createDefaultEditableRequest();
  const target = authorityToTargetState(baseRequest.host, baseRequest.scheme);
  const normalizedTarget = normalizeRepeaterTargetInput(
    seed.targetHost ?? target.host,
    seed.targetPort ?? target.port,
    seed.targetScheme || target.scheme,
  );
  return {
    id: crypto.randomUUID(),
    sequence: state.replayTabSequence,
    customLabel: normalizeReplayTabCustomLabel(seed.customLabel || ""),
    pinned: !!seed.pinned,
    baseRequest,
    sourceTransactionId: seed.sourceTransactionId || null,
    notice: seed.notice || "",
    requestText: seed.requestText ?? buildEditableRawRequest(baseRequest),
    httpVersionMode: normalizeReplayHttpVersion(seed.httpVersionMode || ""),
    responseRecord: cloneTransactionRecord(seed.responseRecord),
    targetScheme: normalizedTarget.scheme,
    targetHost: normalizedTarget.host,
    targetPort: normalizedTarget.port,
    targetManuallyEdited: !!seed.targetManuallyEdited,
    historyEntries: Array.isArray(seed.historyEntries) ? seed.historyEntries.map(cloneRepeaterHistoryEntry) : [],
    historyIndex: normalizeRepeaterHistoryIndex(seed.historyIndex, Array.isArray(seed.historyEntries) ? seed.historyEntries.length : 0),
  };
}

function ensureRepeaterTab() {
  if (!state.replayTabs.length) {
    state.replayTabSequence = 0;
    const tab = createReplayTab();
    state.replayTabs = [tab];
    state.activeReplayTabId = tab.id;
    return tab;
  }

  if (!state.replayTabs.some((tab) => tab.id === state.activeReplayTabId)) {
    state.activeReplayTabId = state.replayTabs[0].id;
  }

  return getActiveReplayTab();
}

function getActiveReplayTab() {
  return state.replayTabs.find((tab) => tab.id === state.activeReplayTabId) || null;
}

function getReplayTabVisualOrder() {
  return [...state.replayTabs].sort((a, b) => {
    if (a.pinned && !b.pinned) return -1;
    if (!a.pinned && b.pinned) return 1;
    return 0;
  });
}

function renderReplayTabs() {
  const sortedTabs = getReplayTabVisualOrder();

  els.replayTabStrip.innerHTML = sortedTabs
    .map((tab) => {
      const isActive = tab.id === state.activeReplayTabId;
      const active = isActive ? "active" : "";
      const pinned = tab.pinned ? "pinned" : "";
      const pinBtnState = tab.pinned ? "on" : (!isActive ? "idle" : "");
      const pinHiddenAttrs = pinBtnState === "idle" ? 'tabindex="-1"' : "";
      const pinLabel = tab.pinned ? "Unpin tab" : "Pin tab";
      const pinBtn = `<button class="replay-tab-pin-btn ${pinBtnState}" type="button" aria-label="${pinLabel}" title="${pinLabel}" aria-pressed="${tab.pinned ? "true" : "false"}" ${pinHiddenAttrs}>\uD83D\uDCCC</button>`;
      const autoLabel = replayTabAutoLabel(tab);
      const label = replayTabLabel(tab);
      const title = tab.customLabel ? `${label} / ${autoLabel}` : label;
      const labelControl = state.replayRenamingTabId === tab.id
        ? `<input class="replay-tab-name-input" type="text" value="${escapeHtml(tab.customLabel || "")}" placeholder="${escapeHtml(autoLabel)}" maxlength="80" aria-label="Replay tab name">`
        : `<button class="replay-tab-button" type="button" title="${escapeHtml(title)}">${escapeHtml(label)}</button>`;
      return `
        <div class="replay-tab ${active} ${pinned}" data-replay-tab-id="${tab.id}">
          ${pinBtn}
          ${labelControl}
          <button class="replay-tab-close" type="button" aria-label="Close replay tab">\u00d7</button>
        </div>
      `;
    })
    .join("");

  Array.from(els.replayTabStrip.querySelectorAll(".replay-tab")).forEach((tabElement) => {
    const id = tabElement.dataset.replayTabId;
    const nameInput = tabElement.querySelector(".replay-tab-name-input");
    if (nameInput) {
      nameInput.addEventListener("click", (event) => event.stopPropagation());
      nameInput.addEventListener("keydown", (event) => {
        if (event.key === "Enter") {
          event.preventDefault();
          commitReplayTabRename(id, nameInput.value);
        } else if (event.key === "Escape") {
          event.preventDefault();
          state.replayRenamingTabId = null;
          renderReplayTabs();
        }
      });
      nameInput.addEventListener("blur", () => {
        commitReplayTabRename(id, nameInput.value);
      });
      requestAnimationFrame(() => {
        if (state.replayRenamingTabId === id) {
          nameInput.focus();
          nameInput.select();
        }
      });
    }
    tabElement.querySelector(".replay-tab-button")?.addEventListener("click", () => {
      if (state.activeReplayTabId === id) {
        beginReplayTabRename(id);
        return;
      }
      state.activeReplayTabId = id;
      state.replayRenamingTabId = null;
      scheduleWorkspaceStateSave();
      renderReplay();
    });
    tabElement.querySelector(".replay-tab-pin-btn")?.addEventListener("click", (event) => {
      event.stopPropagation();
      toggleReplayTabPin(id);
    });
    tabElement.querySelector(".replay-tab-close")?.addEventListener("click", (event) => {
      event.stopPropagation();
      closeRepeaterTab(id);
    });
  });

  // Scroll active tab into view
  scrollActiveReplayTabIntoView();
}

function refreshReplayTabLabel(id) {
  if (!els.replayTabStrip) return;
  const tab = state.replayTabs.find((item) => item.id === id);
  if (!tab) return;
  const tabElement = Array.from(els.replayTabStrip.querySelectorAll(".replay-tab"))
    .find((element) => element.dataset.replayTabId === id);
  if (!tabElement) return;

  const autoLabel = replayTabAutoLabel(tab);
  const label = replayTabLabel(tab);
  const title = tab.customLabel ? `${label} / ${autoLabel}` : label;
  const button = tabElement.querySelector(".replay-tab-button");
  if (button) {
    button.textContent = label;
    button.title = title;
  }
  const input = tabElement.querySelector(".replay-tab-name-input");
  if (input) {
    input.placeholder = autoLabel;
  }
}

function beginReplayTabRename(id) {
  if (!state.replayTabs.some((tab) => tab.id === id)) {
    return;
  }
  state.replayRenamingTabId = id;
  renderReplayTabs();
}

function commitReplayTabRename(id, value) {
  if (state.replayRenamingTabId !== id) {
    return;
  }
  const tab = state.replayTabs.find((item) => item.id === id);
  if (!tab) {
    state.replayRenamingTabId = null;
    renderReplayTabs();
    return;
  }
  const previousLabel = tab.customLabel || "";
  tab.customLabel = normalizeReplayTabCustomLabel(value);
  const attemptedLabel = tab.customLabel;
  state.replayRenamingTabId = null;
  scheduleWorkspaceStateSave();
  flushWorkspaceState().catch((error) => {
    if (tab.customLabel === attemptedLabel) {
      tab.customLabel = previousLabel;
    }
    handleWorkspaceActionError(error);
    renderReplayTabs();
  });
  renderReplayTabs();
}

function normalizeReplayTabCustomLabel(value) {
  return String(value || "").replace(/\s+/g, " ").trim().slice(0, 80);
}

function toggleReplayTabPin(id) {
  const tab = state.replayTabs.find((t) => t.id === id);
  if (!tab) return;
  const previousPinned = !!tab.pinned;
  tab.pinned = !tab.pinned;
  const attemptedPinned = tab.pinned;
  // Flush immediately so pin state survives quick app quit
  scheduleWorkspaceStateSave();
  flushWorkspaceState().catch((error) => {
    if (tab.pinned === attemptedPinned) {
      tab.pinned = previousPinned;
    }
    handleWorkspaceActionError(error);
    renderReplayTabs();
  });
  renderReplayTabs();
}


function scrollActiveReplayTabIntoView() {
  const activeTab = els.replayTabStrip.querySelector(".replay-tab.active");
  if (activeTab) {
    activeTab.scrollIntoView({ behavior: "smooth", inline: "nearest", block: "nearest" });
  }
}

function closeRepeaterTab(id) {
  const index = state.replayTabs.findIndex((tab) => tab.id === id);
  if (index === -1) {
    return;
  }

  const visualOrderBeforeClose = getReplayTabVisualOrder().map((tab) => tab.id);
  const visualIndex = visualOrderBeforeClose.indexOf(id);
  const closingTab = state.replayTabs[index];
  if (closingTab.type === "websocket") {
    cleanupWsReplayTab(closingTab);
  }
  if (_replaySendingTabId === id) {
    const controller = _replayAbortController;
    _replayAbortController = null;
    _replaySendingTabId = null;
    if (controller) {
      controller.abort();
    }
    setReplaySending(false);
  }
  if (state.replayRenamingTabId === id) {
    state.replayRenamingTabId = null;
  }

  state.replayTabs.splice(index, 1);
  if (!state.replayTabs.length) {
    state.replayTabSequence = 0;
    const replacement = createReplayTab();
    state.replayTabs = [replacement];
    state.activeReplayTabId = replacement.id;
  } else if (state.activeReplayTabId === id) {
    const remainingVisualIds = visualOrderBeforeClose.filter((tabId) =>
      tabId !== id && state.replayTabs.some((tab) => tab.id === tabId)
    );
    const replacementIndex = Math.min(Math.max(0, visualIndex - 1), remainingVisualIds.length - 1);
    state.activeReplayTabId = remainingVisualIds[replacementIndex] || state.replayTabs[Math.max(0, index - 1)].id;
  }
  scheduleWorkspaceStateSave();
  renderReplay();
}

function replayTabLabel(tab) {
  if (tab.customLabel) {
    return tab.customLabel;
  }
  return replayTabAutoLabel(tab);
}

function replayTabAutoLabel(tab) {
  if (tab.type === "websocket") {
    const host = tab.wsHost || "draft";
    return `${tab.sequence}. WS ${host}`;
  }
  const request = deriveRepeaterRequest(tab);
  const target = getRepeaterTargetConfig(tab, request);
  const authority = joinAuthority(target.host, target.port) || "draft";
  return `${tab.sequence}. ${request.method} ${authority}`;
}

function deriveRepeaterRequest(tab) {
  const fallback = tab.baseRequest || createDefaultEditableRequest();
  try {
    return parseEditableRawRequest(tab.requestText, fallback);
  } catch (_error) {
    return cloneEditableRequest(fallback);
  }
}

async function applyReplayTargetFields() {
  const tab = getActiveReplayTab();
  if (!tab) {
    return;
  }

  const validation = validateManualRepeaterTargetInput(
    els.replayHostInput.value,
    els.replayPortInput.value,
  );
  setReplayTargetInputValidity(validation);
  if (!validation.valid) {
    return;
  }

  const normalizedTarget = normalizeRepeaterTargetInput(
    els.replayHostInput.value,
    els.replayPortInput.value,
    els.replaySchemeSelect.value || "https",
  );
  tab.targetScheme = normalizedTarget.scheme;
  tab.targetHost = normalizedTarget.host;
  tab.targetPort = normalizedTarget.port;
  tab.targetManuallyEdited = true;
  tab.responseRecord = null;
  scheduleWorkspaceStateSave();
  renderReplay();
}

function setReplayTargetInputValidity(validation) {
  if (!els.replayHostInput || !els.replayPortInput) {
    return;
  }
  els.replayHostInput.setCustomValidity(validation.hostError || "");
  els.replayPortInput.setCustomValidity(validation.portError || "");
  els.replayHostInput.toggleAttribute("aria-invalid", !!validation.hostError);
  els.replayPortInput.toggleAttribute("aria-invalid", !!validation.portError);
}

function applyRepeaterTargetOverride(request, target) {
  request.scheme = target.scheme || request.scheme;
  const authority = joinAuthority(target.host, target.port);
  if (authority) {
    request.host = authority;
  }
}

function getRepeaterTargetConfig(tab, request = null) {
  const fallback = request || deriveRepeaterRequest(tab);
  const derived = authorityToTargetState(fallback.host, fallback.scheme);
  const normalizedOverride = normalizeRepeaterTargetInput(
    tab.targetHost,
    tab.targetPort,
    tab.targetScheme || derived.scheme,
  );
  const target = {
    scheme: normalizedOverride.scheme || derived.scheme,
    host: normalizedOverride.host || derived.host,
    port: normalizedOverride.port || derived.port,
  };
  if (repeaterTargetLooksStale(tab, derived, target)) {
    return derived;
  }
  return target;
}

function replayTargetOverridePayload(tab, request, target) {
  if (!request || !target) return null;
  const requestTarget = authorityToTargetState(request.host, request.scheme);
  if (targetStatesEquivalent(target, requestTarget)) {
    return null;
  }
  return {
    scheme: target.scheme,
    host: target.host,
    port: target.port,
  };
}

function repeaterTargetLooksStale(tab, derivedTarget, target) {
  if (!tab?.baseRequest) {
    return false;
  }
  if (tab.targetManuallyEdited) {
    return false;
  }
  const baseTarget = authorityToTargetState(tab.baseRequest.host, tab.baseRequest.scheme);
  return targetStatesEquivalent(target, baseTarget)
    && !targetStatesEquivalent(derivedTarget, baseTarget);
}

function targetStatesEquivalent(left, right) {
  const scheme = String(left?.scheme || right?.scheme || "https").toLowerCase();
  const leftScheme = String(left?.scheme || scheme).toLowerCase();
  const rightScheme = String(right?.scheme || scheme).toLowerCase();
  if (leftScheme !== rightScheme) {
    return false;
  }
  const leftAuthority = joinAuthority(left?.host, left?.port);
  const rightAuthority = joinAuthority(right?.host, right?.port);
  if (!leftAuthority || !rightAuthority) {
    return leftAuthority === rightAuthority;
  }
  return httpRequestAuthoritiesEquivalent(leftAuthority, rightAuthority, scheme);
}

function authorityToTargetState(authority, scheme = "https") {
  const fallbackScheme = scheme || "https";
  if (!authority) {
    return { scheme: fallbackScheme, host: "", port: "" };
  }

  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(authority)) {
    try {
      const parsed = new URL(authority);
      return {
        scheme: parsed.protocol ? parsed.protocol.replace(":", "") : fallbackScheme,
        host: parsed.hostname ? stripIpv6Brackets(parsed.hostname) : authority,
        port: parsed.port || "",
      };
    } catch (_error) {
      return {
        scheme: fallbackScheme,
        host: authority,
        port: "",
      };
    }
  }

  try {
    const parsed = new URL(`${fallbackScheme}://${authority}`);
    return {
      scheme: fallbackScheme,
      host: parsed.hostname ? stripIpv6Brackets(parsed.hostname) : authority,
      port: parsed.port || "",
    };
  } catch (_error) {
    return {
      scheme: fallbackScheme,
      host: authority,
      port: "",
    };
  }
}

function joinAuthority(host, port) {
  const normalizedHost = String(host || "").trim();
  const normalizedPort = normalizePortValue(port);
  if (!normalizedHost) {
    return "";
  }

  let authorityHost = normalizedHost;
  if (authorityHost.includes(":") && !authorityHost.startsWith("[") && !authorityHost.endsWith("]")) {
    authorityHost = `[${authorityHost}]`;
  }

  return normalizedPort ? `${authorityHost}:${normalizedPort}` : authorityHost;
}

function isDefaultPortForScheme(scheme, port) {
  const normalizedScheme = String(scheme || "").toLowerCase();
  const normalizedPort = normalizePortValue(port);
  return (normalizedScheme === "https" && normalizedPort === "443")
    || (normalizedScheme === "http" && normalizedPort === "80")
    || (normalizedScheme === "wss" && normalizedPort === "443")
    || (normalizedScheme === "ws" && normalizedPort === "80");
}

function buildUrlFromTarget(scheme, host, port, path = "/") {
  const normalizedScheme = scheme || "https";
  const rawPath = String(path || "/");
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(rawPath)) {
    return rawPath;
  }
  if (rawPath.startsWith("//")) {
    return `${normalizedScheme}:${rawPath}`;
  }
  const target = normalizeRepeaterTargetInput(host, port, normalizedScheme);
  const normalizedPort = isDefaultPortForScheme(normalizedScheme, target.port) ? "" : target.port;
  const authority = joinAuthority(target.host, normalizedPort);
  const normalizedPath = rawPath.startsWith("/") ? rawPath : `/${rawPath}`;
  return `${normalizedScheme}://${authority || "localhost"}${normalizedPath}`;
}

function normalizeRepeaterTargetInput(host, port, scheme = "https") {
  const normalizedScheme = scheme || "https";
  const normalizedHost = String(host || "").trim();
  const parsedHost = authorityToTargetState(normalizedHost, normalizedScheme);
  const normalizedPort = normalizePortValue(port);
  const effectiveScheme = parsedHost.scheme || normalizedScheme;
  return {
    scheme: effectiveScheme,
    host: normalizedHost ? parsedHost.host : "",
    port: (parsedHost.port && normalizedHost)
      ? parsedHost.port
      : (normalizedHost ? (normalizedPort || defaultHttpPortForScheme(effectiveScheme)) : normalizedPort),
  };
}

function validateManualRepeaterTargetInput(host, port) {
  const rawHost = String(host || "").trim();
  const rawPort = String(port ?? "").trim();
  let hostError = "";
  let portError = "";

  if (rawHost) {
    const absoluteTarget = /^[a-z][a-z0-9+.-]*:\/\//i.test(rawHost);
    if (/\s/.test(rawHost) || rawHost.includes("\\") || rawHost.includes("@")) {
      hostError = "Target host must not include whitespace, user info, or URL components.";
    } else if (absoluteTarget) {
      try {
        const parsed = new URL(rawHost);
        const scheme = parsed.protocol.replace(":", "").toLowerCase();
        const hasUrlComponents = parsed.username
          || parsed.password
          || (parsed.pathname && parsed.pathname !== "/")
          || parsed.search
          || parsed.hash;
        if (scheme !== "http" && scheme !== "https") {
          hostError = "Target URL scheme must be HTTP or HTTPS.";
        } else if (hasUrlComponents) {
          hostError = "Target host must not include path, query, fragment, or credentials.";
        } else if (parsed.port && rawPort && normalizePortValue(rawPort) !== parsed.port) {
          portError = `Port conflicts with target URL port ${parsed.port}.`;
        }
      } catch (_error) {
        hostError = "Target host is not a valid URL.";
      }
    } else if (/[/?#]/.test(rawHost)) {
      hostError = "Target host must not include path, query, or fragment.";
    } else if (rawHost.includes(":") && !isLikelyIpv6Literal(rawHost)) {
      hostError = "Target host must not include a port; use the Port field.";
    }
  }

  if (rawPort && (!/^\d+$/.test(rawPort) || !normalizePortValue(rawPort))) {
    portError = "Port must be a number from 1 to 65535.";
  }

  return {
    valid: !hostError && !portError,
    hostError,
    portError,
  };
}

function validateWsReplayTargetInput(scheme, host, port, path) {
  const normalizedScheme = String(scheme || "").toLowerCase();
  const base = validateManualRepeaterTargetInput(host, port);
  let schemeError = "";
  let pathError = "";
  if (!["ws", "wss"].includes(normalizedScheme)) {
    schemeError = "WebSocket scheme must be WS or WSS.";
  }
  const rawHost = String(host || "").trim();
  if (!rawHost) {
    base.hostError = "WebSocket host is required.";
  } else if (/^[a-z][a-z0-9+.-]*:\/\//i.test(rawHost)) {
    base.hostError = "WebSocket host must not include URL components.";
  }
  const rawPort = String(port ?? "").trim();
  if (!rawPort) {
    base.portError = "WebSocket port is required.";
  }
  const rawPath = String(path || "").trim();
  if (!rawPath) {
    pathError = "WebSocket path is required.";
  } else if (!rawPath.startsWith("/") || rawPath.startsWith("//") || /[\s#]/.test(rawPath)) {
    pathError = "WebSocket path must start with / and must not include whitespace or fragment.";
  }
  return {
    valid: !schemeError && !base.hostError && !base.portError && !pathError,
    schemeError,
    hostError: base.hostError,
    portError: base.portError,
    pathError,
  };
}

function setWsReplayTargetInputValidity(validation) {
  if (!els.wsSchemeSelect || !els.wsHostInput || !els.wsPortInput || !els.wsPathInput) {
    return;
  }
  els.wsSchemeSelect.setCustomValidity(validation.schemeError || "");
  els.wsHostInput.setCustomValidity(validation.hostError || "");
  els.wsPortInput.setCustomValidity(validation.portError || "");
  els.wsPathInput.setCustomValidity(validation.pathError || "");
  els.wsSchemeSelect.toggleAttribute("aria-invalid", !!validation.schemeError);
  els.wsHostInput.toggleAttribute("aria-invalid", !!validation.hostError);
  els.wsPortInput.toggleAttribute("aria-invalid", !!validation.portError);
  els.wsPathInput.toggleAttribute("aria-invalid", !!validation.pathError);
}

function isLikelyIpv6Literal(host) {
  const normalized = String(host || "").trim();
  if (normalized.startsWith("[") || normalized.endsWith("]")) {
    return normalized.startsWith("[") && normalized.endsWith("]");
  }
  return (normalized.match(/:/g) || []).length >= 2;
}

function stripIpv6Brackets(host) {
  return host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
}

function normalizePortValue(value) {
  const normalized = String(value ?? "").trim();
  if (!normalized) {
    return "";
  }

  if (!/^\d+$/.test(normalized)) {
    return "";
  }
  const parsed = Number(normalized);
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > 65535) {
    return "";
  }

  return String(parsed);
}

function strictIntegerInRange(value, min, max) {
  const normalized = String(value ?? "").trim();
  if (!normalized || !/^\d+$/.test(normalized)) {
    return null;
  }
  const parsed = Number(normalized);
  return Number.isSafeInteger(parsed) && parsed >= min && parsed <= max ? parsed : null;
}

function defaultHttpPortForScheme(scheme) {
  return String(scheme || "").toLowerCase() === "http" ? "80" : "443";
}

function normalizeHttpRequestAuthority(authority, scheme = "https") {
  const normalizedScheme = String(scheme || "https").toLowerCase();
  const target = authorityToTargetState(authority, normalizedScheme);
  return {
    host: stripIpv6Brackets(String(target.host || "").trim()).toLowerCase(),
    port: normalizePortValue(target.port) || defaultHttpPortForScheme(normalizedScheme),
  };
}

function httpRequestAuthoritiesEquivalent(left, right, scheme = "https") {
  const normalizedLeft = normalizeHttpRequestAuthority(left, scheme);
  const normalizedRight = normalizeHttpRequestAuthority(right, scheme);
  return normalizedLeft.host === normalizedRight.host && normalizedLeft.port === normalizedRight.port;
}

function normalizeRepeaterHistoryIndex(index, length) {
  if (!Number.isFinite(index) || length <= 0) {
    return null;
  }

  return clamp(Math.trunc(index), 0, length - 1);
}

function cloneRepeaterHistoryEntry(entry) {
  const normalizedTarget = normalizeRepeaterTargetInput(
    entry.targetHost,
    entry.targetPort,
    entry.targetScheme || "https",
  );
  return {
    request: cloneEditableRequest(entry.request),
    requestText: entry.requestText || "",
    httpVersionMode: normalizeReplayHttpVersion(entry.httpVersionMode || "")
      || replayHttpVersionFromText(entry.requestText || ""),
    responseRecord: cloneTransactionRecord(entry.responseRecord),
    notice: entry.notice || "",
    targetScheme: normalizedTarget.scheme,
    targetHost: normalizedTarget.host,
    targetPort: normalizedTarget.port,
  };
}

function recordRepeaterHistory(tab, snapshot) {
  const entry = {
    request: cloneEditableRequest(snapshot.request),
    requestText: snapshot.requestText || "",
    httpVersionMode: normalizeReplayHttpVersion(snapshot.httpVersionMode || tab.httpVersionMode || "")
      || replayHttpVersionFromText(snapshot.requestText || ""),
    responseRecord: cloneTransactionRecord(snapshot.responseRecord),
    notice: snapshot.notice || "",
    targetScheme: snapshot.target.scheme || "https",
    targetHost: snapshot.target.host || "",
    targetPort: normalizePortValue(snapshot.target.port),
  };

  const baseEntries = Array.isArray(tab.historyEntries) ? tab.historyEntries : [];
  const currentIndex = normalizeRepeaterHistoryIndex(tab.historyIndex, baseEntries.length);
  const trimmedEntries = currentIndex == null ? baseEntries : baseEntries.slice(0, currentIndex + 1);
  trimmedEntries.push(entry);
  if (trimmedEntries.length > REPEATER_HISTORY_LIMIT) {
    trimmedEntries.splice(0, trimmedEntries.length - REPEATER_HISTORY_LIMIT);
  }

  tab.historyEntries = trimmedEntries;
  tab.historyIndex = trimmedEntries.length - 1;
}

function getActiveRepeaterHistoryEntry(tab) {
  if (!Array.isArray(tab.historyEntries) || !tab.historyEntries.length) {
    return null;
  }

  const index = normalizeRepeaterHistoryIndex(tab.historyIndex, tab.historyEntries.length);
  return index == null ? null : tab.historyEntries[index];
}

function restoreRepeaterHistoryEntry(tab, entry) {
  const fallbackTarget = authorityToTargetState(entry.request.host, entry.request.scheme);
  const normalizedTarget = normalizeRepeaterTargetInput(
    entry.targetHost || fallbackTarget.host,
    entry.targetPort || fallbackTarget.port,
    entry.targetScheme || entry.request.scheme || "https",
  );
  tab.baseRequest = cloneEditableRequest(entry.request);
  tab.requestText = entry.requestText || buildEditableRawRequest(entry.request);
  tab.httpVersionMode = normalizeReplayHttpVersion(entry.httpVersionMode || "")
    || replayHttpVersionFromText(tab.requestText);
  tab.responseRecord = entry.responseRecord || null;
  tab.notice = entry.notice || "";
  tab.targetScheme = normalizedTarget.scheme;
  tab.targetHost = normalizedTarget.host;
  tab.targetPort = normalizedTarget.port;
  tab.targetManuallyEdited = !targetStatesEquivalent(
    normalizedTarget,
    authorityToTargetState(entry.request.host, entry.request.scheme),
  );
  // Clear hex state so it re-generates from the new requestText
  tab.requestBytes = null;
  tab.requestOriginalBytes = null;
}

function canNavigateReplayHistory(tab, direction) {
  if (!Array.isArray(tab.historyEntries) || tab.historyEntries.length <= 1) {
    return false;
  }

  const index = normalizeRepeaterHistoryIndex(tab.historyIndex, tab.historyEntries.length);
  if (index == null) {
    return false;
  }

  const nextIndex = index + direction;
  return nextIndex >= 0 && nextIndex < tab.historyEntries.length;
}

function navigateReplayHistory(direction) {
  const tab = getActiveReplayTab();
  if (!tab || !canNavigateReplayHistory(tab, direction)) {
    return;
  }

  const nextIndex = clamp(tab.historyIndex + direction, 0, tab.historyEntries.length - 1);
  const entry = tab.historyEntries[nextIndex];
  if (!entry) {
    return;
  }

  tab.historyIndex = nextIndex;
  restoreRepeaterHistoryEntry(tab, entry);
  scheduleWorkspaceStateSave();
  renderReplay();
}

function createDefaultEditableRequest() {
  return {
    scheme: "https",
    host: "",
    method: "GET",
    path: "/",
    headers: [],
    body: "",
    body_encoding: "utf8",
    preview_truncated: false,
  };
}

function cloneEditableRequest(request) {
  const source = request || {};
  return {
    scheme: source.scheme,
    host: source.host,
    method: source.method,
    path: source.path,
    headers: normalizedHeaders(source.headers),
    body: source.body,
    body_encoding: source.body_encoding,
    preview_truncated: source.preview_truncated,
  };
}

function cloneTransactionRecord(record) {
  return record ? JSON.parse(JSON.stringify(record)) : null;
}

function buildTruncatedBodyNotice(record, tool) {
  const request = record?.request || {};
  const previewCap = state.settings?.body_preview_bytes || String(request.body_preview || "").length;
  const originalSize = request.decoded_body_size ?? request.body_size;
  return `${tool} cannot safely resend this capture yet. The original request body is ${formatSize(originalSize)}, but only a ${formatSize(previewCap)} preview was captured. Increase the preview cap and capture it again, or paste the full body manually before sending.`;
}

function isRequestPreviewTruncated(record) {
  return Boolean(record?.request?.preview_truncated);
}

function openCertificateModal() {
  openDisplaySettingsModal();
}

function closeCertificateModal() {
  closeDisplaySettingsModal();
}

function openDisplaySettingsModal() {
  hydrateDisplaySettingsForm();
  applyDisplaySettingsState();
  displaySettingsPreviewActive = false;
  els.displaySettingsModal.classList.remove("hidden");
}

function closeDisplaySettingsModal() {
  if (displaySettingsPreviewActive) {
    hydrateDisplaySettingsForm();
    applyDisplaySettingsState();
    displaySettingsPreviewActive = false;
  }
  els.displaySettingsModal.classList.add("hidden");
}

function openFilterModal() {
  hydrateFilterForm();
  els.filterModal.classList.remove("hidden");
}

function closeFilterModal() {
  els.filterModal.classList.add("hidden");
}

function isModalVisible(modal) {
  return Boolean(modal) && !modal.classList.contains("hidden");
}

function getActiveModalAction() {
  if (isModalVisible(els.displaySettingsModal)) {
    return {
      close: closeDisplaySettingsModal,
      apply: saveDisplaySettingsFromForm,
    };
  }

  if (isModalVisible(els.filterModal)) {
    return {
      close: closeFilterModal,
      apply: applyFilterSettings,
    };
  }

  if (isModalVisible(els.curlImportModal)) {
    return {
      close: closeCurlImportModal,
      apply: null,
    };
  }

  return null;
}

function loadDisplaySettings() {
  state.displaySettings = createDefaultDisplaySettings();
  applyDisplaySettingsState();
}

function sanitizeDisplaySettings(candidate) {
  const defaults = createDefaultDisplaySettings();
  const parsedSize = Number(candidate?.sizePx);
  return {
    sizePx: Number.isFinite(parsedSize) ? clamp(Math.round(parsedSize), 8, 20) : defaults.sizePx,
    theme: DISPLAY_THEME_OPTIONS.has(candidate?.theme) ? candidate.theme : defaults.theme,
    uiFont: DISPLAY_UI_FONT_OPTIONS.has(candidate?.uiFont) ? candidate.uiFont : defaults.uiFont,
    monoFont: DISPLAY_MONO_FONT_OPTIONS.has(candidate?.monoFont) ? candidate.monoFont : defaults.monoFont,
  };
}

function loadHistoryColumnWidths() {
  state.historyColumnWidths = createDefaultHistoryColumnWidths();
  state.historyColumnOrder = [...DEFAULT_HISTORY_COLUMN_ORDER];
  applyHistoryColumnWidths();
}

function sanitizeHistoryColumnWidths(candidate) {
  return Object.fromEntries(
    Object.entries(HISTORY_COLUMN_RULES).map(([key, limits]) => {
      const parsed = Number(candidate?.[key]);
      const next = Number.isFinite(parsed) ? parsed : limits.default;
      return [key, clamp(Math.round(next), limits.min, limits.max)];
    }),
  );
}

function saveHistoryColumnWidths() {
  scheduleUiSettingsSave();
}

function applyHistoryColumnWidths() {
  if (!els.historyTable) {
    return;
  }

  let totalWidth = 0;
  Object.entries(state.historyColumnWidths).forEach(([key, width]) => {
    els.historyTable.style.setProperty(`--history-col-${key}`, `${width}px`);
    totalWidth += width;
  });
  els.historyTable.style.setProperty("--history-table-width", `${Math.max(totalWidth, 1160)}px`);
}

function sanitizeHistoryColumnOrder(candidate) {
  if (!Array.isArray(candidate) || candidate.length === 0) {
    return [...DEFAULT_HISTORY_COLUMN_ORDER];
  }
  const validKeys = new Set(Object.keys(HISTORY_COLUMN_DEFS));
  const seen = new Set();
  const order = [];
  for (const key of candidate) {
    if (validKeys.has(key) && !seen.has(key)) {
      order.push(key);
      seen.add(key);
    }
  }
  for (const key of DEFAULT_HISTORY_COLUMN_ORDER) {
    if (!seen.has(key)) {
      order.push(key);
    }
  }
  return order;
}

function renderHistoryHeader() {
  const thead = els.historyTable?.querySelector("thead tr");
  if (!thead) return;

  thead.innerHTML = state.historyColumnOrder
    .map((colKey) => {
      const def = HISTORY_COLUMN_DEFS[colKey];
      if (!def) return "";
      return `
        <th class="${def.cssClass}" data-column-key="${colKey}" draggable="true">
          <button class="sort-header" data-sort-key="${def.sortKey}" type="button">
            <span>${def.label}</span>
            <span class="sort-indicator" aria-hidden="true">\u2195</span>
          </button>
          <span class="column-resize-handle" data-column-key="${colKey}" aria-hidden="true"></span>
        </th>
      `;
    })
    .join("");

  sortHeaders = Array.from(els.historyTable.querySelectorAll(".sort-header"));
  historyColumnHandles = Array.from(els.historyTable.querySelectorAll(".column-resize-handle"));

  sortHeaders.forEach((header) => {
    header.addEventListener("click", () => {
      toggleSort(header.dataset.sortKey);
    });
  });

  bindHistoryColumnResizers();
  bindColumnDragAndDrop();
  renderSortHeaders();
}

function renderHistoryCell(colKey, item, entry) {
  switch (colKey) {
    case "index":
      return `<td>${item.sequence != null ? item.sequence : entry.index + 1}</td>`;
    case "host":
      return `<td class="cell-host">${escapeHtml(item.host)}</td>`;
    case "method":
      return `<td><span class="method-pill ${methodTone(item.method)}">${escapeHtml(item.method)}</span></td>`;
    case "path":
      return `<td class="cell-url">${escapeHtml(item.path || "(CONNECT tunnel)")}</td>`;
    case "status":
      return `<td><span class="status-pill-row ${statusTone(item.status)}">${escapeHtml(formatStatus(item.status))}</span></td>`;
    case "length":
      return `<td class="col-center">${escapeHtml(item._sizeLabel || formatSize((item.request_bytes ?? 0) + (item.response_bytes ?? 0)))}</td>`;
    case "mime":
      return `<td class="col-center">${escapeHtml(item._mime || inferMimeType(item))}</td>`;
    case "notes": {
      const tagDot = item.color_tag ? `<span class="row-color-tag row-color-tag-${escapeHtml(item.color_tag)}"></span>` : "";
      const noteIndicator = item.has_user_note ? `<span class="note-icon" title="Has note">\ud83d\udcdd</span>` : "";
      return `<td>${tagDot}${noteIndicator}${item.note_count ? ` ${item.note_count}` : ""}</td>`;
    }
    case "tls": {
      const tls = isTlsRecord(item) ? '<span class="tls-badge">TLS</span>' : '<span class="tls-badge empty">-</span>';
      return `<td class="tls-cell">${tls}</td>`;
    }
    case "started_at":
      return `<td>${escapeHtml(getHistoryTimeLabel(item))}</td>`;
    default:
      return "<td></td>";
  }
}

let columnDragState = null;

function bindColumnDragAndDrop() {
  const headerRow = els.historyTable?.querySelector("thead tr");
  if (!headerRow) return;

  const headers = Array.from(headerRow.querySelectorAll("th[draggable]"));
  headers.forEach((th) => {
    th.addEventListener("dragstart", (event) => {
      columnDragState = th.dataset.columnKey;
      event.dataTransfer.effectAllowed = "move";
      event.dataTransfer.setData("text/plain", columnDragState);
      th.classList.add("column-dragging");
      requestAnimationFrame(() => {
        headers.forEach((h) => h.classList.add("column-drag-active"));
      });
    });

    th.addEventListener("dragend", () => {
      th.classList.remove("column-dragging");
      headers.forEach((h) => {
        h.classList.remove("column-drag-active", "column-drag-over", "column-drag-over-left", "column-drag-over-right");
      });
      columnDragState = null;
    });

    th.addEventListener("dragover", (event) => {
      if (!columnDragState || columnDragState === th.dataset.columnKey) return;
      event.preventDefault();
      event.dataTransfer.dropEffect = "move";
      const rect = th.getBoundingClientRect();
      const midX = rect.left + rect.width / 2;
      const isLeft = event.clientX < midX;
      th.classList.toggle("column-drag-over-left", isLeft);
      th.classList.toggle("column-drag-over-right", !isLeft);
      th.classList.add("column-drag-over");
    });

    th.addEventListener("dragleave", () => {
      th.classList.remove("column-drag-over", "column-drag-over-left", "column-drag-over-right");
    });

    th.addEventListener("drop", (event) => {
      event.preventDefault();
      const fromKey = columnDragState;
      const toKey = th.dataset.columnKey;
      if (!fromKey || fromKey === toKey) return;

      const order = [...state.historyColumnOrder];
      const fromIdx = order.indexOf(fromKey);
      const toIdx = order.indexOf(toKey);
      if (fromIdx === -1 || toIdx === -1) return;

      const rect = th.getBoundingClientRect();
      const midX = rect.left + rect.width / 2;
      const dropLeft = event.clientX < midX;

      order.splice(fromIdx, 1);
      let insertIdx = order.indexOf(toKey);
      if (!dropLeft) insertIdx += 1;
      order.splice(insertIdx, 0, fromKey);

      state.historyColumnOrder = order;
      renderHistoryHeader();
      applyHistoryColumnWidths();
      renderHistory();
      scheduleUiSettingsSave();
    });
  });
}

function loadWorkbenchLayout() {
  state.workbenchHeight = null;
}

function persistWorkbenchLayout(height) {
  state.workbenchHeight = Math.round(height);
  scheduleUiSettingsSave();
}

function hydrateDisplaySettingsForm() {
  els.displayThemeSelect.value = state.displaySettings.theme;
  els.displaySizeInput.value = String(state.displaySettings.sizePx);
  els.displayUiFontSelect.value = state.displaySettings.uiFont;
  els.displayMonoFontSelect.value = state.displaySettings.monoFont;
}

function collectDisplaySettingsFormValues() {
  return sanitizeDisplaySettings({
    sizePx: els.displaySizeInput.value,
    theme: els.displayThemeSelect.value,
    uiFont: els.displayUiFontSelect.value,
    monoFont: els.displayMonoFontSelect.value,
  });
}

function previewDisplaySettingsFromForm() {
  applyDisplaySettingsState(collectDisplaySettingsFormValues());
  displaySettingsPreviewActive = true;
}

function saveDisplaySettingsFromForm() {
  state.displaySettings = collectDisplaySettingsFormValues();
  applyDisplaySettingsState();
  displaySettingsPreviewActive = false;
  window.clearTimeout(uiSettingsSaveTimer);
  uiSettingsSaveTimer = null;
  persistUiSettings().catch((error) => console.error(error));
  closeDisplaySettingsModal();
}

function applyDisplaySettingsState(settings = state.displaySettings) {
  document.documentElement.style.setProperty("--ui-root-size", `${settings.sizePx}px`);
  document.body.dataset.theme = settings.theme;
  document.body.dataset.uiFont = settings.uiFont;
  document.body.dataset.monoFont = settings.monoFont;
}

async function loadUiSettings() {
  try {
    const response = await fetch("/api/ui-settings");
    if (!response.ok) {
      throw new Error(await response.text());
    }
    applyUiSettingsSnapshot(await response.json());
  } catch (error) {
    console.error(error);
  }
}

function applyUiSettingsSnapshot(snapshot) {
  state.displaySettings = sanitizeDisplaySettings({
    sizePx: snapshot?.display_settings?.size_px,
    theme: snapshot?.display_settings?.theme,
    uiFont: snapshot?.display_settings?.ui_font,
    monoFont: snapshot?.display_settings?.mono_font,
  });
  state.historyColumnWidths = sanitizeHistoryColumnWidths(snapshot?.history_column_widths);
  state.historyColumnOrder = sanitizeHistoryColumnOrder(snapshot?.history_column_order);
  if (snapshot?.ws_column_widths && typeof snapshot.ws_column_widths === "object") {
    Object.entries(snapshot.ws_column_widths).forEach(([k, v]) => {
      if (WS_COLUMN_RULES[k] && WS_COLUMN_RULES[k].max > 0 && typeof v === "number") {
        state.wsColumnWidths[k] = clamp(v, WS_COLUMN_RULES[k].min, WS_COLUMN_RULES[k].max);
      }
    });
  }
  state.workbenchHeight = sanitizeWorkbenchHeight(snapshot?.workbench_height);
  applyDisplaySettingsState();
  renderHistoryHeader();
  applyHistoryColumnWidths();
  applyWsColumnWidths();

  if (state.workbenchHeight) {
    applyWorkbenchStackHeight(state.workbenchHeight, false);
  } else {
    els.proxyShell?.style.removeProperty("--workbench-pane-height");
  }
}

function snapshotUiSettings() {
  return {
    display_settings: {
      size_px: state.displaySettings.sizePx,
      theme: state.displaySettings.theme,
      ui_font: state.displaySettings.uiFont,
      mono_font: state.displaySettings.monoFont,
    },
    history_column_widths: { ...state.historyColumnWidths },
    history_column_order: [...state.historyColumnOrder],
    ws_column_widths: { ...state.wsColumnWidths },
    workbench_height: state.workbenchHeight > 0 ? state.workbenchHeight : null,
  };
}

function scheduleUiSettingsSave(delay = 180) {
  window.clearTimeout(uiSettingsSaveTimer);
  uiSettingsSaveTimer = window.setTimeout(() => {
    uiSettingsSaveTimer = null;
    persistUiSettings().catch((error) => console.error(error));
  }, delay);
}

async function persistUiSettings() {
  const response = await fetch("/api/ui-settings", {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify(snapshotUiSettings()),
  });

  if (!response.ok) {
    throw new Error(await response.text());
  }
}

function sanitizeWorkbenchHeight(candidate) {
  const parsed = Number(candidate);
  return Number.isFinite(parsed) && parsed > 0 ? Math.round(parsed) : null;
}

function syncHttpInScopePill() {
  const pill = document.getElementById("httpInScopeToggle");
  if (pill) pill.classList.toggle("active", !!state.filterSettings.inScopeOnly);
}

function hydrateFilterForm() {
  const filters = state.filterSettings;
  els.filterInScopeOnly.checked = filters.inScopeOnly;
  els.filterHideWithoutResponses.checked = filters.hideWithoutResponses;
  els.filterOnlyParameterized.checked = filters.onlyParameterized;
  els.filterOnlyNotes.checked = filters.onlyNotes;
  els.filterSearchTerm.value = filters.searchTerm;
  els.filterRegex.checked = filters.regex;
  els.filterCaseSensitive.checked = filters.caseSensitive;
  els.filterNegativeSearch.checked = filters.negativeSearch;
  els.filterMimeHtml.checked = filters.mime.html;
  els.filterMimeScript.checked = filters.mime.script;
  els.filterMimeJson.checked = filters.mime.json;
  els.filterMimeCss.checked = filters.mime.css;
  els.filterMimeImage.checked = filters.mime.image;
  els.filterMimeOther.checked = filters.mime.other;
  els.filterStatus2xx.checked = filters.status.success;
  els.filterStatus3xx.checked = filters.status.redirect;
  els.filterStatus4xx.checked = filters.status.clientError;
  els.filterStatus5xx.checked = filters.status.serverError;
  els.filterStatusOther.checked = filters.status.other;
  els.filterHiddenExtensions.value = filters.hiddenExtensions;
  els.filterPort.value = filters.port;
  syncColorTagFilterUI();
}

function applyFilterSettings() {
  const searchTerm = els.filterSearchTerm.value.trim();
  const nextMime = {
    html: els.filterMimeHtml.checked,
    script: els.filterMimeScript.checked,
    json: els.filterMimeJson.checked,
    css: els.filterMimeCss.checked,
    image: els.filterMimeImage.checked,
    other: els.filterMimeOther.checked,
  };
  const nextStatus = {
    success: els.filterStatus2xx.checked,
    redirect: els.filterStatus3xx.checked,
    clientError: els.filterStatus4xx.checked,
    serverError: els.filterStatus5xx.checked,
    other: els.filterStatusOther.checked,
  };
  if (!Object.values(nextStatus).some(Boolean)) {
    showToast("Select at least one status filter.", "error");
    return;
  }
  if (!Object.values(nextMime).some(Boolean)) {
    showToast("Select at least one MIME filter.", "error");
    return;
  }
  if (els.filterRegex.checked && searchTerm) {
    try {
      new RegExp(searchTerm, els.filterCaseSensitive.checked ? "" : "i");
    } catch (error) {
      const message = `Invalid regex: ${error.message}`;
      if (els.historyMeta) els.historyMeta.textContent = message;
      showToast(message);
      return;
    }
  }
  state.filterSettings = {
    inScopeOnly: els.filterInScopeOnly.checked,
    hideWithoutResponses: els.filterHideWithoutResponses.checked,
    onlyParameterized: els.filterOnlyParameterized.checked,
    onlyNotes: els.filterOnlyNotes.checked,
    searchTerm,
    regex: els.filterRegex.checked,
    caseSensitive: els.filterCaseSensitive.checked,
    negativeSearch: els.filterNegativeSearch.checked,
    mime: nextMime,
    status: nextStatus,
    hiddenExtensions: els.filterHiddenExtensions.value.trim(),
    port: els.filterPort.value.trim(),
    colorTags: state.filterSettings.colorTags,
  };
  closeFilterModal();
  syncHttpInScopePill();
  scheduleRefresh({ resetScroll: true });
}

async function openCertificateFolder() {
  try {
    const response = await fetch("/api/certificates/reveal", { method: "POST" });
    await requireOkResponse(response, "Failed to open certificate folder.");
  } catch (error) {
    console.error("Failed to open certificate folder:", error);
    showToast(error?.message || "Failed to open certificate folder.", "error");
  }
}

function buildMessagePresentation(target, record) {
  const mode = state.messageViews[target];
  const text = target === "request" ? buildRawRequest(record) : buildRawResponse(record);

  if (mode === "hex") {
    return toHexDump(text);
  }

  if (mode === "pretty") {
    return prettyFormat(text, target === "request" ? record.request : record.response);
  }

  return text;
}

function buildDiffPresentation(target, record) {
  const originalField = target === "request" ? "original_request" : "original_response";
  const original = record[originalField];
  if (!original) {
    return target === "request"
      ? "No match-replace rules were applied to the request."
      : "No match-replace rules were applied to the response.";
  }

  const fakeOriginal = { ...record };
  if (target === "request") {
    fakeOriginal.request = original;
  } else {
    fakeOriginal.response = original;
  }
  return target === "request" ? buildRawRequest(fakeOriginal) : buildRawResponse(fakeOriginal);
}

function buildRawRequest(record) {
  const httpVer = record.http_version || "HTTP/1.1";
  const startLine = record.kind === "tunnel"
    ? `CONNECT ${record.host} ${httpVer}`
    : `${record.method} ${record.path || "/"} ${httpVer}`;
  const request = record.request || {};
  const merged = mergeHeaders(request.headers);
  // Ensure a host header is present — the proxy stores the host separately
  // and some tunnelled HTTPS requests omit Host from the captured headers.
  if (record.host && !merged.some((h) => headerNameEquals(h, "host"))) {
    merged.unshift({ name: "host", value: record.host });
  }
  const headers = merged
    .map((header) => `${header.name}: ${header.value}`)
    .join("\n");
  const body = renderBody(request);
  const head = headers ? `${startLine}\n${headers}` : startLine;
  return body.length > 0 ? `${head}\n\n${body}` : head;
}

function mergeHeaders(headers) {
  const merged = [];
  const cookieParts = [];
  for (const h of normalizedHeaders(headers)) {
    if (headerNameEquals(h, "cookie")) {
      cookieParts.push(h.value);
    } else {
      merged.push(h);
    }
  }
  if (cookieParts.length) {
    merged.push({ name: "cookie", value: cookieParts.join("; ") });
  }
  return merged;
}

function normalizedHeaders(headers) {
  return (Array.isArray(headers) ? headers : [])
    .map((h) => ({
      name: String(h?.name || ""),
      value: String(h?.value ?? ""),
    }))
    .filter((h) => h.name);
}

function headerNameEquals(header, name) {
  return String(header?.name || "").toLowerCase() === String(name || "").toLowerCase();
}

function buildRawResponse(record) {
  if (!record.response) {
    return "No response was captured for this exchange.";
  }

  const response = record.response || {};
  const headers = normalizedHeaders(response.headers)
    .map((header) => `${header.name}: ${header.value}`)
    .join("\n");
  const body = renderBody(response);
  const httpVer = record.http_version || "HTTP/1.1";
  const head = headers ? `${httpVer} ${record.status ?? 0}\n${headers}` : `${httpVer} ${record.status ?? 0}`;
  return body.length > 0 ? `${head}\n\n${body}` : head;
}

function buildFindingsRawMessage(record, side) {
  const msg = side === "request" ? record.request : record.response;
  const httpVer = record.http_version || "HTTP/1.1";
  if (side === "request") {
    const startLine = record.kind === "tunnel"
      ? `CONNECT ${record.host} ${httpVer}`
      : `${record.method} ${record.path || "/"} ${httpVer}`;
    const request = record.request || {};
    const merged = mergeHeaders(request.headers);
    if (record.host && !merged.some((h) => headerNameEquals(h, "host"))) {
      merged.unshift({ name: "host", value: record.host });
    }
    const headers = merged.map((h) => `${h.name}: ${h.value}`).join("\n");
    const body = findingsBodyPlaceholder(msg);
    const head = headers ? `${startLine}\n${headers}` : startLine;
    return body.length > 0 ? `${head}\n\n${body}` : head;
  }
  if (!msg) return "No response was captured for this exchange.";
  const headers = normalizedHeaders(msg.headers).map((h) => `${h.name}: ${h.value}`).join("\n");
  const body = findingsBodyPlaceholder(msg);
  const head = headers ? `${httpVer} ${record.status ?? 0}\n${headers}` : `${httpVer} ${record.status ?? 0}`;
  return body.length > 0 ? `${head}\n\n${body}` : head;
}

function findingsBodyPlaceholder(msg) {
  if (!msg || !msg.body_preview) return "";
  if (msg.body_encoding === "base64") {
    const ct = msg.content_type || "binary";
    return `[${ct}, ${formatSize(msg.body_size)}]`;
  }
  return msg.preview_truncated
    ? `${msg.body_preview}\n\n[preview truncated]`
    : msg.body_preview;
}

function buildRawWebsocketRequest(session) {
  const headers = mergeHeaders(session?.request?.headers)
    .map((header) => `${header.name}: ${header.value}`)
    .join("\n");
  return `GET ${session?.path || "/"} HTTP/1.1\n${headers}`.trim();
}

function buildRawWebsocketResponse(session) {
  if (!session.response) {
    return "No handshake response was captured.";
  }

  const headers = normalizedHeaders(session.response.headers)
    .map((header) => `${header.name}: ${header.value}`)
    .join("\n");
  return `HTTP/1.1 ${session.status ?? 101}\n${headers}`.trim();
}

function renderBody(message) {
  if (!message || !message.body_preview) {
    return "";
  }

  if (message.body_encoding === "base64") {
    return message.body_preview;
  }

  return message.preview_truncated
    ? `${message.body_preview}\n\n[preview truncated]`
    : message.body_preview;
}

function prettyFormat(text, message) {
  if (!message || message.body_encoding === "base64") {
    return text;
  }

  const divider = "\n\n";
  const boundary = text.indexOf(divider);
  if (boundary === -1) {
    return text;
  }

  const head = text.slice(0, boundary);
  const body = text.slice(boundary + divider.length);
  const contentType = (message.content_type || "").toLowerCase();

  if (contentType.includes("json")) {
    try {
      return `${head}${divider}${JSON.stringify(JSON.parse(body), null, 2)}`;
    } catch (_error) {
      return text;
    }
  }

  // Fallback: try to detect JSON even if Content-Type doesn't say json
  const trimmed = body.trimStart();
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    try {
      return `${head}${divider}${JSON.stringify(JSON.parse(body), null, 2)}`;
    } catch (_error) {
      // not valid JSON, return as-is
    }
  }

  return text;
}

function compactFormat(text) {
  const divider = "\n\n";
  const boundary = text.indexOf(divider);
  if (boundary === -1) return text;
  const head = text.slice(0, boundary);
  const body = text.slice(boundary + divider.length);
  const trimmed = body.trimStart();
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    try {
      return `${head}${divider}${JSON.stringify(JSON.parse(body))}`;
    } catch (_) { /* not valid JSON */ }
  }
  return text;
}

function editableRequestFromRecord(record) {
  const request = record.request || {};
  return {
    scheme: record.scheme,
    host: record.host,
    method: record.method,
    path: record.path || "/",
    http_version: record.http_version,
    headers: normalizedHeaders(request.headers),
    body: request.body_preview || "",
    body_encoding: request.body_encoding,
    preview_truncated: request.preview_truncated,
  };
}

function buildEditableRawRequest(request) {
  const source = request || {};
  const headers = normalizedHeaders(source.headers);
  if (!headers.some((header) => headerNameEquals(header, "host")) && source.host) {
    headers.unshift({ name: "host", value: source.host });
  }
  const httpVer = source.http_version || "HTTP/1.1";
  const head = `${source.method || "GET"} ${source.path || "/"} ${httpVer}`;
  const headerBlock = mergeHeaders(headers).map((header) => `${header.name}: ${header.value}`).join("\n");
  const body = source.body || "";
  const rawHead = headerBlock ? `${head}\n${headerBlock}` : head;
  return body.length > 0 ? `${rawHead}\n\n${body}` : rawHead;
}

function parseEditableRawRequest(text, fallback) {
  const { head, body } = splitRawHttpMessage(text);
  const lines = head.split("\n").filter((line) => line.length > 0);
  const [startLine = "GET / HTTP/1.1", ...headerLines] = lines;
  const match = startLine.match(/^([A-Za-z0-9!#$%&'*+.^_`|~-]+)\s+(\S+)(?:\s+(HTTP\/[0-9.]+))?$/);

  if (!match) {
    throw new Error("Invalid request line in editor");
  }

  let [, method, target, httpVersionToken] = match;
  const httpVersion = parseReplayHttpVersionToken(httpVersionToken);
  let scheme = fallback?.scheme || "https";
  let host = fallback?.host || "";
  let path = target;
  let absoluteAuthority = "";
  const headers = headerLines
    .map((line) => {
      const index = line.indexOf(":");
      if (index === -1) {
        throw new Error(`Invalid header line: ${line}`);
      }
      return {
        name: line.slice(0, index).trim(),
        value: line.slice(index + 1).trim(),
      };
    })
    .filter(Boolean);

  if (/^https?:\/\//i.test(target)) {
    const absolute = new URL(target);
    if (absolute.username || absolute.password) {
      throw new Error("Absolute request target must not include credentials");
    }
    if (absolute.hash) {
      throw new Error("Absolute request target must not include a fragment");
    }
    scheme = absolute.protocol.replace(":", "");
    host = absolute.host;
    absoluteAuthority = absolute.host;
    path = `${absolute.pathname || "/"}${absolute.search || ""}`;
  }

  const hostHeader = headerValue(headers, "host");
  if (hostHeader) {
    if (absoluteAuthority) {
      if (!httpRequestAuthoritiesEquivalent(absoluteAuthority, hostHeader, scheme)) {
        throw new Error("Absolute-form request target does not match Host header");
      }
    } else {
      host = hostHeader;
    }
  }

  if (method.toUpperCase() === "CONNECT") {
    throw new Error("CONNECT authority-form requests are not supported by Replay");
  }

  if (path !== "*" && !path.startsWith("/")) {
    path = `/${path}`;
  }

  if (!host) {
    throw new Error("Request is missing a Host header");
  }

  const bodyEncoding = fallback?.body_encoding === "base64" ? "base64" : "utf8";
  const bodyLength = editableRequestBodyLength(body, bodyEncoding);
  const acceptedBodyLengths = [bodyLength];

  // Auto-update Content-Length if enabled
  if (document.getElementById("proxySettingAutoContentLength")?.checked) {
    for (const header of headers) {
      if (headerNameEquals(header, "content-length")) {
        header.value = String(bodyLength);
      }
    }
  }
  validateRawHttpBodyFraming(headers, bodyLength, acceptedBodyLengths);

  return {
    scheme,
    host,
    method,
    path,
    http_version: httpVersion,
    headers,
    body,
    body_encoding: bodyEncoding,
    preview_truncated: false,
  };
}

function validateRawHttpBodyFraming(headers, bodyLength, acceptedBodyLengths = [bodyLength]) {
  if (headers.some((header) => headerNameEquals(header, "transfer-encoding")
    && String(header.value || "").split(",").some((value) => value.trim().toLowerCase() === "chunked"))) {
    throw new Error("Raw HTTP input with Transfer-Encoding: chunked is not supported");
  }

  let contentLength = null;
  for (const header of headers.filter((item) => headerNameEquals(item, "content-length"))) {
    const value = String(header.value || "").trim();
    if (!/^\d+$/.test(value)) {
      throw new Error(`Invalid Content-Length: ${header.value}`);
    }
    const parsed = Number(value);
    if (!Number.isSafeInteger(parsed)) {
      throw new Error(`Invalid Content-Length: ${header.value}`);
    }
    if (contentLength !== null && contentLength !== parsed) {
      throw new Error("Conflicting Content-Length headers");
    }
    contentLength = parsed;
  }

  if (contentLength !== null && !acceptedBodyLengths.includes(contentLength)) {
    throw new Error(`Content-Length ${contentLength} does not match raw body length ${bodyLength}`);
  }
}

function splitRawHttpMessage(text) {
  const raw = String(text ?? "");
  const crlfBoundary = raw.indexOf("\r\n\r\n");
  if (crlfBoundary !== -1) {
    return {
      head: raw.slice(0, crlfBoundary).replace(/\r\n/g, "\n"),
      body: raw.slice(crlfBoundary + 4),
    };
  }

  const lfBoundary = raw.indexOf("\n\n");
  if (lfBoundary !== -1) {
    return {
      head: raw.slice(0, lfBoundary).replace(/\r\n/g, "\n"),
      body: raw.slice(lfBoundary + 2),
    };
  }

  return { head: raw.replace(/\r\n/g, "\n"), body: "" };
}

function headerValue(headers, name) {
  return normalizedHeaders(headers).find((header) => headerNameEquals(header, name))?.value || null;
}

function renderFramePreview(frame) {
  if (!frame.body_preview) {
    return "(empty)";
  }
  return frame.body_encoding === "base64"
    ? `[base64] ${frame.body_preview}`
    : frame.body_preview;
}

function showFrameDetail(frame) {
  const isClient = frame.direction === "client_to_server";
  const dirClass = isClient ? "dir-client" : "dir-server";
  const dirLabel = isClient ? "client \u2192" : "\u2190 server";
  els.frameDetailMeta.innerHTML = `
    <span>#${(frame.index ?? 0) + 1}</span>
    <span class="${dirClass}">${dirLabel}</span>
    <span>${escapeHtml(frame.kind)}</span>
    <span>${escapeHtml(formatSize(frame.body_size))}</span>
  `;

  let body = frame.body_preview || "(empty)";
  if (frame.body_encoding === "base64") {
    body = safeDecodeBase64(frame.body_preview, `[base64] ${frame.body_preview}`);
  }

  // Try to pretty-print JSON
  try {
    const parsed = JSON.parse(body);
    body = JSON.stringify(parsed, null, 2);
  } catch {
    // not JSON, keep as-is
  }

  // Syntax-highlight the body (auto-detect per line)
  const highlighted = body
    .split("\n")
    .map((line) => highlightBodyLine(line))
    .join("\n");
  els.frameDetailBody.innerHTML = highlighted;
  els.frameDetailResizer.classList.remove("hidden");
  els.frameDetailPanel.classList.remove("hidden");
}

function hideFrameDetail() {
  state.selectedFrameIdx = null;
  els.frameDetailResizer.classList.add("hidden");
  els.frameDetailPanel.classList.add("hidden");
  els.websocketFramesBody.querySelectorAll(".ws-frame-bubble.selected").forEach((r) => r.classList.remove("selected"));
  els.websocketFramesBody.querySelectorAll(".frame-selected").forEach((r) => r.classList.remove("frame-selected"));
}

function initFrameDetailResizer() {
  const resizer = els.frameDetailResizer;
  if (!resizer) return;
  const container = resizer.parentElement;

  let startY = 0;
  let startHeight = 0;

  resizer.addEventListener("mousedown", (e) => {
    e.preventDefault();
    startY = e.clientY;
    startHeight = els.frameDetailPanel.getBoundingClientRect().height;
    document.addEventListener("mousemove", onMouseMove);
    document.addEventListener("mouseup", onMouseUp);
    document.body.style.cursor = "row-resize";
    document.body.style.userSelect = "none";
  });

  function onMouseMove(e) {
    const delta = startY - e.clientY;
    const newHeight = Math.max(120, startHeight + delta);
    const maxHeight = container.getBoundingClientRect().height * 0.8;
    const h = Math.min(newHeight, maxHeight);
    els.frameDetailPanel.style.flex = "0 0 " + h + "px";
  }

  function onMouseUp() {
    document.removeEventListener("mousemove", onMouseMove);
    document.removeEventListener("mouseup", onMouseUp);
    document.body.style.cursor = "";
    document.body.style.userSelect = "";
  }
}

function toHexDump(text) {
  const encoder = new TextEncoder();
  const bytes = encoder.encode(text);
  const rows = [];

  for (let offset = 0; offset < bytes.length; offset += 16) {
    const chunk = Array.from(bytes.slice(offset, offset + 16));
    // Group bytes: first 8 | space | next 8
    const left = chunk.slice(0, 8).map((v) => v.toString(16).padStart(2, "0")).join(" ");
    const right = chunk.slice(8).map((v) => v.toString(16).padStart(2, "0")).join(" ");
    const hex = (left + "  " + right).padEnd(49, " ");
    const ascii = chunk
      .map((value) => (value >= 32 && value <= 126 ? String.fromCharCode(value) : "."))
      .join("");
    rows.push(`${offset.toString(16).padStart(8, "0")}  ${hex} ${ascii}`);
  }

  return rows.join("\n") || "00000000";
}

function toHexDumpFromBytes(bytes) {
  const rows = [];
  for (let offset = 0; offset < bytes.length; offset += 16) {
    const chunk = Array.from(bytes.slice(offset, offset + 16));
    const left = chunk.slice(0, 8).map((v) => v.toString(16).padStart(2, "0")).join(" ");
    const right = chunk.slice(8).map((v) => v.toString(16).padStart(2, "0")).join(" ");
    const hex = (left + "  " + right).padEnd(49, " ");
    const ascii = chunk
      .map((value) => (value >= 32 && value <= 126 ? String.fromCharCode(value) : "."))
      .join("");
    rows.push(`${offset.toString(16).padStart(8, "0")}  ${hex} ${ascii}`);
  }
  return rows.join("\n") || "00000000";
}

function renderEditableHexHtml(bytes, originalBytes) {
  const lines = [];
  for (let offset = 0; offset < bytes.length; offset += 16) {
    const chunk = Array.from(bytes.slice(offset, offset + 16));
    const offsetStr = offset.toString(16).padStart(8, "0");

    // Build hex bytes as individual clickable spans, highlight modified
    const hexSpans = chunk.map((b, i) => {
      const globalIdx = offset + i;
      const gap = (i === 8) ? " " : "";
      const modified = originalBytes && globalIdx < originalBytes.length && b !== originalBytes[globalIdx] ? " hex-byte-modified" : "";
      return `${gap}<span class="hex-byte${modified}" data-idx="${globalIdx}" tabindex="0">${b.toString(16).padStart(2, "0")}</span>`;
    }).join(" ");

    // Pad if less than 16 bytes
    const totalChars = chunk.length * 3 - 1 + (chunk.length > 8 ? 1 : 0);
    const pad = " ".repeat(Math.max(0, 49 - totalChars));

    const ascii = chunk
      .map((v) => (v >= 32 && v <= 126 ? escapeHtml(String.fromCharCode(v)) : "."))
      .join("");

    lines.push(wrapCodeLine(
      `<span class="hex-col hex-col-offset">${offsetStr}</span><span class="hex-col hex-col-bytes">${hexSpans}${pad}</span><span class="hex-col hex-col-ascii">${ascii}</span>`,
      "code-line code-line-hex",
    ));
  }
  return lines.join("") || wrapCodeLine("00000000", "code-line code-line-hex");
}

function bindHexByteHandlers(container, tab) {
  container.querySelectorAll(".hex-byte").forEach((span) => {
    span.addEventListener("click", (e) => {
      e.stopPropagation();
      startHexByteEdit(span, tab, container);
    });
  });
}

function startHexByteEdit(span, tab, container) {
  // Remove any existing edit input
  container.querySelectorAll(".hex-byte-input").forEach((el) => el.remove());
  container.querySelectorAll(".hex-byte.editing").forEach((el) => el.classList.remove("editing"));

  const idx = parseInt(span.dataset.idx, 10);
  if (isNaN(idx) || !tab.requestBytes) return;

  span.classList.add("editing");
  const input = document.createElement("input");
  input.type = "text";
  input.className = "hex-byte-input";
  input.maxLength = 2;
  input.value = tab.requestBytes[idx].toString(16).padStart(2, "0");
  input.size = 2;

  span.textContent = "";
  span.appendChild(input);
  input.focus();
  input.select();

  function commit() {
    const val = parseInt(input.value, 16);
    if (!isNaN(val) && val >= 0 && val <= 255) {
      tab.requestBytes[idx] = val;
    }
    // Re-render the entire hex view with modification highlights
    container.innerHTML = renderEditableHexHtml(tab.requestBytes, tab.requestOriginalBytes);
    bindHexByteHandlers(container, tab);
    // Sync text
    tab.requestText = new TextDecoder().decode(tab.requestBytes);
    if (els.replayRequestEditor) els.replayRequestEditor.value = tab.requestText;
    renderReplayTabs();
    updateReplaySearchPane("request", tab.requestText);
    scheduleWorkspaceStateSave();
  }

  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === "Tab") {
      e.preventDefault();
      commit();
      // Move to next/prev byte
      const nextIdx = e.shiftKey ? idx - 1 : idx + 1;
      const nextSpan = container.querySelector(`.hex-byte[data-idx="${nextIdx}"]`);
      if (nextSpan) startHexByteEdit(nextSpan, tab, container);
    } else if (e.key === "Escape") {
      e.preventDefault();
      commit();
    } else if (e.key === "ArrowRight") {
      e.preventDefault();
      commit();
      const nextSpan = container.querySelector(`.hex-byte[data-idx="${idx + 1}"]`);
      if (nextSpan) startHexByteEdit(nextSpan, tab, container);
    } else if (e.key === "ArrowLeft") {
      e.preventDefault();
      commit();
      const prevSpan = container.querySelector(`.hex-byte[data-idx="${idx - 1}"]`);
      if (prevSpan) startHexByteEdit(prevSpan, tab, container);
    }
  });

  input.addEventListener("input", () => {
    // Only allow hex characters
    input.value = input.value.replace(/[^0-9a-fA-F]/g, "").substring(0, 2);
    // Auto-advance after 2 chars
    if (input.value.length === 2) {
      commit();
      const nextSpan = container.querySelector(`.hex-byte[data-idx="${idx + 1}"]`);
      if (nextSpan) startHexByteEdit(nextSpan, tab, container);
    }
  });

  input.addEventListener("blur", () => {
    // Delay to allow click on another byte
    setTimeout(() => {
      if (!container.querySelector(".hex-byte-input")) return;
      commit();
    }, 100);
  });
}

function updateCodePane(viewElement, lineElement, text, mode, target) {
  const lineCount = countLines(text);
  const savedFocus = window._saveCodeViewFocus?.(viewElement);
  viewElement.innerHTML = renderCodeHtml(text, mode, target);
  lineElement.textContent = buildLineNumbers(lineCount);
  const searchResult = applyCodeSearch(viewElement, state.messageSearch[target]);
  if (savedFocus) {
    window._restoreCodeViewFocus?.(viewElement, savedFocus);
  } else if (searchResult.firstMatch) {
    viewElement.scrollTop = Math.max(searchResult.firstMatch.offsetTop - 24, 0);
  } else {
    viewElement.scrollTop = 0;
  }
  lineElement.scrollTop = viewElement.scrollTop;
  return {
    lineCount,
    matchCount: searchResult.count,
  };
}

function renderCodeHtml(text, mode, target) {
  if (!text) {
    return '<span class="code-line code-line-empty">&nbsp;</span>';
  }

  if (mode === "hex") {
    return renderHexHtml(text);
  }

  if (mode === "diff") {
    return renderDiffHtml(text);
  }

  // Both "pretty" and "raw" use the same HTTP syntax highlighting.
  // The difference is in data preparation: "pretty" applies prettyFormat (JSON body formatting).
  return renderHttpHtml(text, target);
}

function renderDiffHtml(text) {
  const lines = String(text).split("\n");
  return lines
    .map((line) => {
      const escaped = escapeHtml(line);
      if (line.startsWith("--- ") || line.startsWith("+++ ")) {
        return wrapCodeLine(escaped, "code-line diff-line-header");
      }
      if (line.startsWith("+ ")) {
        return wrapCodeLine(escaped, "code-line diff-line-added");
      }
      if (line.startsWith("- ")) {
        return wrapCodeLine(escaped, "code-line diff-line-removed");
      }
      return wrapCodeLine(escaped, "code-line");
    })
    .join("");
}

function renderHttpHtml(text, target) {
  const lines = String(text).split("\n");
  let inBody = false;
  let contentType = "";
  let bodyMode = "plain";

  return lines
    .map((line, index) => {
      if (!inBody && line === "") {
        inBody = true;
        bodyMode = inferBodyHighlightMode(contentType);
        return wrapCodeLine("&nbsp;", "code-line code-line-gap");
      }

      if (!inBody) {
        if (index === 0) {
          return wrapCodeLine(highlightStartLine(line, target), "code-line code-line-start");
        }

        const headerMatch = line.match(/^([^:]+):(.*)$/);
        if (headerMatch && headerMatch[1].trim().toLowerCase() === "content-type") {
          contentType = headerMatch[2].trim();
        }

        return wrapCodeLine(highlightHeaderLine(line), "code-line");
      }

      return wrapCodeLine(highlightBodyLine(line, bodyMode), "code-line code-line-body");
    })
    .join("");
}

function renderHexHtml(text) {
  return String(text)
    .split("\n")
    .map((line) => {
      if (line.length < 10) {
        return wrapCodeLine(escapeHtml(line), "code-line code-line-hex");
      }
      const offset = line.substring(0, 8);
      const hex = line.substring(10, 59);
      const ascii = line.substring(60);
      return wrapCodeLine(
        `<span class="hex-col hex-col-offset">${escapeHtml(offset)}</span><span class="hex-col hex-col-bytes">${escapeHtml(hex)}</span><span class="hex-col hex-col-ascii">${escapeHtml(ascii)}</span>`,
        "code-line code-line-hex",
      );
    })
    .join("");
}

function wrapCodeLine(content, className) {
  return `<span class="${className}">${content || "&nbsp;"}</span>`;
}

function bindCodePaneScroll(viewElement, lineElement) {
  if (!viewElement || !lineElement) return;
  viewElement.addEventListener("scroll", () => {
    lineElement.scrollTop = viewElement.scrollTop;
  });
}

function bindMessagePaneActivation() {
  document.addEventListener("pointerdown", (event) => {
    if (!(event.target instanceof HTMLElement)) {
      state.activeMessagePane = null;
      return;
    }

    if (event.target.closest("#requestColumn")) {
      state.activeMessagePane = "request";
      return;
    }

    if (event.target.closest("#responseColumn")) {
      state.activeMessagePane = "response";
      return;
    }

    state.activeMessagePane = null;
  });

  els.requestView?.addEventListener("focus", () => {
    state.activeMessagePane = "request";
  });

  els.responseView?.addEventListener("focus", () => {
    state.activeMessagePane = "response";
  });
}

function applyWsColumnWidths() {
  const table = document.getElementById("websocketTable");
  if (!table) return;
  Object.entries(state.wsColumnWidths).forEach(([key, width]) => {
    table.style.setProperty(`--ws-col-${key}`, `${width}px`);
  });
}

function bindWsColumnResizers() {
  const handles = document.querySelectorAll("#websocketTable .ws-col-resize-handle");
  handles.forEach((handle) => {
    handle.addEventListener("dblclick", (event) => {
      event.preventDefault();
      event.stopPropagation();
      const key = handle.dataset.wsColKey;
      if (!key || !WS_COLUMN_RULES[key] || WS_COLUMN_RULES[key].max === 0) return;
      state.wsColumnWidths[key] = WS_COLUMN_RULES[key].default;
      applyWsColumnWidths();
      scheduleUiSettingsSave();
    });

    handle.addEventListener("mousedown", (event) => {
      const key = handle.dataset.wsColKey;
      const limits = WS_COLUMN_RULES[key];
      if (!key || !limits || limits.max === 0) return;

      event.preventDefault();
      event.stopPropagation();

      const header = handle.closest("th");
      const startWidth = header?.getBoundingClientRect().width ?? limits.default;
      document.body.classList.add("pane-resizing-x");
      handle.classList.add("active");

      const onMove = (moveEvent) => {
        const delta = moveEvent.clientX - event.clientX;
        state.wsColumnWidths[key] = clamp(Math.round(startWidth + delta), limits.min, limits.max);
        applyWsColumnWidths();
      };

      const onUp = () => {
        document.body.classList.remove("pane-resizing-x");
        handle.classList.remove("active");
        document.removeEventListener("mousemove", onMove);
        document.removeEventListener("mouseup", onUp);
        scheduleUiSettingsSave();
      };

      document.addEventListener("mousemove", onMove);
      document.addEventListener("mouseup", onUp);
    });
  });
}

function bindHistoryColumnResizers() {
  historyColumnHandles.forEach((handle) => {
    handle.addEventListener("dblclick", (event) => {
      event.preventDefault();
      event.stopPropagation();
      const key = handle.dataset.columnKey;
      if (!key || !HISTORY_COLUMN_RULES[key]) {
        return;
      }
      state.historyColumnWidths[key] = HISTORY_COLUMN_RULES[key].default;
      applyHistoryColumnWidths();
      saveHistoryColumnWidths();
    });

    handle.addEventListener("mousedown", (event) => {
      const key = handle.dataset.columnKey;
      const limits = HISTORY_COLUMN_RULES[key];
      if (!key || !limits) {
        return;
      }

      event.preventDefault();
      event.stopPropagation();

      const header = handle.closest("th");
      const startWidth = header?.getBoundingClientRect().width ?? limits.default;
      document.body.classList.add("pane-resizing-x");
      handle.classList.add("active");

      const onMove = (moveEvent) => {
        const delta = moveEvent.clientX - event.clientX;
        state.historyColumnWidths[key] = clamp(
          Math.round(startWidth + delta),
          limits.min,
          limits.max,
        );
        applyHistoryColumnWidths();
      };

      const onUp = () => {
        document.body.classList.remove("pane-resizing-x");
        handle.classList.remove("active");
        document.removeEventListener("mousemove", onMove);
        document.removeEventListener("mouseup", onUp);
        saveHistoryColumnWidths();
      };

      document.addEventListener("mousemove", onMove);
      document.addEventListener("mouseup", onUp);
    });
  });
}

function bindWorkbenchStackResizer(handle) {
  if (!handle) {
    return;
  }

  handle.addEventListener("dblclick", () => {
    resetWorkbenchStackHeight();
  });

  handle.addEventListener("mousedown", (event) => {
    if (!els.trafficRegion || !els.lowerWorkbench || els.historyWorkbenchResizer.classList.contains("hidden")) {
      return;
    }

    event.preventDefault();
    const start = {
      history: els.trafficRegion.getBoundingClientRect().height,
      messages: els.lowerWorkbench.getBoundingClientRect().height,
    };
    const combinedHeight = start.history + start.messages;

    document.body.classList.add("pane-resizing-y");
    handle.classList.add("active");

    const onMove = (moveEvent) => {
      const delta = moveEvent.clientY - event.clientY;
      const nextMessages = clamp(
        start.messages - delta,
        WORKBENCH_STACK_MIN_HEIGHTS.messages,
        combinedHeight - WORKBENCH_STACK_MIN_HEIGHTS.history,
      );
      applyWorkbenchStackHeight(nextMessages);
    };

    const onUp = () => {
      document.body.classList.remove("pane-resizing-y");
      handle.classList.remove("active");
      document.removeEventListener("mousemove", onMove);
      document.removeEventListener("mouseup", onUp);
      normalizeWorkbenchStackHeight();
    };

    document.addEventListener("mousemove", onMove);
    document.addEventListener("mouseup", onUp);
  });
}

function bindPaneResizer(handle, mode) {
  if (!handle) {
    return;
  }

  handle.addEventListener("dblclick", () => {
    resetWorkbenchPaneWidths();
  });

  handle.addEventListener("mousedown", (event) => {
    if (window.matchMedia(WORKBENCH_STACK_BREAKPOINT).matches) {
      return;
    }

    event.preventDefault();
    const start = getWorkbenchWidths();
    if (!start) {
      return;
    }

    document.body.classList.add("pane-resizing-x");
    handle.classList.add("active");

    const onMove = (moveEvent) => {
      const delta = moveEvent.clientX - event.clientX;
      if (mode === "request-response") {
        const combinedWidth = start.request + start.response;
        const nextRequest = clamp(
          start.request + delta,
          WORKBENCH_MIN_WIDTHS.request,
          combinedWidth - WORKBENCH_MIN_WIDTHS.response,
        );
        applyWorkbenchPaneWidths(nextRequest, combinedWidth - nextRequest, start.total);
        return;
      }
    };

    const onUp = () => {
      document.body.classList.remove("pane-resizing-x");
      handle.classList.remove("active");
      document.removeEventListener("mousemove", onMove);
      document.removeEventListener("mouseup", onUp);
      normalizeWorkbenchPaneWidths();
    };

    document.addEventListener("mousemove", onMove);
    document.addEventListener("mouseup", onUp);
  });
}

function getWorkbenchWidths() {
  if (!els.lowerWorkbench || !els.requestColumn || !els.responseColumn) {
    return null;
  }

  return {
    total: els.lowerWorkbench.getBoundingClientRect().width,
    request: els.requestColumn.getBoundingClientRect().width,
    response: els.responseColumn.getBoundingClientRect().width,
  };
}

function applyWorkbenchPaneWidths(requestWidth, responseWidth, totalWidth = els.lowerWorkbench.getBoundingClientRect().width) {
  if (!totalWidth) {
    return;
  }

  const requestPercent = clamp((requestWidth / totalWidth) * 100, 18, 72);
  const responsePercent = clamp((responseWidth / totalWidth) * 100, 18, 72);
  els.lowerWorkbench.style.setProperty("--request-pane-width", `${requestPercent}%`);
  els.lowerWorkbench.style.setProperty("--response-pane-width", `${responsePercent}%`);
}

function normalizeWorkbenchPaneWidths() {
  if (!els.lowerWorkbench || window.matchMedia(WORKBENCH_STACK_BREAKPOINT).matches) {
    return;
  }

  const hasCustomWidths = els.lowerWorkbench.style.getPropertyValue("--request-pane-width")
    || els.lowerWorkbench.style.getPropertyValue("--response-pane-width");
  if (!hasCustomWidths) {
    return;
  }

  const bounds = getWorkbenchWidths();
  if (!bounds) {
    return;
  }

  const visibleHandleWidth = 10;
  const maxRequestAndResponse = Math.max(
    WORKBENCH_MIN_WIDTHS.request + WORKBENCH_MIN_WIDTHS.response,
    bounds.total - visibleHandleWidth,
  );
  const currentCombined = bounds.request + bounds.response;
  const combinedWidth = Math.min(currentCombined, maxRequestAndResponse);
  const requestRatio = currentCombined ? bounds.request / currentCombined : 0.5;
  const requestWidth = clamp(
    combinedWidth * requestRatio,
    WORKBENCH_MIN_WIDTHS.request,
    combinedWidth - WORKBENCH_MIN_WIDTHS.response,
  );
  const responseWidth = combinedWidth - requestWidth;
  applyWorkbenchPaneWidths(requestWidth, responseWidth, bounds.total);
}

function resetWorkbenchPaneWidths() {
  els.lowerWorkbench.style.removeProperty("--request-pane-width");
  els.lowerWorkbench.style.removeProperty("--response-pane-width");
}

function bindWebsocketPaneResizer(handle) {
  if (!handle) {
    return;
  }

  handle.addEventListener("dblclick", () => {
    resetWebsocketPaneWidth();
  });

  handle.addEventListener("mousedown", (event) => {
    if (window.matchMedia(WEBSOCKET_WORKBENCH_BREAKPOINT).matches) {
      return;
    }

    event.preventDefault();
    const start = getWebsocketWorkbenchWidths();
    if (!start) {
      return;
    }

    document.body.classList.add("pane-resizing-x");
    handle.classList.add("active");

    const onMove = (moveEvent) => {
      const delta = moveEvent.clientX - event.clientX;
      const combinedWidth = start.handshake + start.frames;
      const nextHandshake = clamp(
        start.handshake + delta,
        WEBSOCKET_WORKBENCH_MIN_WIDTHS.handshake,
        combinedWidth - WEBSOCKET_WORKBENCH_MIN_WIDTHS.frames,
      );
      applyWebsocketPaneWidth(nextHandshake);
    };

    const onUp = () => {
      document.body.classList.remove("pane-resizing-x");
      handle.classList.remove("active");
      document.removeEventListener("mousemove", onMove);
      document.removeEventListener("mouseup", onUp);
      normalizeWebsocketPaneWidth();
    };

    document.addEventListener("mousemove", onMove);
    document.addEventListener("mouseup", onUp);
  });
}

function getWebsocketWorkbenchWidths() {
  if (!els.websocketWorkbench || !els.websocketHandshakeColumn || !els.websocketFramesColumn) {
    return null;
  }

  return {
    total: els.websocketHandshakeColumn.getBoundingClientRect().width
      + els.websocketFramesColumn.getBoundingClientRect().width,
    handshake: els.websocketHandshakeColumn.getBoundingClientRect().width,
    frames: els.websocketFramesColumn.getBoundingClientRect().width,
  };
}

function applyWebsocketPaneWidth(handshakeWidth) {
  if (!els.websocketWorkbench) {
    return;
  }
  els.websocketWorkbench.style.setProperty("--websocket-left-pane-width", `${Math.round(handshakeWidth)}px`);
}

function normalizeWebsocketPaneWidth() {
  if (!els.websocketWorkbench || window.matchMedia(WEBSOCKET_WORKBENCH_BREAKPOINT).matches) {
    resetWebsocketPaneWidth();
    return;
  }

  const customWidth = els.websocketWorkbench.style.getPropertyValue("--websocket-left-pane-width");
  if (!customWidth) {
    return;
  }

  const bounds = getWebsocketWorkbenchWidths();
  if (!bounds) {
    return;
  }

  const nextHandshake = clamp(
    bounds.handshake,
    WEBSOCKET_WORKBENCH_MIN_WIDTHS.handshake,
    bounds.total - WEBSOCKET_WORKBENCH_MIN_WIDTHS.frames,
  );
  applyWebsocketPaneWidth(nextHandshake);
}

function resetWebsocketPaneWidth() {
  els.websocketWorkbench?.style.removeProperty("--websocket-left-pane-width");
}

function bindWebsocketStackResizer(handle) {
  if (!handle) return;
  const stackPanel = handle.parentElement;
  if (!stackPanel) return;

  const sessionsCard = stackPanel.querySelector(".panel-card-top");

  handle.addEventListener("dblclick", () => {
    if (sessionsCard) {
      sessionsCard.style.flex = "";
      sessionsCard.style.height = "";
    }
  });

  handle.addEventListener("mousedown", (event) => {
    event.preventDefault();
    const workbench = els.websocketWorkbench;
    if (!sessionsCard || !workbench) return;

    const startY = event.clientY;
    const startSessions = sessionsCard.getBoundingClientRect().height;
    const combinedHeight = startSessions + workbench.getBoundingClientRect().height;

    document.body.classList.add("pane-resizing-y");
    handle.classList.add("active");

    const onMove = (moveEvent) => {
      const delta = moveEvent.clientY - startY;
      const nextSessions = clamp(
        startSessions + delta,
        WEBSOCKET_STACK_MIN_HEIGHTS.sessions,
        combinedHeight - WEBSOCKET_STACK_MIN_HEIGHTS.workbench,
      );
      sessionsCard.style.flex = "none";
      sessionsCard.style.height = `${Math.round(nextSessions)}px`;
    };

    const onUp = () => {
      document.body.classList.remove("pane-resizing-y");
      handle.classList.remove("active");
      document.removeEventListener("mousemove", onMove);
      document.removeEventListener("mouseup", onUp);
    };

    document.addEventListener("mousemove", onMove);
    document.addEventListener("mouseup", onUp);
  });
}

function applyWorkbenchStackHeight(height, persist = true) {
  const roundedHeight = Math.round(height);
  els.proxyShell.style.setProperty("--workbench-pane-height", `${roundedHeight}px`);
  if (persist) {
    persistWorkbenchLayout(roundedHeight);
  }
}

function normalizeWorkbenchStackHeight() {
  if (
    !els.proxyShell
    || !els.trafficRegion
    || !els.lowerWorkbench
    || els.historyWorkbenchResizer?.classList.contains("hidden")
  ) {
    return;
  }

  const rawHeight = els.proxyShell.style.getPropertyValue("--workbench-pane-height");
  if (!rawHeight) {
    return;
  }

  const historyHeight = els.trafficRegion.getBoundingClientRect().height;
  const messagesHeight = els.lowerWorkbench.getBoundingClientRect().height;
  const combinedHeight = historyHeight + messagesHeight;
  const nextMessages = clamp(
    messagesHeight,
    WORKBENCH_STACK_MIN_HEIGHTS.messages,
    combinedHeight - WORKBENCH_STACK_MIN_HEIGHTS.history,
  );
  applyWorkbenchStackHeight(nextMessages);
}

function resetWorkbenchStackHeight() {
  els.proxyShell.style.removeProperty("--workbench-pane-height");
  state.workbenchHeight = null;
  scheduleUiSettingsSave();
}

function applyCodeSearch(viewElement, query) {
  // Remove any previous search highlights first
  clearSearchHighlights(viewElement);

  const normalizedQuery = String(query || "").trim();
  if (!normalizedQuery) {
    return { count: 0, firstMatch: null };
  }

  // Build a flat text map across all text nodes so we can match across
  // element boundaries (e.g. "<span>accept-encoding</span>: gzip").
  const lowerQuery = normalizedQuery.toLowerCase();
  const walker = document.createTreeWalker(viewElement, NodeFilter.SHOW_TEXT, null);
  const textNodes = [];
  let fullText = "";
  const nodeOffsets = []; // { node, start }
  while (walker.nextNode()) {
    const node = walker.currentNode;
    nodeOffsets.push({ node, start: fullText.length });
    fullText += node.nodeValue;
    textNodes.push(node);
  }

  const lowerFull = fullText.toLowerCase();
  const matches = []; // { start, end } in fullText coordinates
  let cursor = 0;
  while (true) {
    const idx = lowerFull.indexOf(lowerQuery, cursor);
    if (idx === -1) break;
    matches.push({ start: idx, end: idx + normalizedQuery.length });
    cursor = idx + 1;
  }

  if (!matches.length) {
    return { count: 0, firstMatch: null };
  }

  // Wrap each match in <mark class="search-hit"> using Range API.
  // Process matches in reverse order to preserve earlier node offsets.
  let firstMatch = null;
  for (let m = matches.length - 1; m >= 0; m--) {
    const match = matches[m];

    // Find start node/offset
    let startNode = null, startOffset = 0;
    let endNode = null, endOffset = 0;
    for (let i = 0; i < nodeOffsets.length; i++) {
      const entry = nodeOffsets[i];
      const nodeEnd = entry.start + entry.node.nodeValue.length;
      if (!startNode && match.start < nodeEnd) {
        startNode = entry.node;
        startOffset = match.start - entry.start;
      }
      if (match.end <= nodeEnd) {
        endNode = entry.node;
        endOffset = match.end - entry.start;
        break;
      }
    }
    if (!startNode || !endNode) continue;

    const range = document.createRange();
    range.setStart(startNode, startOffset);
    range.setEnd(endNode, endOffset);

    const mark = document.createElement("mark");
    mark.className = "search-hit";
    try {
      range.surroundContents(mark);
    } catch (_) {
      // surroundContents fails when the range spans partial elements.
      // Fall back to extractContents + insertion.
      const fragment = range.extractContents();
      mark.appendChild(fragment);
      range.insertNode(mark);
    }
    firstMatch = mark;

    // Rebuild nodeOffsets after DOM mutation for earlier matches
    if (m > 0) {
      nodeOffsets.length = 0;
      fullText = "";
      const w2 = document.createTreeWalker(viewElement, NodeFilter.SHOW_TEXT, null);
      while (w2.nextNode()) {
        nodeOffsets.push({ node: w2.currentNode, start: fullText.length });
        fullText += w2.currentNode.nodeValue;
      }
    }
  }

  return { count: matches.length, firstMatch };
}

function clearSearchHighlights(viewElement) {
  const marks = viewElement.querySelectorAll("mark.search-hit");
  marks.forEach((mark) => {
    const parent = mark.parentNode;
    while (mark.firstChild) {
      parent.insertBefore(mark.firstChild, mark);
    }
    parent.removeChild(mark);
    parent.normalize(); // merge adjacent text nodes back together
  });
}

function buildSearchMeta(lineCount, mode, matchCount) {
  const searchCopy = matchCount
    ? `<span class="search-hit-count">${matchCount} highlight${matchCount === 1 ? "" : "s"}</span>`
    : "No highlights";
  return `${searchCopy} · ${lineCount} lines · ${titleCase(mode)} view`;
}

function initSearchHitNavigation(metaElement, getViewFn) {
  if (!metaElement) return;
  let currentIndex = -1;
  metaElement.addEventListener("click", (e) => {
    if (!e.target.closest(".search-hit-count")) return;
    const view = getViewFn();
    if (!view) return;
    const marks = view.querySelectorAll("mark.search-hit");
    if (!marks.length) return;
    // Remove active class from previous
    const prev = view.querySelector("mark.search-hit-active");
    if (prev) prev.classList.remove("search-hit-active");
    // Advance to next
    currentIndex = (currentIndex + 1) % marks.length;
    const target = marks[currentIndex];
    target.classList.add("search-hit-active");
    // Scroll the view container to bring the match into view
    const container = target.closest(".code-view, .simple-code-view, .replay-highlight-editable, .replay-response-view") || view;
    const targetTop = target.offsetTop - container.offsetTop;
    container.scrollTop = Math.max(targetTop - 40, 0);
  });
  // Reset index when search changes (observer on innerHTML changes)
  new MutationObserver(() => { currentIndex = -1; }).observe(metaElement, { childList: true, subtree: true });
}

function initReplayResponseCMSearchNavigation() {
  if (!els.replayResponseSearchMeta) return;
  els.replayResponseSearchMeta.addEventListener("click", (event) => {
    if (!event.target.closest(".search-hit-count") || !_replayResponseCMView) return;
    event.preventDefault();
    event.stopImmediatePropagation();
    _replayResponseCMView.nextSearchMatch();
  });
}

function clamp(value, min, max) {
  return Math.min(Math.max(value, min), max);
}

function toggleSort(key) {
  if (state.sortKey === key) {
    state.sortDirection = state.sortDirection === "asc" ? "desc" : "asc";
  } else {
    state.sortKey = key;
    state.sortDirection = defaultSortDirection(key);
  }

  invalidateVisibleEntriesCache();
  scheduleRefresh({ resetScroll: true });
}

function renderSortHeaders() {
  sortHeaders.forEach((header) => {
    const active = header.dataset.sortKey === state.sortKey;
    const indicator = header.querySelector(".sort-indicator");
    header.classList.toggle("active", active);
    header.dataset.direction = active ? state.sortDirection : "none";
    if (indicator) {
      indicator.textContent = active ? (state.sortDirection === "asc" ? "↑" : "↓") : "↕";
    }
    header
      .closest("th")
      ?.setAttribute("aria-sort", active ? (state.sortDirection === "asc" ? "ascending" : "descending") : "none");
  });
}

function highlightStartLine(line, target) {
  const requestMatch = line.match(/^([A-Z]+)\s+(\S+)(?:\s+(HTTP\/[0-9.]+))?$/);
  if (target === "request" && requestMatch) {
    const [, method, path, version = "HTTP/1.1"] = requestMatch;
    return `<span class="token-method">${escapeHtml(method)}</span> ${highlightRequestTarget(path)} <span class="token-version">${escapeHtml(version)}</span>`;
  }

  const responseMatch = line.match(/^(HTTP\/[0-9.]+)\s+(\d{3})(?:\s+(.*))?$/);
  if (target === "response" && responseMatch) {
    const [, version, status, detail = ""] = responseMatch;
    return `<span class="token-version">${escapeHtml(version)}</span> <span class="token-status ${statusTone(Number(status))}">${escapeHtml(status)}</span>${detail ? ` <span class="token-plain">${escapeHtml(detail)}</span>` : ""}`;
  }

  return `<span class="token-plain">${escapeHtml(line)}</span>`;
}

function highlightRequestTarget(rawTarget) {
  const [pathPart, queryPart] = rawTarget.split("?", 2);
  if (!queryPart) {
    return `<span class="token-target">${escapeHtml(rawTarget)}</span>`;
  }

  return `<span class="token-target">${escapeHtml(pathPart)}</span><span class="token-punctuation">?</span>${highlightQueryString(queryPart)}`;
}

function highlightHeaderLine(line) {
  const separator = line.indexOf(":");
  if (separator === -1) {
    return `<span class="token-plain">${escapeHtml(line)}</span>`;
  }

  const name = line.slice(0, separator);
  const value = line.slice(separator + 1).trimStart();
  const lowerName = name.trim().toLowerCase();
  if (lowerName === "cookie" || lowerName === "set-cookie") {
    return `<span class="token-header">${escapeHtml(name)}</span><span class="token-punctuation">:</span> ${highlightCookieValue(value)}`;
  }
  return `<span class="token-header">${escapeHtml(name)}</span><span class="token-punctuation">:</span> ${highlightHeaderValue(value)}`;
}

function highlightHeaderValue(value) {
  if (!value) {
    return '<span class="token-plain"></span>';
  }

  if (value.startsWith("http://") || value.startsWith("https://")) {
    return `<span class="token-url">${escapeHtml(value)}</span>`;
  }

  if (value.includes("=") && value.includes("&") && !value.includes(" ")) {
    return highlightQueryString(value);
  }

  return `<span class="token-plain">${escapeHtml(value)}</span>`;
}

function highlightCookieValue(value) {
  // Cookie: name1=val1; name2=val2  OR  Set-Cookie: name=val; Path=/; HttpOnly
  const parts = value.split(";");
  return parts.map((part, i) => {
    const eqIdx = part.indexOf("=");
    const sep = i < parts.length - 1 ? `<span class="token-cookie-sep">;</span>` : "";
    if (eqIdx === -1) {
      // Flags like HttpOnly, Secure
      return `<span class="token-cookie-flag">${escapeHtml(part)}</span>${sep}`;
    }
    const name = part.slice(0, eqIdx);
    const val = part.slice(eqIdx + 1);
    return `<span class="token-cookie-name">${escapeHtml(name)}</span><span class="token-punctuation">=</span><span class="token-cookie-value">${escapeHtml(val)}</span>${sep}`;
  }).join("");
}

function inferBodyHighlightMode(contentType) {
  const normalized = String(contentType || "")
    .split(";", 1)[0]
    .trim()
    .toLowerCase();

  if (!normalized) {
    return "plain";
  }

  if (normalized.includes("json") || normalized.endsWith("+json")) {
    return "json";
  }

  if (
    normalized === "text/html"
    || normalized === "application/xhtml+xml"
  ) {
    return "html";
  }

  if (
    normalized === "text/xml"
    || normalized === "application/xml"
    || normalized === "image/svg+xml"
    || normalized.endsWith("+xml")
  ) {
    return "xml";
  }

  if (normalized === "text/css") {
    return "css";
  }

  if (
    normalized === "application/javascript"
    || normalized === "text/javascript"
    || normalized === "application/x-javascript"
    || normalized.includes("javascript")
    || normalized.includes("ecmascript")
  ) {
    return "javascript";
  }

  if (normalized === "application/x-www-form-urlencoded") {
    return "form";
  }

  return "plain";
}

function highlightBodyLine(line, mode = "plain") {
  const trimmed = line.trim();

  if (!trimmed) {
    return "&nbsp;";
  }

  if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
    return `<span class="token-meta">${escapeHtml(line)}</span>`;
  }

  if (mode === "json") {
    return highlightJsonLine(line);
  }

  if (mode === "form" && looksLikeFormEncoded(trimmed)) {
    return highlightQueryString(trimmed);
  }

  if (mode === "html" || mode === "xml") {
    return highlightMarkupLine(line);
  }

  if (mode === "css") {
    return highlightCssLine(line);
  }

  if (mode === "javascript") {
    return highlightJavaScriptLine(line);
  }

  if (looksLikeJson(trimmed)) {
    return highlightJsonLine(line);
  }

  if (looksLikeMarkup(trimmed)) {
    return highlightMarkupLine(line);
  }

  if (looksLikeFormEncoded(trimmed)) {
    return highlightQueryString(trimmed);
  }

  return `<span class="token-plain">${escapeHtml(line)}</span>`;
}

function looksLikeJson(line) {
  return /^[\s,[\]{}"]/u.test(line) || /:\s*/u.test(line);
}

function looksLikeMarkup(line) {
  return /^<\/?[a-z!?][^>]*>$/iu.test(line) || /^<!DOCTYPE/i.test(line);
}

function looksLikeFormEncoded(line) {
  return line.includes("=") && !/\s/u.test(line);
}

function highlightJsonLine(line) {
  const regex = /("(?:\\.|[^"\\])*")(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d+)?/g;
  let cursor = 0;
  let html = "";
  let match;

  while ((match = regex.exec(line)) !== null) {
    html += escapeHtml(line.slice(cursor, match.index));

    if (match[1]) {
      html += match[2]
        ? `<span class="token-json-key">${escapeHtml(match[1])}</span><span class="token-punctuation">:</span>`
        : `<span class="token-json-string">${escapeHtml(match[1])}</span>`;
    } else if (match[3]) {
      html += `<span class="token-json-boolean">${escapeHtml(match[3])}</span>`;
    } else {
      html += `<span class="token-json-number">${escapeHtml(match[0])}</span>`;
    }

    cursor = regex.lastIndex;
  }

  html += escapeHtml(line.slice(cursor));
  return html || `<span class="token-plain">${escapeHtml(line)}</span>`;
}

function highlightMarkupLine(line) {
  const tagPattern = /<!--.*?-->|<!DOCTYPE[^>]*>|<\?[^>]*\?>|<\/?[\w:-]+(?:\s+[\w:-]+(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s"'=<>`]+))?)*\s*\/?>/g;
  let cursor = 0;
  let html = "";
  let match;

  while ((match = tagPattern.exec(line)) !== null) {
    html += escapeHtml(line.slice(cursor, match.index));
    html += highlightMarkupToken(match[0]);
    cursor = tagPattern.lastIndex;
  }

  html += escapeHtml(line.slice(cursor));
  return html || `<span class="token-plain">${escapeHtml(line)}</span>`;
}

function highlightMarkupToken(token) {
  if (token.startsWith("<!--") || token.startsWith("<!") || token.startsWith("<?")) {
    return `<span class="token-markup-meta">${escapeHtml(token)}</span>`;
  }

  const tagMatch = token.match(/^(<\/?)([\w:-]+)([\s\S]*?)(\/?>)$/);
  if (!tagMatch) {
    return `<span class="token-markup-tag">${escapeHtml(token)}</span>`;
  }

  const [, open, name, attributes, close] = tagMatch;
  return `${highlightMarkupPunctuation(open)}<span class="token-markup-tag">${escapeHtml(name)}</span>${highlightMarkupAttributes(attributes)}${highlightMarkupPunctuation(close)}`;
}

function highlightMarkupAttributes(attributes) {
  if (!attributes) {
    return "";
  }

  const attributePattern = /([\w:-]+)(\s*=\s*)(".*?"|'.*?'|[^\s"'=<>`]+)/g;
  let cursor = 0;
  let html = "";
  let match;

  while ((match = attributePattern.exec(attributes)) !== null) {
    html += escapeHtml(attributes.slice(cursor, match.index));
    html += `<span class="token-markup-attr">${escapeHtml(match[1])}</span>${highlightMarkupPunctuation(match[2])}<span class="token-markup-string">${escapeHtml(match[3])}</span>`;
    cursor = attributePattern.lastIndex;
  }

  html += escapeHtml(attributes.slice(cursor));
  return html;
}

function highlightMarkupPunctuation(value) {
  return `<span class="token-punctuation">${escapeHtml(value)}</span>`;
}

function highlightCssLine(line) {
  const trimmed = line.trim();

  if (!trimmed) {
    return "&nbsp;";
  }

  if (trimmed.startsWith("/*") || trimmed.startsWith("*") || trimmed.endsWith("*/")) {
    return `<span class="token-meta">${escapeHtml(line)}</span>`;
  }

  const propertyMatch = line.match(/^(\s*)([\w-]+)(\s*:\s*)(.*?)(\s*;?\s*)$/);
  if (propertyMatch) {
    const [, indent, property, separator, value, suffix] = propertyMatch;
    return `${escapeHtml(indent)}<span class="token-css-property">${escapeHtml(property)}</span><span class="token-punctuation">${escapeHtml(separator)}</span>${highlightCssValue(value)}${highlightMarkupPunctuation(suffix)}`;
  }

  const selectorMatch = line.match(/^(\s*)([^{}]+?)(\s*)([{}])(\s*)$/);
  if (selectorMatch) {
    const [, indent, selector, innerSpace, brace, suffix] = selectorMatch;
    return `${escapeHtml(indent)}<span class="token-css-selector">${escapeHtml(selector)}</span>${escapeHtml(innerSpace)}<span class="token-punctuation">${escapeHtml(brace)}</span>${escapeHtml(suffix)}`;
  }

  const atRuleMatch = line.match(/^(\s*)(@[\w-]+)(.*)$/);
  if (atRuleMatch) {
    const [, indent, keyword, rest] = atRuleMatch;
    return `${escapeHtml(indent)}<span class="token-css-keyword">${escapeHtml(keyword)}</span>${highlightCssValue(rest)}`;
  }

  if (trimmed === "{" || trimmed === "}") {
    return `<span class="token-punctuation">${escapeHtml(line)}</span>`;
  }

  return `<span class="token-plain">${escapeHtml(line)}</span>`;
}

function highlightCssValue(value) {
  const tokenPattern = /(".*?"|'.*?'|#[0-9a-f]{3,8}\b|-?\d+(?:\.\d+)?(?:px|em|rem|%|vh|vw|ms|s|deg)?)/gi;
  let cursor = 0;
  let html = "";
  let match;

  while ((match = tokenPattern.exec(value)) !== null) {
    html += escapeHtml(value.slice(cursor, match.index));
    if (match[0].startsWith('"') || match[0].startsWith("'")) {
      html += `<span class="token-markup-string">${escapeHtml(match[0])}</span>`;
    } else {
      html += `<span class="token-json-number">${escapeHtml(match[0])}</span>`;
    }
    cursor = tokenPattern.lastIndex;
  }

  html += escapeHtml(value.slice(cursor));
  return html || `<span class="token-plain">${escapeHtml(value)}</span>`;
}

function highlightJavaScriptLine(line) {
  const tokenPattern = /\/\/.*$|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`|\b(?:const|let|var|function|return|if|else|for|while|true|false|null|undefined|class|new|await|async|import|export|switch|case|break|continue|throw|try|catch|finally)\b|-?\d+(?:\.\d+)?/gm;
  let cursor = 0;
  let html = "";
  let match;

  while ((match = tokenPattern.exec(line)) !== null) {
    html += escapeHtml(line.slice(cursor, match.index));
    const token = match[0];

    if (token.startsWith("//")) {
      html += `<span class="token-meta">${escapeHtml(token)}</span>`;
    } else if (token.startsWith('"') || token.startsWith("'") || token.startsWith("`")) {
      html += `<span class="token-js-string">${escapeHtml(token)}</span>`;
    } else if (/^-?\d/u.test(token)) {
      html += `<span class="token-json-number">${escapeHtml(token)}</span>`;
    } else {
      html += `<span class="token-js-keyword">${escapeHtml(token)}</span>`;
    }

    cursor = tokenPattern.lastIndex;
  }

  html += escapeHtml(line.slice(cursor));
  return html || `<span class="token-plain">${escapeHtml(line)}</span>`;
}

function highlightQueryString(query) {
  return query
    .split("&")
    .map((pair) => {
      const [key, value = ""] = pair.split("=", 2);
      return `<span class="token-query-key">${escapeHtml(key)}</span><span class="token-punctuation">=</span><span class="token-query-value">${escapeHtml(value)}</span>`;
    })
    .join('<span class="token-punctuation">&amp;</span>');
}

function buildLineNumbers(count) {
  return Array.from({ length: Math.max(count, 1) }, (_value, index) => index + 1).join("\n");
}

function countLines(text) {
  return String(text || "").split("\n").length;
}

function updateWsHandshakeLineNumbers() {
  if (!els.wsHandshakeLines) return;
  const cv = getCMView("wsHandshake");
  if (cv) {
    els.wsHandshakeLines.textContent = buildLineNumbers(cv.view.state.doc.lines);
    return;
  }
  const resBtn = document.getElementById("wsHandshakeResBtn");
  const showingResponse = resBtn?.classList.contains("active");
  const activeView = showingResponse ? els.websocketResponseView : els.websocketRequestView;
  if (!activeView) return;
  const lineCount = activeView.querySelectorAll(".code-line").length || 1;
  els.wsHandshakeLines.textContent = buildLineNumbers(lineCount);
}

function getCurrentSelectedRecord() {
  return state.selectedRecord?.id === state.selectedId ? state.selectedRecord : null;
}

function updateWsHandshakeSearch() {
  const query = els.wsHandshakeSearchInput?.value || "";
  // CM path
  const cv = getCMView("wsHandshake");
  if (cv) {
    const result = cv.applySearch(query);
    const lineCount = cv.view.state.doc.lines;
    if (els.wsHandshakeSearchMeta) {
      els.wsHandshakeSearchMeta.innerHTML = buildSearchMeta(lineCount, "pretty", result.matchCount);
    }
    return;
  }
  // Legacy path
  const resBtn = document.getElementById("wsHandshakeResBtn");
  const showingResponse = resBtn?.classList.contains("active");
  const activeView = showingResponse ? els.websocketResponseView : els.websocketRequestView;
  if (!activeView) return;
  const result = applyCodeSearch(activeView, query);
  const lineCount = activeView.querySelectorAll(".code-line").length || 1;
  if (els.wsHandshakeSearchMeta) {
    els.wsHandshakeSearchMeta.innerHTML = buildSearchMeta(lineCount, "pretty", result.count);
  }
}

function setWsMessageHighlightText(text) {
  if (!els.wsMessageHighlight) return;
  els.wsMessageHighlight.textContent = text;
  applyWsMessageJsonHighlight();
}

function applyWsMessageJsonHighlight() {
  if (!els.wsMessageHighlight) return;
  const text = els.wsMessageHighlight.innerText || "";
  // Only apply JSON highlighting if it looks like JSON
  const trimmed = text.trim();
  if ((trimmed.startsWith("{") && trimmed.endsWith("}")) || (trimmed.startsWith("[") && trimmed.endsWith("]"))) {
    // Save cursor position
    const sel = window.getSelection();
    let cursorOffset = 0;
    if (sel.rangeCount > 0 && els.wsMessageHighlight.contains(sel.anchorNode)) {
      const range = document.createRange();
      range.selectNodeContents(els.wsMessageHighlight);
      range.setEnd(sel.anchorNode, sel.anchorOffset);
      cursorOffset = range.toString().length;
    }

    els.wsMessageHighlight.innerHTML = highlightJson(text);

    // Restore cursor position
    if (document.activeElement === els.wsMessageHighlight && cursorOffset > 0) {
      restoreCursorPosition(els.wsMessageHighlight, cursorOffset);
    }
  }
}

function highlightJson(text) {
  const source = String(text ?? "");
  const tokenPattern = /("(?:[^"\\]|\\.)*")\s*:|("(?:[^"\\]|\\.)*")|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)\b|(true|false)\b|(null)\b|([{}[\]:,])/g;
  let cursor = 0;
  let html = "";
  let match;

  while ((match = tokenPattern.exec(source)) !== null) {
    html += escapeHtml(source.slice(cursor, match.index));
    const [token, key, str, num, bool, nul, punct] = match;
    if (key) html += `<span class="json-key">${escapeHtml(key)}</span>:`;
    else if (str) html += `<span class="json-string">${escapeHtml(str)}</span>`;
    else if (num) html += `<span class="json-number">${escapeHtml(num)}</span>`;
    else if (bool) html += `<span class="json-bool">${escapeHtml(bool)}</span>`;
    else if (nul) html += `<span class="json-null">${escapeHtml(nul)}</span>`;
    else if (punct) html += `<span class="json-punct">${escapeHtml(punct)}</span>`;
    else html += escapeHtml(token);
    cursor = tokenPattern.lastIndex;
  }

  html += escapeHtml(source.slice(cursor));
  return html;
}

function restoreCursorPosition(element, offset) {
  const walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT, null);
  let remaining = offset;
  let node;
  while ((node = walker.nextNode())) {
    if (remaining <= node.textContent.length) {
      const sel = window.getSelection();
      const range = document.createRange();
      range.setStart(node, remaining);
      range.collapse(true);
      sel.removeAllRanges();
      sel.addRange(range);
      return;
    }
    remaining -= node.textContent.length;
  }
}

function renderHeaderList(headers) {
  if (!headers.length) {
    return "<p class=\"empty-copy\">No headers were captured.</p>";
  }

  return headers
    .map(
      (header) => `
        <div class="header-row">
          <span>${escapeHtml(header.name)}</span>
          <strong>${escapeHtml(header.value)}</strong>
        </div>
      `,
    )
    .join("");
}

function renderSummaryRows(rows) {
  return rows
    .map((row) => {
      const label = Array.isArray(row) ? row[0] : row.label;
      const value = Array.isArray(row) ? row[1] : row.value;
      const isHtml = !Array.isArray(row) && row.html === true;
      return `
        <dt>${escapeHtml(String(label))}</dt>
        <dd>${isHtml ? value : escapeHtml(String(value))}</dd>
      `;
    })
    .join("");
}

function inferProtocolState(record) {
  const headerNames = normalizedHeaders(record.request?.headers).map((header) => header.name);
  const looksLikeHttp2 = headerNames.some((name) => name.startsWith(":"));
  return {
    current: looksLikeHttp2 ? "HTTP/2" : "HTTP/1",
    supportsHttp2: looksLikeHttp2,
  };
}

function renderProtocolStrip(protocolState) {
  const current = protocolState?.current || "HTTP/1";
  const supportsHttp2 = Boolean(protocolState?.supportsHttp2);
  return `
    <div class="protocol-strip-label">Protocol</div>
    <div class="protocol-pill-group" aria-label="Captured protocol">
      <span class="protocol-pill ${current === "HTTP/1" ? "active" : ""}">HTTP/1</span>
      <span class="protocol-pill ${current === "HTTP/2" ? "active" : ""} ${supportsHttp2 ? "" : "muted"}">HTTP/2</span>
    </div>
  `;
}

function inferMimeType(item) {
  if (item._mime) return item._mime;
  const contentType = (item.content_type || "").toLowerCase();
  if (contentType.includes("html")) return (item._mime = "html");
  if (contentType.includes("javascript")) return (item._mime = "script");
  if (contentType.includes("css")) return (item._mime = "css");
  if (contentType.includes("json") || contentType.includes("text")) return (item._mime = "json");
  if (contentType.includes("image")) return (item._mime = "image");
  const path = (item.path || "").toLowerCase();
  if (path.endsWith(".js")) return (item._mime = "script");
  if (path.endsWith(".css")) return (item._mime = "css");
  if (path.endsWith(".json")) return (item._mime = "json");
  if (path.endsWith(".html")) return (item._mime = "html");
  if (/\.(png|jpg|jpeg|gif|svg|ico)$/i.test(path)) return (item._mime = "image");
  if (item.is_websocket) return (item._mime = "websocket");
  return (item._mime = "other");
}

function isTlsRecord(item) {
  return item.kind === "tunnel" || item.scheme === "https";
}

function getVisibleItems() {
  return getVisibleEntries().map((entry) => entry.item);
}

function invalidateVisibleEntriesCache() {
  state._cachedVisibleEntries = null;
  state._cachedVisibleEntriesKey = "";
}

function getVisibleEntries() {
  const cacheKey = String(state._itemsVersion);
  if (state._cachedVisibleEntries && state._cachedVisibleEntriesKey === cacheKey) {
    return state._cachedVisibleEntries;
  }

  const result = [];
  const items = state.items;
  for (let i = 0, len = items.length; i < len; i++) {
    const item = items[i];
    result.push({ item, index: i });
  }

  state._cachedVisibleEntries = result;
  state._cachedVisibleEntriesKey = cacheKey;
  return state._cachedVisibleEntries;
}

function syncColorTagFilterUI() {
  const tags = state.filterSettings.colorTags;
  els.colorTagFilter.querySelectorAll(".color-dot-btn").forEach((btn) => {
    btn.classList.toggle("active", tags.has(btn.dataset.color));
  });
}

function isInScopeHost(host) {
  const patterns = state.runtime?.scope_patterns || [];
  if (!patterns.length) {
    return true;
  }

  const hostname = hostWithoutPort(host).toLowerCase();
  return patterns.some((pattern) => {
    const normalized = hostWithoutPort(pattern).toLowerCase();
    if (normalized.startsWith("*.")) {
      const suffix = normalized.slice(2);
      return hostname === suffix || hostname.endsWith(`.${suffix}`);
    }
    return hostname === normalized;
  });
}

function hostWithoutPort(host) {
  const value = String(host || "").trim();
  if (value.startsWith("[")) {
    const end = value.indexOf("]");
    if (end > 0) return value.slice(1, end);
  }
  return (value.match(/:/g) || []).length === 1 ? value.split(":")[0] : value;
}

function extractHostPort(host) {
  const value = String(host || "").trim();
  if (value.startsWith("[")) {
    const end = value.indexOf("]");
    return end > 0 && value[end + 1] === ":" ? value.slice(end + 2) : "";
  }
  return (value.match(/:/g) || []).length === 1 ? value.split(":")[1] : "";
}

/** Pre-compute per-item display values and lookup indexes used by the history table. */
function precomputeItemIndexes() {
  let connectCount = 0;
  const items = state.items;
  for (let i = 0, len = items.length; i < len; i++) {
    const item = items[i];
    prepareHistoryItem(item);
    if (item.method === "CONNECT") connectCount++;
  }
  state._connectCount = connectCount;
  rebuildHistoryItemIndex();
}

function prepareHistoryItem(item) {
  item._totalBytes = (item.request_bytes ?? 0) + (item.response_bytes ?? 0);
  item._sizeLabel = formatSize(item._totalBytes);
  item._mime = inferMimeType(item);
  item._timeLabel = "";
  return item;
}

function getHistoryTimeLabel(item) {
  if (!item._timeLabel) {
    item._timeLabel = formatTimestamp(item.started_at);
  }
  return item._timeLabel;
}

function rebuildHistoryItemIndex() {
  state._itemById = new Map();
  state._itemIndexById = new Map();
  for (let i = 0, len = state.items.length; i < len; i++) {
    const item = state.items[i];
    state._itemById.set(item.id, item);
    state._itemIndexById.set(item.id, i);
  }
}

function getHistoryItem(id) {
  return state._itemById?.get(id) || null;
}

function getHistoryItemIndex(id) {
  const index = state._itemIndexById?.get(id);
  return Number.isInteger(index) ? index : -1;
}

function countHiddenConnectItems() {
  const hiddenTotal = state.historyPaging?.hiddenConnectTotal;
  if (isKnownCount(hiddenTotal)) return hiddenTotal;
  // Use precomputed count when available; fall back to scan otherwise.
  if (typeof state._connectCount === "number") return state._connectCount;
  return state.items.filter((item) => item.method === "CONNECT").length;
}

function humanizeProxyTab(value) {
  return value
    .split("-")
    .map((segment) => titleCase(segment))
    .join(" ");
}

function humanizeSortKey(key) {
  switch (key) {
    case "index":
      return "#";
    case "started_at":
      return "time";
    case "path":
      return "url";
    default:
      return key.replaceAll("_", " ");
  }
}

function defaultSortDirection(key) {
  return ["index", "started_at", "status", "length", "notes", "tls"].includes(key) ? "desc" : "asc";
}

function compareSortValues(left, right) {
  if (typeof left === "number" && typeof right === "number") {
    return left - right;
  }

  const leftText = String(left);
  const rightText = String(right);
  if (leftText === rightText) return 0;
  return HISTORY_SORT_COLLATOR.compare(leftText, rightText);
}

function formatKind(kind) {
  return kind === "tunnel" ? "CONNECT tunnel" : "HTTP exchange";
}

function formatStatus(status) {
  if (status == null) return "n/a";
  return String(status);
}

function statusTone(status) {
  const code = Number(status);
  if (!Number.isFinite(code)) return "none";
  if (code >= 200 && code < 300) return "ok";
  if (code >= 300 && code < 400) return "info";
  if (code >= 400 && code < 500) return "warn";
  return "error";
}

function methodTone(method) {
  switch (method) {
    case "GET":
      return "is-get";
    case "POST":
      return "is-post";
    case "PUT":
      return "is-put";
    case "PATCH":
      return "is-patch";
    case "DELETE":
      return "is-delete";
    default:
      return "is-generic";
  }
}

function formatTimestamp(value) {
  if (value == null || value === "") {
    return "-";
  }
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) {
    return "-";
  }
  return HISTORY_TIME_FORMATTER.format(date);
}

function formatSize(bytes) {
  let size = Number(bytes);
  if (!Number.isFinite(size) || size <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  let index = 0;
  while (size >= 1024 && index < units.length - 1) {
    size /= 1024;
    index += 1;
  }
  return `${size.toFixed(size >= 10 || index === 0 ? 0 : 1)} ${units[index]}`;
}

function titleCase(value) {
  const text = String(value || "");
  return text.charAt(0).toUpperCase() + text.slice(1);
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

/* ─── WebSocket Replay ─── */

function normalizeWebsocketFrames(frames) {
  return (Array.isArray(frames) ? frames : [])
    .filter((frame) => frame && typeof frame === "object")
    .map((frame, fallbackIndex) => {
      const index = Number(frame.index);
      return {
        ...frame,
        index: Number.isFinite(index) ? index : fallbackIndex,
        direction: frame.direction === "client_to_server" ? "client_to_server" : "server_to_client",
        kind: String(frame.kind || "text"),
        body: String(frame.body ?? frame.body_preview ?? ""),
        body_preview: String(frame.body_preview ?? frame.body ?? ""),
      };
    });
}

function getWebsocketFrames(session) {
  return normalizeWebsocketFrames(session?.frames);
}

function getWsReplayFrames(tab) {
  return normalizeWebsocketFrames(tab?.wsFrames);
}

function utf8ByteLength(value) {
  return new TextEncoder().encode(String(value || "")).length;
}

function truncateUtf8Preview(value, maxBytes) {
  const text = String(value || "");
  const fullBytes = utf8ByteLength(text);
  if (fullBytes <= maxBytes) {
    return { body: text, storedBytes: fullBytes, truncated: false };
  }
  const encoder = new TextEncoder();
  let body = "";
  let storedBytes = 0;
  for (const char of text) {
    const charBytes = encoder.encode(char).length;
    if (storedBytes + charBytes > maxBytes) break;
    body += char;
    storedBytes += charBytes;
  }
  return { body, storedBytes, truncated: true };
}

function truncateBase64Preview(value, maxBytes) {
  const encoded = String(value || "");
  let decoded = "";
  try {
    decoded = atob(encoded);
  } catch (_error) {
    return { body: "", storedBytes: 0, truncated: true };
  }
  if (decoded.length <= maxBytes) {
    return { body: encoded, storedBytes: decoded.length, truncated: false };
  }
  return {
    body: btoa(decoded.slice(0, maxBytes)),
    storedBytes: maxBytes,
    truncated: true,
  };
}

function snapshotWsReplayFrames(tab, budget = null) {
  const frameLimit = budget
    ? Math.min(WS_REPLAY_MAX_PERSISTED_FRAMES, Math.max(0, budget.frames))
    : WS_REPLAY_MAX_PERSISTED_FRAMES;
  const frames = getWsReplayFrames(tab).slice(-frameLimit);
  const selected = [];
  for (let reverseIndex = frames.length - 1; reverseIndex >= 0; reverseIndex -= 1) {
    const frame = frames[reverseIndex];
    const fallbackIndex = reverseIndex;
    if (budget && (budget.frames <= 0 || budget.bytes <= 0)) {
      break;
    }
    const encoding = frame.body_encoding === "base64" ? "base64" : "utf8";
    const bodySource = String(frame.body ?? frame.body_preview ?? "");
    const frameByteLimit = budget
      ? Math.min(WS_REPLAY_MAX_PERSISTED_FRAME_BODY_BYTES, Math.max(0, budget.bytes))
      : WS_REPLAY_MAX_PERSISTED_FRAME_BODY_BYTES;
    const preview = encoding === "base64"
      ? truncateBase64Preview(bodySource, frameByteLimit)
      : truncateUtf8Preview(bodySource, frameByteLimit);
    const declaredBodySize = Number(frame.body_size);
    const bodySize = Number.isFinite(declaredBodySize) && declaredBodySize >= preview.storedBytes
      ? declaredBodySize
      : preview.storedBytes;
    const capturedAt = Number.isFinite(Date.parse(frame.captured_at))
      ? String(frame.captured_at)
      : new Date().toISOString();
    const index = Number(frame.index);
    if (budget) {
      budget.frames -= 1;
      budget.bytes -= preview.storedBytes;
    }
    selected.push({
      index: Number.isFinite(index) ? index : fallbackIndex,
      captured_at: capturedAt,
      direction: frame.direction === "client_to_server" ? "client_to_server" : "server_to_client",
      kind: normalizeWsFrameKind(frame.kind),
      body: preview.body,
      body_encoding: encoding,
      body_size: bodySize,
      preview_truncated: Boolean(frame.preview_truncated || preview.truncated || bodySize > preview.storedBytes),
    });
  }
  return selected.reverse();
}

function normalizeWsMessageType(value) {
  const normalized = String(value || "").trim().toLowerCase();
  return ["binary", "ping", "pong"].includes(normalized) ? normalized : "text";
}

function normalizeWsFrameKind(value) {
  const normalized = String(value || "").trim().toLowerCase();
  return ["binary", "ping", "pong", "close", "other"].includes(normalized) ? normalized : "text";
}

function normalizeWsSetupItem(item = {}) {
  const kind = normalizeWsMessageType(item.kind || item.messageType || item.message_type);
  const body = String(item.body ?? "");
  const bodyEncoded = !!(item.bodyEncoded ?? item.body_encoded);
  return {
    body,
    kind,
    bodyEncoded,
    autoSend: !!item.autoSend,
    sent: !!item.sent,
    label: item.label || truncateSetupLabel(body, kind),
  };
}

function wsSetupItemFromCapturedFrame(frame) {
  const kind = wsReplayMessageTypeForFrame(frame);
  const rawFrameBody = frame.body || frame.body_preview || "";
  const bodyEncoded = kind !== "text" && frame.body_encoding === "base64";
  const body = kind === "text" && frame.body_encoding === "base64"
    ? safeDecodeBase64(rawFrameBody, rawFrameBody)
    : rawFrameBody;
  return normalizeWsSetupItem({
    body,
    kind,
    bodyEncoded,
    autoSend: true,
    sent: false,
    label: truncateSetupLabel(body, kind),
  });
}

function createWsReplayTab(seed = {}) {
  state.replayTabSequence += 1;
  const selectedFrameIndex = Number(seed.selectedFrameIndex);
  const tab = {
    id: crypto.randomUUID(),
    type: "websocket",
    sequence: state.replayTabSequence,
    customLabel: normalizeReplayTabCustomLabel(seed.customLabel || ""),
    label: `WS ${seed.host || "draft"}`,
    wsScheme: seed.scheme || "wss",
    wsHost: seed.host || "",
    wsPort: seed.port || defaultWsPortForScheme(seed.scheme),
    wsPath: seed.path || "/",
    wsHeaders: normalizedHeaders(seed.headers),
    wsHandshakeText: seed.handshakeText || "",
    wsHandshakeEdited: !!seed.handshakeEdited,
    wsStatus: "disconnected",
    wsFrames: [],
    wsSelectedFrameIndex: -1,
    wsSessionId: null,
    wsEditorText: seed.editorText || "",
    wsMessageType: normalizeWsMessageType(seed.messageType),
    wsEditorBodyEncoded: !!seed.editorBodyEncoded,
    wsError: null,
    wsPollTimer: null,
    wsLifecycleToken: 0,
    wsSetupPending: false,
    wsSetupRunning: false,
    wsSetupQueue: Array.isArray(seed.setupQueue)
      ? seed.setupQueue.map((item) => normalizeWsSetupItem(item))
      : normalizeWebsocketFrames(seed.capturedFrames)
        .filter((f) => f.direction === "client_to_server")
        .filter((f) => !Number.isFinite(selectedFrameIndex) || f.index < selectedFrameIndex)
        .filter((f) => !f.preview_truncated)
        .map((f) => wsSetupItemFromCapturedFrame(f)),
  };
  state.replayTabs.push(tab);
  state.activeReplayTabId = tab.id;
  scheduleWorkspaceStateSave();
  renderReplay();
  return tab;
}

function truncateSetupLabel(body, kind = "text") {
  const messageKind = normalizeWsMessageType(kind);
  if (messageKind !== "text") {
    return messageKind.toUpperCase();
  }
  try {
    const parsed = JSON.parse(body);
    if (parsed.event) return parsed.event;
    if (parsed.topic) return parsed.topic;
    if (parsed.type) return parsed.type;
  } catch (e) {}
  return body.length > 30 ? body.substring(0, 30) + "…" : body;
}

async function wsConnect() {
  const tab = getActiveReplayTab();
  if (!tab || tab.type !== "websocket") return;
  const sessionId = state.activeSession?.id || null;
  const lifecycleToken = (tab.wsLifecycleToken || 0) + 1;
  tab.wsLifecycleToken = lifecycleToken;
  tab.wsSessionId = sessionId;

  // Sync fields from UI
  const wsScheme = els.wsSchemeSelect.value;
  const wsHost = els.wsHostInput.value.trim();
  const wsPortText = els.wsPortInput.value.trim();
  const wsPath = els.wsPathInput.value.trim();
  const validation = validateWsReplayTargetInput(wsScheme, wsHost, wsPortText, wsPath);
  setWsReplayTargetInputValidity(validation);
  if (!validation.valid) {
    els.wsSchemeSelect.reportValidity();
    els.wsHostInput.reportValidity();
    els.wsPortInput.reportValidity();
    els.wsPathInput.reportValidity();
    return;
  }
  const wsPort = normalizePortValue(wsPortText);
  tab.wsScheme = wsScheme;
  tab.wsHost = wsHost;
  tab.wsPort = wsPort;
  tab.wsPath = wsPath;

  tab.wsStatus = "connecting";
  tab.wsFrames = [];
  tab.wsSelectedFrameIndex = -1;
  tab.wsError = null;
  tab.wsSetupPending = Array.isArray(tab.wsSetupQueue)
    && tab.wsSetupQueue.some((item) => item.autoSend && !item.sent);
  tab.wsSetupRunning = false;
  for (const item of Array.isArray(tab.wsSetupQueue) ? tab.wsSetupQueue : []) {
    item.sent = false;
  }
  scheduleWorkspaceStateSave();
  renderWsStatus();
  renderWsFrameList();

  try {
    const headers = parseWsHandshakeHeaders(tab);
    const resp = await fetch("/api/replay/ws-connect", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        session_id: sessionId,
        id: tab.id,
        scheme: wsScheme,
        host: wsHost,
        port: Number(wsPort),
        path: wsPath,
        headers,
      }),
    });
    if (!isWsReplayTabAlive(tab, lifecycleToken)) {
      await disconnectWsReplayBackend(tab.id, { remove: true, sessionId });
      return;
    }
    if (!resp.ok) {
      const text = await resp.text().catch(() => "Connection failed");
      throw new Error(text);
    }
    startWsPoll(tab);
    renderReplayTabs();

    // Auto-send setup queue after connection
    await runSetupQueue(tab, lifecycleToken);
  } catch (e) {
    if (!isWsReplayTabAlive(tab, lifecycleToken)) {
      return;
    }
    tab.wsStatus = "error";
    tab.wsError = e.message;
    scheduleWorkspaceStateSave();
    renderWsStatus();
    renderReplayTabs();
    showToast(tab.wsError || "WebSocket connection failed.", "error");
  }
}

async function runSetupQueue(tab, lifecycleToken = tab?.wsLifecycleToken) {
  const setupQueue = Array.isArray(tab?.wsSetupQueue) ? tab.wsSetupQueue : [];
  if (!setupQueue.some((item) => item.autoSend && !item.sent)) {
    if (tab) tab.wsSetupPending = false;
    return;
  }
  if (tab.wsSetupRunning) return;
  tab.wsSetupRunning = true;

  try {
    // Wait for connection to be established
    for (let i = 0; i < 20; i++) {
      await new Promise((r) => setTimeout(r, 150));
      if (!isWsReplayTabAlive(tab, lifecycleToken)) return;
      if (tab.wsStatus === "connected") break;
      if (tab.wsStatus === "error" || tab.wsStatus === "disconnected") return;
    }
    if (tab.wsStatus !== "connected") {
      tab.wsSetupPending = true;
      return;
    }
    tab.wsSetupPending = false;

    for (const item of setupQueue) {
      if (!item.autoSend || item.sent) continue;
      if (!isWsReplayTabAlive(tab, lifecycleToken)) return;
      if (tab.wsStatus !== "connected") break;

      try {
        const kind = normalizeWsMessageType(item.kind);
        const sendBody = wsReplayBodyForSend(item.body, kind, !!item.bodyEncoded);
        const resp = await fetch("/api/replay/ws-send", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ session_id: tab.wsSessionId || state.activeSession?.id || null, id: tab.id, body: sendBody, binary: kind !== "text", kind }),
        });
        if (!isWsReplayTabAlive(tab, lifecycleToken)) return;
        if (resp.ok) {
          item.sent = true;
          renderWsSetupQueue();
          scheduleWorkspaceStateSave();
        }
      } catch (e) {
        break;
      }
      // Small delay between messages
      await new Promise((r) => setTimeout(r, 100));
    }
  } finally {
    if (isWsReplayTabAlive(tab, lifecycleToken)) {
      tab.wsSetupRunning = false;
    }
  }
}

function parseWsHandshakeHeaders(tab) {
  const headers = [];
  const text = els.wsHandshakeHeaders ? els.wsHandshakeHeaders.value : (tab.wsHandshakeText || "");
  if (text.trim()) {
    for (const line of text.split("\n")) {
      if (!line.trim()) {
        continue;
      }
      const colonIdx = line.indexOf(":");
      const name = colonIdx > 0 ? line.slice(0, colonIdx).trim() : "";
      if (!name) {
        throw new Error(`Invalid WebSocket handshake header: ${line.trim()}`);
      }
      headers.push({
        name,
        value: line.slice(colonIdx + 1).trim(),
      });
    }
  }
  if (tab.wsHandshakeEdited) {
    return headers;
  }
  // Merge with any pre-set headers from seed
  const merged = [...headers];
  for (const h of normalizedHeaders(tab.wsHeaders)) {
    if (!merged.some(m => headerNameEquals(m, h.name))) {
      merged.push(h);
    }
  }
  return merged;
}

async function wsSend() {
  const tab = getActiveReplayTab();
  if (!tab || tab.type !== "websocket" || tab.wsStatus !== "connected") return;

  const body = els.wsMessageEditor.value;

  tab.wsMessageType = normalizeWsMessageType(els.wsMessageType.value);
  const binary = tab.wsMessageType !== "text";
  const sendBody = wsReplayBodyForSend(body, tab.wsMessageType, tab.wsEditorBodyEncoded);
  scheduleWorkspaceStateSave();

  try {
    const resp = await fetch("/api/replay/ws-send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ session_id: tab.wsSessionId || state.activeSession?.id || null, id: tab.id, body: sendBody, binary, kind: tab.wsMessageType }),
    });
    if (!resp.ok) {
      const text = await resp.text().catch(() => "Send failed");
      showToast(text, "error");
    }
  } catch (e) {
    showToast(`Send failed: ${e.message}`, "error");
  }
}

async function wsDisconnect() {
  const tab = getActiveReplayTab();
  if (!tab || tab.type !== "websocket") return;

  await cleanupWsReplayTab(tab, {
    markDisconnected: true,
    removeBackend: tab.wsStatus === "connecting",
  });
}

async function cleanupWsReplayTab(tab, { markDisconnected = false, removeBackend = true } = {}) {
  if (!tab || tab.type !== "websocket") return;
  tab.wsLifecycleToken = (tab.wsLifecycleToken || 0) + 1;
  clearWsFrameListRender(tab);
  await refreshWsReplayFramesOnce(tab);
  stopWsPoll(tab);
  await disconnectWsReplayBackend(tab.id, { remove: removeBackend, sessionId: tab.wsSessionId || state.activeSession?.id || null });
  if (!removeBackend) {
    await refreshWsReplayFramesUntilSettled(tab);
  }
  if (markDisconnected) {
    tab.wsStatus = "disconnected";
    tab.wsError = null;
    scheduleWorkspaceStateSave();
    if (state.activeReplayTabId === tab.id) {
      renderWsStatus();
    }
  }
}

async function refreshWsReplayFramesOnce(tab) {
  if (!tab || tab.type !== "websocket") return false;
  const sessionId = encodeURIComponent(tab.wsSessionId || state.activeSession?.id || "");
  if (!sessionId) return false;
  const sinceIndex = nextWsFrameIndex(tab);
  const resp = await fetch(`/api/replay/ws-frames/${tab.id}?since=${sinceIndex}&session_id=${sessionId}`)
    .catch(() => null);
  if (!resp || !resp.ok) {
    return false;
  }
  const data = await resp.json().catch(() => null) || {};
  const incomingFrames = normalizeWebsocketFrames(data.frames);
  let addedFrames = false;
  if (incomingFrames.length > 0) {
    const existing = new Set(getWsReplayFrames(tab).map((frame) => frame.index));
    const fresh = incomingFrames.filter((frame) => !existing.has(frame.index));
    if (fresh.length) {
      if (!Array.isArray(tab.wsFrames)) tab.wsFrames = [];
      tab.wsFrames.push(...fresh);
      trimWsReplayFrames(tab);
      scheduleWsTranscriptWorkspaceSave();
      addedFrames = true;
      if (state.activeReplayTabId === tab.id) {
        scheduleWsFrameListRender(tab);
      }
    }
  }
  if (data.status && data.status !== tab.wsStatus) {
    tab.wsStatus = data.status;
    tab.wsError = data.error || null;
    scheduleWorkspaceStateSave();
    if (state.activeReplayTabId === tab.id) {
      renderWsStatus();
    }
  }
  return addedFrames;
}

async function refreshWsReplayFramesUntilSettled(tab) {
  const started = Date.now();
  let sawFrame = false;
  do {
    const added = await refreshWsReplayFramesOnce(tab);
    sawFrame = sawFrame || added;
    if (!added) {
      return sawFrame;
    }
    await new Promise((resolve) => window.setTimeout(resolve, WS_REPLAY_FINAL_POLL_INTERVAL_MS));
  } while (Date.now() - started < WS_REPLAY_FINAL_POLL_TIMEOUT_MS);
  return sawFrame;
}

async function disconnectWsReplayBackend(id, { remove = false, sessionId = state.activeSession?.id || null } = {}) {
  try {
    await fetch("/api/replay/ws-disconnect", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ session_id: sessionId, id, remove }),
    });
  } catch (e) {
    // ignore disconnect errors
  }
}

function isWsReplayTabAlive(tab, lifecycleToken) {
  return Boolean(
    tab
    && state.replayTabs.includes(tab)
    && tab.wsLifecycleToken === lifecycleToken
  );
}

function clearWsFrameListRender(tab) {
  if (tab?.wsFrameRenderTimer) {
    window.clearTimeout(tab.wsFrameRenderTimer);
    tab.wsFrameRenderTimer = null;
  }
}

function scheduleWsFrameListRender(tab) {
  if (!tab || state.activeReplayTabId !== tab.id || tab.wsFrameRenderTimer) {
    return;
  }
  tab.wsFrameRenderTimer = window.setTimeout(() => {
    tab.wsFrameRenderTimer = null;
    if (state.activeReplayTabId === tab.id && state.replayTabs.includes(tab)) {
      renderWsFrameList();
    }
  }, 300);
}

function startWsPoll(tab) {
  stopWsPoll(tab);
  let sinceIndex = nextWsFrameIndex(tab);
  const generation = (tab.wsPollGeneration || 0) + 1;
  const lifecycleToken = tab.wsLifecycleToken;
  tab.wsPollGeneration = generation;

  const poll = async () => {
    if (!tab.wsPollTimer || tab.wsPollGeneration !== generation || !isWsReplayTabAlive(tab, lifecycleToken)) return;
    try {
      const sessionId = encodeURIComponent(tab.wsSessionId || state.activeSession?.id || "");
      const resp = await fetch(`/api/replay/ws-frames/${tab.id}?since=${sinceIndex}&session_id=${sessionId}`);
      if (!tab.wsPollTimer || tab.wsPollGeneration !== generation || !isWsReplayTabAlive(tab, lifecycleToken)) return;
      if (!resp.ok) {
        if (resp.status === 404 || resp.status === 409) {
          const text = await resp.text().catch(() => "");
          if (!tab.wsPollTimer || tab.wsPollGeneration !== generation || !isWsReplayTabAlive(tab, lifecycleToken)) return;
          tab.wsStatus = resp.status === 404 ? "disconnected" : "error";
          tab.wsError = text || (resp.status === 404
            ? "WebSocket replay connection is no longer available."
            : "WebSocket replay session changed.");
          stopWsPoll(tab);
          scheduleWorkspaceStateSave();
          if (state.activeReplayTabId === tab.id) {
            renderWsStatus();
          }
          renderReplayTabs();
        }
        return;
      }
      const data = await resp.json() || {};
      if (!tab.wsPollTimer || tab.wsPollGeneration !== generation || !isWsReplayTabAlive(tab, lifecycleToken)) return;

      const incomingFrames = normalizeWebsocketFrames(data.frames);
      if (incomingFrames.length > 0) {
        const existing = new Set(getWsReplayFrames(tab).map((frame) => frame.index));
        const fresh = incomingFrames.filter((frame) => !existing.has(frame.index));
        if (fresh.length) {
          if (!Array.isArray(tab.wsFrames)) tab.wsFrames = [];
          tab.wsFrames.push(...fresh);
          trimWsReplayFrames(tab);
          scheduleWsTranscriptWorkspaceSave();
        }
        sinceIndex = Math.max(sinceIndex, nextWsFrameIndex({ wsFrames: incomingFrames }), nextWsFrameIndex(tab));
        // Only re-render if this tab is still active
        if (fresh.length && state.activeReplayTabId === tab.id) {
          scheduleWsFrameListRender(tab);
        }
      }

      if (data.status && data.status !== tab.wsStatus) {
        tab.wsStatus = data.status;
        if (data.error) tab.wsError = data.error;
        if (state.activeReplayTabId === tab.id) {
          renderWsStatus();
        }
        if (data.status === "connected" && tab.wsSetupPending) {
          runSetupQueue(tab, tab.wsLifecycleToken).catch((error) => console.error(error));
        }
        if (data.status === "disconnected" || data.status === "error") {
          scheduleWorkspaceStateSave();
          stopWsPoll(tab);
          return;
        }
      }
    } catch (_e) {
      // ignore poll errors
    } finally {
      if (tab.wsPollTimer && tab.wsPollGeneration === generation && isWsReplayTabAlive(tab, lifecycleToken)) {
        tab.wsPollTimer = setTimeout(poll, 200);
      }
    }
  };

  tab.wsPollTimer = setTimeout(poll, 0);
}

function stopWsPoll(tab) {
  if (!tab) return;
  tab.wsPollGeneration = (tab.wsPollGeneration || 0) + 1;
  if (tab && tab.wsPollTimer) {
    clearTimeout(tab.wsPollTimer);
    tab.wsPollTimer = null;
  }
}

function nextWsFrameIndex(tab) {
  const frames = getWsReplayFrames(tab);
  return frames.reduce((next, frame) => {
    const index = Number(frame?.index);
    return Number.isFinite(index) ? Math.max(next, index + 1) : next;
  }, frames.length);
}

function trimWsReplayFrames(tab) {
  if (!tab) return;
  tab.wsFrames = getWsReplayFrames(tab);
  const overflow = tab.wsFrames.length - WS_REPLAY_MAX_LOADED_FRAMES;
  if (overflow <= 0) return;
  tab.wsFrames.splice(0, overflow);
  if (
    tab.wsSelectedFrameIndex !== -1
    && !tab.wsFrames.some((frame) => frame.index === tab.wsSelectedFrameIndex)
  ) {
    tab.wsSelectedFrameIndex = -1;
  }
}

function renderWsReplay() {
  const tab = getActiveReplayTab();
  if (!tab || tab.type !== "websocket") return;

  els.wsSchemeSelect.value = tab.wsScheme;
  els.wsHostInput.value = tab.wsHost;
  els.wsPortInput.value = tab.wsPort;
  els.wsPathInput.value = tab.wsPath;

  // Restore handshake headers
  if (els.wsHandshakeHeaders) {
    if (tab.wsHandshakeEdited) {
      els.wsHandshakeHeaders.value = tab.wsHandshakeText;
    } else {
      const wsHeaders = normalizedHeaders(tab.wsHeaders);
      els.wsHandshakeHeaders.value = wsHeaders.length > 0
        ? wsHeaders
        .map(h => `${h.name}: ${h.value}`)
        .join("\n")
        : "";
    }
  }

  // Restore editor text
  if (els.wsMessageType) {
    els.wsMessageType.value = normalizeWsMessageType(tab.wsMessageType);
  }
  els.wsMessageEditor.value = tab.wsEditorText || "";
  setWsMessageHighlightText(tab.wsEditorText || "");

  renderWsStatus();
  renderWsSetupQueue();
  renderWsFrameList();
}

function renderWsSetupQueue() {
  const container = document.getElementById("wsSetupQueue");
  if (!container) return;
  const tab = getActiveReplayTab();
  const setupQueue = Array.isArray(tab?.wsSetupQueue) ? tab.wsSetupQueue : [];
  if (tab && tab.type === "websocket" && !Array.isArray(tab.wsSetupQueue)) {
    tab.wsSetupQueue = setupQueue;
  }
  if (!tab || tab.type !== "websocket" || !setupQueue.length) {
    container.classList.add("hidden");
    return;
  }
  container.classList.remove("hidden");

  const listEl = document.getElementById("wsSetupQueueList");
  if (!listEl) return;

  listEl.innerHTML = setupQueue.map((item, i) => {
    const sentClass = item.sent ? "sent" : "";
    const checked = item.autoSend ? "checked" : "";
    return `<div class="ws-setup-row ${sentClass}" data-idx="${i}">
      <input type="checkbox" class="ws-setup-check" data-idx="${i}" ${checked} />
      <span class="ws-setup-index">#${i + 1}</span>
      <span class="ws-setup-label" title="${escapeHtml(item.label)}">${escapeHtml(item.label)}</span>
      <button class="ws-setup-send" data-idx="${i}" title="Send this message">▶</button>
      ${item.sent ? '<span class="ws-setup-sent-badge">✓</span>' : ""}
    </div>`;
  }).join("");

  // Checkbox toggle
  listEl.querySelectorAll(".ws-setup-check").forEach((cb) => {
    cb.addEventListener("change", () => {
      const idx = parseInt(cb.dataset.idx);
      const item = setupQueue[idx];
      if (!item) return;
      item.autoSend = cb.checked;
      scheduleWorkspaceStateSave();
    });
  });

  // Individual send button
  listEl.querySelectorAll(".ws-setup-send").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const idx = parseInt(btn.dataset.idx);
      const item = setupQueue[idx];
      if (!item || tab.wsStatus !== "connected") return;
      const lifecycleToken = tab.wsLifecycleToken;
      try {
        const kind = normalizeWsMessageType(item.kind);
        const sendBody = wsReplayBodyForSend(item.body, kind, !!item.bodyEncoded);
        const resp = await fetch("/api/replay/ws-send", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ session_id: tab.wsSessionId || state.activeSession?.id || null, id: tab.id, body: sendBody, binary: kind !== "text", kind }),
        });
        if (!isWsReplayTabAlive(tab, lifecycleToken) || tab.wsStatus !== "connected") return;
        if (!resp.ok) {
          const text = await resp.text().catch(() => "Setup message send failed");
          showToast(text, "error");
          return;
        }
        item.sent = true;
        renderWsSetupQueue();
        scheduleWorkspaceStateSave();
      } catch (e) {
        console.error(e);
        showToast(e?.message || "Setup message send failed.", "error");
      }
    });
  });

  // Click row to load into editor
  listEl.querySelectorAll(".ws-setup-row").forEach((row) => {
    row.addEventListener("dblclick", () => {
      const idx = parseInt(row.dataset.idx);
      const item = setupQueue[idx];
      if (item) {
        const kind = normalizeWsMessageType(item.kind);
        els.wsMessageEditor.value = item.body;
        if (els.wsMessageType) {
          els.wsMessageType.value = kind;
        }
        tab.wsMessageType = kind;
        tab.wsEditorText = item.body;
        tab.wsEditorBodyEncoded = !!item.bodyEncoded;
        setWsMessageHighlightText(item.body);
        scheduleWorkspaceStateSave();
      }
    });
  });
}

function renderWsStatus() {
  const tab = getActiveReplayTab();
  if (!tab || tab.type !== "websocket") return;

  const status = tab.wsStatus;
  els.wsStatusIndicator.className = `ws-status-dot ${status}`;
  els.wsStatusText.textContent = status === "connected" ? "Connected"
    : status === "connecting" ? "Connecting..."
    : status === "error" ? `Error: ${tab.wsError || "unknown"}`
    : "Disconnected";

  els.wsConnectButton.disabled = status === "connected" || status === "connecting";
  els.wsDisconnectButton.disabled = status !== "connected" && status !== "connecting";
  els.wsSendButton.disabled = status !== "connected";
  const targetLocked = status === "connected" || status === "connecting";
  els.wsSchemeSelect.disabled = targetLocked;
  els.wsHostInput.disabled = targetLocked;
  els.wsPortInput.disabled = targetLocked;
  els.wsPathInput.disabled = targetLocked;
  if (els.wsHandshakeHeaders) {
    els.wsHandshakeHeaders.disabled = targetLocked;
  }
}

function wsRenderedFrameWindow(frames, selectedFrameIndex) {
  if (frames.length <= WS_REPLAY_MAX_RENDERED_FRAMES) {
    return frames;
  }
  const tailStart = frames.length - WS_REPLAY_MAX_RENDERED_FRAMES;
  const selectedPosition = frames.findIndex((frame) => frame.index === selectedFrameIndex);
  if (selectedPosition === -1 || selectedPosition >= tailStart) {
    return frames.slice(tailStart);
  }
  const halfWindow = Math.floor(WS_REPLAY_MAX_RENDERED_FRAMES / 2);
  const start = Math.max(
    0,
    Math.min(selectedPosition - halfWindow, frames.length - WS_REPLAY_MAX_RENDERED_FRAMES),
  );
  return frames.slice(start, start + WS_REPLAY_MAX_RENDERED_FRAMES);
}

function renderWsFrameList() {
  const tab = getActiveReplayTab();
  if (!tab || tab.type !== "websocket") return;
  clearWsFrameListRender(tab);

  const frames = getWsReplayFrames(tab);
  tab.wsFrames = frames;
  els.wsFrameCount.textContent = `${frames.length} frame${frames.length === 1 ? "" : "s"}`;
  const previousFrameListScrollTop = els.wsFrameList.scrollTop;
  const wasNearBottom = els.wsFrameList.scrollHeight - els.wsFrameList.scrollTop - els.wsFrameList.clientHeight < 24;

  if (!frames.length) {
    els.wsFrameList.onclick = null;
    els.wsFrameList.ondblclick = null;
    els.wsFrameList.innerHTML = '<div class="empty-copy">Connect to start a WebSocket conversation.</div>';
    renderWsFrameDetail();
    return;
  }

  const renderedFrames = wsRenderedFrameWindow(frames, tab.wsSelectedFrameIndex);

  els.wsFrameList.innerHTML = renderedFrames.map((frame) => {
    const isClient = frame.direction === "client_to_server";
    const dirClass = isClient ? "client" : "server";
    const dirLabel = isClient ? "you" : "server";
    const selected = tab.wsSelectedFrameIndex === frame.index ? "selected" : "";
    const rawBody = frame.body_encoding === "base64"
      ? `[binary ${formatWsFrameSize(frame.body_size)}]`
      : (frame.body || "").substring(0, 120);
    const time = frame.captured_at
      ? new Date(frame.captured_at).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false })
      : "";
    const size = formatWsFrameSize(frame.body_size);

    return `<div class="ws-frame-bubble ${dirClass} ${selected}" data-frame-index="${frame.index}">
      <div class="ws-frame-bubble-meta"><span>${dirLabel}</span><span>${size} · ${time}</span></div>
      <div class="ws-frame-bubble-body">${escapeHtml(rawBody)}</div>
    </div>`;
  }).join("");

  if (wasNearBottom || tab.wsSelectedFrameIndex == null || tab.wsSelectedFrameIndex < 0) {
    els.wsFrameList.scrollTop = els.wsFrameList.scrollHeight;
  } else {
    els.wsFrameList.scrollTop = previousFrameListScrollTop;
  }

  els.wsFrameList.onclick = (event) => {
    const target = event.target instanceof Element ? event.target : event.target?.parentElement;
    const bubble = target?.closest(".ws-frame-bubble");
    if (!bubble || !els.wsFrameList.contains(bubble)) return;
    const idx = parseInt(bubble.dataset.frameIndex, 10);
    tab.wsSelectedFrameIndex = idx;
    els.wsFrameList.querySelectorAll(".ws-frame-bubble").forEach((node) => node.classList.remove("selected"));
    bubble.classList.add("selected");
    renderWsFrameDetail();
  };
  els.wsFrameList.ondblclick = (event) => {
    const target = event.target instanceof Element ? event.target : event.target?.parentElement;
    const bubble = target?.closest(".ws-frame-bubble");
    if (!bubble || !els.wsFrameList.contains(bubble)) return;
    const idx = parseInt(bubble.dataset.frameIndex, 10);
    const frame = frames.find((item) => item.index === idx);
    if (frame && frame.direction === "client_to_server") {
      const messageType = wsReplayMessageTypeForFrame(frame);
      if (frame.preview_truncated) {
        showToast("Frame preview is truncated and cannot be replayed safely.", "error");
        return;
      }
      const editorText = wsReplayEditorTextForFrame(frame);
      const editorBodyEncoded = messageType !== "text" && frame.body_encoding === "base64";
      if (els.wsMessageType) {
        els.wsMessageType.value = messageType;
      }
      els.wsMessageEditor.value = editorText;
      tab.wsMessageType = messageType;
      tab.wsEditorText = editorText;
      tab.wsEditorBodyEncoded = editorBodyEncoded;
      setWsMessageHighlightText(editorText);
      scheduleWorkspaceStateSave();
    }
  };

  renderWsFrameDetail();
}

function renderWsFrameDetail() {
  const tab = getActiveReplayTab();
  if (!tab || tab.type !== "websocket") return;

  const frames = getWsReplayFrames(tab);
  const frame = frames.find(f => f.index === tab.wsSelectedFrameIndex);
  if (!frame) {
    els.wsFrameDetailPath.textContent = "DETAIL";
    els.wsFrameDetailTitle.textContent = "Select a frame";
    els.wsFrameDetailView.innerHTML = "";
    return;
  }

  const isClient = frame.direction === "client_to_server";
  const sizeStr = formatWsFrameSize(frame.body_size);
  const dirClass = isClient ? "dir-client" : "dir-server";
  const dirLabel = isClient ? "client \u2192" : "\u2190 server";
  els.wsFrameDetailPath.innerHTML = `<span class="${dirClass}">${dirLabel}</span> · ${escapeHtml(frame.kind || "")} · ${escapeHtml(sizeStr)}`;
  els.wsFrameDetailTitle.textContent = `Frame #${frame.index + 1}`;

  let text = decodeWsFrameBody(frame);

  // Try to pretty-print JSON
  try {
    const parsed = JSON.parse(text);
    text = JSON.stringify(parsed, null, 2);
  } catch (_e) { /* not JSON */ }

  els.wsFrameDetailView.innerHTML = renderCodeHtml(text, "pretty", "response");
}

function decodeWsFrameBody(frame) {
  if (!frame || !frame.body) return "";
  if (frame.body_encoding === "base64") {
    return safeDecodeBase64(frame.body);
  }
  return frame.body;
}

function wsReplayMessageTypeForFrame(frame) {
  const kind = normalizeWsMessageType(frame?.kind);
  if (kind === "ping" || kind === "pong") return kind;
  return kind === "binary" || frame?.body_encoding === "base64" ? "binary" : "text";
}

function wsReplayEditorTextForFrame(frame) {
  const rawBody = frame?.body || frame?.body_preview || "";
  if (wsReplayMessageTypeForFrame(frame) !== "text") {
    return rawBody;
  }
  return frame?.body_encoding === "base64" ? safeDecodeBase64(rawBody) : rawBody;
}

function formatWsFrameSize(bytes) {
  const size = Number(bytes);
  if (!Number.isFinite(size) || size < 0) return "";
  if (size < 1024) return `${size} B`;
  return `${(size / 1024).toFixed(1)} KB`;
}

function handleWsReplayActionError(error) {
  console.error(error);
  showToast(error?.message || "WebSocket Replay action failed.", "error");
}

function bindWsReplayEvents() {
  if (!els.wsConnectButton) return;

  els.wsConnectButton.addEventListener("click", () => {
    wsConnect().catch(handleWsReplayActionError);
  });
  els.wsDisconnectButton.addEventListener("click", () => {
    wsDisconnect().catch(handleWsReplayActionError);
  });
  els.wsSendButton.addEventListener("click", () => {
    wsSend().catch(handleWsReplayActionError);
  });

  els.wsSchemeSelect.addEventListener("change", () => {
    const tab = getActiveReplayTab();
    if (tab && tab.type === "websocket") {
      tab.wsScheme = els.wsSchemeSelect.value;
      tab.wsPort = defaultWsPortForScheme(tab.wsScheme);
      els.wsPortInput.value = tab.wsPort;
      setWsReplayTargetInputValidity(validateWsReplayTargetInput(
        tab.wsScheme,
        els.wsHostInput.value,
        els.wsPortInput.value,
        els.wsPathInput.value,
      ));
      renderReplayTabs();
      scheduleWorkspaceStateSave();
    }
  });
  els.wsHostInput.addEventListener("input", () => {
    const tab = getActiveReplayTab();
    if (tab && tab.type === "websocket") {
      tab.wsHost = els.wsHostInput.value.trim();
      setWsReplayTargetInputValidity(validateWsReplayTargetInput(
        els.wsSchemeSelect.value,
        tab.wsHost,
        els.wsPortInput.value,
        els.wsPathInput.value,
      ));
      renderReplayTabs();
      scheduleWorkspaceStateSave();
    }
  });
  els.wsPortInput.addEventListener("change", () => {
    const tab = getActiveReplayTab();
    if (tab && tab.type === "websocket") {
      const rawPort = els.wsPortInput.value.trim();
      const normalizedPort = normalizePortValue(rawPort);
      const validation = validateWsReplayTargetInput(
        els.wsSchemeSelect.value,
        els.wsHostInput.value,
        rawPort,
        els.wsPathInput.value,
      );
      setWsReplayTargetInputValidity(validation);
      if (!validation.valid || !normalizedPort) {
        els.wsPortInput.reportValidity();
        return;
      }
      tab.wsPort = normalizedPort;
      els.wsPortInput.value = normalizedPort;
      scheduleWorkspaceStateSave();
    }
  });
  els.wsPathInput.addEventListener("input", () => {
    const tab = getActiveReplayTab();
    if (tab && tab.type === "websocket") {
      tab.wsPath = els.wsPathInput.value.trim();
      setWsReplayTargetInputValidity(validateWsReplayTargetInput(
        els.wsSchemeSelect.value,
        els.wsHostInput.value,
        els.wsPortInput.value,
        tab.wsPath,
      ));
      scheduleWorkspaceStateSave();
    }
  });
  els.wsHandshakeHeaders.addEventListener("input", () => {
    const tab = getActiveReplayTab();
    if (tab && tab.type === "websocket") {
      tab.wsHandshakeText = els.wsHandshakeHeaders.value;
      tab.wsHandshakeEdited = true;
      scheduleWorkspaceStateSave();
    }
  });
  els.wsMessageType?.addEventListener("change", () => {
    const tab = getActiveReplayTab();
    if (tab && tab.type === "websocket") {
      tab.wsMessageType = normalizeWsMessageType(els.wsMessageType.value);
      tab.wsEditorBodyEncoded = false;
      scheduleWorkspaceStateSave();
    }
  });
  // WS Message highlight editor: input → sync to hidden textarea + JSON highlight
  els.wsMessageHighlight.addEventListener("input", () => {
    const plainText = els.wsMessageHighlight.innerText || "";
    els.wsMessageEditor.value = plainText;
	    const tab = getActiveReplayTab();
    if (tab && tab.type === "websocket") {
      tab.wsEditorText = plainText;
      tab.wsEditorBodyEncoded = false;
      scheduleWorkspaceStateSave();
    }
    applyWsMessageJsonHighlight();
  });

  // Cmd+Enter to send in WS editor
  els.wsMessageHighlight.addEventListener("keydown", (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
      e.preventDefault();
      wsSend().catch(handleWsReplayActionError);
    }
  });

  // WS Replay pane resizer (left/right)
  if (els.wsReplayPaneResizer) {
    let startX = 0;
    let startW = 0;
    const onMove = (e) => {
      const delta = e.clientX - startX;
      const panel = els.wsReplayPanel;
      const total = panel.getBoundingClientRect().width - 10;
      const newW = Math.max(280, Math.min(total - 280, startW + delta));
      panel.style.setProperty("--ws-replay-left-width", `${newW}px`);
    };
    const onUp = () => {
      document.body.classList.remove("pane-resizing-x");
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
    };
    els.wsReplayPaneResizer.addEventListener("mousedown", (e) => {
      e.preventDefault();
      startX = e.clientX;
      const left = els.wsReplayPanel.querySelector(".ws-replay-left");
      startW = left ? left.getBoundingClientRect().width : 400;
      document.body.classList.add("pane-resizing-x");
      window.addEventListener("mousemove", onMove);
      window.addEventListener("mouseup", onUp);
    });
    els.wsReplayPaneResizer.addEventListener("dblclick", () => {
      els.wsReplayPanel.style.removeProperty("--ws-replay-left-width");
    });
  }

  // WS Replay frame detail resizer (vertical)
  if (els.wsReplayFrameResizer) {
    let startY = 0;
    let startH = 0;
    const onMove = (e) => {
      const delta = startY - e.clientY;
      const right = els.wsReplayPanel.querySelector(".ws-replay-right");
      const total = right ? right.getBoundingClientRect().height : 600;
      const newH = Math.max(120, Math.min(total * 0.8, startH + delta));
      const detail = right.querySelector(".ws-frame-detail");
      if (detail) detail.style.flex = `0 0 ${newH}px`;
    };
    const onUp = () => {
      document.body.classList.remove("pane-resizing-y");
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
    };
    els.wsReplayFrameResizer.addEventListener("mousedown", (e) => {
      e.preventDefault();
      startY = e.clientY;
      const detail = els.wsReplayPanel.querySelector(".ws-frame-detail");
      startH = detail ? detail.getBoundingClientRect().height : 200;
      document.body.classList.add("pane-resizing-y");
      window.addEventListener("mousemove", onMove);
      window.addEventListener("mouseup", onUp);
    });
  }

}

/* ─── Compare / Diff ─── */
let compareBaseId = null;
let compareBaseSessionId = null;
let compareActiveTab = "request";
let compareBaseRecord = null;
let compareTargetRecord = null;

function computeUnifiedDiff(linesA, linesB, labelA, labelB) {
  const result = [`--- ${labelA}`, `+++ ${labelB}`];
  const maxLen = Math.max(linesA.length, linesB.length);
  for (let i = 0; i < maxLen; i++) {
    const a = i < linesA.length ? linesA[i] : undefined;
    const b = i < linesB.length ? linesB[i] : undefined;
    if (a === b) {
      result.push(`  ${a}`);
    } else {
      if (a !== undefined) result.push(`- ${a}`);
      if (b !== undefined) result.push(`+ ${b}`);
    }
  }
  return result.join("\n");
}

async function setCompareBase(transactionId) {
  compareBaseId = transactionId;
  compareBaseSessionId = currentSessionId();
  const btn = document.getElementById("compareWithBaseBtn");
  if (btn) btn.disabled = false;
  const item = getHistoryItem(transactionId);
  if (btn && item) btn.textContent = `Compare with #${item.index ?? "?"}`;
}

async function openCompareModal(targetId) {
  if (!compareBaseId || compareBaseId === targetId) return;
  const sessionId = currentSessionId();
  if (compareBaseSessionId !== sessionId) {
    clearCompareState();
    return;
  }
  const [baseRes, targetRes] = await Promise.all([
    fetch(transactionPath(compareBaseId, sessionId)).then((r) => r.ok ? r.json() : null),
    fetch(transactionPath(targetId, sessionId)).then((r) => r.ok ? r.json() : null),
  ]);
  if (currentSessionId() !== sessionId) return;
  if (!baseRes || !targetRes) return;
  compareBaseRecord = baseRes;
  compareTargetRecord = targetRes;
  compareActiveTab = "request";
  renderCompareModal();
  document.getElementById("compareModal").classList.remove("hidden");
}

function renderCompareModal() {
  if (!compareBaseRecord || !compareTargetRecord) return;
  const baseItem = getHistoryItem(compareBaseRecord.id);
  const targetItem = getHistoryItem(compareTargetRecord.id);
  const baseLabel = `#${baseItem?.index ?? "?"} ${compareBaseRecord.method} ${compareBaseRecord.host}${compareBaseRecord.path}`;
  const targetLabel = `#${targetItem?.index ?? "?"} ${compareTargetRecord.method} ${compareTargetRecord.host}${compareTargetRecord.path}`;
  document.getElementById("compareKicker").textContent = `${baseLabel}  vs  ${targetLabel}`;
  document.getElementById("compareTitle").textContent = compareActiveTab === "request" ? "Request Diff" : "Response Diff";
  document.querySelectorAll("[data-compare-tab]").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.compareTab === compareActiveTab);
  });
  let textA, textB;
  if (compareActiveTab === "request") {
    textA = buildRawRequest(compareBaseRecord);
    textB = buildRawRequest(compareTargetRecord);
  } else {
    textA = buildRawResponse(compareBaseRecord);
    textB = buildRawResponse(compareTargetRecord);
  }
  const linesA = textA.split("\n");
  const linesB = textB.split("\n");
  const diff = computeUnifiedDiff(linesA, linesB, "base", "target");
  document.getElementById("compareDiffView").innerHTML = renderDiffHtml(diff);
}

function closeCompareModal() {
  document.getElementById("compareModal").classList.add("hidden");
}

function clearCompareState() {
  compareBaseId = null;
  compareBaseSessionId = null;
  compareBaseRecord = null;
  compareTargetRecord = null;
  compareActiveTab = "request";
  const btn = document.getElementById("compareWithBaseBtn");
  if (btn) {
    btn.disabled = true;
    btn.textContent = "Compare with base";
  }
  document.getElementById("compareModal")?.classList.add("hidden");
}

/* ─── Context menu (color tags & notes) ─── */
let contextMenuTargetId = null;
let contextMenuSessionId = null;
let contextMenuNoteTimer = null;

function openContextMenu(x, y, transactionId) {
  contextMenuTargetId = transactionId;
  contextMenuSessionId = currentSessionId();
  const menu = els.contextMenu;
  menu.classList.remove("hidden");

  const item = getHistoryItem(transactionId);
  const currentColor = item?.color_tag || "";

  menu.querySelectorAll(".color-dot").forEach((dot) => {
    dot.classList.toggle("active", dot.dataset.color === currentColor);
  });

  els.contextMenuNote.value = "";
  if (transactionId) {
    loadUserNote(transactionId);
  }

  const menuWidth = menu.offsetWidth;
  const menuHeight = menu.offsetHeight;
  const maxX = window.innerWidth - menuWidth - 8;
  const maxY = window.innerHeight - menuHeight - 8;
  menu.style.left = `${Math.min(x, maxX)}px`;
  menu.style.top = `${Math.min(y, maxY)}px`;
}

function closeContextMenu() {
  window.clearTimeout(contextMenuNoteTimer);
  contextMenuNoteTimer = null;
  els.contextMenu.classList.add("hidden");
  contextMenuTargetId = null;
  contextMenuSessionId = null;
}

function contextMenuSessionIsCurrent() {
  return !!contextMenuSessionId && contextMenuSessionId === currentSessionId();
}

async function loadUserNote(transactionId) {
  const sessionId = currentSessionId();
  try {
    const response = await fetch(transactionPath(transactionId, sessionId));
    if (currentSessionId() !== sessionId) return;
    if (response.ok) {
      const record = await response.json();
      if (currentSessionId() === sessionId && contextMenuTargetId === transactionId) {
        els.contextMenuNote.value = record.user_note || "";
      }
    }
  } catch { /* ignore */ }
}

async function updateAnnotations(transactionId, payload, sessionId = currentSessionId()) {
  if (!state._pendingAnnotations) state._pendingAnnotations = new Map();
  if (!state._annotationInFlight) state._annotationInFlight = new Set();
  const pending = state._pendingAnnotations;
  const existing = pending.get(transactionId);
  pending.set(transactionId, {
    sessionId,
    payload: { ...(existing?.sessionId === sessionId ? existing.payload : {}), ...payload },
  });
  if (!state._annotationInFlight.has(transactionId)) {
    flushPendingAnnotations(transactionId);
  }
}

async function flushPendingAnnotations(transactionId) {
  if (!state._pendingAnnotations) return;
  if (!state._annotationInFlight) state._annotationInFlight = new Set();
  const pending = state._pendingAnnotations;
  const entry = pending.get(transactionId);
  if (!entry) return;
  const { sessionId, payload } = entry;

  state._annotationInFlight.add(transactionId);
  let failureMessage = "";
  try {
    const response = await fetch(sessionQueryPath(`/api/transactions/${encodeURIComponent(transactionId)}/annotations`, sessionId), {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!response.ok) {
      failureMessage = await response.text().catch(() => "Failed to save annotation");
      throw new Error(failureMessage || "Failed to save annotation");
    }
    const summary = await response.json();
    if (currentSessionId() !== sessionId) {
      return;
    } else if (pending.get(transactionId) === entry) {
      const index = getHistoryItemIndex(transactionId);
      if (index !== -1) {
        Object.assign(state.items[index], summary);
        prepareHistoryItem(state.items[index]);
        if (!summaryMatchesActiveHistoryFilters(state.items[index])) {
          state.items.splice(index, 1);
          if (state.historyPaging && isKnownCount(state.historyPaging.filteredTotal)) {
            state.historyPaging.filteredTotal = Math.max(0, state.historyPaging.filteredTotal - 1);
          }
          if (state.selectedId === transactionId) {
            state.selectedId = null;
            state.selectedRecord = null;
            renderEmptyDetail();
          }
          rebuildHistoryItemIndex();
        } else {
          state._itemById.set(transactionId, state.items[index]);
        }
        state._itemsVersion += 1;
        invalidateVisibleEntriesCache();
        renderHistory();
      }
      if (state.selectedRecord && state.selectedRecord.id === transactionId) {
        if (payload.color_tag !== undefined) {
          state.selectedRecord.color_tag = payload.color_tag;
        }
        if (payload.user_note !== undefined) {
          state.selectedRecord.user_note = payload.user_note;
        }
        renderDetail(state.selectedRecord, { preserveOriginalToggles: true });
      }
    }
  } catch (error) {
    console.error("Failed to update annotations:", error);
    if (currentSessionId() === sessionId) {
      showToast(failureMessage || error.message || "Failed to save annotation", "error");
      loadTransactions(true).catch((reloadError) => console.error(reloadError));
    }
  } finally {
    state._annotationInFlight.delete(transactionId);
    if (pending.get(transactionId) === entry) {
      pending.delete(transactionId);
    } else if (pending.get(transactionId) !== entry) {
      flushPendingAnnotations(transactionId);
    }
  }
}

document.addEventListener("click", (event) => {
  if (!els.contextMenu.contains(event.target)) {
    closeContextMenu();
  }
});

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && !els.contextMenu.classList.contains("hidden")) {
    closeContextMenu();
  }
});

els.contextMenu.querySelectorAll(".color-dot").forEach((dot) => {
  dot.addEventListener("click", () => {
    if (!contextMenuTargetId) return;
    if (!contextMenuSessionIsCurrent()) {
      closeContextMenu();
      return;
    }
    const color = dot.dataset.color || null;
    updateAnnotations(contextMenuTargetId, { color_tag: color }, contextMenuSessionId);
    els.contextMenu.querySelectorAll(".color-dot").forEach((d) => {
      d.classList.toggle("active", d.dataset.color === (color || ""));
    });
  });
});

els.contextMenu.querySelectorAll(".context-menu-item").forEach((item) => {
  item.addEventListener("click", () => {
    const action = item.dataset.action;
    const targetId = contextMenuTargetId;
    if (!targetId) return;
    if (!contextMenuSessionIsCurrent()) {
      closeContextMenu();
      return;
    }
    state.selectedId = targetId;
    closeContextMenu();
    if (action === "send-to-replay") {
      openReplayFromSelection().catch(handleSendActionError);
    } else if (action === "send-to-fuzzer") {
      openFuzzerFromSelection().catch(handleSendActionError);
    } else if (action === "send-to-sequence") {
      sendToSequenceFromSelection().catch(handleSendActionError);
    } else if (action === "copy-url") {
      copyTransactionUrl(targetId);
    } else if (action?.startsWith("copy-as-")) {
      const format = action.replace("copy-as-", "");
      // Use selectedRecord if available (sync, preserves user gesture for clipboard)
      if (state.selectedRecord && state.selectedRecord.id === targetId) {
        const text = selectedRecordToFormat(format);
        if (text) {
          copyTextToClipboard(text)
            .then(() => showToast(`Copied as ${format}`))
            .catch(() => showToast("Failed to copy", "error"));
        }
      } else {
        historyRequestToFormat(targetId, format).then((text) => {
          if (text) {
            copyTextToClipboard(text)
              .then(() => showToast(`Copied as ${format}`))
              .catch(() => showToast("Failed to copy", "error"));
          }
        });
      }
    } else if (action === "compare-set-base") {
      setCompareBase(targetId);
    } else if (action === "compare-with-base") {
      openCompareModal(targetId).catch((error) => console.error(error));
    }
  });
});

els.contextMenuNote.addEventListener("input", () => {
  if (!contextMenuTargetId) return;
  if (!contextMenuSessionIsCurrent()) {
    closeContextMenu();
    return;
  }
  clearTimeout(contextMenuNoteTimer);
  const id = contextMenuTargetId;
  const sessionId = contextMenuSessionId;
  const value = els.contextMenuNote.value;
  contextMenuNoteTimer = setTimeout(() => {
    updateAnnotations(id, { user_note: value || null }, sessionId);
  }, 500);
});

els.contextMenuNote.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    event.preventDefault();
    if (!contextMenuTargetId) return;
    if (!contextMenuSessionIsCurrent()) {
      closeContextMenu();
      return;
    }
    const id = contextMenuTargetId;
    const sessionId = contextMenuSessionId;
    const value = els.contextMenuNote.value;
    clearTimeout(contextMenuNoteTimer);
    updateAnnotations(id, { user_note: value || null }, sessionId);
    closeContextMenu();
  }
  event.stopPropagation();
});

/* ─── WS Frame context menu ─── */

function openWsFrameContextMenu(x, y) {
  const menu = els.wsFrameContextMenu;
  menu.classList.remove("hidden");
  const menuWidth = menu.offsetWidth;
  const menuHeight = menu.offsetHeight;
  const maxX = window.innerWidth - menuWidth - 8;
  const maxY = window.innerHeight - menuHeight - 8;
  menu.style.left = `${Math.min(x, maxX)}px`;
  menu.style.top = `${Math.min(y, maxY)}px`;
}

function closeWsFrameContextMenu() {
  els.wsFrameContextMenu.classList.add("hidden");
}

document.getElementById("wsFrameToReplayBtn").addEventListener("click", () => {
  closeWsFrameContextMenu();
  sendWsFrameToReplay(state.selectedFrameIdx);
});

document.addEventListener("click", (event) => {
  if (!els.wsFrameContextMenu.contains(event.target)) {
    closeWsFrameContextMenu();
  }
});

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && !els.wsFrameContextMenu.classList.contains("hidden")) {
    closeWsFrameContextMenu();
  }
});

function sendWsFrameToReplay(frameIdx) {
  const session = state.selectedWebsocketRecord;
  if (!session) return;
  if (session.id && state.selectedWebsocketId && session.id !== state.selectedWebsocketId) {
    showToast("WebSocket session is still loading. Select the frame again.", "error");
    return;
  }
  if (frameIdx == null) {
    showToast("Select a WebSocket frame first.", "error");
    return;
  }
  const frames = getWebsocketFrames(session);
  const requestedIndex = Number(frameIdx);
  if (!Number.isFinite(requestedIndex)) {
    showToast("Select a WebSocket frame first.", "error");
    return;
  }
  const frame = frames.find((candidate) => candidate.index === requestedIndex);
  if (!frame) return;

  // Determine WS scheme
  let wsScheme;
  if (session.scheme === "wss" || session.scheme === "ws") {
    wsScheme = session.scheme;
  } else if (session.scheme === "https" || (session.host && session.host.endsWith(":443"))) {
    wsScheme = "wss";
  } else {
    wsScheme = "ws";
  }

  const messageType = wsReplayMessageTypeForFrame(frame);
  if (frame.preview_truncated) {
    showToast("Frame preview is truncated and cannot be replayed safely.", "error");
    return;
  }
  const body = wsReplayEditorTextForFrame(frame);
  const editorBodyEncoded = messageType !== "text" && frame.body_encoding === "base64";

  const target = authorityToTargetState(session.host || "", wsScheme === "ws" ? "http" : "https");
  const port = normalizePortValue(target.port) || defaultWsPortForScheme(wsScheme);
  createWsReplayTab({
    scheme: wsScheme,
    host: target.host,
    port,
    path: session.path || "/",
    headers: normalizedHeaders(session.request?.headers),
    capturedFrames: frames,
    selectedFrameIndex: frame.index,
    editorText: body,
    messageType,
    editorBodyEncoded,
  });
  state.activeTool = "replay";
  renderToolPanels();
}

// duplicate removed — renderWsReplay() at line ~9443 is the canonical version

/* ─── Replay request context menu ─── */

// Lazy-initialised: the element may not yet exist when top-level code runs,
// and bindEvents() → initReplayContextMenu() is called early in init().
function getReplayContextMenu() {
  if (!getReplayContextMenu._el) {
    getReplayContextMenu._el = document.getElementById("replayContextMenu");
  }
  return getReplayContextMenu._el;
}

function showReplayContextMenu(event) {
  event.preventDefault();
  const tab = getActiveReplayTab();
  if (!tab) return;

  // Highlight current method
  const currentMethod = (tab.requestText.match(/^([A-Z]+)\s/)?.[1] || "GET").toUpperCase();
  getReplayContextMenu().querySelectorAll(".method-btn").forEach((btn) => {
    btn.classList.toggle("active-method", btn.dataset.method === currentMethod);
  });

  getReplayContextMenu().classList.remove("hidden");
  const x = Math.min(event.clientX, window.innerWidth - 240);
  const y = Math.min(event.clientY, window.innerHeight - 300);
  getReplayContextMenu().style.left = `${x}px`;
  getReplayContextMenu().style.top = `${y}px`;
}

function closeReplayContextMenu() {
  getReplayContextMenu().classList.add("hidden");
}

function changeReplayMethod(newMethod) {
  const tab = getActiveReplayTab();
  if (!tab) return;

  const cv = getCMView("replayReq");
  const text = cv ? cv.getContent() : (tab.requestText || (els.replayRequestEditor ? els.replayRequestEditor.value : "") || "");
  const updated = text.replace(/^[A-Z]+(\s)/i, newMethod + "$1");
  tab.requestText = updated;
  if (cv) {
    cv.setContent(updated);
  } else if (els.replayRequestEditor) {
    els.replayRequestEditor.value = updated;
    renderReplayRequestHighlight(updated);
  }
  updateReplaySearchPane("request", updated);
  syncReplayToolbar(tab);
  renderReplayTabs();
  scheduleWorkspaceStateSave();
}

function replayRequestToCurl() {
  const tab = getActiveReplayTab();
  if (!tab) return "";
  const blocked = replayExportBlockedReason(tab);
  if (blocked) {
    showToast(blocked, "error");
    return "";
  }
  const target = getReplayExportTarget(tab);
  const parsed = parseRequestForExport(
    tab.requestText ?? "",
    target.scheme || "https",
    target.host || "localhost",
    target.port || "",
  );
  return requestToCurl(parsed);
}

function replayExportBlockedReason(tab) {
  if (!tab || tab.type === "websocket") return "";
  const request = deriveRepeaterRequest(tab);
  if (request.body_encoding === "base64" && String(request.body || "").length > 0) {
    return "Binary request bodies cannot be exported safely from Replay.";
  }
  return "";
}

function historyRequestExportBlockedReason(record) {
  const request = record?.request;
  if (!request) return "";
  if (request.body_encoding === "base64" && String(request.body_preview || "").length > 0) {
    return "Binary captured request bodies cannot be exported safely.";
  }
  if (request.preview_truncated) {
    return "Truncated captured request bodies cannot be exported safely.";
  }
  return "";
}

function getReplayExportTarget(tab) {
  const request = deriveRepeaterRequest(tab);
  return getRepeaterTargetConfig(tab, request);
}

function shellQuote(value) {
  return `'${String(value).replace(/'/g, "'\\''")}'`;
}

function parseRequestForExport(rawText, scheme, host, port) {
  const lines = String(rawText || "").replace(/\r\n/g, "\n").split("\n");
  const [startLine = "GET / HTTP/1.1", ...rest] = lines;
  const match = startLine.match(/^([A-Za-z0-9!#$%&'*+.^_`|~-]+)\s+(\S+)/);
  if (!match) return null;
  const method = match[1];
  const path = match[2];
  const url = buildUrlFromTarget(scheme, host, port, path);
  let bodyIdx = rest.indexOf("");
  if (bodyIdx === -1) {
    for (let i = 0; i < rest.length; i++) {
      const c = rest[i].charAt(0);
      if (c === "{" || c === "[" || c === "<" || c === '"') { bodyIdx = i; break; }
      if (!rest[i].includes(":")) { bodyIdx = i; break; }
    }
  }
  const headerLines = bodyIdx === -1 ? rest : rest.slice(0, bodyIdx);
  const body = bodyIdx === -1 ? "" : (rest[bodyIdx] === "" ? rest.slice(bodyIdx + 1) : rest.slice(bodyIdx)).join("\n");
  const bodyProvided = bodyIdx !== -1;
  const headers = headerLines.map((h) => {
    const idx = h.indexOf(":");
    return idx === -1 ? null : { name: h.slice(0, idx).trim(), value: h.slice(idx + 1).trim() };
  }).filter(Boolean);
  return { method, url, headers, body, bodyProvided };
}

function requestToPython(parsed) {
  if (!parsed) return "";
  const py = (s) => JSON.stringify(String(s));
  const lines = [`import requests`, ""];
  const hasBody = parsed.bodyProvided || parsed.body.length > 0;
  const headerObj = exportableHeaders(parsed.headers, parsed.url);
  if (headerObj.length) {
    lines.push("headers = {");
    for (const h of headerObj) lines.push(`    ${py(h.name)}: ${py(h.value)},`);
    lines.push("}");
    lines.push("");
  }
  if (hasBody) {
    lines.push(`data = ${py(parsed.body)}`);
    lines.push("");
  }
  const args = [py(parsed.url)];
  args.unshift(py(parsed.method));
  if (headerObj.length) args.push("headers=headers");
  if (hasBody) args.push("data=data");
  lines.push(`response = requests.request(${args.join(", ")})`);
  lines.push(`print(response.status_code)`);
  lines.push(`print(response.text)`);
  return lines.join("\n");
}

function exportableHeaders(headers, url = "") {
  return exportableHeadersForUrl(headers, url);
}

function exportableHeadersForUrl(headers, url = "") {
  const normalized = normalizedHeaders(headers);
  const hostHeader = normalized.find((h) => headerNameEquals(h, "host"));
  const preserveHost = hostHeader && hostHeaderDiffersFromUrl(hostHeader.value, url);
  return normalized
    .filter((h) => {
      if (headerNameEquals(h, "content-length")) return false;
      if (headerNameEquals(h, "host")) return !!preserveHost;
      return true;
    });
}

function hostHeaderDiffersFromUrl(hostHeader, url) {
  if (!url) return false;
  try {
    const parsed = new URL(url);
    const scheme = parsed.protocol.replace(":", "") || "https";
    const port = parsed.port || (scheme === "https" ? "443" : "80");
    const authority = joinAuthority(stripIpv6Brackets(parsed.hostname), port);
    return !httpRequestAuthoritiesEquivalent(authority, hostHeader, scheme);
  } catch (_error) {
    return false;
  }
}

function requestToFetch(parsed) {
  if (!parsed) return "";
  const js = (s) => JSON.stringify(String(s));
  if (fetchExportBlockedReason(parsed)) {
    return "";
  }
  const headerObj = exportableHeadersForUrl(parsed.headers, parsed.url);
  const opts = [];
  if (parsed.method !== "GET") opts.push(`  method: ${js(parsed.method)}`);
  if (headerObj.length) {
    const hLines = headerObj.map((h) => `    ${js(h.name)}: ${js(h.value)}`).join(",\n");
    opts.push(`  headers: {\n${hLines}\n  }`);
  }
  if (parsed.bodyProvided || parsed.body.length > 0) {
    opts.push(`  body: ${JSON.stringify(parsed.body)}`);
  }
  if (!opts.length) return `fetch(${js(parsed.url)})\n  .then(res => res.text())\n  .then(console.log);`;
  return `fetch(${js(parsed.url)}, {\n${opts.join(",\n")}\n})\n  .then(res => res.text())\n  .then(console.log);`;
}

function fetchExportBlockedReason(parsed) {
  if (!parsed) return "";
  const hasBody = parsed.bodyProvided || parsed.body.length > 0;
  if (hasBody && ["GET", "HEAD"].includes(parsed.method.toUpperCase())) {
    return "Fetch cannot send GET or HEAD requests with a body. Use cURL or Python export instead.";
  }
  const hostHeader = normalizedHeaders(parsed.headers).find((h) => headerNameEquals(h, "host"));
  if (hostHeader && hostHeaderDiffersFromUrl(hostHeader.value, parsed.url)) {
    return "Fetch cannot preserve a custom Host header. Use cURL or Python export instead.";
  }
  return "";
}

function requestToPowerShell(parsed) {
  if (!parsed) return "";
  const esc = (s) => s.replace(/'/g, "''");
  const parts = [`Invoke-WebRequest -Uri '${esc(parsed.url)}'`];
  if (parsed.method !== "GET") parts.push(`-Method ${parsed.method}`);
  const headerObj = exportableHeaders(parsed.headers, parsed.url);
  if (headerObj.length) {
    const hLines = headerObj.map((h) => `'${esc(h.name)}'='${esc(h.value)}'`).join("; ");
    parts.push(`-Headers @{${hLines}}`);
  }
  if (parsed.bodyProvided || parsed.body.length > 0) {
    parts.push(`-Body '${esc(parsed.body)}'`);
  }
  return parts.join(" `\n  ");
}

function requestToCurl(parsed) {
  if (!parsed) return "";
  const parts = [`curl -X ${shellQuote(parsed.method)}`];
  if (urlNeedsPathAsIs(parsed.url)) parts.push("--path-as-is");
  for (const h of exportableHeaders(parsed.headers, parsed.url)) {
    parts.push(`-H ${shellQuote(`${h.name}: ${h.value}`)}`);
  }
  if (parsed.bodyProvided || parsed.body.length > 0) {
    parts.push(`--data-raw ${shellQuote(parsed.body)}`);
  }
  parts.push(shellQuote(parsed.url));
  return parts.join(" \\\n  ");
}

function urlNeedsPathAsIs(url) {
  return /(?:^|\/)\.\.?(?=\/|\?|$)/.test(rawPathFromUrlString(url || "") || "");
}

function replayRequestToFormat(format) {
  const tab = getActiveReplayTab();
  if (!tab) return "";
  const blocked = replayExportBlockedReason(tab);
  if (blocked) {
    showToast(blocked, "error");
    return "";
  }
  const target = getReplayExportTarget(tab);
  const parsed = parseRequestForExport(
    tab.requestText,
    target.scheme || "https",
    target.host || "localhost",
    target.port || "",
  );
  if (format === "fetch") {
    const fetchBlocked = fetchExportBlockedReason(parsed);
    if (fetchBlocked) {
      showToast(fetchBlocked, "error");
      return "";
    }
  }
  if (format === "curl") return requestToCurl(parsed);
  if (format === "python") return requestToPython(parsed);
  if (format === "fetch") return requestToFetch(parsed);
  if (format === "powershell") return requestToPowerShell(parsed);
  return "";
}

function copySelectedTransactionUrl() {
  const record = getCurrentSelectedRecord();
  if (!record) return;
  const scheme = record.scheme || "https";
  const host = record.host || "";
  const path = record.path || "/";
  const url = buildUrlFromTarget(scheme, host, "", path);
  copyTextToClipboard(url);
  showToast("Copied URL");
}

function copyResponseContent(format) {
  const record = getCurrentSelectedRecord();
  if (!record?.response) return;
  let text = "";
  if (format === "response-headers") {
    text = `HTTP/1.1 ${record.status || 200}\r\n`;
    for (const h of normalizedHeaders(record.response.headers)) text += `${h.name}: ${h.value}\r\n`;
  } else if (format === "response-body") {
    text = record.response.body_encoding === "base64"
      ? safeDecodeBase64(record.response.body_preview || "")
      : (record.response.body_preview || "");
  } else {
    text = buildRawResponse(record);
  }
  const label = format === "response-headers" ? "Copied headers" : format === "response-body" ? "Copied body" : "Copied raw response";
  copyTextToClipboard(text);
  showToast(label);
}

// Synchronous version using already-loaded selectedRecord (preserves user gesture for clipboard)
function selectedRecordToFormat(format) {
  const record = getCurrentSelectedRecord();
  if (!record) return "";
  const blocked = historyRequestExportBlockedReason(record);
  if (blocked) {
    showToast(blocked, "error");
    return "";
  }
  const rawText = buildRawRequest(record);
  const scheme = record.scheme || "https";
  const hostHeader = normalizedHeaders(record.request?.headers).find((h) => headerNameEquals(h, "host"));
  const host = record.host || hostHeader?.value || "";
  const parsed = parseRequestForExport(rawText, scheme, host, "");
  if (!parsed) return "";
  if (format === "fetch") {
    const fetchBlocked = fetchExportBlockedReason(parsed);
    if (fetchBlocked) {
      showToast(fetchBlocked, "error");
      return "";
    }
  }
  if (format === "curl") return requestToCurl(parsed);
  if (format === "python") return requestToPython(parsed);
  if (format === "fetch") return requestToFetch(parsed);
  if (format === "powershell") return requestToPowerShell(parsed);
  return "";
}

async function historyRequestToFormat(transactionId, format) {
  const sessionId = currentSessionId();
  const response = await fetch(transactionPath(transactionId, sessionId));
  if (currentSessionId() !== sessionId) return "";
  if (!response.ok) return "";
  const record = await response.json();
  if (currentSessionId() !== sessionId) return "";
  const blocked = historyRequestExportBlockedReason(record);
  if (blocked) {
    showToast(blocked, "error");
    return "";
  }
  const rawText = buildRawRequest(record);
  const scheme = record.scheme || "https";
  const hostHeader = normalizedHeaders(record.request?.headers).find((h) => headerNameEquals(h, "host"));
  const host = record.host || hostHeader?.value || "";
  const parsed = parseRequestForExport(rawText, scheme, host, "");
  if (!parsed) return "";
  if (format === "fetch") {
    const fetchBlocked = fetchExportBlockedReason(parsed);
    if (fetchBlocked) {
      showToast(fetchBlocked, "error");
      return "";
    }
  }
  if (format === "curl") return requestToCurl(parsed);
  if (format === "python") return requestToPython(parsed);
  if (format === "fetch") return requestToFetch(parsed);
  if (format === "powershell") return requestToPowerShell(parsed);
  return "";
}

function copyTransactionUrl(transactionId) {
  const item = getHistoryItem(transactionId);
  if (!item) return;
  const scheme = item.scheme || "https";
  const host = item.host || "";
  const path = item.path || "/";
  const url = buildUrlFromTarget(scheme, host, "", path);
  copyTextToClipboard(url).then(() => showToast("Copied URL")).catch(() => {});
}

function copyReplayUrl() {
  const tab = getActiveReplayTab();
  if (!tab) return;
  const target = getReplayExportTarget(tab);
  const scheme = target.scheme || "https";
  const host = target.host || "localhost";
  const port = target.port || "";
  const text = tab.requestText || "";
  const match = text.match(/^[A-Z]+\s+(\S+)/i);
  const path = match ? match[1] : "/";
  const url = buildUrlFromTarget(scheme, host, port, path);
  copyTextToClipboard(url).then(() => showToast("Copied URL")).catch(() => {});
}

function parseCurlCommand(text) {
  const normalized = text.replace(/\\\s*\n/g, " ").trim();
  const shellWords = splitShellWords(normalized);
  if (!shellWords.length || shellWords[0].toLowerCase() !== "curl") return null;
  const tokens = shellWords.slice(1);
  let method = "GET";
  let methodExplicit = false;
  let getMode = false;
  let pathAsIs = false;
  let url = "";
  const headers = [];
  const bodyParts = [];
  let bodyProvided = false;
  const addBodyPart = (flag, value) => {
    if (flag === "--data-urlencode") {
      const encoded = encodeCurlDataUrlencode(value);
      if (encoded.error) return encoded.error;
      bodyParts.push(encoded.value);
      bodyProvided = true;
      if (!getMode && !methodExplicit && (!method || method === "GET")) method = "POST";
      return "";
    }
    if (flag !== "--data-raw" && value.startsWith("@")) {
      return "cURL @file body imports are not supported. Use --data-raw for literal @ bodies.";
    }
    bodyParts.push(value);
    bodyProvided = true;
    if (!getMode && !methodExplicit && (!method || method === "GET")) method = "POST";
    return "";
  };
  const ensureHeader = (name, value) => {
    if (!normalizedHeaders(headers).some((header) => headerNameEquals(header, name))) {
      headers.push({ name, value });
    }
  };
  const addJsonBody = (value) => {
    const raw = String(value ?? "");
    if (raw.startsWith("@")) {
      return "cURL --json @file imports are not supported.";
    }
    const error = addBodyPart("--data-raw", raw);
    if (error) return error;
    ensureHeader("Content-Type", "application/json");
    ensureHeader("Accept", "application/json");
    return "";
  };
  for (let t = 0; t < tokens.length; t++) {
    const tok = tokens[t];
    if (tok === "-X" || tok === "--request") {
      method = (tokens[++t] || "GET").toUpperCase();
      methodExplicit = true;
    }
    else if (tok.startsWith("-X") && tok.length > 2) {
      method = tok.slice(2).toUpperCase() || "GET";
      methodExplicit = true;
    }
    else if (tok.startsWith("--request=")) {
      method = tok.slice("--request=".length).toUpperCase() || "GET";
      methodExplicit = true;
    }
    else if (tok === "-I" || tok === "--head") {
      method = "HEAD";
      methodExplicit = true;
    }
    else if (tok === "-G" || tok === "--get") {
      getMode = true;
      if (!methodExplicit) method = "GET";
    }
    else if (tok === "-H" || tok === "--header") {
      const hVal = tokens[++t] || "";
      const ci = hVal.indexOf(":");
      if (ci > 0) headers.push({ name: hVal.slice(0, ci).trim(), value: hVal.slice(ci + 1).trim() });
    }
    else if (tok.startsWith("-H") && tok.length > 2) {
      const hVal = tok.slice(2);
      const ci = hVal.indexOf(":");
      if (ci > 0) headers.push({ name: hVal.slice(0, ci).trim(), value: hVal.slice(ci + 1).trim() });
    }
    else if (tok.startsWith("--header=")) {
      const hVal = tok.slice("--header=".length);
      const ci = hVal.indexOf(":");
      if (ci > 0) headers.push({ name: hVal.slice(0, ci).trim(), value: hVal.slice(ci + 1).trim() });
    }
    else if (tok === "-d" || tok === "--data" || tok === "--data-raw" || tok === "--data-binary" || tok === "--data-urlencode") {
      const error = addBodyPart(tok, tokens[++t] || "");
      if (error) return { error };
    }
    else if (tok === "--json") {
      const error = addJsonBody(tokens[++t] || "");
      if (error) return { error };
    }
    else if (tok.startsWith("-d") && tok.length > 2) {
      const error = addBodyPart("-d", tok.slice(2));
      if (error) return { error };
    }
    else if (tok.startsWith("--data=") || tok.startsWith("--data-raw=") || tok.startsWith("--data-binary=") || tok.startsWith("--data-urlencode=")) {
      const flag = tok.slice(0, tok.indexOf("="));
      const error = addBodyPart(flag, tok.slice(tok.indexOf("=") + 1));
      if (error) return { error };
    }
    else if (tok.startsWith("--json=")) {
      const error = addJsonBody(tok.slice("--json=".length));
      if (error) return { error };
    }
    else if (tok === "-F" || tok === "--form" || tok === "--form-string") {
      t++;
      return { error: "cURL multipart form imports are not supported yet." };
    }
    else if ((tok.startsWith("-F") && tok.length > 2) || tok.startsWith("--form=") || tok.startsWith("--form-string=")) {
      return { error: "cURL multipart form imports are not supported yet." };
    }
    else if (tok === "-u" || tok === "--user") {
      const cred = tokens[++t] || "";
      headers.push({ name: "Authorization", value: `Basic ${safeEncodeBase64(cred)}` });
    }
    else if (tok.startsWith("-u") && tok.length > 2) {
      const cred = tok.slice(2);
      headers.push({ name: "Authorization", value: `Basic ${safeEncodeBase64(cred)}` });
    }
    else if (tok.startsWith("--user=")) {
      const cred = tok.slice("--user=".length);
      headers.push({ name: "Authorization", value: `Basic ${safeEncodeBase64(cred)}` });
    }
    else if (tok === "-A" || tok === "--user-agent") {
      headers.push({ name: "User-Agent", value: tokens[++t] || "" });
    }
    else if (tok.startsWith("-A") && tok.length > 2) {
      headers.push({ name: "User-Agent", value: tok.slice(2) });
    }
    else if (tok.startsWith("--user-agent=")) {
      headers.push({ name: "User-Agent", value: tok.slice("--user-agent=".length) });
    }
    else if (tok === "-e" || tok === "--referer") {
      headers.push({ name: "Referer", value: tokens[++t] || "" });
    }
    else if (tok.startsWith("-e") && tok.length > 2) {
      headers.push({ name: "Referer", value: tok.slice(2) });
    }
    else if (tok.startsWith("--referer=")) {
      headers.push({ name: "Referer", value: tok.slice("--referer=".length) });
    }
    else if (tok === "-b" || tok === "--cookie") {
      headers.push({ name: "Cookie", value: tokens[++t] || "" });
    }
    else if (tok.startsWith("-b") && tok.length > 2) {
      headers.push({ name: "Cookie", value: tok.slice(2) });
    }
    else if (tok.startsWith("--cookie=")) {
      headers.push({ name: "Cookie", value: tok.slice("--cookie=".length) });
    }
    else if (tok === "--url") {
      url = tokens[++t] || "";
    }
    else if (tok.startsWith("--url=")) {
      url = tok.slice("--url=".length);
    }
    else if (tok === "--path-as-is") {
      pathAsIs = true;
    }
    else if (tok === "--compressed" || tok === "-k" || tok === "--insecure" || tok === "-s" || tok === "--silent" || tok === "-v" || tok === "--verbose" || tok === "-L" || tok === "--location") { /* skip flags */ }
    else if (["-o", "--output", "-x", "--proxy", "--connect-timeout", "--max-time"].includes(tok)) { t++; }
    else if (/^--(?:output|proxy|connect-timeout|max-time)=/.test(tok)) { /* skip option=value */ }
    else if (!tok.startsWith("-") && !url) { url = tok; }
  }
  if (!url) return null;
  if (getMode && !methodExplicit) {
    method = "GET";
  }
  if (!HTTP_METHOD_TOKEN_RE.test(method)) {
    return { error: "Invalid HTTP method in cURL command." };
  }
  let body = bodyParts.join("&");
  if (getMode && body) {
    url += `${url.includes("?") ? "&" : "?"}${body}`;
    body = "";
    bodyProvided = false;
  }
  let scheme = "https";
  let host = "";
  let path = "/";
  try {
    const parsed = new URL(url);
    scheme = parsed.protocol.replace(":", "");
    host = parsed.host;
    path = pathAsIs ? rawPathFromUrlString(url) : `${parsed.pathname || "/"}${parsed.search || ""}`;
  } catch (_) { return null; }
  const hasHost = normalizedHeaders(headers).some((h) => headerNameEquals(h, "host"));
  if (!hasHost) headers.unshift({ name: "Host", value: host });
  const headerText = headers.map((h) => `${h.name}: ${h.value}`).join("\n");
  const requestText = bodyProvided ? `${method} ${path} HTTP/1.1\n${headerText}\n\n${body}` : `${method} ${path} HTTP/1.1\n${headerText}`;
  return { scheme, host, port: "", method, path, headers, body, requestText };
}

function encodeCurlDataUrlencode(value) {
  const raw = String(value ?? "");
  if (raw.startsWith("@") || (!raw.includes("=") && /^[^@=]+@/.test(raw))) {
    return { error: "cURL --data-urlencode @file imports are not supported." };
  }
  const formEncode = (part) => encodeURIComponent(part).replace(/%20/g, "+");
  const eq = raw.indexOf("=");
  if (eq > 0) {
    return { value: `${raw.slice(0, eq)}=${formEncode(raw.slice(eq + 1))}` };
  }
  if (eq === 0) {
    return { value: formEncode(raw.slice(1)) };
  }
  return { value: formEncode(raw) };
}

function rawPathFromUrlString(url) {
  const input = String(url || "");
  const schemeIndex = input.indexOf("://");
  if (schemeIndex < 0) return "";
  const authorityStart = schemeIndex + 3;
  let pathStart = input.length;
  for (const marker of ["/", "?", "#"]) {
    const index = input.indexOf(marker, authorityStart);
    if (index >= 0 && index < pathStart) pathStart = index;
  }
  const raw = pathStart < input.length ? input.slice(pathStart) : "/";
  const hashIndex = raw.indexOf("#");
  const withoutHash = hashIndex >= 0 ? raw.slice(0, hashIndex) : raw;
  if (withoutHash.startsWith("?")) return `/${withoutHash}`;
  return withoutHash || "/";
}

function splitShellWords(input) {
  const tokens = [];
  let token = "";
  let quote = null;
  let active = false;

  for (let i = 0; i < input.length; i++) {
    const ch = input[i];
    if (quote === "'") {
      if (ch === "'") quote = null;
      else { token += ch; active = true; }
      continue;
    }
    if (quote === '"') {
      if (ch === '"') {
        quote = null;
      } else if (ch === "\\" && i + 1 < input.length) {
        token += input[++i];
        active = true;
      } else {
        token += ch;
        active = true;
      }
      continue;
    }
    if (quote === "$'") {
      if (ch === "'") {
        quote = null;
      } else if (ch === "\\" && i + 1 < input.length) {
        const decoded = decodeAnsiCStringEscape(input, i + 1);
        token += decoded.value;
        i = decoded.index;
        active = true;
      } else {
        token += ch;
        active = true;
      }
      continue;
    }

    if (/\s/.test(ch)) {
      if (active || token.length) tokens.push(token);
      token = "";
      active = false;
      continue;
    }
    if (ch === "$" && input[i + 1] === "'") {
      quote = "$'";
      active = true;
      i += 1;
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      active = true;
      continue;
    }
    if (ch === "\\" && i + 1 < input.length) {
      token += input[++i];
      active = true;
      continue;
    }
    token += ch;
    active = true;
  }

  if (quote) return [];
  if (active || token.length) tokens.push(token);
  return tokens;
}

function decodeAnsiCStringEscape(input, index) {
  const ch = input[index] || "";
  const simple = {
    a: "\x07",
    b: "\b",
    e: "\x1b",
    E: "\x1b",
    f: "\f",
    n: "\n",
    r: "\r",
    t: "\t",
    v: "\v",
    "\\": "\\",
    "'": "'",
    "\"": "\"",
    "?": "?",
  };
  if (Object.prototype.hasOwnProperty.call(simple, ch)) {
    return { value: simple[ch], index };
  }
  if (ch === "x") {
    const hex = input.slice(index + 1).match(/^[0-9a-fA-F]{1,2}/)?.[0] || "";
    if (hex) {
      return { value: String.fromCharCode(parseInt(hex, 16)), index: index + hex.length };
    }
  }
  if (ch === "u") {
    const hex = input.slice(index + 1, index + 5);
    if (/^[0-9a-fA-F]{4}$/.test(hex)) {
      return { value: String.fromCharCode(parseInt(hex, 16)), index: index + 4 };
    }
  }
  if (ch === "U") {
    const hex = input.slice(index + 1, index + 9);
    if (/^[0-9a-fA-F]{8}$/.test(hex)) {
      const codePoint = parseInt(hex, 16);
      if (codePoint <= 0x10ffff) {
        return { value: String.fromCodePoint(codePoint), index: index + 8 };
      }
    }
  }
  if (/^[0-7]$/.test(ch)) {
    const octal = input.slice(index, index + 3).match(/^[0-7]{1,3}/)?.[0] || ch;
    return { value: String.fromCharCode(parseInt(octal, 8)), index: index + octal.length - 1 };
  }
  return { value: ch, index };
}

function openCurlImportModal() {
  const modal = document.getElementById("curlImportModal");
  document.getElementById("curlImportInput").value = "";
  modal.classList.remove("hidden");
  document.getElementById("curlImportInput").focus();
}

function closeCurlImportModal() {
  document.getElementById("curlImportModal").classList.add("hidden");
}

function applyCurlImport() {
  const text = document.getElementById("curlImportInput").value;
  const result = parseCurlCommand(text);
  if (!result) {
    showToast("Could not parse cURL command", "error");
    return;
  }
  if (result.error) {
    showToast(result.error, "error");
    return;
  }
  const tab = createReplayTab();
  const target = authorityToTargetState(result.host, result.scheme || "https");
  tab.requestText = result.requestText;
  tab.targetScheme = result.scheme;
  tab.targetHost = target.host;
  tab.targetPort = target.port;
  tab.targetManuallyEdited = hostHeaderDiffersFromUrl(
    headerValue(result.headers, "host") || result.host,
    buildUrlFromTarget(result.scheme, target.host, target.port, result.path),
  );
  tab.baseRequest = {
    scheme: result.scheme,
    host: result.host,
    method: result.method,
    path: result.path,
    headers: normalizedHeaders(result.headers),
    body: result.body,
    body_encoding: "utf8",
    preview_truncated: false,
  };
  state.replayTabs.push(tab);
  state.activeReplayTabId = tab.id;
  state.activeTool = "replay";
  closeCurlImportModal();
  scheduleWorkspaceStateSave();
  renderToolPanels();
}

function initReplayContextMenu() {
  // Method buttons
  getReplayContextMenu().querySelectorAll(".method-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      changeReplayMethod(btn.dataset.method);
      closeReplayContextMenu();
    });
  });

  // Action buttons
  getReplayContextMenu().querySelectorAll("[data-replay-action]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const action = btn.dataset.replayAction;
      const tab = getActiveReplayTab();
      if (!tab) { closeReplayContextMenu(); return; }

      if (action === "toggle-body") {
        const text = tab.requestText || "";
        if (text.includes("\n\n")) {
          // Remove body
          tab.requestText = text.split("\n\n")[0];
        } else {
          // Add empty body section
          tab.requestText = text + "\n\n";
        }
        const cv = getCMView("replayReq");
        if (cv) {
          cv.setContent(tab.requestText);
        } else if (els.replayRequestEditor) {
          els.replayRequestEditor.value = tab.requestText;
          renderReplayRequestHighlight(tab.requestText);
        }
        scheduleWorkspaceStateSave();
      } else if (action === "add-content-type-json") {
        setReplayHeader("Content-Type", "application/json");
      } else if (action === "add-content-type-form") {
        setReplayHeader("Content-Type", "application/x-www-form-urlencoded");
      } else if (action === "copy-url") {
        copyReplayUrl();
      } else if (action === "copy-as-curl" || action === "copy-as-python" || action === "copy-as-fetch" || action === "copy-as-powershell") {
        const format = action.replace("copy-as-", "");
        const text = replayRequestToFormat(format);
        if (text) {
          copyTextToClipboard(text).then(() => showToast(`Copied as ${format}`)).catch(() => {});
        }
      } else if (action === "import-curl") {
        openCurlImportModal();
      }

      closeReplayContextMenu();
    });
  });

  // Close on outside click
  document.addEventListener("click", (event) => {
    if (!getReplayContextMenu().contains(event.target)) {
      closeReplayContextMenu();
    }
  });
}

function setReplayHeader(name, value) {
  const tab = getActiveReplayTab();
  if (!tab) return;

  const text = tab.requestText || "";
  const normalized = text.replace(/\r\n/g, "\n");
  const bodyIdx = normalized.indexOf("\n\n");
  const head = bodyIdx === -1 ? normalized : normalized.slice(0, bodyIdx);
  const body = bodyIdx === -1 ? "" : normalized.slice(bodyIdx);
  const lines = head.split("\n");

  // Check if header already exists (case-insensitive)
  const lowerName = name.toLowerCase();
  const existingIdx = lines.findIndex((l, i) => i > 0 && l.toLowerCase().startsWith(lowerName + ":"));

  if (existingIdx !== -1) {
    lines[existingIdx] = `${name}: ${value}`;
  } else {
    lines.push(`${name}: ${value}`);
  }

  tab.requestText = lines.join("\n") + body;
  const cv = getCMView("replayReq");
  if (cv) {
    cv.setContent(tab.requestText);
  } else if (els.replayRequestEditor) {
    els.replayRequestEditor.value = tab.requestText;
    renderReplayRequestHighlight(tab.requestText);
  }
  updateReplaySearchPane("request", tab.requestText);
  scheduleWorkspaceStateSave();
}

/* ─── Code-view line keyboard navigation + cursor + Cmd+C ─── */

(function initCodeViewLineNav() {
  const READONLY_ATTR = "data-readonly-editable";

  // Make read-only code-views show a text cursor by enabling contenteditable
  // but blocking all mutations so the content stays untouched.
  function enableReadonlyCaret(view) {
    if (view.getAttribute(READONLY_ATTR)) return;
    // Skip views that are already editable for editing purposes (replay editor, ws message)
    if (view.dataset.placeholder) return;
    view.setAttribute("contenteditable", "true");
    view.setAttribute(READONLY_ATTR, "1");
    view.addEventListener("beforeinput", (e) => e.preventDefault());
    view.addEventListener("paste", (e) => e.preventDefault());
    view.addEventListener("drop", (e) => e.preventDefault());
  }

  // Auto-enable for all code-view / simple-code-view with tabindex
  function initAllReadonlyCarets() {
    document.querySelectorAll(".code-view[tabindex], .simple-code-view[tabindex]").forEach((v) => {
      if (!v.dataset.placeholder) enableReadonlyCaret(v);
    });
  }
  // Run once at load and observe DOM for late-added panels
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initAllReadonlyCarets);
  } else {
    initAllReadonlyCarets();
  }
  // Expose helpers so render functions can re-enable after innerHTML swap
  // and preserve line focus across re-renders.
  window._enableReadonlyCaret = enableReadonlyCaret;

  // Save current focus state for a code-view (call before innerHTML swap)
  window._saveCodeViewFocus = function(view) {
    if (!view) return null;
    const focused = view.querySelector(".code-line.line-focus");
    if (!focused) return null;
    const lines = getCodeLines(view);
    const idx = lines.indexOf(focused);
    const wasActive = (document.activeElement === view);
    return { viewId: view.id, lineIndex: idx, wasActive };
  };

  // Restore focus state after innerHTML swap
  window._restoreCodeViewFocus = function(view, saved) {
    if (!view || !saved || saved.lineIndex < 0) return;
    enableReadonlyCaret(view);
    const lines = getCodeLines(view);
    if (saved.lineIndex < lines.length) {
      // Only restore visual highlight — never steal focus from other elements
      clearFocus(view);
      lines[saved.lineIndex].classList.add("line-focus");
      if (saved.wasActive) {
        setFocus(view, lines[saved.lineIndex], true);
      }
    }
  };

  function isReadonlyView(el) {
    return el && el.getAttribute(READONLY_ATTR) === "1";
  }

  function getCodeLines(view) {
    return Array.from(view.querySelectorAll(".code-line"));
  }

  function clearFocus(view) {
    const prev = view.querySelector(".code-line.line-focus");
    if (prev) prev.classList.remove("line-focus");
  }

  function setFocus(view, line, moveCaret) {
    clearFocus(view);
    line.classList.add("line-focus");
    line.scrollIntoView({ block: "nearest" });
    // Only move caret on arrow-key navigation or restore; clicks keep natural position
    if (moveCaret) {
      try {
        const sel = window.getSelection();
        const textNode = line.firstChild;
        if (sel && textNode) {
          const range = document.createRange();
          range.setStart(textNode, 0);
          range.collapse(true);
          sel.removeAllRanges();
          sel.addRange(range);
        }
      } catch (_) { /* ignore if range fails */ }
    }
  }

  function focusedIndex(lines) {
    return lines.findIndex((l) => l.classList.contains("line-focus"));
  }

  // Click: set line focus and ensure the view has keyboard focus
  document.addEventListener("click", (event) => {
    const view = event.target.closest(".code-view, .simple-code-view");
    if (!view || !isReadonlyView(view)) return;
    const line = event.target.closest(".code-line");
    if (line && view.contains(line)) {
      setFocus(view, line, false);
      if (document.activeElement !== view) view.focus({ preventScroll: true });
    }
  });

  // ArrowUp/Down/Home/End: line navigation
  document.addEventListener("keydown", (event) => {
    if (event.key !== "ArrowUp" && event.key !== "ArrowDown" && event.key !== "Home" && event.key !== "End") return;
    let view = document.activeElement;
    if (view && !isReadonlyView(view)) {
      view = view.closest?.(".code-view, .simple-code-view");
    }
    if (!view || !isReadonlyView(view)) return;
    const lines = getCodeLines(view);
    if (!lines.length) return;
    event.preventDefault();
    if (event.key === "Home") {
      setFocus(view, lines[0], true);
      return;
    }
    if (event.key === "End") {
      setFocus(view, lines[lines.length - 1], true);
      return;
    }
    let idx = focusedIndex(lines);
    if (idx === -1) {
      setFocus(view, lines[0], true);
      return;
    }
    const next = event.key === "ArrowDown" ? idx + 1 : idx - 1;
    if (next >= 0 && next < lines.length) {
      setFocus(view, lines[next], true);
    }
  });

  // Cmd+C / Ctrl+C: copy focused line when no text selection
  document.addEventListener("keydown", (event) => {
    if (!(event.metaKey || event.ctrlKey) || event.key.toLowerCase() !== "c") return;
    let view = document.activeElement;
    if (view && !isReadonlyView(view)) {
      view = view.closest?.(".code-view, .simple-code-view");
    }
    if (!view || !isReadonlyView(view)) return;
    const sel = window.getSelection();
    if (sel && sel.toString().length > 0) return; // native copy handles selected text
    const focused = view.querySelector(".code-line.line-focus");
    if (!focused) return;
    event.preventDefault();
    copyTextToClipboard(focused.textContent).catch(() => {});
  });
})();

// ─── CodeMirror 6 Integration ───────────────────────────────────────────────

const sniperCMTheme = CM.EditorView.theme({
  "&": {
    fontSize: "var(--font-xs, 10px)",
    fontFamily: "var(--mono, monospace)",
    backgroundColor: "var(--panel-code, #161616)",
    color: "var(--text, #f1f1f1)",
    height: "100%",
  },
  ".cm-content": {
    padding: "12px 14px",
    caretColor: "var(--accent, #e0a050)",
    lineHeight: "1.48",
    fontFamily: "var(--mono, monospace)",
    color: "var(--text, #f1f1f1)",
  },
  ".cm-gutters": {
    backgroundColor: "var(--code-gutter-bg, rgba(12,12,12,0.78))",
    color: "var(--code-gutter-text, rgba(255,255,255,0.28))",
    border: "none",
    minWidth: "36px",
  },
  ".cm-gutter.cm-lineNumbers .cm-gutterElement": {
    padding: "0 6px 0 12px",
    fontSize: "var(--font-xs)",
    fontFamily: "var(--mono)",
  },
  ".cm-activeLine": {
    backgroundColor: "rgba(255, 255, 255, 0.07)",
    outline: "1px solid rgba(255, 255, 255, 0.12)",
    outlineOffset: "-1px",
    borderRadius: "2px",
  },
  "&:not(.cm-focused) .cm-activeLine": {
    backgroundColor: "transparent",
    outline: "none",
  },
  ".cm-selectionBackground, ::selection": {
    backgroundColor: "rgba(255,255,255,0.12) !important",
  },
  ".cm-cursor": {
    borderLeftColor: "var(--accent, #e0a050)",
  },
  ".cm-scroller": {
    overflow: "auto",
    fontFamily: "var(--mono)",
  },
  ".cm-specialChar": {
    color: "#d19a66",
    backgroundColor: "rgba(209,154,102,0.15)",
    borderRadius: "2px",
    padding: "0 1px",
  },
  ".cm-line": {
    padding: "0",
  },
  "&.cm-focused .cm-selectionBackground": {
    backgroundColor: "rgba(255,255,255,0.15) !important",
  },
  "&.cm-focused": {
    outline: "none",
  },
  /* ── HTTP syntax highlight tokens (scoped via CM theme for WKWebView) ── */
  ".tok-method":       { color: "var(--token-method-color, #73c991)" },
  ".tok-target":       { color: "var(--token-target-color, #e0e4ea)" },
  ".tok-url":          { color: "var(--token-url-color, #6cb6d9)" },
  ".tok-version":      { color: "var(--token-version-color, #808898)" },
  ".tok-header":       { color: "var(--token-info-color, #c9a96e)" },
  ".tok-status":       { color: "var(--token-info-color, #c9a96e)", fontWeight: "700" },
  ".tok-status-ok":    { color: "var(--success, #73c991)", fontWeight: "700" },
  ".tok-status-info":  { color: "var(--info, #6cb6d9)", fontWeight: "700" },
  ".tok-status-warn":  { color: "var(--warning, #e0a050)", fontWeight: "700" },
  ".tok-status-error": { color: "var(--danger, #f87171)", fontWeight: "700" },
  ".tok-plain":        { color: "var(--token-plain-color, #cdd2da)" },
  ".tok-punct":        { color: "var(--token-plain-color, #cdd2da)" },
  ".tok-cookie-name":  { color: "#e06c88" },
  ".tok-cookie-val":   { color: "var(--text-soft, #aab0bc)" },
  ".tok-cookie-sep":   { color: "#6cb6d9" },
  ".tok-cookie-flag":  { color: "#7cb8a0" },
  ".tok-json-key":     { color: "var(--token-info-color, #c9a96e)" },
  ".tok-json-str":     { color: "var(--token-string-color, #e8e8e8)" },
  ".tok-json-num":     { color: "var(--warning, #e0a050)" },
  ".tok-json-bool":    { color: "#b89f7c" },
  ".tok-query-key":    { color: "var(--token-info-color, #c9a96e)" },
  ".tok-query-val":    { color: "var(--token-query-value-color, #e8e8e8)" },
  ".tok-markup-tag":   { color: "var(--token-info-color, #c9a96e)" },
  ".tok-markup-attr":  { color: "var(--token-info-color, #c9a96e)" },
  ".tok-markup-str":   { color: "var(--token-string-color, #e8e8e8)" },
  ".tok-markup-meta":  { color: "#b89f7c" },
  ".tok-meta":         { color: "#b89f7c" },
  ".tok-kw":           { color: "var(--token-info-color, #c9a96e)" },
  /* ── Hex view tokens ── */
  ".tok-hex-offset":   { color: "var(--token-info-color, #c9a96e)", display: "inline-block", width: "70px", paddingRight: "12px", overflow: "hidden", verticalAlign: "top", whiteSpace: "pre", fontFamily: "'Menlo', 'Monaco', 'Cascadia Mono', 'Courier New', monospace", fontSize: "11px" },
  ".tok-hex-bytes":    { color: "var(--token-string-color, #e8e8e8)", display: "inline-block", width: "355px", paddingRight: "8px", overflow: "hidden", verticalAlign: "top", whiteSpace: "pre", fontFamily: "'Menlo', 'Monaco', 'Cascadia Mono', 'Courier New', monospace", fontSize: "11px" },
  ".tok-hex-ascii":    { color: "var(--token-plain-color, #cdd2da)", fontFamily: "'Menlo', 'Monaco', 'Cascadia Mono', 'Courier New', monospace", fontSize: "11px" },
  /* ── Diff view tokens ── */
  ".tok-diff-added":   { color: "var(--success, #50c878)", background: "rgba(80, 200, 120, 0.12)" },
  ".tok-diff-removed": { color: "var(--danger, #e05252)", background: "rgba(200, 80, 80, 0.12)", textDecoration: "line-through" },
  ".tok-diff-header":  { color: "var(--point, #7d91ab)", fontWeight: "600" },
  /* ── Payload placeholder ── */
  ".tok-payload":      { color: "#f8d06b", background: "rgba(248, 208, 107, 0.18)", borderRadius: "3px", padding: "0 2px", fontWeight: "600" },
  /* ── Search highlight ── */
  ".tok-search-hit":   { background: "rgba(132, 151, 173, 0.2)", borderRadius: "4px", padding: "0 1px" },
  ".tok-search-active": { background: "rgba(201, 169, 110, 0.4)", borderRadius: "4px", padding: "0 1px" },
}, { dark: true });

// ─── HTTP decoration plugin ─────────────────────────────────────────────────
//
// Reuses the existing highlight* functions (highlightStartLine, highlightHeaderLine,
// highlightBodyLine, highlightCookieValue) to produce CM Decoration.mark() spans
// with the same CSS classes as the legacy <pre> renderer.  This ensures pixel-perfect
// colour parity with the non-CM code path.

/** Map legacy CSS class → CM-scoped tok-* class. */
const _tokMap = {
  "token-method": "tok-method",
  "token-target": "tok-target",
  "token-url": "tok-url",
  "token-version": "tok-version",
  "token-header": "tok-header",
  "token-plain": "tok-plain",
  "token-punctuation": "tok-punct",
  "token-cookie-name": "tok-cookie-name",
  "token-cookie-value": "tok-cookie-val",
  "token-cookie-sep": "tok-cookie-sep",
  "token-cookie-flag": "tok-cookie-flag",
  "token-json-key": "tok-json-key",
  "token-json-string": "tok-json-str",
  "token-json-number": "tok-json-num",
  "token-json-boolean": "tok-json-bool",
  "token-meta": "tok-meta",
  "token-query-key": "tok-query-key",
  "token-query-value": "tok-query-val",
  "token-markup-tag": "tok-markup-tag",
  "token-markup-attr": "tok-markup-attr",
  "token-markup-string": "tok-markup-str",
  "token-markup-meta": "tok-markup-meta",
  "token-js-keyword": "tok-kw",
  "token-js-string": "tok-json-str",
  "token-css-property": "tok-kw",
  "token-css-selector": "tok-kw",
  "token-css-keyword": "tok-kw",
  "token-css-value": "tok-json-str",
  "token-hex-offset": "tok-header",
  "token-hex-bytes": "tok-json-str",
  "token-hex-ascii": "tok-plain",
  "token-string": "tok-json-str",
};

function mapTokenClass(legacyCls) {
  // Handle compound status classes like "token-status ok"
  if (legacyCls.startsWith("token-status")) {
    const tone = legacyCls.replace("token-status", "").trim();
    if (tone === "ok") return "tok-status-ok";
    if (tone === "info") return "tok-status-info";
    if (tone === "warn") return "tok-status-warn";
    if (tone === "error") return "tok-status-error";
    return "tok-status";
  }
  return _tokMap[legacyCls] || "";
}

/** Parse an HTML-highlighted line into [{cls, start, end}] token ranges. */
function extractTokenRanges(htmlStr, plainText) {
  const ranges = [];
  const tagRe = /<span class="([^"]+)">([^<]*)<\/span>/g;
  let m;
  let searchFrom = 0;
  while ((m = tagRe.exec(htmlStr)) !== null) {
    const cls = mapTokenClass(m[1]);
    if (!cls) continue;
    const text = m[2].replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&#39;/g, "'").replace(/&quot;/g, '"');
    if (!text) continue;
    const idx = plainText.indexOf(text, searchFrom);
    if (idx === -1) continue;
    ranges.push({ cls, from: idx, to: idx + text.length });
    searchFrom = idx + text.length;
  }
  return ranges;
}

/** Build a RangeSet<Decoration> for an HTTP message document. */
function buildHttpDecorations(view) {
  const doc = view.state.doc;
  const text = doc.toString();
  if (!text) return CM.Decoration.none;

  const lines = text.split("\n");
  const builder = [];

  // Determine where blank separator line is (end of headers)
  let blankIdx = -1;
  for (let i = 1; i < lines.length; i++) {
    if (lines[i] === "") { blankIdx = i; break; }
  }

  // Detect body highlight mode from Content-Type header
  let bodyMode = "plain";
  for (let i = 1; i < (blankIdx === -1 ? lines.length : blankIdx); i++) {
    const lower = lines[i].toLowerCase();
    if (lower.startsWith("content-type:")) {
      bodyMode = inferBodyHighlightMode(lines[i].slice(13).trim());
      break;
    }
  }

  // Detect request vs response from first line
  const isResponse = /^HTTP\/[\d.]+\s/.test(lines[0]);
  const target = isResponse ? "response" : "request";

  let offset = 0;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineStart = offset;
    offset += line.length + 1; // +1 for \n

    if (!line) continue;

    let highlighted;
    if (i === 0) {
      highlighted = highlightStartLine(line, target);
    } else if (blankIdx === -1 || i < blankIdx) {
      highlighted = highlightHeaderLine(line);
    } else if (i > blankIdx) {
      highlighted = highlightBodyLine(line, bodyMode);
    } else {
      continue; // blank line
    }

    const ranges = extractTokenRanges(highlighted, line);
    for (const r of ranges) {
      const from = lineStart + r.from;
      const to = lineStart + r.to;
      if (from >= to || to > doc.length) continue;
      builder.push(CM.Decoration.mark({ class: r.cls }).range(from, to));
    }
  }

  // Sort by from position (required by RangeSet)
  builder.sort((a, b) => a.from - b.from || a.to - b.to);
  return CM.Decoration.set(builder);
}

const httpDecoPlugin = CM.ViewPlugin.fromClass(
  class {
    constructor(view) { this.decorations = buildHttpDecorations(view); }
    update(update) {
      if (update.docChanged || update.startState.facet !== update.state.facet) {
        this.decorations = buildHttpDecorations(update.view);
      }
    }
  },
  { decorations: (v) => v.decorations },
);

/** Build decorations for hex dump (offset / bytes / ascii columns). */
function buildHexDecorations(view) {
  const doc = view.state.doc;
  const text = doc.toString();
  if (!text) return CM.Decoration.none;
  const builder = [];
  let offset = 0;
  for (const line of text.split("\n")) {
    if (line.length >= 10) {
      // offset column: "00000000" (8 chars), same as non-CM .hex-col-offset
      builder.push(CM.Decoration.mark({ class: "tok-hex-offset" }).range(offset, offset + 8));
      if (line.length > 10) {
        // bytes column: chars 10-58 (49 chars of hex pairs), same as non-CM .hex-col-bytes
        const hEnd = Math.min(59, line.length);
        builder.push(CM.Decoration.mark({ class: "tok-hex-bytes" }).range(offset + 10, offset + hEnd));
      }
      if (line.length > 60) {
        // ascii column: rest of line
        builder.push(CM.Decoration.mark({ class: "tok-hex-ascii" }).range(offset + 60, offset + line.length));
      }
    }
    offset += line.length + 1;
  }
  return CM.Decoration.set(builder);
}

const hexDecoPlugin = CM.ViewPlugin.fromClass(
  class {
    constructor(view) { this.decorations = buildHexDecorations(view); }
    update(update) {
      if (update.docChanged) this.decorations = buildHexDecorations(update.view);
    }
  },
  { decorations: (v) => v.decorations },
);

/** Build decorations for diff view (+/- lines). */
function buildDiffDecorations(view) {
  const doc = view.state.doc;
  const text = doc.toString();
  if (!text) return CM.Decoration.none;
  const builder = [];
  let offset = 0;
  for (const line of text.split("\n")) {
    if (line.length > 0) {
      let cls = "";
      if (line.startsWith("--- ") || line.startsWith("+++ ")) cls = "tok-diff-header";
      else if (line.startsWith("+ ")) cls = "tok-diff-added";
      else if (line.startsWith("- ")) cls = "tok-diff-removed";
      if (cls) builder.push(CM.Decoration.mark({ class: cls }).range(offset, offset + line.length));
    }
    offset += line.length + 1;
  }
  return CM.Decoration.set(builder);
}

const diffDecoPlugin = CM.ViewPlugin.fromClass(
  class {
    constructor(view) { this.decorations = buildDiffDecorations(view); }
    update(update) {
      if (update.docChanged) this.decorations = buildDiffDecorations(update.view);
    }
  },
  { decorations: (v) => v.decorations },
);

// ─── Payload marker decoration plugin ($payload$) ────────
function buildPayloadDecorations(view) {
  const doc = view.state.doc;
  const text = doc.toString();
  if (!text) return CM.Decoration.none;
  const re = /\$payload\$/gi;
  const builder = [];
  let m;
  while ((m = re.exec(text)) !== null) {
    builder.push(CM.Decoration.mark({ class: "tok-payload" }).range(m.index, m.index + m[0].length));
  }
  return builder.length ? CM.Decoration.set(builder) : CM.Decoration.none;
}

const payloadDecoPlugin = CM.ViewPlugin.fromClass(
  class {
    constructor(view) { this.decorations = buildPayloadDecorations(view); }
    update(update) {
      if (update.docChanged) this.decorations = buildPayloadDecorations(update.view);
    }
  },
  { decorations: (v) => v.decorations },
);

const cmProgrammaticSetContent = CM.Annotation.define();

/** Add an update listener to a CM EditorView; returns a dispose function. */
function addCMUpdateListener(view, callback) {
  const listener = CM.EditorView.updateListener.of((update) => {
    const programmatic = update.transactions.some((tr) => tr.annotation(cmProgrammaticSetContent));
    if (update.docChanged && !programmatic) callback(update.state.doc.toString());
  });
  view.dispatch({ effects: CM.StateEffect.appendConfig.of(listener) });
  return () => {}; // CM does not support removing extensions, but the view will be destroyed
}

const CM_SEARCH_DECORATION_LIMIT = 5000;

/** Build search highlight decorations. Returns { decos, matchCount, matchPositions }. */
function buildSearchDecorations(doc, query, activeIndex = -1) {
  if (!query) return { query: "", activeIndex: -1, decos: CM.Decoration.none, matchCount: 0, matchPositions: [] };
  const text = doc.toString();
  const lower = text.toLowerCase();
  const lq = query.toLowerCase();
  const builder = [];
  const positions = [];
  let matchCount = 0;
  let pos = 0;
  while ((pos = lower.indexOf(lq, pos)) !== -1) {
    const matchIndex = positions.length;
    positions.push(pos);
    if (matchIndex < CM_SEARCH_DECORATION_LIMIT || matchIndex === activeIndex) {
      const cls = matchIndex === activeIndex ? "tok-search-active" : "tok-search-hit";
      builder.push(CM.Decoration.mark({ class: cls }).range(pos, pos + lq.length));
    }
    matchCount += 1;
    pos += 1;
  }
  const safeActiveIndex = activeIndex >= 0 && activeIndex < positions.length ? activeIndex : -1;
  return {
    query,
    activeIndex: safeActiveIndex,
    decos: CM.Decoration.set(builder),
    matchCount,
    matchPositions: positions,
  };
}

function createBaseExtensions(options = {}) {
  const exts = [
    sniperCMTheme,
    CM.lineNumbers(),
    CM.highlightSpecialChars(),
    CM.drawSelection(),
    CM.highlightSelectionMatches(),
  ];
  // Hex mode: no line wrapping for column alignment
  if (!options.hexHighlight) {
    exts.push(CM.EditorView.lineWrapping);
  }
  if (options.readOnly) {
    exts.push(CM.EditorState.readOnly.of(true));
    // Keep editable:true so text selection and native copy work.
    // readOnly prevents actual edits while allowing cursor placement.
    // Cmd+C with no selection → copy current line
    exts.push(CM.keymap.of([{
      key: "Mod-c",
      run(view) {
        const sel = view.state.selection.main;
        if (sel.from !== sel.to) return false; // has selection → let native copy handle it
        const line = view.state.doc.lineAt(sel.head);
        navigator.clipboard.writeText(line.text).catch(() => {});
        return true;
      },
    }]));
  } else {
    exts.push(CM.history());
    exts.push(CM.keymap.of([...CM.defaultKeymap, ...CM.historyKeymap]));
  }
  if (options.placeholder) {
    exts.push(CM.placeholder(options.placeholder));
  }
  if (options.httpHighlight) exts.push(httpDecoPlugin);
  if (options.hexHighlight) {
    exts.push(hexDecoPlugin);
    // Match non-CM hex font exactly
    exts.push(CM.EditorView.theme({
      ".cm-content": { fontFamily: "'Menlo', 'Monaco', 'Cascadia Mono', 'Courier New', monospace", fontSize: "11px", lineHeight: "1.48" },
      ".cm-line": { fontFamily: "'Menlo', 'Monaco', 'Cascadia Mono', 'Courier New', monospace", fontSize: "11px" },
    }));
  }
  if (options.diffHighlight) exts.push(diffDecoPlugin);
  if (options.payloadHighlight) exts.push(payloadDecoPlugin);
  return exts;
}

// Search decoration effect & field
const setSearchQuery = CM.StateEffect.define();
const setSearchActiveIndex = CM.StateEffect.define();
const searchDecoField = CM.StateField.define({
  create() { return { query: "", activeIndex: -1, decos: CM.Decoration.none, matchCount: 0, matchPositions: [] }; },
  update(value, tr) {
    for (const e of tr.effects) {
      if (e.is(setSearchQuery)) {
        return buildSearchDecorations(tr.state.doc, e.value);
      }
      if (e.is(setSearchActiveIndex)) {
        return buildSearchDecorations(tr.state.doc, value.query, e.value);
      }
    }
    if (tr.docChanged && value.query) {
      return buildSearchDecorations(tr.state.doc, value.query, value.activeIndex);
    }
    return value;
  },
  provide: (f) => CM.EditorView.decorations.from(f, (val) => val.decos),
});

/** Reusable CodeMirror wrapper for Sniper code views. */
class SniperCodeView {
  constructor(container, options = {}) {
    this._options = options;
    this._searchNavIndex = -1;
    this.view = new CM.EditorView({
      state: CM.EditorState.create({
        doc: "",
        extensions: [...createBaseExtensions(options), searchDecoField],
      }),
      parent: container,
    });
  }

  setContent(text) {
    const { view } = this;
    const nextText = text || "";
    if (view.state.doc.toString() === nextText) {
      return;
    }
	view.dispatch({
	  changes: { from: 0, to: view.state.doc.length, insert: nextText },
	  annotations: [
	    cmProgrammaticSetContent.of(true),
	    CM.Transaction.addToHistory.of(false),
	  ],
	});
  }

  /** Apply search highlights and return match info. */
  applySearch(query, options = {}) {
    this._searchNavIndex = -1;
    this.view.dispatch({ effects: setSearchQuery.of(query || "") });
    const field = this.view.state.field(searchDecoField);
    // Scroll to first match
    if (options.scrollToFirst !== false && field.matchPositions.length > 0) {
      const pos = field.matchPositions[0];
      this.view.dispatch({ selection: { anchor: pos }, scrollIntoView: true });
    }
    return field;
  }

  /** Navigate to next search match (cyclic). Returns current index or -1. */
  nextSearchMatch() {
    const field = this.view.state.field(searchDecoField);
    if (!field.matchPositions.length) return -1;
    this._searchNavIndex = (this._searchNavIndex + 1) % field.matchPositions.length;
    const pos = field.matchPositions[this._searchNavIndex];
    this.view.dispatch({
      effects: setSearchActiveIndex.of(this._searchNavIndex),
      selection: { anchor: pos, head: pos + field.query.length },
      scrollIntoView: true,
    });
    return this._searchNavIndex;
  }

  getContent() {
    return this.view.state.doc.toString();
  }

  destroy() {
    this.view.destroy();
  }
}

// CodeMirror-based code pane instances (lazy-initialized)
const _cmViews = {};

/** Hook CM search navigation onto a search-meta element. */
function initCMSearchNavigation(metaElement, cmKey) {
  if (!metaElement) return;
  metaElement.addEventListener("click", (e) => {
    if (!e.target.closest(".search-hit-count")) return;
    const cv = _cmViews[cmKey];
    if (!cv) return;
    cv.nextSearchMatch();
  });
}

function updateCodePaneCM(key, container, text, options = {}) {
  const mode = options.mode || "http"; // "http" | "hex" | "diff"
  const editable = options.readOnly === false;
  // Recreate CM view if highlight mode or editable changed
  if (_cmViews[key] && (_cmViews[key]._hlMode !== mode || !!_cmViews[key]._editable !== editable)) {
    _cmViews[key].destroy();
    delete _cmViews[key];
  }
  if (!_cmViews[key]) {
    const cmOpts = {};
    cmOpts.readOnly = !editable;
    if (mode === "http") cmOpts.httpHighlight = true;
    else if (mode === "hex") cmOpts.hexHighlight = true;
    else if (mode === "diff") cmOpts.diffHighlight = true;
    if (options.placeholder) cmOpts.placeholder = options.placeholder;
    if (options.payloadHighlight) cmOpts.payloadHighlight = true;
    _cmViews[key] = new SniperCodeView(container, cmOpts);
    _cmViews[key]._hlMode = mode;
    _cmViews[key]._editable = editable;
  }
  const cv = _cmViews[key];
  if (editable && options.onChange && !cv._onChangeWired) {
    cv._onChangeDispose = addCMUpdateListener(cv.view, options.onChange);
    cv._onChangeWired = true;
  }
  cv.setContent(text || "");

  // Search highlights
  const query = (options.search || "").trim();
  const searchResult = cv.applySearch(query);

  const lineCount = (text || "").split("\n").length;
  return { lineCount, matchCount: searchResult.matchCount };
}

/** Helper: get a CM view from the managed pool by key. */
function getCMView(key) {
  return _cmViews[key] || null;
}
