use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, Utc};
use http::HeaderMap;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrafficKind {
    #[default]
    Http,
    Tunnel,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BodyEncoding {
    #[default]
    Utf8,
    Base64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HeaderRecord {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub value: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EditableRequest {
    pub scheme: String,
    pub host: String,
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub headers: Vec<HeaderRecord>,
    #[serde(default)]
    pub body: String,
    #[serde(default)]
    pub body_encoding: BodyEncoding,
    #[serde(default)]
    pub preview_truncated: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EditableResponse {
    pub status: u16,
    pub headers: Vec<HeaderRecord>,
    pub body: String,
    pub body_encoding: BodyEncoding,
}

impl EditableResponse {
    pub fn from_status_headers_body(status: u16, headers: &HeaderMap, body: &[u8]) -> Self {
        let content_type = headers
            .get(http::header::CONTENT_TYPE)
            .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned());

        // Decompress body based on Content-Encoding header (gzip, deflate, br)
        let decoded_body = decode_content_encoding(headers, body);
        let content_decoded = decoded_body.is_some();
        let body_ref = decoded_body.as_deref().unwrap_or(body);

        let body_encoding = if is_textual_body(content_type.as_deref(), body_ref) {
            BodyEncoding::Utf8
        } else {
            BodyEncoding::Base64
        };

        Self {
            status,
            headers: header_records_for_decoded_body(headers, content_decoded),
            body: match body_encoding {
                BodyEncoding::Utf8 => String::from_utf8_lossy(body_ref).into_owned(),
                BodyEncoding::Base64 => STANDARD.encode(body_ref),
            },
            body_encoding,
        }
    }

    pub fn body_bytes(&self) -> Vec<u8> {
        self.try_body_bytes().unwrap_or_default()
    }

    pub fn try_body_bytes(&self) -> Result<Vec<u8>, base64::DecodeError> {
        match self.body_encoding {
            BodyEncoding::Utf8 => Ok(self.body.as_bytes().to_vec()),
            BodyEncoding::Base64 => STANDARD.decode(self.body.as_bytes()),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RequestTargetOverride {
    pub scheme: String,
    pub host: String,
    pub port: String,
}

impl EditableRequest {
    pub fn from_headers_and_body(
        scheme: impl Into<String>,
        host: impl Into<String>,
        method: impl Into<String>,
        path: impl Into<String>,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Self {
        let content_type = headers
            .get(http::header::CONTENT_TYPE)
            .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned());

        // Decompress body based on Content-Encoding header (gzip, deflate, br)
        let decoded_body = decode_content_encoding(headers, body);
        let content_decoded = decoded_body.is_some();
        let body_ref = decoded_body.as_deref().unwrap_or(body);

        let body_encoding = if is_textual_body(content_type.as_deref(), body_ref) {
            BodyEncoding::Utf8
        } else {
            BodyEncoding::Base64
        };

        let host = host.into();
        let mut headers = header_records_for_decoded_body(headers, content_decoded);
        // HTTP/2 sends the host as the :authority pseudo-header which hyper
        // places in the URI authority rather than in the headers map.  Ensure a
        // Host header is always present so match-replace rules and UI display
        // work consistently.
        if !headers.iter().any(|h| h.name.eq_ignore_ascii_case("host")) && !host.is_empty() {
            headers.insert(
                0,
                HeaderRecord {
                    name: "host".to_string(),
                    value: host.clone(),
                },
            );
        }

        Self {
            scheme: scheme.into(),
            host,
            method: method.into(),
            path: path.into(),
            headers,
            body: match body_encoding {
                BodyEncoding::Utf8 => String::from_utf8_lossy(body_ref).into_owned(),
                BodyEncoding::Base64 => STANDARD.encode(body_ref),
            },
            body_encoding,
            preview_truncated: false,
        }
    }

    pub fn from_message_record(
        scheme: impl Into<String>,
        host: impl Into<String>,
        method: impl Into<String>,
        path: impl Into<String>,
        message: &MessageRecord,
    ) -> Self {
        Self {
            scheme: scheme.into(),
            host: host.into(),
            method: method.into(),
            path: path.into(),
            headers: header_records_from_message(message),
            body: message.body_preview.clone(),
            body_encoding: message.body_encoding.clone(),
            preview_truncated: message.preview_truncated,
        }
    }

    pub fn body_bytes(&self) -> Vec<u8> {
        self.try_body_bytes().unwrap_or_default()
    }

    pub fn try_body_bytes(&self) -> Result<Vec<u8>, base64::DecodeError> {
        match self.body_encoding {
            BodyEncoding::Utf8 => Ok(self.body.as_bytes().to_vec()),
            BodyEncoding::Base64 => STANDARD.decode(self.body.as_bytes()),
        }
    }

    pub fn content_type(&self) -> Option<String> {
        self.headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case("content-type"))
            .map(|header| header.value.clone())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageRecord {
    #[serde(default)]
    pub headers: Vec<HeaderRecord>,
    #[serde(default)]
    pub body_preview: String,
    #[serde(default)]
    pub body_encoding: BodyEncoding,
    #[serde(default)]
    pub body_size: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decoded_body_size: Option<usize>,
    #[serde(default)]
    pub preview_truncated: bool,
    pub content_type: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub content_decoded: bool,
}

impl MessageRecord {
    pub fn from_headers_and_body(headers: &HeaderMap, body: &[u8], max_preview: usize) -> Self {
        let content_type = headers
            .get(http::header::CONTENT_TYPE)
            .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned());

        // Decompress body based on Content-Encoding header
        let decoded_body = decode_content_encoding(headers, body);
        let content_decoded = decoded_body.is_some();
        let body_ref = decoded_body.as_deref().unwrap_or(body);
        let original_size = body.len();
        let decoded_body_size = decoded_body.as_ref().map(|body| body.len());

        let preview_len = max_preview.min(body_ref.len());
        let preview_bytes = &body_ref[..preview_len];
        let preview_truncated = body_ref.len() > max_preview;
        let textual =
            is_textual_body_preview(content_type.as_deref(), preview_bytes, preview_truncated);
        let preview_bytes = if textual {
            &preview_bytes[..utf8_preview_len(preview_bytes)]
        } else {
            preview_bytes
        };
        let body_preview = if textual {
            String::from_utf8_lossy(preview_bytes).into_owned()
        } else {
            STANDARD.encode(preview_bytes)
        };

        Self {
            headers: header_records(headers),
            body_preview,
            body_encoding: if textual {
                BodyEncoding::Utf8
            } else {
                BodyEncoding::Base64
            },
            body_size: original_size,
            decoded_body_size,
            preview_truncated,
            content_type,
            content_decoded,
        }
    }

    pub fn body_bytes(&self) -> Vec<u8> {
        match self.body_encoding {
            BodyEncoding::Utf8 => self.body_preview.as_bytes().to_vec(),
            BodyEncoding::Base64 => STANDARD
                .decode(self.body_preview.as_bytes())
                .unwrap_or_default(),
        }
    }

    pub fn header_value(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case(name))
            .map(|header| header.value.as_str())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionRecord {
    pub id: Uuid,
    pub started_at: DateTime<Utc>,
    #[serde(default)]
    pub kind: TrafficKind,
    /// Stable capture sequence number (1-based, monotonically increasing).
    #[serde(default)]
    pub sequence: u64,
    pub method: String,
    pub scheme: String,
    pub host: String,
    pub path: String,
    pub status: Option<u16>,
    #[serde(default)]
    pub duration_ms: u64,
    pub request: MessageRecord,
    pub response: Option<MessageRecord>,
    #[serde(default)]
    pub notes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub color_tag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_note: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_request: Option<MessageRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_response: Option<MessageRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_version: Option<String>,
}

impl TransactionRecord {
    pub fn http(
        started_at: DateTime<Utc>,
        method: String,
        scheme: String,
        host: String,
        path: String,
        status: Option<u16>,
        duration_ms: u64,
        request: MessageRecord,
        response: Option<MessageRecord>,
        notes: Vec<String>,
        original_request: Option<MessageRecord>,
        original_response: Option<MessageRecord>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            started_at,
            kind: TrafficKind::Http,
            sequence: 0,
            method,
            scheme,
            host,
            path,
            status,
            duration_ms,
            request,
            response,
            notes,
            color_tag: None,
            user_note: None,
            original_request,
            original_response,
            http_version: None,
        }
    }

    pub fn with_http_version(mut self, version: http::Version) -> Self {
        self.http_version = Some(format_http_version(version));
        self
    }

    pub fn with_response(mut self, response: MessageRecord) -> Self {
        self.response = Some(response);
        self
    }

    pub fn tunnel(
        started_at: DateTime<Utc>,
        host: String,
        status: Option<u16>,
        duration_ms: u64,
        request: MessageRecord,
        notes: Vec<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            started_at,
            kind: TrafficKind::Tunnel,
            sequence: 0,
            method: "CONNECT".to_string(),
            scheme: "tcp".to_string(),
            host,
            path: String::new(),
            status,
            duration_ms,
            request,
            response: None,
            notes,
            color_tag: None,
            user_note: None,
            original_request: None,
            original_response: None,
            http_version: None,
        }
    }

    pub fn summary(&self) -> TransactionSummary {
        TransactionSummary {
            id: self.id,
            started_at: self.started_at,
            kind: self.kind.clone(),
            sequence: self.sequence,
            method: self.method.clone(),
            scheme: self.scheme.clone(),
            host: self.host.clone(),
            path: self.path.clone(),
            status: self.status,
            duration_ms: self.duration_ms,
            request_bytes: self.request.body_size,
            response_bytes: self
                .response
                .as_ref()
                .map_or(0, |response| response.body_size),
            note_count: self.notes.len(),
            has_response: self.response.is_some(),
            content_type: self
                .response
                .as_ref()
                .and_then(|message| message.content_type.clone())
                .or_else(|| self.request.content_type.clone()),
            is_websocket: self.is_websocket(),
            has_match_replace: self.original_request.is_some() || self.original_response.is_some(),
            color_tag: self.color_tag.clone(),
            has_user_note: self.user_note.is_some(),
        }
    }

    pub fn editable_request(&self) -> EditableRequest {
        EditableRequest::from_message_record(
            self.scheme.clone(),
            self.host.clone(),
            self.method.clone(),
            self.path.clone(),
            &self.request,
        )
    }

    pub fn is_websocket(&self) -> bool {
        self.status == Some(101)
            || self
                .request
                .header_value("upgrade")
                .map(|value| value.eq_ignore_ascii_case("websocket"))
                .unwrap_or(false)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionSummary {
    pub id: Uuid,
    pub started_at: DateTime<Utc>,
    pub kind: TrafficKind,
    #[serde(default)]
    pub sequence: u64,
    pub method: String,
    pub scheme: String,
    pub host: String,
    pub path: String,
    pub status: Option<u16>,
    pub duration_ms: u64,
    pub request_bytes: usize,
    pub response_bytes: usize,
    pub note_count: usize,
    pub has_response: bool,
    pub content_type: Option<String>,
    pub is_websocket: bool,
    #[serde(default)]
    pub has_match_replace: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub color_tag: Option<String>,
    #[serde(default)]
    pub has_user_note: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebSocketFrameDirection {
    ClientToServer,
    ServerToClient,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebSocketFrameKind {
    Text,
    Binary,
    Ping,
    Pong,
    Close,
    Other,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WebSocketFrameRecord {
    #[serde(default)]
    pub index: usize,
    pub captured_at: DateTime<Utc>,
    pub direction: WebSocketFrameDirection,
    pub kind: WebSocketFrameKind,
    #[serde(default)]
    pub body_preview: String,
    #[serde(default)]
    pub body_encoding: BodyEncoding,
    #[serde(default)]
    pub body_size: usize,
    #[serde(default)]
    pub preview_truncated: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WebSocketSessionRecord {
    pub id: Uuid,
    pub started_at: DateTime<Utc>,
    pub closed_at: Option<DateTime<Utc>>,
    pub duration_ms: Option<u64>,
    pub scheme: String,
    pub host: String,
    pub path: String,
    pub status: Option<u16>,
    pub request: MessageRecord,
    pub response: Option<MessageRecord>,
    #[serde(default)]
    pub frames: Vec<WebSocketFrameRecord>,
    #[serde(default)]
    pub notes: Vec<String>,
}

impl WebSocketSessionRecord {
    pub fn summary(&self) -> WebSocketSessionSummary {
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
            note_count: self.notes.len(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WebSocketSessionSummary {
    pub id: Uuid,
    pub started_at: DateTime<Utc>,
    pub closed_at: Option<DateTime<Utc>>,
    pub duration_ms: Option<u64>,
    pub scheme: String,
    pub host: String,
    pub path: String,
    pub status: Option<u16>,
    pub frame_count: usize,
    pub note_count: usize,
}

pub fn format_http_version(version: http::Version) -> String {
    match version {
        http::Version::HTTP_09 => "HTTP/0.9".to_string(),
        http::Version::HTTP_10 => "HTTP/1.0".to_string(),
        http::Version::HTTP_11 => "HTTP/1.1".to_string(),
        http::Version::HTTP_2 => "HTTP/2".to_string(),
        http::Version::HTTP_3 => "HTTP/3".to_string(),
        _ => format!("{version:?}"),
    }
}

fn header_records(headers: &HeaderMap) -> Vec<HeaderRecord> {
    headers
        .iter()
        .map(|(name, value)| HeaderRecord {
            name: name.as_str().to_string(),
            value: String::from_utf8_lossy(value.as_bytes()).into_owned(),
        })
        .collect()
}

fn header_records_for_decoded_body(
    headers: &HeaderMap,
    content_decoded: bool,
) -> Vec<HeaderRecord> {
    let records = header_records(headers);
    if content_decoded {
        sanitize_decoded_body_headers(records)
    } else {
        records
    }
}

fn header_records_from_message(message: &MessageRecord) -> Vec<HeaderRecord> {
    if message.content_decoded {
        sanitize_decoded_body_headers(message.headers.clone())
    } else {
        message.headers.clone()
    }
}

fn sanitize_decoded_body_headers(headers: Vec<HeaderRecord>) -> Vec<HeaderRecord> {
    headers
        .into_iter()
        .filter(|header| {
            !header.name.eq_ignore_ascii_case("content-encoding")
                && !header.name.eq_ignore_ascii_case("content-length")
        })
        .collect()
}

fn is_false(value: &bool) -> bool {
    !*value
}

pub(crate) fn decode_content_encoding(headers: &HeaderMap, body: &[u8]) -> Option<Vec<u8>> {
    if body.is_empty() {
        return None;
    }
    let encodings = headers
        .get(http::header::CONTENT_ENCODING)?
        .to_str()
        .ok()?
        .split(',')
        .map(|encoding| encoding.trim().to_ascii_lowercase())
        .filter(|encoding| !encoding.is_empty())
        .collect::<Vec<_>>();
    if encodings.is_empty() {
        return None;
    }

    let mut decoded = body.to_vec();
    for encoding in encodings.iter().rev() {
        decoded = decode_single_content_encoding(encoding, &decoded)?;
    }

    Some(decoded)
}

fn decode_single_content_encoding(encoding: &str, body: &[u8]) -> Option<Vec<u8>> {
    match encoding {
        "gzip" | "x-gzip" => {
            use std::io::Read;
            let mut decoder = flate2::read::GzDecoder::new(body);
            let mut out = Vec::new();
            decoder.read_to_end(&mut out).ok()?;
            Some(out)
        }
        "deflate" => {
            use std::io::Read;
            let mut zlib_decoder = flate2::read::ZlibDecoder::new(body);
            let mut out = Vec::new();
            if zlib_decoder.read_to_end(&mut out).is_ok() {
                return Some(out);
            }
            let mut raw_decoder = flate2::read::DeflateDecoder::new(body);
            let mut out = Vec::new();
            raw_decoder.read_to_end(&mut out).ok()?;
            Some(out)
        }
        "br" => {
            let mut out = Vec::new();
            brotli::BrotliDecompress(&mut std::io::Cursor::new(body), &mut out).ok()?;
            Some(out)
        }
        "zstd" | "zstandard" => zstd::decode_all(std::io::Cursor::new(body)).ok(),
        _ => None,
    }
}

fn is_textual_body(content_type: Option<&str>, sample: &[u8]) -> bool {
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

fn is_textual_body_preview(content_type: Option<&str>, sample: &[u8], truncated: bool) -> bool {
    if sample.is_empty() {
        return true;
    }

    let valid_utf8 = match std::str::from_utf8(sample) {
        Ok(_) => true,
        Err(error) if truncated && error.error_len().is_none() => !sample.contains(&0),
        Err(_) => false,
    };

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

fn utf8_preview_len(sample: &[u8]) -> usize {
    match std::str::from_utf8(sample) {
        Ok(_) => sample.len(),
        Err(error) if error.error_len().is_none() => error.valid_up_to(),
        Err(_) => sample.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{
        write::{GzEncoder, ZlibEncoder},
        Compression,
    };
    use http::header::{CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE};
    use std::io::Write;

    fn gzip(body: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(body).unwrap();
        encoder.finish().unwrap()
    }

    fn zlib_deflate(body: &[u8]) -> Vec<u8> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(body).unwrap();
        encoder.finish().unwrap()
    }

    fn compressed_headers(compressed_len: usize) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, "application/json".parse().unwrap());
        headers.insert(CONTENT_ENCODING, "gzip".parse().unwrap());
        headers.insert(CONTENT_LENGTH, compressed_len.to_string().parse().unwrap());
        headers
    }

    #[test]
    fn message_record_decodes_gzip_preview_but_keeps_wire_size() {
        let raw = br#"{"ok":true}"#;
        let compressed = gzip(raw);
        let headers = compressed_headers(compressed.len());

        let record = MessageRecord::from_headers_and_body(&headers, &compressed, 1024);

        assert_eq!(record.body_preview, String::from_utf8_lossy(raw));
        assert_eq!(record.body_encoding, BodyEncoding::Utf8);
        assert_eq!(record.body_size, compressed.len());
        assert_eq!(record.decoded_body_size, Some(raw.len()));
        assert!(!record.preview_truncated);
        assert!(record.content_decoded);
    }

    #[test]
    fn message_record_decodes_zlib_wrapped_deflate() {
        let raw = br#"{"ok":"deflate"}"#;
        let compressed = zlib_deflate(raw);
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, "application/json".parse().unwrap());
        headers.insert(CONTENT_ENCODING, "deflate".parse().unwrap());
        headers.insert(
            CONTENT_LENGTH,
            compressed.len().to_string().parse().unwrap(),
        );

        let record = MessageRecord::from_headers_and_body(&headers, &compressed, 1024);

        assert_eq!(record.body_preview, String::from_utf8_lossy(raw));
        assert_eq!(record.body_size, compressed.len());
        assert_eq!(record.decoded_body_size, Some(raw.len()));
        assert!(record.content_decoded);
    }

    #[test]
    fn message_record_decodes_stacked_content_encodings() {
        let raw = br#"{"ok":"stacked"}"#;
        let compressed = gzip(&gzip(raw));
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, "application/json".parse().unwrap());
        headers.insert(CONTENT_ENCODING, "gzip, gzip".parse().unwrap());
        headers.insert(
            CONTENT_LENGTH,
            compressed.len().to_string().parse().unwrap(),
        );

        let record = MessageRecord::from_headers_and_body(&headers, &compressed, 1024);

        assert_eq!(record.body_preview, String::from_utf8_lossy(raw));
        assert_eq!(record.body_size, compressed.len());
        assert_eq!(record.decoded_body_size, Some(raw.len()));
        assert!(record.content_decoded);
    }

    #[test]
    fn message_record_text_preview_does_not_split_utf8_codepoint() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, "text/plain".parse().unwrap());

        let record = MessageRecord::from_headers_and_body(&headers, "ab😀cd".as_bytes(), 4);

        assert_eq!(record.body_preview, "ab");
        assert_eq!(record.body_encoding, BodyEncoding::Utf8);
        assert!(record.preview_truncated);
    }

    #[test]
    fn message_record_accepts_legacy_missing_body_metadata() {
        let record: MessageRecord = serde_json::from_value(serde_json::json!({
            "headers": [{ "name": "host", "value": "example.com" }]
        }))
        .expect("legacy message record should deserialize");

        assert_eq!(record.body_preview, "");
        assert_eq!(record.body_encoding, BodyEncoding::Utf8);
        assert_eq!(record.body_size, 0);
        assert_eq!(record.decoded_body_size, None);
        assert!(!record.preview_truncated);
        assert_eq!(record.header_value("host"), Some("example.com"));
    }

    #[test]
    fn websocket_record_accepts_legacy_missing_collections_and_frame_metadata() {
        let record: WebSocketSessionRecord = serde_json::from_value(serde_json::json!({
            "id": "00000000-0000-0000-0000-00000000f001",
            "started_at": "2026-01-01T00:00:00Z",
            "scheme": "wss",
            "host": "socket.example.com",
            "path": "/stream",
            "request": { "headers": [] },
            "frames": [{
                "captured_at": "2026-01-01T00:00:01Z",
                "direction": "server_to_client",
                "kind": "text"
            }]
        }))
        .expect("legacy websocket session should deserialize");

        assert!(record.notes.is_empty());
        assert_eq!(record.summary().frame_count, 1);
        let frame = &record.frames[0];
        assert_eq!(frame.index, 0);
        assert_eq!(frame.body_preview, "");
        assert_eq!(frame.body_encoding, BodyEncoding::Utf8);
        assert_eq!(frame.body_size, 0);
        assert!(!frame.preview_truncated);
    }

    #[test]
    fn transaction_record_accepts_legacy_missing_kind_duration_and_notes() {
        let record: TransactionRecord = serde_json::from_value(serde_json::json!({
            "id": "00000000-0000-0000-0000-00000000b001",
            "started_at": "2026-01-01T00:00:00Z",
            "method": "GET",
            "scheme": "https",
            "host": "example.com",
            "path": "/legacy",
            "status": 200,
            "request": {
                "headers": [{ "name": "host" }],
                "body_preview": "",
                "body_encoding": "utf8"
            }
        }))
        .expect("legacy transaction record should deserialize");

        assert!(matches!(record.kind, TrafficKind::Http));
        assert_eq!(record.duration_ms, 0);
        assert!(record.notes.is_empty());
        assert_eq!(record.summary().note_count, 0);
        assert_eq!(record.request.header_value("host"), Some(""));
    }

    #[test]
    fn editable_request_from_compressed_body_sanitizes_decoded_entity_headers() {
        let raw = br#"{"ok":true}"#;
        let compressed = gzip(raw);
        let headers = compressed_headers(compressed.len());

        let request = EditableRequest::from_headers_and_body(
            "https",
            "example.com",
            "POST",
            "/submit",
            &headers,
            &compressed,
        );

        assert_eq!(request.body, String::from_utf8_lossy(raw));
        assert!(request
            .headers
            .iter()
            .all(|h| !h.name.eq_ignore_ascii_case("content-encoding")));
        assert!(request
            .headers
            .iter()
            .all(|h| !h.name.eq_ignore_ascii_case("content-length")));
    }

    #[test]
    fn editable_request_from_decoded_message_sanitizes_entity_headers() {
        let raw = br#"{"ok":true}"#;
        let compressed = gzip(raw);
        let headers = compressed_headers(compressed.len());
        let message = MessageRecord::from_headers_and_body(&headers, &compressed, 1024);

        let request = EditableRequest::from_message_record(
            "https",
            "example.com",
            "POST",
            "/submit",
            &message,
        );

        assert_eq!(request.body, String::from_utf8_lossy(raw));
        assert!(request
            .headers
            .iter()
            .all(|h| !h.name.eq_ignore_ascii_case("content-encoding")));
        assert!(request
            .headers
            .iter()
            .all(|h| !h.name.eq_ignore_ascii_case("content-length")));
    }

    #[test]
    fn editable_request_preserves_invalid_utf8_text_body_as_base64() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, "text/plain".parse().unwrap());

        let request = EditableRequest::from_headers_and_body(
            "https",
            "example.com",
            "POST",
            "/upload",
            &headers,
            &[0xff],
        );

        assert_eq!(request.body_encoding, BodyEncoding::Base64);
        assert_eq!(request.try_body_bytes().unwrap(), vec![0xff]);
    }

    #[test]
    fn editable_response_preserves_invalid_utf8_text_body_as_base64() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, "text/plain".parse().unwrap());

        let response = EditableResponse::from_status_headers_body(200, &headers, &[0xff]);

        assert_eq!(response.body_encoding, BodyEncoding::Base64);
        assert_eq!(response.try_body_bytes().unwrap(), vec![0xff]);
    }

    #[test]
    fn editable_response_from_compressed_body_sanitizes_decoded_entity_headers() {
        let raw = br#"{"ok":true}"#;
        let compressed = gzip(raw);
        let headers = compressed_headers(compressed.len());

        let response = EditableResponse::from_status_headers_body(200, &headers, &compressed);

        assert_eq!(response.body, String::from_utf8_lossy(raw));
        assert!(response
            .headers
            .iter()
            .all(|h| !h.name.eq_ignore_ascii_case("content-encoding")));
        assert!(response
            .headers
            .iter()
            .all(|h| !h.name.eq_ignore_ascii_case("content-length")));
    }
}
