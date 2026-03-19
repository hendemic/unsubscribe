use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Messages list
// ---------------------------------------------------------------------------

/// Response from GET /gmail/v1/users/me/messages
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessagesListResponse {
    #[serde(default)]
    pub messages: Vec<MessageRef>,
    pub next_page_token: Option<String>,
    pub result_size_estimate: Option<u32>,
}

/// A message reference returned by the list endpoint.
#[derive(Debug, Deserialize)]
pub struct MessageRef {
    pub id: String,
}

// ---------------------------------------------------------------------------
// Message metadata
// ---------------------------------------------------------------------------

/// Response from GET /gmail/v1/users/me/messages/{id}?format=metadata
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageMetadata {
    pub id: String,
    pub payload: Option<MessagePayload>,
    /// Milliseconds since Unix epoch, returned as a string by the Gmail API.
    #[serde(default)]
    pub internal_date: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct MessagePayload {
    #[serde(default)]
    pub headers: Vec<Header>,
}

#[derive(Debug, Deserialize)]
pub struct Header {
    pub name: String,
    pub value: String,
}

impl MessageMetadata {
    /// Find the first header value matching the given name (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.payload.as_ref()?.headers.iter().find_map(|h| {
            h.name.eq_ignore_ascii_case(name).then(|| h.value.as_str())
        })
    }

    /// Returns the message timestamp as Unix seconds, or `None` if not available.
    pub fn timestamp_secs(&self) -> Option<i64> {
        self.internal_date
            .as_deref()
            .and_then(|s| s.parse::<i64>().ok())
            .map(|ms| ms / 1000)
    }
}

// ---------------------------------------------------------------------------
// Batch modify
// ---------------------------------------------------------------------------

/// Request body for POST /gmail/v1/users/me/messages/batchModify
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchModifyRequest {
    pub ids: Vec<String>,
    pub remove_label_ids: Vec<String>,
    pub add_label_ids: Vec<String>,
}

// ---------------------------------------------------------------------------
// Labels
// ---------------------------------------------------------------------------

/// Response from GET /gmail/v1/users/me/labels
#[derive(Debug, Deserialize)]
pub struct LabelsListResponse {
    #[serde(default)]
    pub labels: Vec<LabelRef>,
}

#[derive(Debug, Deserialize)]
pub struct LabelRef {
    pub id: String,
    pub name: String,
}

/// Request body for POST /gmail/v1/users/me/labels
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateLabelRequest {
    pub name: String,
    pub label_list_visibility: &'static str,
    pub message_list_visibility: &'static str,
}

/// Response from POST /gmail/v1/users/me/labels
#[derive(Debug, Deserialize)]
pub struct CreateLabelResponse {
    pub id: String,
}
