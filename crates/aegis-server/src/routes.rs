//! Server API routes

use axum::{
    extract::{Path, Query, State},
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use base64::Engine;
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::crypto::{constant_time_eq, hash_token};
use crate::error::ServerError;
use crate::state::{RelayMode, ServerState};

pub type AppState = std::sync::Arc<ServerState>;

const DEFAULT_QUEUE_TTL_SECONDS: i64 = 86_400;
const DEFAULT_ENVELOPE_TTL_SECONDS: i64 = 3_600;
const MAX_QUEUE_TTL_SECONDS: i64 = 7 * 24 * 60 * 60;
const MAX_ENVELOPE_TTL_SECONDS: i64 = 7 * 24 * 60 * 60;
const MAX_ENVELOPE_BYTES: usize = 1024 * 1024;

fn current_bucket() -> String {
    let now = Utc::now();
    format!(
        "{:04}-{:02}-{:02}T{:02}:00:00Z",
        now.format("%Y"),
        now.format("%m"),
        now.format("%d"),
        now.format("%H")
    )
}

#[derive(Debug, Deserialize)]
struct CreateAccount {
    #[serde(default)]
    public_metadata: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct AccountResponse {
    account_id: String,
    created_at: String,
}

async fn create_account(
    State(state): State<AppState>,
    Json(body): Json<CreateAccount>,
) -> Result<impl IntoResponse, ServerError> {
    let account_id = aegis_crypto::random::random_32bytes();
    let bucket = current_bucket();

    let account = crate::state::Account {
        account_id,
        created_at_bucket: bucket.clone(),
        public_metadata: body.public_metadata.unwrap_or(serde_json::json!({})),
    };

    state
        .accounts
        .write()
        .map_err(|e| ServerError::Internal(e.to_string()))?
        .insert(account_id, account);

    Ok(Json(AccountResponse {
        account_id: base64_url_encode(&account_id),
        created_at: bucket,
    }))
}

#[derive(Debug, Deserialize)]
struct CreateQueue {
    ttl_seconds: Option<i64>,
}

#[derive(Debug, Serialize)]
struct QueueResponse {
    queue_id: String,
    read_token: String,
    write_token: String,
    expires_at: String,
}

async fn create_queue(
    State(state): State<AppState>,
    Json(body): Json<CreateQueue>,
) -> Result<impl IntoResponse, ServerError> {
    let queue_id = aegis_crypto::random::random_32bytes();
    let read_token = aegis_crypto::random::random_32bytes();
    let write_token = aegis_crypto::random::random_32bytes();
    let account_id = aegis_crypto::random::random_32bytes();

    let ttl = validate_ttl(
        body.ttl_seconds,
        DEFAULT_QUEUE_TTL_SECONDS,
        MAX_QUEUE_TTL_SECONDS,
    )?;
    let expires_at = Utc::now() + chrono::Duration::seconds(ttl);

    let queue = crate::state::Queue {
        id_hash: hash_token(&queue_id),
        read_cap_hash: hash_token(&read_token),
        write_cap_hash: hash_token(&write_token),
        account_id,
        created_at_bucket: current_bucket(),
        expires_at,
    };

    state
        .queues
        .write()
        .map_err(|e| ServerError::Internal(e.to_string()))?
        .insert(hash_token(&queue_id), queue);

    Ok(Json(QueueResponse {
        queue_id: base64_url_encode(&queue_id),
        read_token: base64_url_encode(&read_token),
        write_token: base64_url_encode(&write_token),
        expires_at: expires_at.to_rfc3339(),
    }))
}

#[derive(Debug, Deserialize)]
struct UploadEnvelope {
    #[serde(alias = "queue_id")]
    queue_id_hash: String,
    ciphertext_blob: String,
    padded_size_bucket: i32,
    ttl_seconds: Option<i64>,
}

#[derive(Debug, Serialize)]
struct EnvelopeResponse {
    envelope_id: String,
    expires_at: String,
}

async fn upload_envelope(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<UploadEnvelope>,
) -> Result<impl IntoResponse, ServerError> {
    let envelope_id = aegis_crypto::random::random_32bytes();
    let bucket = current_bucket();

    let queue_id_bytes = decode_base64_url_32(&body.queue_id_hash, "queue id")?;
    let queue_id_hash = hash_token(&queue_id_bytes);
    authorize_queue_capability(&state, &headers, &queue_id_hash, Capability::Write)?;

    let ciphertext = base64_url_decode(&body.ciphertext_blob)
        .map_err(|_| ServerError::BadRequest("invalid base64".into()))?;
    if ciphertext.len() > MAX_ENVELOPE_BYTES {
        return Err(ServerError::PayloadTooLarge);
    }
    if body.padded_size_bucket < 0 {
        return Err(ServerError::BadRequest("invalid padded size bucket".into()));
    }

    let ttl = validate_ttl(
        body.ttl_seconds,
        DEFAULT_ENVELOPE_TTL_SECONDS,
        MAX_ENVELOPE_TTL_SECONDS,
    )?;
    let expires_at = Utc::now() + chrono::Duration::seconds(ttl);

    let envelope = crate::state::Envelope {
        id: envelope_id,
        queue_id_hash,
        ciphertext,
        padded_size_bucket: body.padded_size_bucket,
        created_at_bucket: bucket,
        expires_at,
        delivery_state: "pending".to_string(),
    };

    let env_id_copy = envelope.id;
    state
        .envelopes
        .write()
        .map_err(|e| ServerError::Internal(e.to_string()))?
        .insert(env_id_copy, envelope);

    state
        .queue_envelopes
        .write()
        .map_err(|e| ServerError::Internal(e.to_string()))?
        .entry(queue_id_hash)
        .or_insert_with(Vec::new)
        .push(env_id_copy);

    Ok(Json(EnvelopeResponse {
        envelope_id: base64_url_encode(&envelope_id),
        expires_at: expires_at.to_rfc3339(),
    }))
}

#[derive(Debug, Deserialize)]
struct PollParams {
    queue: String,
    #[serde(rename = "since")]
    _since: Option<String>,
}

async fn poll_envelopes(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<PollParams>,
) -> Result<impl IntoResponse, ServerError> {
    let queue_id_bytes = decode_base64_url_32(&params.queue, "queue id")?;
    let queue_id_hash = hash_token(&queue_id_bytes);
    authorize_queue_capability(&state, &headers, &queue_id_hash, Capability::Read)?;

    let envelopes_lock = state
        .envelopes
        .read()
        .map_err(|e| ServerError::Internal(e.to_string()))?;
    let queue_env_lock = state
        .queue_envelopes
        .read()
        .map_err(|e| ServerError::Internal(e.to_string()))?;

    let env_ids = queue_env_lock.get(&queue_id_hash);

    let mut result = Vec::new();
    if let Some(ids) = env_ids {
        for id in ids {
            if let Some(env) = envelopes_lock.get(id) {
                if env.expires_at < Utc::now() {
                    continue;
                }
                result.push(serde_json::json!({
                    "envelope_id": base64_url_encode(&env.id),
                    "ciphertext_blob": base64_url_encode(&env.ciphertext),
                    "created_at_bucket": env.created_at_bucket,
                }));
            }
        }
    }

    Ok(Json(serde_json::json!({ "envelopes": result })))
}

async fn ack_envelope(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(envelope_id_b64): Path<String>,
) -> Result<StatusCode, ServerError> {
    let env_id = decode_base64_url_32(&envelope_id_b64, "envelope id")?;

    let queue_id_hash = {
        let envelopes = state
            .envelopes
            .read()
            .map_err(|e| ServerError::Internal(e.to_string()))?;
        let envelope = envelopes.get(&env_id).ok_or(ServerError::NotFound)?;
        if envelope.expires_at < Utc::now() {
            return Err(ServerError::EnvelopeExpired);
        }
        envelope.queue_id_hash
    };
    authorize_queue_capability(&state, &headers, &queue_id_hash, Capability::Write)?;

    state
        .envelopes
        .write()
        .map_err(|e| ServerError::Internal(e.to_string()))?
        .remove(&env_id);

    Ok(StatusCode::NO_CONTENT)
}

async fn get_prekey_bundle(
    State(state): State<AppState>,
    Path(device_id_b64): Path<String>,
) -> Result<impl IntoResponse, ServerError> {
    let device_id = decode_base64_url_32(&device_id_b64, "device id")?;

    let devices = state
        .devices
        .read()
        .map_err(|e| ServerError::Internal(e.to_string()))?;

    let device = devices.get(&device_id).ok_or(ServerError::NotFound)?;

    Ok(Json(serde_json::json!({
        "signed_prekey_public": base64_url_encode(&device.signed_prekey_public),
        "pq_prekey_public": device.pq_prekey_public.as_ref().map(|p| base64_url_encode(p)),
        "signature": base64_url_encode(&device.signature),
    })))
}

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "timestamp": Utc::now().to_rfc3339(),
    }))
}

fn base64_url_encode(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

fn base64_url_decode(data: &str) -> Result<Vec<u8>, ()> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(data)
        .map_err(|_| ())
}

fn decode_base64_url_32(data: &str, label: &str) -> Result<[u8; 32], ServerError> {
    let bytes = base64_url_decode(data)
        .map_err(|_| ServerError::BadRequest(format!("invalid {label} base64")))?;
    bytes
        .try_into()
        .map_err(|_| ServerError::BadRequest(format!("invalid {label} length")))
}

fn validate_ttl(
    requested: Option<i64>,
    default_seconds: i64,
    max_seconds: i64,
) -> Result<i64, ServerError> {
    let ttl = requested.unwrap_or(default_seconds);
    if ttl <= 0 || ttl > max_seconds {
        return Err(ServerError::BadRequest("invalid ttl".into()));
    }
    Ok(ttl)
}

#[derive(Debug, Clone, Copy)]
enum Capability {
    Read,
    Write,
}

fn bearer_token_hash(headers: &HeaderMap) -> Result<[u8; 32], ServerError> {
    let header = headers
        .get(AUTHORIZATION)
        .ok_or(ServerError::Unauthorized)?
        .to_str()
        .map_err(|_| ServerError::InvalidToken)?;
    let token = header
        .strip_prefix("Bearer ")
        .ok_or(ServerError::InvalidToken)?;
    let token_bytes = base64_url_decode(token).map_err(|_| ServerError::InvalidToken)?;
    if token_bytes.len() != 32 {
        return Err(ServerError::InvalidToken);
    }
    Ok(hash_token(&token_bytes))
}

fn authorize_queue_capability(
    state: &AppState,
    headers: &HeaderMap,
    queue_id_hash: &[u8; 32],
    capability: Capability,
) -> Result<(), ServerError> {
    let token_hash = bearer_token_hash(headers)?;
    let queues = state
        .queues
        .read()
        .map_err(|e| ServerError::Internal(e.to_string()))?;
    let queue = queues.get(queue_id_hash).ok_or(ServerError::NotFound)?;
    if queue.expires_at < Utc::now() {
        return Err(ServerError::QueueExpired);
    }
    let expected = match capability {
        Capability::Read => &queue.read_cap_hash,
        Capability::Write => &queue.write_cap_hash,
    };
    if !constant_time_eq(&token_hash, expected) {
        return Err(ServerError::InvalidToken);
    }
    Ok(())
}

pub fn build_router(relay_mode: RelayMode) -> Router {
    let state: AppState = std::sync::Arc::new(ServerState::new(relay_mode));

    Router::new()
        .route("/health", get(health))
        .route("/v1/accounts", post(create_account))
        .route("/v1/queues", post(create_queue))
        .route("/v1/envelopes", post(upload_envelope))
        .route("/v1/envelopes", get(poll_envelopes))
        .route("/v1/envelopes/{envelope_id}", delete(ack_envelope))
        .route("/v1/prekeys/{device_id}", get(get_prekey_bundle))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
    };
    use serde_json::{json, Value};
    use tower::ServiceExt;

    async fn create_queue(app: Router) -> Value {
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/queues")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    async fn send_json(
        app: Router,
        method: &str,
        uri: &str,
        bearer: Option<&str>,
        body: Value,
    ) -> axum::response::Response {
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json");
        if let Some(token) = bearer {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        app.oneshot(builder.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn upload_and_poll_require_matching_queue_capabilities() {
        let app = build_router(RelayMode::Strict);
        let queue = create_queue(app.clone()).await;
        let queue_id = queue["queue_id"].as_str().unwrap();
        let read_token = queue["read_token"].as_str().unwrap();
        let write_token = queue["write_token"].as_str().unwrap();

        let envelope_body = json!({
            "queue_id_hash": queue_id,
            "ciphertext_blob": base64_url_encode(b"ciphertext"),
            "padded_size_bucket": 64
        });

        let missing_auth = send_json(
            app.clone(),
            "POST",
            "/v1/envelopes",
            None,
            envelope_body.clone(),
        )
        .await;
        assert_eq!(missing_auth.status(), StatusCode::UNAUTHORIZED);

        let wrong_capability = send_json(
            app.clone(),
            "POST",
            "/v1/envelopes",
            Some(read_token),
            envelope_body.clone(),
        )
        .await;
        assert_eq!(wrong_capability.status(), StatusCode::FORBIDDEN);

        let uploaded = send_json(
            app.clone(),
            "POST",
            "/v1/envelopes",
            Some(write_token),
            envelope_body,
        )
        .await;
        assert_eq!(uploaded.status(), StatusCode::OK);

        let wrong_poll = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/v1/envelopes?queue={queue_id}"))
                    .header("authorization", format!("Bearer {write_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(wrong_poll.status(), StatusCode::FORBIDDEN);

        let poll = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/v1/envelopes?queue={queue_id}"))
                    .header("authorization", format!("Bearer {read_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(poll.status(), StatusCode::OK);
        let body = to_bytes(poll.into_body(), usize::MAX).await.unwrap();
        let payload: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["envelopes"].as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn short_ids_return_bad_request_instead_of_panicking() {
        let app = build_router(RelayMode::Strict);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/prekeys/abc")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
