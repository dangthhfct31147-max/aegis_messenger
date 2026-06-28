//! Server API routes

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use base64::Engine;
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::state::{RelayMode, ServerState};
use crate::crypto::hash_token;
use crate::error::ServerError;

pub type AppState = std::sync::Arc<ServerState>;

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

    let ttl = body.ttl_seconds.unwrap_or(86400);
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
    Json(body): Json<UploadEnvelope>,
) -> Result<impl IntoResponse, ServerError> {
    let envelope_id = aegis_crypto::random::random_32bytes();
    let bucket = current_bucket();

    let queue_id_bytes = base64_url_decode(&body.queue_id_hash)
        .map_err(|_| ServerError::BadRequest("invalid base64".into()))?;
    let queue_id_hash = hash_token(&queue_id_bytes);

    let ciphertext = base64_url_decode(&body.ciphertext_blob)
        .map_err(|_| ServerError::BadRequest("invalid base64".into()))?;

    let ttl = body.ttl_seconds.unwrap_or(3600);
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
    since: Option<String>,
}

async fn poll_envelopes(
    State(state): State<AppState>,
    Query(params): Query<PollParams>,
) -> Result<impl IntoResponse, ServerError> {
    let queue_id_bytes = base64_url_decode(&params.queue)
        .map_err(|_| ServerError::BadRequest("invalid base64".into()))?;
    let queue_id_hash = hash_token(&queue_id_bytes);

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
    Path(envelope_id_b64): Path<String>,
) -> Result<StatusCode, ServerError> {
    let envelope_id_bytes = base64_url_decode(&envelope_id_b64)
        .map_err(|_| ServerError::BadRequest("invalid base64".into()))?;
    let env_id: [u8; 32] = envelope_id_bytes[..32]
        .try_into()
        .map_err(|_| ServerError::BadRequest("invalid id".into()))?;

    state
        .envelopes
        .write()
        .map_err(|e| ServerError::Internal(e.to_string()))?
        .remove(&env_id);

    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
struct RegisterDevice {
    device_public_id_key: String,
    signed_prekey_public: String,
    pq_prekey_public: Option<String>,
    signature: String,
}

#[derive(Debug, Serialize)]
struct DeviceResponse {
    device_id: String,
    key_version: i32,
}

async fn register_device(
    State(state): State<AppState>,
    Path(_account_id): Path<String>,
    Json(body): Json<RegisterDevice>,
) -> Result<impl IntoResponse, ServerError> {
    let device_id = aegis_crypto::random::random_32bytes();
    let bucket = current_bucket();

    let device = crate::state::Device {
        device_id,
        account_id: [0u8; 32],
        public_id_key: base64_url_decode(&body.device_public_id_key).unwrap_or_default(),
        signed_prekey_public: base64_url_decode(&body.signed_prekey_public).unwrap_or_default(),
        pq_prekey_public: body
            .pq_prekey_public
            .as_ref()
            .and_then(|s| base64_url_decode(s).ok()),
        signature: base64_url_decode(&body.signature).unwrap_or_default(),
        key_version: 1,
        created_at_bucket: bucket,
        revoked_at: None,
    };

    state
        .devices
        .write()
        .map_err(|e| ServerError::Internal(e.to_string()))?
        .insert(device_id, device);

    Ok(Json(DeviceResponse {
        device_id: base64_url_encode(&device_id),
        key_version: 1,
    }))
}

async fn get_prekey_bundle(
    State(state): State<AppState>,
    Path(device_id_b64): Path<String>,
) -> Result<impl IntoResponse, ServerError> {
    let device_id_bytes = base64_url_decode(&device_id_b64)
        .map_err(|_| ServerError::BadRequest("invalid".into()))?;
    let device_id: [u8; 32] = device_id_bytes[..32]
        .try_into()
        .map_err(|_| ServerError::BadRequest("invalid".into()))?;

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

pub fn build_router(relay_mode: RelayMode) -> Router {
    let state: AppState = std::sync::Arc::new(ServerState::new(relay_mode));

    Router::new()
        .route("/health", get(health))
        .route("/v1/accounts", post(create_account))
        .route("/v1/queues", post(create_queue))
        .route("/v1/envelopes", post(upload_envelope))
        .route("/v1/envelopes", get(poll_envelopes))
        .route("/v1/prekeys/{device_id}", get(get_prekey_bundle))
        .with_state(state)
}
