//! Server API routes

use axum::{
    extract::{DefaultBodyLimit, Path, Query, State},
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
const MAX_PUBLIC_KEY_BYTES: usize = 2 * 1024;
const ED25519_SIGNATURE_BYTES: usize = 64;
const MAX_DEVICE_LINK_BYTES: usize = 256 * 1024;
const MAX_DEVICE_LINK_TTL_SECONDS: i64 = 10 * 60;

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
    state.save_to_disk().map_err(ServerError::Internal)?;

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
    state.save_to_disk().map_err(ServerError::Internal)?;

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
    #[serde(default)]
    dummy: bool,
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
    cleanup_expired(&state)?;
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

    let default_ttl = match state.relay_mode {
        RelayMode::StrictEphemeral => DEFAULT_ENVELOPE_TTL_SECONDS,
        RelayMode::TtlPersistent { ttl_seconds } => ttl_seconds,
    };
    let ttl = validate_ttl(body.ttl_seconds, default_ttl, MAX_ENVELOPE_TTL_SECONDS)?;
    let expires_at = Utc::now() + chrono::Duration::seconds(ttl);

    let envelope = crate::state::Envelope {
        id: envelope_id,
        queue_id_hash,
        ciphertext,
        padded_size_bucket: body.padded_size_bucket,
        created_at_bucket: bucket,
        expires_at,
        delivery_state: "pending".to_string(),
        is_dummy: body.dummy,
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
    state.save_to_disk().map_err(ServerError::Internal)?;

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
    cleanup_expired(&state)?;
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
    cleanup_expired(&state)?;
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
    state.save_to_disk().map_err(ServerError::Internal)?;

    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
struct RegisterDevice {
    account_id: Option<String>,
    device_id: Option<String>,
    public_id_key: String,
    signed_prekey_public: String,
    pq_prekey_public: Option<String>,
    signature: String,
    key_version: Option<i32>,
}

#[derive(Debug, Serialize)]
struct DeviceResponse {
    account_id: String,
    device_id: String,
    created_at: String,
}

async fn register_device(
    State(state): State<AppState>,
    Json(body): Json<RegisterDevice>,
) -> Result<impl IntoResponse, ServerError> {
    let account_id = match body.account_id {
        Some(account_id) => decode_base64_url_32(&account_id, "account id")?,
        None => aegis_crypto::random::random_32bytes(),
    };
    let device_id = match body.device_id {
        Some(device_id) => decode_base64_url_32(&device_id, "device id")?,
        None => aegis_crypto::random::random_32bytes(),
    };

    let public_id_key = decode_public_material(&body.public_id_key, "public_id_key")?;
    let signed_prekey_public =
        decode_public_material(&body.signed_prekey_public, "signed_prekey_public")?;
    let pq_prekey_public = body
        .pq_prekey_public
        .as_deref()
        .map(|value| decode_public_material(value, "pq_prekey_public"))
        .transpose()?;
    let signature = base64_url_decode(&body.signature)
        .map_err(|_| ServerError::BadRequest("invalid signature base64".into()))?;
    if signature.len() != ED25519_SIGNATURE_BYTES {
        return Err(ServerError::BadRequest("invalid signature length".into()));
    }

    let bucket = current_bucket();
    let device = crate::state::Device {
        device_id,
        account_id,
        public_id_key,
        signed_prekey_public,
        pq_prekey_public,
        signature,
        key_version: body.key_version.unwrap_or(1),
        created_at_bucket: bucket.clone(),
        revoked_at: None,
    };

    let mut devices = state
        .devices
        .write()
        .map_err(|e| ServerError::Internal(e.to_string()))?;
    if devices.contains_key(&device_id) {
        return Err(ServerError::Conflict("device already registered".into()));
    }
    devices.insert(device_id, device);
    drop(devices);
    state.save_to_disk().map_err(ServerError::Internal)?;

    Ok(Json(DeviceResponse {
        account_id: base64_url_encode(&account_id),
        device_id: base64_url_encode(&device_id),
        created_at: bucket,
    }))
}

async fn upload_prekey_bundle(
    State(state): State<AppState>,
    Json(body): Json<RegisterDevice>,
) -> Result<impl IntoResponse, ServerError> {
    register_device(State(state), Json(body)).await
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
    if device.revoked_at.is_some() {
        return Err(ServerError::NotFound);
    }

    Ok(Json(serde_json::json!({
        "account_id": base64_url_encode(&device.account_id),
        "device_id": base64_url_encode(&device.device_id),
        "public_id_key": base64_url_encode(&device.public_id_key),
        "signed_prekey_public": base64_url_encode(&device.signed_prekey_public),
        "pq_prekey_public": device.pq_prekey_public.as_ref().map(|p| base64_url_encode(p)),
        "signature": base64_url_encode(&device.signature),
        "key_version": device.key_version,
        "cipher_suite": 0x0001u16,
        "one_time_prekey": null,
        "created_at_bucket": device.created_at_bucket,
    })))
}

async fn health() -> impl IntoResponse {
    let gates = aegis_protocol::mls::SecurityClaimGates::conservative_default();
    Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "timestamp": Utc::now().to_rfc3339(),
        "security_claim_gates": gates,
    }))
}

#[derive(Debug, Deserialize)]
struct CoverTraffic {
    padding: String,
    padded_size_bucket: i32,
}

async fn cover_traffic(Json(body): Json<CoverTraffic>) -> Result<StatusCode, ServerError> {
    let padding = base64_url_decode(&body.padding)
        .map_err(|_| ServerError::BadRequest("invalid cover padding base64".into()))?;
    if padding.len() > MAX_ENVELOPE_BYTES || body.padded_size_bucket < 0 {
        return Err(ServerError::PayloadTooLarge);
    }
    Err(ServerError::BadRequest(
        "deprecated: send encrypted dummy envelopes through /v1/envelopes".into(),
    ))
}

#[derive(Debug, Deserialize)]
struct PublishDeviceKeyPackage {
    account_id: String,
    device_id: String,
    mls_key_package: String,
    device_list_signature: String,
    key_version: i32,
}

async fn publish_device_key_package(
    State(state): State<AppState>,
    Json(body): Json<PublishDeviceKeyPackage>,
) -> Result<impl IntoResponse, ServerError> {
    let account_id = decode_base64_url_32(&body.account_id, "account id")?;
    let device_id = decode_base64_url_32(&body.device_id, "device id")?;
    let mls_key_package = decode_public_material(&body.mls_key_package, "mls_key_package")?;
    let device_list_signature = base64_url_decode(&body.device_list_signature)
        .map_err(|_| ServerError::BadRequest("invalid device list signature base64".into()))?;
    if device_list_signature.len() != ED25519_SIGNATURE_BYTES {
        return Err(ServerError::BadRequest(
            "invalid device list signature length".into(),
        ));
    }

    let package = crate::state::DeviceKeyPackage {
        account_id,
        device_id,
        mls_key_package,
        device_list_signature,
        key_version: body.key_version,
        created_at_bucket: current_bucket(),
    };
    state
        .device_key_packages
        .write()
        .map_err(|e| ServerError::Internal(e.to_string()))?
        .insert(device_id, package.clone());
    state.save_to_disk().map_err(ServerError::Internal)?;

    Ok(Json(serde_json::json!({
        "account_id": base64_url_encode(&package.account_id),
        "device_id": base64_url_encode(&package.device_id),
        "mls_key_package": base64_url_encode(&package.mls_key_package),
        "device_list_signature": base64_url_encode(&package.device_list_signature),
        "key_version": package.key_version,
        "created_at_bucket": package.created_at_bucket,
    })))
}

async fn get_device_key_package(
    State(state): State<AppState>,
    Path(device_id_b64): Path<String>,
) -> Result<impl IntoResponse, ServerError> {
    let device_id = decode_base64_url_32(&device_id_b64, "device id")?;
    let packages = state
        .device_key_packages
        .read()
        .map_err(|e| ServerError::Internal(e.to_string()))?;
    let package = packages.get(&device_id).ok_or(ServerError::NotFound)?;
    Ok(Json(serde_json::json!({
        "account_id": base64_url_encode(&package.account_id),
        "device_id": base64_url_encode(&package.device_id),
        "mls_key_package": base64_url_encode(&package.mls_key_package),
        "device_list_signature": base64_url_encode(&package.device_list_signature),
        "key_version": package.key_version,
        "created_at_bucket": package.created_at_bucket,
    })))
}

#[derive(Debug, Deserialize)]
struct AppendTransparencyLogEvent {
    account_id: String,
    device_id: String,
    event_type: String,
    event_hash: String,
    prev_hash: String,
    signature: String,
}

async fn append_transparency_log_event(
    State(state): State<AppState>,
    Json(body): Json<AppendTransparencyLogEvent>,
) -> Result<impl IntoResponse, ServerError> {
    let event = crate::state::TransparencyLogEvent {
        event_id: aegis_crypto::random::random_32bytes(),
        account_id: decode_base64_url_32(&body.account_id, "account id")?,
        device_id: decode_base64_url_32(&body.device_id, "device id")?,
        event_type: body.event_type,
        event_hash: base64_url_decode(&body.event_hash)
            .map_err(|_| ServerError::BadRequest("invalid event hash base64".into()))?,
        prev_hash: base64_url_decode(&body.prev_hash)
            .map_err(|_| ServerError::BadRequest("invalid previous hash base64".into()))?,
        signature: base64_url_decode(&body.signature)
            .map_err(|_| ServerError::BadRequest("invalid signature base64".into()))?,
        created_at_bucket: current_bucket(),
    };
    if event.signature.len() != ED25519_SIGNATURE_BYTES {
        return Err(ServerError::BadRequest("invalid signature length".into()));
    }
    state
        .transparency_log
        .write()
        .map_err(|e| ServerError::Internal(e.to_string()))?
        .push(event.clone());
    state.save_to_disk().map_err(ServerError::Internal)?;
    Ok(Json(transparency_event_json(&event)))
}

#[derive(Debug, Deserialize)]
struct TransparencyQuery {
    account_id: String,
}

async fn list_transparency_log_events(
    State(state): State<AppState>,
    Query(params): Query<TransparencyQuery>,
) -> Result<impl IntoResponse, ServerError> {
    let account_id = decode_base64_url_32(&params.account_id, "account id")?;
    let events: Vec<_> = state
        .transparency_log
        .read()
        .map_err(|e| ServerError::Internal(e.to_string()))?
        .iter()
        .filter(|event| event.account_id == account_id)
        .map(transparency_event_json)
        .collect();
    Ok(Json(serde_json::json!({ "events": events })))
}

fn transparency_event_json(event: &crate::state::TransparencyLogEvent) -> serde_json::Value {
    serde_json::json!({
        "event_id": base64_url_encode(&event.event_id),
        "account_id": base64_url_encode(&event.account_id),
        "device_id": base64_url_encode(&event.device_id),
        "event_type": event.event_type,
        "event_hash": base64_url_encode(&event.event_hash),
        "prev_hash": base64_url_encode(&event.prev_hash),
        "signature": base64_url_encode(&event.signature),
        "created_at_bucket": event.created_at_bucket,
    })
}

#[derive(Debug, Deserialize)]
struct SubmitDeviceLinkBundle {
    account_id: String,
    target_device_id: String,
    encrypted_payload: String,
    ttl_seconds: Option<i64>,
}

async fn submit_device_link_bundle(
    State(state): State<AppState>,
    Json(body): Json<SubmitDeviceLinkBundle>,
) -> Result<impl IntoResponse, ServerError> {
    let encrypted_payload = base64_url_decode(&body.encrypted_payload)
        .map_err(|_| ServerError::BadRequest("invalid encrypted payload base64".into()))?;
    if encrypted_payload.is_empty() || encrypted_payload.len() > MAX_DEVICE_LINK_BYTES {
        return Err(ServerError::PayloadTooLarge);
    }
    let ttl = validate_ttl(
        body.ttl_seconds,
        MAX_DEVICE_LINK_TTL_SECONDS,
        MAX_DEVICE_LINK_TTL_SECONDS,
    )?;
    let bundle = crate::state::DeviceLinkBundle {
        bundle_id: aegis_crypto::random::random_32bytes(),
        account_id: decode_base64_url_32(&body.account_id, "account id")?,
        target_device_id: decode_base64_url_32(&body.target_device_id, "target device id")?,
        encrypted_payload,
        created_at_bucket: current_bucket(),
        expires_at: Utc::now() + chrono::Duration::seconds(ttl),
    };
    state
        .device_link_bundles
        .write()
        .map_err(|e| ServerError::Internal(e.to_string()))?
        .insert(bundle.bundle_id, bundle.clone());
    state.save_to_disk().map_err(ServerError::Internal)?;
    Ok(Json(device_link_bundle_json(&bundle)))
}

async fn get_device_link_bundle(
    State(state): State<AppState>,
    Path(bundle_id_b64): Path<String>,
) -> Result<impl IntoResponse, ServerError> {
    cleanup_expired_device_links(&state)?;
    let bundle_id = decode_base64_url_32(&bundle_id_b64, "bundle id")?;
    let bundles = state
        .device_link_bundles
        .read()
        .map_err(|e| ServerError::Internal(e.to_string()))?;
    let bundle = bundles.get(&bundle_id).ok_or(ServerError::NotFound)?;
    Ok(Json(device_link_bundle_json(bundle)))
}

fn device_link_bundle_json(bundle: &crate::state::DeviceLinkBundle) -> serde_json::Value {
    serde_json::json!({
        "bundle_id": base64_url_encode(&bundle.bundle_id),
        "account_id": base64_url_encode(&bundle.account_id),
        "target_device_id": base64_url_encode(&bundle.target_device_id),
        "encrypted_payload": base64_url_encode(&bundle.encrypted_payload),
        "expires_at": bundle.expires_at.to_rfc3339(),
        "created_at_bucket": bundle.created_at_bucket,
    })
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

fn decode_public_material(data: &str, label: &str) -> Result<Vec<u8>, ServerError> {
    let bytes = base64_url_decode(data)
        .map_err(|_| ServerError::BadRequest(format!("invalid {label} base64")))?;
    if bytes.is_empty() || bytes.len() > MAX_PUBLIC_KEY_BYTES {
        return Err(ServerError::BadRequest(format!("invalid {label} length")));
    }
    Ok(bytes)
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

fn cleanup_expired(state: &AppState) -> Result<(), ServerError> {
    let now = Utc::now();
    let expired_ids: Vec<[u8; 32]> = {
        let envelopes = state
            .envelopes
            .read()
            .map_err(|e| ServerError::Internal(e.to_string()))?;
        envelopes
            .iter()
            .filter_map(|(id, env)| (env.expires_at < now).then_some(*id))
            .collect()
    };

    if expired_ids.is_empty() {
        return Ok(());
    }

    {
        let mut envelopes = state
            .envelopes
            .write()
            .map_err(|e| ServerError::Internal(e.to_string()))?;
        for id in &expired_ids {
            envelopes.remove(id);
        }
    }

    let mut queue_envelopes = state
        .queue_envelopes
        .write()
        .map_err(|e| ServerError::Internal(e.to_string()))?;
    for ids in queue_envelopes.values_mut() {
        ids.retain(|id| !expired_ids.contains(id));
    }
    drop(queue_envelopes);
    state.save_to_disk().map_err(ServerError::Internal)?;

    Ok(())
}

fn cleanup_expired_device_links(state: &AppState) -> Result<(), ServerError> {
    let now = Utc::now();
    let expired_ids: Vec<[u8; 32]> = state
        .device_link_bundles
        .read()
        .map_err(|e| ServerError::Internal(e.to_string()))?
        .iter()
        .filter_map(|(id, bundle)| (bundle.expires_at < now).then_some(*id))
        .collect();

    if expired_ids.is_empty() {
        return Ok(());
    }

    let mut bundles = state
        .device_link_bundles
        .write()
        .map_err(|e| ServerError::Internal(e.to_string()))?;
    for id in expired_ids {
        bundles.remove(&id);
    }
    drop(bundles);
    state.save_to_disk().map_err(ServerError::Internal)?;

    Ok(())
}

pub fn build_router(relay_mode: RelayMode) -> Router {
    let state: AppState = std::sync::Arc::new(ServerState::new(relay_mode));
    build_router_with_state(state)
}

pub fn build_router_with_persistence(
    relay_mode: RelayMode,
    persistence_path: std::path::PathBuf,
) -> Router {
    let state: AppState = std::sync::Arc::new(ServerState::new_with_persistence(
        relay_mode,
        persistence_path,
    ));
    build_router_with_state(state)
}

fn build_router_with_state(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/accounts", post(create_account))
        .route("/v1/devices/register", post(register_device))
        .route("/v1/prekeys/upload", post(upload_prekey_bundle))
        .route("/v1/device-key-packages", post(publish_device_key_package))
        .route(
            "/v1/device-key-packages/{device_id}",
            get(get_device_key_package),
        )
        .route("/v1/transparency-log", post(append_transparency_log_event))
        .route("/v1/transparency-log", get(list_transparency_log_events))
        .route("/v1/device-link-bundles", post(submit_device_link_bundle))
        .route(
            "/v1/device-link-bundles/{bundle_id}",
            get(get_device_link_bundle),
        )
        .route("/v1/queues", post(create_queue))
        .route("/v1/cover", post(cover_traffic))
        .route("/v1/envelopes", post(upload_envelope))
        .route("/v1/envelopes", get(poll_envelopes))
        .route("/v1/envelopes/{envelope_id}", delete(ack_envelope))
        .route("/v1/prekeys/{device_id}", get(get_prekey_bundle))
        .layer(DefaultBodyLimit::max(MAX_ENVELOPE_BYTES + 4096))
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
        let app = build_router(RelayMode::StrictEphemeral);
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
        let app = build_router(RelayMode::StrictEphemeral);
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

    #[tokio::test]
    async fn register_device_then_fetch_prekey_bundle() {
        let app = build_router(RelayMode::StrictEphemeral);
        let body = json!({
            "public_id_key": base64_url_encode(&[1u8; 32]),
            "signed_prekey_public": base64_url_encode(&[2u8; 32]),
            "pq_prekey_public": base64_url_encode(&[3u8; 1184]),
            "signature": base64_url_encode(&[4u8; 64]),
            "key_version": 7
        });
        let response = send_json(app.clone(), "POST", "/v1/devices/register", None, body).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let payload: Value = serde_json::from_slice(&body).unwrap();
        let device_id = payload["device_id"].as_str().unwrap();

        let fetched = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/v1/prekeys/{device_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(fetched.status(), StatusCode::OK);
        let body = to_bytes(fetched.into_body(), usize::MAX).await.unwrap();
        let prekey: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(prekey["public_id_key"], base64_url_encode(&[1u8; 32]));
        assert_eq!(
            prekey["signed_prekey_public"],
            base64_url_encode(&[2u8; 32])
        );
        assert_eq!(prekey["key_version"], 7);
    }

    #[tokio::test]
    async fn expired_envelopes_are_removed_on_poll() {
        let app = build_router(RelayMode::TtlPersistent { ttl_seconds: 1 });
        let queue = create_queue(app.clone()).await;
        let queue_id = queue["queue_id"].as_str().unwrap();
        let read_token = queue["read_token"].as_str().unwrap();
        let write_token = queue["write_token"].as_str().unwrap();

        let uploaded = send_json(
            app.clone(),
            "POST",
            "/v1/envelopes",
            Some(write_token),
            json!({
                "queue_id_hash": queue_id,
                "ciphertext_blob": base64_url_encode(b"expires"),
                "padded_size_bucket": 64,
                "ttl_seconds": 1
            }),
        )
        .await;
        assert_eq!(uploaded.status(), StatusCode::OK);

        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

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
        assert!(payload["envelopes"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn ttl_persistent_mode_survives_restart_with_unexpired_ciphertext() {
        let path = std::env::temp_dir().join(format!(
            "aegis-relay-{}.json",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mode = RelayMode::TtlPersistent { ttl_seconds: 60 };
        let app = build_router_with_persistence(mode, path.clone());
        let queue = create_queue(app.clone()).await;
        let queue_id = queue["queue_id"].as_str().unwrap().to_string();
        let read_token = queue["read_token"].as_str().unwrap().to_string();
        let write_token = queue["write_token"].as_str().unwrap().to_string();

        let uploaded = send_json(
            app,
            "POST",
            "/v1/envelopes",
            Some(&write_token),
            json!({
                "queue_id_hash": queue_id,
                "ciphertext_blob": base64_url_encode(b"persisted-ciphertext"),
                "padded_size_bucket": 64,
                "ttl_seconds": 60
            }),
        )
        .await;
        assert_eq!(uploaded.status(), StatusCode::OK);

        let restarted = build_router_with_persistence(mode, path.clone());
        let poll = restarted
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

        std::fs::remove_file(path).ok();
    }

    #[tokio::test]
    async fn deprecated_cover_endpoint_tells_clients_to_use_dummy_envelopes() {
        let app = build_router(RelayMode::StrictEphemeral);
        let response = send_json(
            app,
            "POST",
            "/v1/cover",
            None,
            json!({
                "padding": base64_url_encode(&[9u8; 1024]),
                "padded_size_bucket": 1024
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn dummy_traffic_uses_the_same_envelope_endpoint_as_real_traffic() {
        let app = build_router(RelayMode::StrictEphemeral);
        let queue = create_queue(app.clone()).await;
        let queue_id = queue["queue_id"].as_str().unwrap();
        let read_token = queue["read_token"].as_str().unwrap();
        let write_token = queue["write_token"].as_str().unwrap();

        let uploaded = send_json(
            app.clone(),
            "POST",
            "/v1/envelopes",
            Some(write_token),
            json!({
                "queue_id_hash": queue_id,
                "ciphertext_blob": base64_url_encode(&[7u8; 1024]),
                "padded_size_bucket": 1024,
                "dummy": true
            }),
        )
        .await;
        assert_eq!(uploaded.status(), StatusCode::OK);

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
    async fn device_key_package_transparency_and_link_bundle_round_trip() {
        let app = build_router(RelayMode::StrictEphemeral);
        let account_id = base64_url_encode(&[1u8; 32]);
        let device_id = base64_url_encode(&[2u8; 32]);

        let package = send_json(
            app.clone(),
            "POST",
            "/v1/device-key-packages",
            None,
            json!({
                "account_id": account_id,
                "device_id": device_id,
                "mls_key_package": base64_url_encode(b"mls-key-package"),
                "device_list_signature": base64_url_encode(&[3u8; 64]),
                "key_version": 1
            }),
        )
        .await;
        assert_eq!(package.status(), StatusCode::OK);

        let fetched = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/v1/device-key-packages/{device_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(fetched.status(), StatusCode::OK);

        let event = send_json(
            app.clone(),
            "POST",
            "/v1/transparency-log",
            None,
            json!({
                "account_id": account_id,
                "device_id": device_id,
                "event_type": "device_add",
                "event_hash": base64_url_encode(&[4u8; 32]),
                "prev_hash": base64_url_encode(&[0u8; 32]),
                "signature": base64_url_encode(&[5u8; 64])
            }),
        )
        .await;
        assert_eq!(event.status(), StatusCode::OK);

        let log = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/v1/transparency-log?account_id={account_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(log.status(), StatusCode::OK);

        let bundle = send_json(
            app,
            "POST",
            "/v1/device-link-bundles",
            None,
            json!({
                "account_id": account_id,
                "target_device_id": device_id,
                "encrypted_payload": base64_url_encode(b"encrypted-device-state"),
                "ttl_seconds": 60
            }),
        )
        .await;
        assert_eq!(bundle.status(), StatusCode::OK);
    }
}
