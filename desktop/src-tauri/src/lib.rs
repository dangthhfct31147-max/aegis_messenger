//! Aegis Messenger — Tauri Desktop Application Backend

use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use tauri::State;
use tracing_subscriber::prelude::*;

mod vault_state;

pub use vault_state::{AppVault, ProxyMode};

// ============================================================================
// Application State
// ============================================================================

pub struct AppState {
    pub vault: Mutex<AppVault>,
    pub server_url: Mutex<String>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            vault: Mutex::new(AppVault::new()),
            server_url: Mutex::new("http://localhost:8080".to_string()),
        }
    }
}

// ============================================================================
// Tauri Commands — Vault
// ============================================================================

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultStatus {
    is_locked: bool,
    auto_lock_seconds: u32,
    records_count: usize,
}

#[tauri::command]
fn vault_status(state: State<AppState>) -> Result<VaultStatus, String> {
    let vault = state.vault.lock().map_err(|e| e.to_string())?;
    Ok(vault.status())
}

#[tauri::command]
fn vault_unlock(passphrase: String, state: State<AppState>) -> Result<(), String> {
    let mut vault = state.vault.lock().map_err(|e| e.to_string())?;
    vault.unlock(&passphrase).map_err(|e| e.to_string())?;
    tracing::info!("Vault unlocked successfully");
    Ok(())
}

#[tauri::command]
fn vault_lock(state: State<AppState>) -> Result<(), String> {
    let mut vault = state.vault.lock().map_err(|e| e.to_string())?;
    vault.lock();
    tracing::info!("Vault locked");
    Ok(())
}

#[tauri::command]
fn vault_create(passphrase: String, state: State<AppState>) -> Result<(), String> {
    let mut vault = state.vault.lock().map_err(|e| e.to_string())?;
    vault.create(&passphrase).map_err(|e| e.to_string())?;
    tracing::info!("Vault created and unlocked");
    Ok(())
}

#[tauri::command]
fn vault_is_initialized(state: State<AppState>) -> Result<bool, String> {
    let vault = state.vault.lock().map_err(|e| e.to_string())?;
    Ok(vault.is_initialized())
}

// ============================================================================
// Tauri Commands — Contacts
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactInfo {
    pub id: String,
    pub display_name: String,
    pub safety_number: String,
    pub pq_status: String,
    pub added_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub id: String,
    pub contact_id: String,
    pub direction: String,
    pub text: String,
    pub created_at: String,
    pub envelope_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub device_id: String,
    pub display_name: String,
    pub revoked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupInfo {
    pub id: String,
    pub name: String,
    pub member_count: usize,
    pub created_at: String,
}

#[tauri::command]
fn list_contacts(state: State<AppState>) -> Result<Vec<ContactInfo>, String> {
    let vault = state.vault.lock().map_err(|e| e.to_string())?;
    vault.list_contacts().map_err(|e| e.to_string())
}

#[tauri::command]
async fn create_invite(display_name: String, state: State<'_, AppState>) -> Result<String, String> {
    let client = transport_client_for_state(&state)?;
    let queue = client.create_queue(None).await.map_err(|e| e.to_string())?;

    let registration = {
        let vault = state.vault.lock().map_err(|e| e.to_string())?;
        let profile = vault
            .ensure_profile(
                &display_name,
                queue.queue_id,
                queue.read_token,
                queue.write_token,
            )
            .map_err(|e| e.to_string())?;
        aegis_protocol::DeviceRegistration {
            account_id: profile.account_id.clone(),
            device_id: profile.device_id.clone(),
            public_id_key: profile.identity_public.to_base64(),
            signed_prekey_public: profile.signed_prekey_public.to_base64(),
            pq_prekey_public: Some(base64_url_encode(&profile.pq_prekey_public)),
            signature: profile.signed_prekey_signature.to_base64(),
            key_version: profile.key_version,
        }
    };

    let registered = client
        .register_device(&registration)
        .await
        .map_err(|e| e.to_string())?;

    let invite = {
        let vault = state.vault.lock().map_err(|e| e.to_string())?;
        let mut profile = vault
            .ensure_profile(&display_name, String::new(), String::new(), String::new())
            .map_err(|e| e.to_string())?;
        profile.account_id = Some(registered.account_id);
        profile.device_id = Some(registered.device_id);
        vault.save_profile(&profile).map_err(|e| e.to_string())?;
        vault.export_invite().map_err(|e| e.to_string())?
    };

    serde_json::to_string_pretty(&invite).map_err(|e| e.to_string())
}

#[tauri::command]
fn import_contact(
    invite_json: String,
    display_name: Option<String>,
    state: State<AppState>,
) -> Result<ContactInfo, String> {
    let vault = state.vault.lock().map_err(|e| e.to_string())?;
    vault
        .import_contact(&invite_json, display_name)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn verify_contact(contact_id: String, state: State<AppState>) -> Result<ContactInfo, String> {
    let vault = state.vault.lock().map_err(|e| e.to_string())?;
    vault.verify_contact(&contact_id).map_err(|e| e.to_string())
}

#[tauri::command]
fn list_messages(contact_id: String, state: State<AppState>) -> Result<Vec<ChatMessage>, String> {
    let vault = state.vault.lock().map_err(|e| e.to_string())?;
    vault.list_messages(&contact_id).map_err(|e| e.to_string())
}

#[tauri::command]
async fn send_message(
    contact_id: String,
    text: String,
    state: State<'_, AppState>,
) -> Result<ChatMessage, String> {
    let client = transport_client_for_state(&state)?;
    let (contact, wire_bytes, message) = {
        let vault = state.vault.lock().map_err(|e| e.to_string())?;
        vault
            .encrypt_outbound_message(&contact_id, &text)
            .map_err(|e| e.to_string())?
    };

    let envelope = client
        .upload_envelope(&contact.queue_id, &contact.write_token, &wire_bytes, 1024)
        .await
        .map_err(|e| e.to_string())?;

    let mut message = message;
    message.envelope_id = Some(envelope.envelope_id);
    let vault = state.vault.lock().map_err(|e| e.to_string())?;
    vault.save_message(message).map_err(|e| e.to_string())
}

#[tauri::command]
async fn poll_messages(state: State<'_, AppState>) -> Result<Vec<ChatMessage>, String> {
    let client = transport_client_for_state(&state)?;
    let (queue_id, read_token, write_token) = {
        let vault = state.vault.lock().map_err(|e| e.to_string())?;
        vault.queue_credentials().map_err(|e| e.to_string())?
    };
    let envelopes = client
        .poll_envelopes(&queue_id, &read_token)
        .await
        .map_err(|e| e.to_string())?;

    let mut received = Vec::new();
    for envelope in envelopes {
        let wire_bytes = base64_url_decode(&envelope.ciphertext_blob).map_err(|e| e.to_string())?;
        let maybe_message = {
            let vault = state.vault.lock().map_err(|e| e.to_string())?;
            vault
                .decrypt_inbound_wire(&wire_bytes, Some(envelope.envelope_id.clone()))
                .map_err(|e| e.to_string())?
        };
        if let Some(message) = maybe_message {
            client
                .ack_envelope(&envelope.envelope_id, &write_token)
                .await
                .map_err(|e| e.to_string())?;
            received.push(message);
        }
    }

    Ok(received)
}

// ============================================================================
// Tauri Commands — Server
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerHealth {
    pub status: String,
    pub version: String,
    pub timestamp: String,
}

#[tauri::command]
async fn server_health(state: State<'_, AppState>) -> Result<ServerHealth, String> {
    let health = transport_client_for_state(&state)?
        .health_check()
        .await
        .map_err(|e| e.to_string())?;
    Ok(ServerHealth {
        status: health.status,
        version: health.version,
        timestamp: health.timestamp,
    })
}

#[tauri::command]
fn set_server_url(url: String, state: State<AppState>) -> Result<(), String> {
    let parsed = reqwest::Url::parse(&url).map_err(|e| format!("invalid url: {e}"))?;
    match parsed.scheme() {
        "http"
            if parsed.host_str() == Some("localhost") || parsed.host_str() == Some("127.0.0.1") => {
        }
        "https" => {}
        _ => return Err("server url must use https, except localhost development".into()),
    }
    let mut server_url = state.server_url.lock().map_err(|e| e.to_string())?;
    *server_url = url.trim_end_matches('/').to_string();
    Ok(())
}

#[tauri::command]
fn set_transport_proxy(
    mode: String,
    proxy_url: Option<String>,
    state: State<AppState>,
) -> Result<serde_json::Value, String> {
    let mode = match mode.as_str() {
        "direct" => ProxyMode::Direct,
        "tor" => ProxyMode::Tor,
        "i2p" => ProxyMode::I2p,
        _ => return Err("unknown proxy mode".into()),
    };
    let vault = state.vault.lock().map_err(|e| e.to_string())?;
    let settings = vault
        .set_proxy(mode, proxy_url)
        .map_err(|e| e.to_string())?;
    serde_json::to_value(settings).map_err(|e| e.to_string())
}

// ============================================================================
// Tauri Commands — Identity
// ============================================================================

#[tauri::command]
fn get_identity_display(state: State<AppState>) -> Result<serde_json::Value, String> {
    let vault = state.vault.lock().map_err(|e| e.to_string())?;
    vault.get_identity_display().map_err(|e| e.to_string())
}

#[tauri::command]
fn enable_hardware_unlock(label: String, state: State<AppState>) -> Result<DeviceInfo, String> {
    let vault = state.vault.lock().map_err(|e| e.to_string())?;
    vault
        .enable_hardware_unlock(label)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn list_devices(state: State<AppState>) -> Result<Vec<DeviceInfo>, String> {
    let vault = state.vault.lock().map_err(|e| e.to_string())?;
    vault.list_devices().map_err(|e| e.to_string())
}

#[tauri::command]
async fn create_device_link_bundle(
    target_device_id: String,
    link_secret: String,
    state: State<'_, AppState>,
) -> Result<aegis_protocol::DeviceLinkBundle, String> {
    let client = transport_client_for_state(&state)?;
    let (account_id, encrypted_payload) = {
        let vault = state.vault.lock().map_err(|e| e.to_string())?;
        let account_id = vault
            .account_id()
            .map_err(|e| e.to_string())?
            .unwrap_or_else(|| base64_url_encode(&[0u8; 32]));
        let payload = vault
            .create_device_sync_bundle(target_device_id.clone(), &link_secret)
            .map_err(|e| e.to_string())?;
        (account_id, payload)
    };
    client
        .submit_device_link_bundle(&aegis_protocol::SubmitDeviceLinkBundle {
            account_id,
            target_device_id,
            encrypted_payload,
            ttl_seconds: Some(600),
        })
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn import_device_link_bundle(
    bundle_id: String,
    link_secret: String,
    state: State<'_, AppState>,
) -> Result<Vec<DeviceInfo>, String> {
    let client = transport_client_for_state(&state)?;
    let bundle = client
        .get_device_link_bundle(&bundle_id)
        .await
        .map_err(|e| e.to_string())?;
    let vault = state.vault.lock().map_err(|e| e.to_string())?;
    vault
        .import_device_sync_bundle(&bundle.encrypted_payload, &link_secret)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn revoke_device(device_id: String, state: State<AppState>) -> Result<Vec<DeviceInfo>, String> {
    let vault = state.vault.lock().map_err(|e| e.to_string())?;
    vault.revoke_device(device_id).map_err(|e| e.to_string())
}

#[tauri::command]
fn set_traffic_privacy_profile(
    mode: String,
    state: State<AppState>,
) -> Result<aegis_protocol::mls::TrafficProfile, String> {
    let mode = match mode.as_str() {
        "direct" => aegis_protocol::mls::TrafficProfileMode::Direct,
        "padded" => aegis_protocol::mls::TrafficProfileMode::Padded,
        "high_privacy" => aegis_protocol::mls::TrafficProfileMode::HighPrivacy,
        _ => return Err("unknown traffic profile".into()),
    };
    let profile = aegis_protocol::mls::TrafficProfile {
        mode,
        ..Default::default()
    };
    let vault = state.vault.lock().map_err(|e| e.to_string())?;
    vault
        .set_traffic_profile(profile)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn create_group(
    name: String,
    member_contact_ids: Vec<String>,
    state: State<AppState>,
) -> Result<GroupInfo, String> {
    let vault = state.vault.lock().map_err(|e| e.to_string())?;
    vault
        .create_group(name, member_contact_ids)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn list_groups(state: State<AppState>) -> Result<Vec<GroupInfo>, String> {
    let vault = state.vault.lock().map_err(|e| e.to_string())?;
    vault.list_groups().map_err(|e| e.to_string())
}

#[tauri::command]
async fn send_group_message(
    group_id: String,
    text: String,
    state: State<'_, AppState>,
) -> Result<Vec<ChatMessage>, String> {
    let client = transport_client_for_state(&state)?;
    let members = {
        let vault = state.vault.lock().map_err(|e| e.to_string())?;
        vault
            .group_member_contacts(&group_id)
            .map_err(|e| e.to_string())?
    };
    let mut sent = Vec::new();
    for member in members {
        let (contact, wire_bytes, mut message) = {
            let vault = state.vault.lock().map_err(|e| e.to_string())?;
            vault
                .encrypt_outbound_message(&member.id, &text)
                .map_err(|e| e.to_string())?
        };
        let envelope = client
            .upload_envelope(&contact.queue_id, &contact.write_token, &wire_bytes, 1024)
            .await
            .map_err(|e| e.to_string())?;
        message.envelope_id = Some(envelope.envelope_id);
        let saved = {
            let vault = state.vault.lock().map_err(|e| e.to_string())?;
            vault.save_message(message).map_err(|e| e.to_string())?
        };
        sent.push(saved);
    }
    Ok(sent)
}

fn current_server_url(state: &State<AppState>) -> Result<String, String> {
    Ok(state
        .server_url
        .lock()
        .map_err(|e| e.to_string())?
        .trim_end_matches('/')
        .to_string())
}

fn transport_client_for_state(
    state: &State<AppState>,
) -> Result<aegis_transport::TransportClient, String> {
    let server_url = current_server_url(state)?;
    let settings = {
        let vault = state.vault.lock().map_err(|e| e.to_string())?;
        vault
            .load_transport_settings()
            .unwrap_or(vault_state::TransportSettings {
                proxy_mode: ProxyMode::Direct,
                proxy_url: None,
            })
    };
    let proxy = match settings.proxy_mode {
        ProxyMode::Direct => None,
        ProxyMode::Tor => Some(
            settings
                .proxy_url
                .unwrap_or_else(|| "socks5h://127.0.0.1:9050".into()),
        ),
        ProxyMode::I2p => Some(
            settings
                .proxy_url
                .unwrap_or_else(|| "http://127.0.0.1:4444".into()),
        ),
    };
    aegis_transport::TransportClient::with_proxy(&server_url, proxy.as_deref())
        .map_err(|e| e.to_string())
}

fn base64_url_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

fn base64_url_decode(data: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(data)
}

// ============================================================================
// Application Entry
// ============================================================================

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "aegis_desktop=info,warn".into()),
        )
        .with(tracing_subscriber::fmt::layer().with_target(false))
        .init();

    tracing::info!("Aegis Messenger starting");

    let app_state = AppState::default();

    tauri::Builder::default()
        .manage(app_state)
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            vault_status,
            vault_unlock,
            vault_lock,
            vault_create,
            vault_is_initialized,
            list_contacts,
            create_invite,
            import_contact,
            verify_contact,
            list_messages,
            send_message,
            poll_messages,
            server_health,
            set_server_url,
            set_transport_proxy,
            get_identity_display,
            enable_hardware_unlock,
            list_devices,
            create_device_link_bundle,
            import_device_link_bundle,
            revoke_device,
            set_traffic_privacy_profile,
            create_group,
            list_groups,
            send_group_message,
        ])
        .setup(|app| {
            tracing::info!("Aegis Messenger setup complete");
            let _ = app;
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running Aegis Messenger");
}
