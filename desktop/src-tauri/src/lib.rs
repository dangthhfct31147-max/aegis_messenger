//! Aegis Messenger — Tauri Desktop Application Backend

use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use tauri::State;
use tracing_subscriber::prelude::*;

mod vault_state;

pub use vault_state::AppVault;

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
    pub added_at: String,
}

#[tauri::command]
fn list_contacts(state: State<AppState>) -> Result<Vec<ContactInfo>, String> {
    let vault = state.vault.lock().map_err(|e| e.to_string())?;
    vault.list_contacts().map_err(|e| e.to_string())
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
    let server_url = state
        .server_url
        .lock()
        .map_err(|e| e.to_string())?
        .trim_end_matches('/')
        .to_string();
    let url = format!("{server_url}/health");
    let resp = reqwest::get(url)
        .await
        .map_err(|e| format!("connection failed: {}", e))?;
    if !resp.status().is_success() {
        return Err(format!("server returned {}", resp.status()));
    }
    let health: ServerHealth = resp
        .json()
        .await
        .map_err(|e| format!("parse error: {}", e))?;
    Ok(health)
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

// ============================================================================
// Tauri Commands — Identity
// ============================================================================

#[tauri::command]
fn get_identity_display(state: State<AppState>) -> Result<serde_json::Value, String> {
    let vault = state.vault.lock().map_err(|e| e.to_string())?;
    vault.get_identity_display().map_err(|e| e.to_string())
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
            server_health,
            set_server_url,
            get_identity_display,
        ])
        .setup(|app| {
            tracing::info!("Aegis Messenger setup complete");
            let _ = app;
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running Aegis Messenger");
}
