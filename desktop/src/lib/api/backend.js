// Aegis Messenger — Tauri Backend API

import { invoke } from '@tauri-apps/api/core';

// Vault Commands
export async function vaultStatus() {
  return invoke('vault_status');
}

/**
 * @param {string} passphrase
 */
export async function vaultUnlock(passphrase) {
  return invoke('vault_unlock', { passphrase });
}

export async function vaultLock() {
  return invoke('vault_lock');
}

/**
 * @param {string} passphrase
 */
export async function vaultCreate(passphrase) {
  return invoke('vault_create', { passphrase });
}

export async function vaultIsInitialized() {
  return invoke('vault_is_initialized');
}

// Contact Commands
export async function listContacts() {
  return invoke('list_contacts');
}

// Server Commands
export async function serverHealth() {
  return invoke('server_health');
}

/**
 * @param {string} url
 */
export async function setServerUrl(url) {
  return invoke('set_server_url', { url });
}

// Identity Commands
export async function getIdentityDisplay() {
  return invoke('get_identity_display');
}
