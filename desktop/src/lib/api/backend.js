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

/**
 * @param {string} displayName
 */
export async function createInvite(displayName) {
  return invoke('create_invite', { displayName });
}

/**
 * @param {string} inviteJson
 * @param {string | null} [displayName]
 */
export async function importContact(inviteJson, displayName = null) {
  return invoke('import_contact', { inviteJson, displayName });
}

/**
 * @param {string} contactId
 */
export async function verifyContact(contactId) {
  return invoke('verify_contact', { contactId });
}

/**
 * @param {string} contactId
 */
export async function listMessages(contactId) {
  return invoke('list_messages', { contactId });
}

/**
 * @param {string} contactId
 * @param {string} text
 */
export async function sendMessage(contactId, text) {
  return invoke('send_message', { contactId, text });
}

export async function pollMessages() {
  return invoke('poll_messages');
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

/**
 * @param {string} mode
 * @param {string | null} [proxyUrl]
 */
export async function setTransportProxy(mode, proxyUrl = null) {
  return invoke('set_transport_proxy', { mode, proxyUrl });
}

// Identity Commands
export async function getIdentityDisplay() {
  return invoke('get_identity_display');
}

/**
 * @param {string} label
 */
export async function enableHardwareUnlock(label) {
  return invoke('enable_hardware_unlock', { label });
}

/**
 * @param {string} name
 * @param {string[]} memberContactIds
 */
export async function createGroup(name, memberContactIds) {
  return invoke('create_group', { name, memberContactIds });
}

export async function listGroups() {
  return invoke('list_groups');
}

/**
 * @param {string} groupId
 * @param {string} text
 */
export async function sendGroupMessage(groupId, text) {
  return invoke('send_group_message', { groupId, text });
}
