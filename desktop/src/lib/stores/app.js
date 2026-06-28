// Aegis Messenger — App State Store

import { writable, derived } from 'svelte/store';

/**
 * @typedef {{ id: string, display_name: string, safety_number: string, added_at: string }} Contact
 * @typedef {{ id: string, contact_id: string, direction: string, text: string, created_at: string, envelope_id?: string | null }} ChatMessage
 * @typedef {{ id: string, name: string, member_count: number, created_at: string }} GroupInfo
 */

// Vault state
export const vaultState = writable({
  isLocked: true,
  isInitialized: false,
  autoLockSeconds: 300,
  recordsCount: 0,
});

// Connection state
export const serverUrl = writable('http://localhost:8080');
export const serverHealth = writable({ status: 'unknown', version: '', timestamp: '' });

// UI state
export const currentView = writable('unlock'); // 'unlock' | 'setup' | 'conversations' | 'chat' | 'settings'
export const selectedContactId = writable(/** @type {string | null} */ (null));

// Contacts
export const contacts = writable(/** @type {Contact[]} */ ([]));
export const groups = writable(/** @type {GroupInfo[]} */ ([]));

// Messages (per contact)
export const messages = writable(/** @type {Record<string, ChatMessage[]>} */ ({}));

// Notifications
export const notifications = writable([]);

// Derived
export const isVaultUnlocked = derived(vaultState, ($vault) => !$vault.isLocked);
