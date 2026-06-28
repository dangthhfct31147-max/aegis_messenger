// Aegis Messenger — App State Store

import { writable, derived } from 'svelte/store';

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
export const selectedContactId = writable(null);

// Contacts
export const contacts = writable([]);

// Messages (per contact)
export const messages = writable({}); // { [contactId]: Message[] }

// Notifications
export const notifications = writable([]);

// Derived
export const isVaultUnlocked = derived(vaultState, ($vault) => !$vault.isLocked);
