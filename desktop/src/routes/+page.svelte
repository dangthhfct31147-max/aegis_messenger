<script>
  import { onMount } from 'svelte';
  import {
    vaultState,
    currentView,
    serverHealth,
    contacts,
    selectedContactId,
  } from '$lib/stores/app.js';
  import {
    vaultStatus,
    vaultUnlock,
    vaultLock,
    vaultCreate,
    vaultIsInitialized,
    serverHealth as fetchServerHealth,
  } from '$lib/api/backend.js';

  let passphrase = '';
  let confirmPassphrase = '';
  let error = '';
  let loading = false;
  let initMode = false;

  // Check vault state on mount
  onMount(async () => {
    try {
      const status = await vaultStatus();
      vaultState.set(status);
      if (!status.is_locked) {
        currentView.set('conversations');
      }

      // Check server health
      try {
        const health = await fetchServerHealth();
        serverHealth.set(health);
      } catch {
        serverHealth.set({ status: 'disconnected', version: 'unknown', timestamp: '' });
      }
    } catch (e) {
      error = e.toString();
    }
  });

  async function handleUnlock() {
    if (!passphrase) return;
    error = '';
    loading = true;
    try {
      await vaultUnlock(passphrase);
      vaultState.update((s) => ({ ...s, isLocked: false }));
      currentView.set('conversations');
      passphrase = '';
    } catch (e) {
      error = 'Invalid passphrase. Please try again.';
    } finally {
      loading = false;
    }
  }

  async function handleSetup() {
    if (passphrase.length < 12) {
      error = 'Passphrase must be at least 12 characters.';
      return;
    }
    if (passphrase !== confirmPassphrase) {
      error = 'Passphrases do not match.';
      return;
    }
    error = '';
    loading = true;
    try {
      await vaultCreate(passphrase);
      vaultState.update((s) => ({ ...s, isLocked: false, isInitialized: true }));
      currentView.set('conversations');
      passphrase = '';
      confirmPassphrase = '';
    } catch (e) {
      error = `Setup failed: ${e}`;
    } finally {
      loading = false;
    }
  }

  function handleLock() {
    vaultState.update((s) => ({ ...s, isLocked: true }));
    currentView.set('unlock');
  }
</script>

<div class="app">
  {#if $vaultState.isLocked}
    <!-- Lock Screen -->
    <div class="lock-screen">
      <div class="lock-card">
        <div class="lock-icon">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
            <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
          </svg>
        </div>
        <h1 class="lock-title">Aegis Messenger</h1>
        <p class="lock-subtitle">
          {#if $vaultState.isInitialized}
            Enter your passphrase to unlock your vault
          {:else}
            Create a passphrase to secure your vault
          {/if}
        </p>

        {#if error}
          <div class="error-banner">{error}</div>
        {/if}

        <form on:submit|preventDefault={$vaultState.isInitialized ? handleUnlock : handleSetup}>
          <div class="form-group">
            <input
              type="password"
              bind:value={passphrase}
              placeholder="Passphrase"
              autocomplete="current-password"
              autofocus
            />
          </div>

          {#if !$vaultState.isInitialized}
            <div class="form-group">
              <input
                type="password"
                bind:value={confirmPassphrase}
                placeholder="Confirm passphrase"
                autocomplete="new-password"
              />
            </div>
            <p class="hint">
              Choose a strong passphrase (12+ characters). It cannot be recovered.
            </p>
          {/if}

          <button type="submit" class="btn-primary w-full" disabled={loading}>
            {#if loading}
              {#if $vaultState.isInitialized}
                Unlocking...
              {:else}
                Creating Vault...
              {/if}
            {:else}
              {#if $vaultState.isInitialized}
                Unlock Vault
              {:else}
                Create Vault
              {/if}
            {/if}
          </button>
        </form>

        <div class="lock-footer">
          <div class="server-status">
            <span class="status-dot" class:connected={$serverHealth.status === 'ok'}></span>
            {#if $serverHealth.status === 'ok'}
              Relay online — v{$serverHealth.version}
            {:else}
              Relay offline
            {/if}
          </div>
        </div>
      </div>
    </div>

  {:else}
    <!-- Main App -->
    <div class="app-layout">
      <!-- Sidebar -->
      <aside class="sidebar">
        <div class="sidebar-header">
          <h2 class="sidebar-title">Aegis</h2>
          <button class="btn-ghost btn-icon" on:click={handleLock} title="Lock vault">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
              <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
            </svg>
          </button>
        </div>

        <div class="sidebar-search">
          <input type="text" placeholder="Search conversations..." />
        </div>

        <div class="contact-list">
          {#if $contacts.length === 0}
            <div class="empty-contacts">
              <p>No contacts yet</p>
              <p class="hint">Share your invite link to start chatting</p>
            </div>
          {:else}
            {#each $contacts as contact}
              <button
                class="contact-item"
                class:active={$selectedContactId === contact.id}
                on:click={() => selectedContactId.set(contact.id)}
              >
                <div class="contact-avatar">{contact.display_name[0]?.toUpperCase() || '?'}</div>
                <div class="contact-info">
                  <div class="contact-name">{contact.display_name}</div>
                  <div class="contact-preview truncate">End-to-end encrypted</div>
                </div>
              </button>
            {/each}
          {/if}
        </div>

        <div class="sidebar-footer">
          <button class="btn-ghost w-full" on:click={() => currentView.set('settings')}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <circle cx="12" cy="12" r="3"/>
              <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>
            </svg>
            Settings
          </button>
        </div>
      </aside>

      <!-- Content Area -->
      <main class="content">
        {#if $currentView === 'conversations'}
          <div class="conversations-view">
            <div class="empty-state">
              <div class="empty-icon">
                <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1">
                  <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>
                </svg>
              </div>
              <h2>Your conversations</h2>
              <p class="text-secondary">
                Add a contact to start an encrypted conversation
              </p>
              <button class="btn-primary" on:click={() => {}}>
                Add Contact
              </button>
            </div>
          </div>
        {/if}
      </main>
    </div>
  {/if}
</div>

<style>
  .app {
    height: 100vh;
    display: flex;
    flex-direction: column;
  }

  /* Lock Screen */
  .lock-screen {
    height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    background: var(--bg-primary);
    background-image:
      radial-gradient(ellipse at 50% 0%, rgba(0, 200, 150, 0.06) 0%, transparent 60%);
  }

  .lock-card {
    width: 100%;
    max-width: 400px;
    padding: 48px 40px;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 16px;
    box-shadow: 0 24px 48px rgba(0, 0, 0, 0.4);
  }

  .lock-icon {
    display: flex;
    justify-content: center;
    margin-bottom: 24px;
    color: var(--accent);
  }

  .lock-title {
    font-size: 24px;
    font-weight: 700;
    text-align: center;
    margin-bottom: 8px;
    letter-spacing: -0.5px;
  }

  .lock-subtitle {
    text-align: center;
    color: var(--text-secondary);
    font-size: 13px;
    margin-bottom: 24px;
    line-height: 1.6;
  }

  .error-banner {
    background: var(--danger-dim);
    border: 1px solid rgba(255, 77, 106, 0.3);
    color: var(--danger);
    padding: 10px 14px;
    border-radius: var(--radius);
    font-size: 13px;
    margin-bottom: 16px;
  }

  .form-group {
    margin-bottom: 12px;
  }

  .form-group input {
    width: 100%;
  }

  .hint {
    font-size: 12px;
    color: var(--text-muted);
    margin: 4px 0 16px;
    line-height: 1.5;
  }

  .lock-footer {
    margin-top: 24px;
    padding-top: 16px;
    border-top: 1px solid var(--border);
  }

  .server-status {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 12px;
    color: var(--text-muted);
  }

  .status-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--danger);
    flex-shrink: 0;
  }
  .status-dot.connected {
    background: var(--success);
    box-shadow: 0 0 6px var(--success);
  }

  /* App Layout */
  .app-layout {
    height: 100vh;
    display: flex;
  }

  /* Sidebar */
  .sidebar {
    width: var(--sidebar-width);
    background: var(--bg-secondary);
    border-right: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    flex-shrink: 0;
  }

  .sidebar-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 16px 16px 12px;
    border-bottom: 1px solid var(--border);
  }

  .sidebar-title {
    font-size: 18px;
    font-weight: 700;
    color: var(--accent);
    letter-spacing: -0.3px;
  }

  .btn-icon {
    padding: 8px;
    border-radius: var(--radius-sm);
  }

  .sidebar-search {
    padding: 12px 12px 8px;
  }

  .sidebar-search input {
    width: 100%;
    padding: 8px 12px;
    font-size: 13px;
    border-radius: var(--radius);
    background: var(--bg-tertiary);
    border: 1px solid var(--border);
    color: var(--text-primary);
  }

  .contact-list {
    flex: 1;
    overflow-y: auto;
    padding: 4px 8px;
  }

  .empty-contacts {
    padding: 32px 16px;
    text-align: center;
    color: var(--text-muted);
    font-size: 13px;
  }

  .contact-item {
    width: 100%;
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 10px 8px;
    border-radius: var(--radius);
    background: transparent;
    color: var(--text-primary);
    cursor: pointer;
    transition: background var(--transition);
    text-align: left;
  }

  .contact-item:hover {
    background: var(--bg-tertiary);
  }

  .contact-item.active {
    background: var(--accent-dim);
  }

  .contact-avatar {
    width: 40px;
    height: 40px;
    border-radius: 50%;
    background: var(--bg-elevated);
    border: 1px solid var(--border);
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: 600;
    font-size: 15px;
    color: var(--accent);
    flex-shrink: 0;
  }

  .contact-info {
    flex: 1;
    min-width: 0;
  }

  .contact-name {
    font-size: 14px;
    font-weight: 500;
  }

  .contact-preview {
    font-size: 12px;
    color: var(--text-muted);
    margin-top: 2px;
  }

  .sidebar-footer {
    padding: 8px;
    border-top: 1px solid var(--border);
  }

  .sidebar-footer button {
    display: flex;
    align-items: center;
    gap: 8px;
    justify-content: flex-start;
    padding: 8px 12px;
    border-radius: var(--radius);
    font-size: 13px;
    color: var(--text-secondary);
    background: transparent;
  }

  .sidebar-footer button:hover {
    background: var(--bg-tertiary);
    color: var(--text-primary);
  }

  /* Content */
  .content {
    flex: 1;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }

  .conversations-view {
    flex: 1;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .empty-state {
    text-align: center;
    max-width: 320px;
    padding: 40px;
  }

  .empty-icon {
    color: var(--text-muted);
    margin-bottom: 20px;
    opacity: 0.5;
  }

  .empty-state h2 {
    font-size: 18px;
    font-weight: 600;
    margin-bottom: 8px;
  }

  .empty-state p {
    font-size: 13px;
    color: var(--text-secondary);
    margin-bottom: 20px;
    line-height: 1.6;
  }
</style>
