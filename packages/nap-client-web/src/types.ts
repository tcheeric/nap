import type { AuthSuccessResponse } from '@imani/nap-core';
import type { EventSigner } from '@imani/nap-client-http';
import type { KeyStore } from './keyStore.js';

export interface SessionState {
  pubkey: string;
  npub: string;
  roles: string[];
  permissions: string[];
  expiresAt: number;
}

export interface SessionSigner extends EventSigner {
  getNpub(): Promise<string> | string;
}

export interface NapClientOptions {
  baseUrl: string;
  signer: SessionSigner;
  cookie?: { name?: string };
  autoLock?: {
    enabled: boolean;
    timeoutMs: number;
    /** Optional shutdown timeout (ms). When set, a second timer fires after extended inactivity. */
    shutdownTimeoutMs?: number;
  };
  broadcast?: { enabled: boolean; channelName?: string };
  onSessionExpired?: () => void;
  onLock?: () => void;
  onUnlock?: () => void;
  /** Called when the shutdown timer fires (extended inactivity). */
  onShutdown?: () => void;
  onLogout?: () => void;
  keyStore?: KeyStore;
  fetch?: typeof fetch;
}

export interface NapSession {
  login(): Promise<AuthSuccessResponse>;
  logout(): Promise<void>;
  resume(): Promise<AuthSuccessResponse | null>;
  stepUp(): Promise<string>;
  isAuthenticated(): boolean;
  getSession(): SessionState | null;
  hasPermission(permission: string): boolean;
  hasRole(role: string): boolean;
  lock(): void;
  isLocked(): boolean;
  /** Trigger session shutdown (extended inactivity). Clears key and blocks UI. */
  shutdown(): void;
  /** Whether the session is in shutdown state (requires passphrase to resume). */
  isShutdown(): boolean;
  reunlock(passphrase: string): Promise<void>;
  destroy(): void;
}
