import type { AuthSuccessResponse } from '@imani/nap-core';
import type { EventSigner } from '@imani/nap-client-http';
import type { IdentityChangedDetail } from './broadcast.js';
import type { KeyStore } from './keyStore.js';

/**
 * How a locked session gets back to signing. The signer decides first, the
 * `keyStore` only breaks the tie for signers that hold a key in the page.
 *
 * - `'unlock'` — nothing was evicted, because the key never was in the page.
 *   NIP-07 and NIP-46. `unlock()` clears the lock; there is no passphrase
 *   because there is nothing to decrypt. Per RFC §28.6(4) a caller-supplied
 *   signer that holds a key *without* implementing `EvictableSigner` also lands
 *   here — it owns its own eviction, and the session cannot tell it apart from
 *   a NIP-07 one.
 * - `'passphrase'` — an `EvictableSigner` whose key can be decrypted back out of
 *   a configured `keyStore`. `reunlock(passphrase)`.
 * - `'reauthenticate'` — an `EvictableSigner` with no `keyStore`. The lock zeroed
 *   the key and nothing can restore it: not `unlock()`, which would report a
 *   session that still cannot sign, and not `reunlock()`, which has no store to
 *   read. The app must build a fresh signer and log in again. Locking still
 *   *happens* — zeroing the key is the point — this only names the way back.
 */
export type LockRecovery = 'unlock' | 'passphrase' | 'reauthenticate';

export interface SessionState {
  pubkey: string;
  npub: string;
  roles: string[];
  permissions: string[];
  expiresAt: number;
}

/**
 * The seam every authentication path goes through. A private key in the page, a
 * NIP-07 extension, and a NIP-46 remote signer are substitutable here, and the
 * server cannot tell which one produced a signature (SC-011).
 *
 * One caveat is inherent rather than incidental: each `login()` or `stepUp()`
 * signs a fresh NIP-98 challenge, so an external signer prompts once per session
 * lifetime. `resume()` never invokes the signer, so returning to an existing
 * session is prompt-free; renewing an expired one is not (FR-024).
 */
export interface SessionSigner extends EventSigner {
  getNpub(): Promise<string> | string;
}

/**
 * A signer whose key material the session can evict and restore.
 *
 * RFC §28.6 requires that a lock actually clear key material rather than only
 * mark session state. A signer holding a private key in the page must implement
 * this so `lock()` can zero it and `reunlock()` can put it back.
 *
 * Signers that never hold a key in the page — NIP-07 and NIP-46 — deliberately
 * do not implement it: there is nothing in reach to evict, which is exactly why
 * they are preferred under RFC §28.2. Per §28.6(4), a caller supplying its own
 * key-holding signer without this interface owns eviction itself.
 */
export interface EvictableSigner extends SessionSigner {
  /** Zero the in-memory key. `signEvent()` throws `SessionLockedError` until `setKey()`. */
  clearKey(): void;
  /** Restore the key. Must belong to the same identity the signer was created with. */
  setKey(privateKeyHex: string): void;
  hasKey(): boolean;
}

export function isEvictableSigner(signer: SessionSigner): signer is EvictableSigner {
  const candidate = signer as Partial<EvictableSigner>;
  return (
    typeof candidate.clearKey === 'function' &&
    typeof candidate.setKey === 'function' &&
    typeof candidate.hasKey === 'function'
  );
}

/**
 * Thrown when the signer's identity stops matching the established session.
 *
 * Switching accounts in an extension, or repointing a bunker at a different key,
 * would otherwise leave the page authenticated as one npub while signing as
 * another. The session is terminated rather than migrated: a new identity is a
 * new login, and silently carrying the old session's roles across would be a
 * privilege transfer nobody asked for (FR-021).
 */
export class IdentityMismatchError extends Error {
  readonly code = 'IDENTITY_MISMATCH' as const;
  readonly expectedPubkey: string;
  readonly actualPubkey: string;

  constructor(expectedPubkey: string, actualPubkey: string) {
    super('Signer identity does not match the established session');
    this.name = 'IdentityMismatchError';
    this.expectedPubkey = expectedPubkey;
    this.actualPubkey = actualPubkey;
  }
}

/**
 * This package is cookie-mode only, and deliberately so. Every request goes out
 * with `credentials: 'include'` and no `Authorization` header, and the
 * `access_token` from a completion is never retained — holding it in JS is what
 * an `HttpOnly` cookie exists to avoid. Point it at a backend running
 * `writeNapCookieSuccess`; for bearer mode use `@imani/nap-client-http` and own
 * the token yourself.
 *
 * There is therefore no cookie option here. The name, attributes, and lifetime
 * are the server's, the browser attaches the cookie without being asked, and an
 * `HttpOnly` cookie is not readable from this side even if it were named.
 */
export interface NapClientOptions {
  baseUrl: string;
  signer: SessionSigner;
  autoLock?: {
    enabled: boolean;
    timeoutMs: number;
    /** Optional shutdown timeout (ms). When set, a second timer fires after extended inactivity. */
    shutdownTimeoutMs?: number;
  };
  broadcast?: { enabled: boolean; channelName?: string };
  onSessionExpired?: () => void;
  /**
   * Called after a successful `login()` or a `resume()` that restored a session.
   *
   * `via` separates them because they prove different things. A `login()` is a
   * fresh signature from the signer in the page; a `resume()` only proves the
   * cookie is still valid, and the identity guard sends no `/auth/logout`, so a
   * terminated identity's cookie outlives the session it belonged to. Anything
   * that treats authentication as evidence about *who is signing* — clearing an
   * identity-changed banner, most obviously — must act on `'login'` only.
   */
  onLogin?: (detail: { via: 'login' | 'resume' }) => void;
  onLock?: () => void;
  onUnlock?: () => void;
  /** Called when the shutdown timer fires (extended inactivity). */
  onShutdown?: () => void;
  onLogout?: () => void;
  /**
   * Fires when a signer presents a different identity and the session is
   * terminated as a result. Prompt for a fresh login; do not retry silently.
   */
  onIdentityChanged?: (detail: IdentityChangedDetail) => void;
  keyStore?: KeyStore;
  fetch?: typeof fetch;
}

export interface NapSession {
  login(): Promise<AuthSuccessResponse>;
  logout(): Promise<void>;
  /**
   * Restore a session from the cookie. Never invokes the signer, so it is
   * prompt-free (FR-024) — which is also why it cannot tell that the signer
   * changed while the page was away.
   *
   * Pass `verifyIdentity` when it might have: after a reload that rebuilt the
   * signer from a remembered choice, above all. It costs one `getNpub()` and
   * terminates the session with `IdentityMismatchError` rather than restoring
   * the previous account's roles under a signer that is now somebody else.
   */
  resume(options?: { verifyIdentity?: boolean }): Promise<AuthSuccessResponse | null>;
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
  /**
   * How a lock on this session clears. Constant for the session's lifetime.
   *
   * This replaced a `requiresPassphrase(): boolean`, which was a two-way answer
   * to a three-way question and produced a bug in each arm it did not model: a
   * key-free signer sent to a passphrase modal it can never satisfy, or an
   * unrecoverable session sent to an `unlock()` that throws.
   */
  lockRecovery(): LockRecovery;
  /**
   * Clear a lock on a session whose signer holds the key — NIP-07, NIP-46.
   * There is nothing to restore, so there is no passphrase; the signer's own
   * prompt on the next signature is the re-authorization. Throws for a session
   * with an in-page key, which must go through `reunlock()`.
   */
  unlock(): void;
  destroy(): void;
}
