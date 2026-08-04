import { nip19 } from 'nostr-tools';
import { buildAuthCompleteRequest } from '@imani/nap-client-http';
import type { AuthSuccessResponse } from '@imani/nap-core';
import { createActivityLock } from './activityLock.js';
import { createBroadcastBus } from './broadcast.js';
import { SessionLockedError, fetchJson } from './httpClient.js';
import { reunlock as reunlockCore } from './reunlock.js';
import type { KeyHolder } from './keyStore.js';
import { IdentityMismatchError, isEvictableSigner } from './types.js';
import type { NapClientOptions, NapSession, SessionState } from './types.js';

function normalizeBaseUrl(value: string): string {
  return value.endsWith('/') ? value.slice(0, -1) : value;
}

function sessionPath(baseUrl: string, path: string): string {
  return `${normalizeBaseUrl(baseUrl)}/auth/${path}`;
}

/**
 * The identity guard compares pubkeys, but the pre-flight check only has the
 * signer's npub. Decode where possible and fall back to the npub verbatim so an
 * unparseable value still produces a useful error rather than an exception
 * inside the guard.
 */
function pubkeyOfNpub(npub: string): string {
  try {
    const decoded = nip19.decode(npub);
    return decoded.type === 'npub' ? decoded.data : npub;
  } catch {
    return npub;
  }
}

function toSessionState(response: AuthSuccessResponse): SessionState {
  return {
    pubkey: response.principal.pubkey,
    npub: response.principal.npub,
    roles: response.roles ?? [],
    permissions: response.permissions ?? [],
    expiresAt: response.expires_at,
  };
}

export function createNapSession(options: NapClientOptions): NapSession {
  const fetchImpl = options.fetch ?? fetch;
  let sessionState: SessionState | null = null;
  let locked = false;
  let shutdownState = false;

  // Null for NIP-07/NIP-46 signers, which hold no key in the page. Per RFC
  // §28.6(4), a caller-supplied signer that holds a key without implementing
  // EvictableSigner owns its own eviction — we cannot reach into its closure.
  const evictable = isEvictableSigner(options.signer) ? options.signer : null;

  // Evicting the key and marking the session locked are separate concerns:
  // logout and destroy evict without locking, since "logged out" is not "locked".
  const evictKey = (): void => {
    evictable?.clearKey();
  };

  // RFC §28.6: locking must evict key material, not just flip a flag.
  const keyHolder: KeyHolder = {
    setKey(key: string) {
      evictable?.setKey(key);
      locked = false;
      shutdownState = false;
    },
    clearKey() {
      evictKey();
      locked = true;
    },
    hasKey() {
      return evictable ? evictable.hasKey() : !locked;
    },
  };

  /**
   * Tear the session down because the signer is no longer the same person.
   *
   * Returns the error rather than throwing so callers read as
   * `throw terminateForIdentity(...)` — the termination and the rejection are
   * one decision.
   *
   * No `/auth/logout` is sent. The server's session belongs to the old identity
   * and the cookie is `HttpOnly`; a network round trip that can fail must not
   * stand between "wrong identity detected" and "local session gone".
   */
  const terminateForIdentity = (
    expectedPubkey: string,
    actualPubkey: string
  ): IdentityMismatchError => {
    sessionState = null;
    evictKey();
    locked = false;
    shutdownState = false;
    options.onIdentityChanged?.({ expectedPubkey, actualPubkey });
    broadcast.publish('identity-changed', { expectedPubkey, actualPubkey });
    return new IdentityMismatchError(expectedPubkey, actualPubkey);
  };

  const publishLock = (): void => {
    keyHolder.clearKey();
    options.onLock?.();
    broadcast.publish('lock');
  };

  const publishShutdown = (): void => {
    keyHolder.clearKey();
    shutdownState = true;
    options.onShutdown?.();
    broadcast.publish('shutdown');
  };

  const broadcast = createBroadcastBus(
    options.broadcast?.enabled ?? true,
    options.broadcast?.channelName ?? 'nap-session',
    (type, detail) => {
      if (type === 'identity-changed') {
        // Another tab saw the signer change identity. This tab's session is the
        // same session, so it is gone here too.
        sessionState = null;
        evictKey();
        locked = false;
        shutdownState = false;
        if (detail) {
          options.onIdentityChanged?.(detail);
        }
        return;
      }

      if (type === 'logout') {
        sessionState = null;
        evictKey();
        locked = false;
        shutdownState = false;
        options.onLogout?.();
        return;
      }

      if (type === 'unlock') {
        // Only this tab's own key can un-evict itself, so an evictable session
        // stays locked here until it reunlocks here. A key-free one has nothing
        // to restore, and staying locked would strand it (see unlock()).
        if (!evictable) {
          locked = false;
          shutdownState = false;
        }

        options.onUnlock?.();
        return;
      }

      if (type === 'shutdown') {
        keyHolder.clearKey();
        shutdownState = true;
        options.onShutdown?.();
        return;
      }

      // Handle incoming lock from another tab without re-broadcasting
      // to avoid ping-pong between tabs. This tab evicts its own key copy:
      // a lock in one tab that left the key live in another would not be a lock.
      if (type === 'lock') {
        keyHolder.clearKey();
        options.onLock?.();
        return;
      }
    }
  );

  const activityLock = createActivityLock(
    options.autoLock?.enabled ?? false,
    options.autoLock?.timeoutMs ?? 15 * 60 * 1000,
    publishLock,
    options.autoLock?.shutdownTimeoutMs,
    publishShutdown
  );

  async function authenticate(stepUp = false): Promise<AuthSuccessResponse> {
    // Fail before mutating state: with the key evicted, signEvent() would throw
    // partway through and leave the session claiming to be unlocked. A key-free
    // signer has nothing to evict, but a locked session must still refuse —
    // otherwise lock() would mean nothing for NIP-07 and NIP-46 (FR-023).
    if (!keyHolder.hasKey()) {
      throw new SessionLockedError();
    }

    // Ask who the signer is before spending a challenge on them. An extension
    // that switched accounts is caught here, without a network round trip and
    // without a prompt (FR-021).
    const npub = await options.signer.getNpub();

    if (sessionState && sessionState.npub !== npub) {
      throw terminateForIdentity(sessionState.pubkey, pubkeyOfNpub(npub));
    }

    locked = false;
    shutdownState = false;
    activityLock.touch();

    const initResponse = await fetchJson<{ challenge_id: string; challenge: string; auth_url: string; auth_method: 'POST'; issued_at: number; expires_at: number }>(
      fetchImpl,
      sessionPath(options.baseUrl, 'init'),
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
        },
        body: JSON.stringify({ npub }),
      }
    );

    if (initResponse.status !== 200 || !initResponse.body) {
      throw new Error(`NAP init failed with status ${initResponse.status}`);
    }

    const completion = await buildAuthCompleteRequest({
      challenge: initResponse.body,
      signer: options.signer,
      stepUp,
    });
    const completeResponse = await fetchJson<AuthSuccessResponse>(
      fetchImpl,
      sessionPath(options.baseUrl, 'complete'),
      {
        method: 'POST',
        headers: {
          authorization: completion.authorization,
          'content-type': 'application/json',
        },
        body: new TextDecoder().decode(completion.rawBody),
      }
    );

    if (completeResponse.status !== 200 || !completeResponse.body) {
      throw new Error(`NAP completion failed with status ${completeResponse.status}`);
    }

    const next = toSessionState(completeResponse.body);

    // The signer's npub matched, but the server is the authority on which key
    // actually signed. A mismatch here means the signature came from someone
    // other than the identity the signer claimed.
    if (sessionState && sessionState.pubkey !== next.pubkey) {
      throw terminateForIdentity(sessionState.pubkey, next.pubkey);
    }

    sessionState = next;
    return completeResponse.body;
  }

  return {
    async login(): Promise<AuthSuccessResponse> {
      const response = await authenticate(false);
      options.onLogin?.();
      return response;
    },
    async logout(): Promise<void> {
      await fetchJson(fetchImpl, sessionPath(options.baseUrl, 'logout'), {
        method: 'POST',
      });
      sessionState = null;
      // RFC §28.3: zero the decrypted key on logout. A later login() therefore
      // needs the key supplied again via reunlock() or a fresh signer.
      evictKey();
      locked = false;
      shutdownState = false;
      options.onLogout?.();
      broadcast.publish('logout');
    },
    async resume(): Promise<AuthSuccessResponse | null> {
      const response = await fetchJson<AuthSuccessResponse>(
        fetchImpl,
        sessionPath(options.baseUrl, 'session'),
        { method: 'GET' }
      );

      if (response.status === 401) {
        sessionState = null;
        options.onSessionExpired?.();
        return null;
      }

      if (response.status !== 200 || !response.body) {
        throw new Error(`NAP session lookup failed with status ${response.status}`);
      }

      sessionState = toSessionState(response.body);
      locked = false;
      options.onLogin?.();
      return response.body;
    },
    async stepUp(): Promise<string> {
      const response = await authenticate(true);

      if (!response.step_up_token) {
        throw new Error('NAP step-up response did not include a step-up token');
      }

      return response.step_up_token;
    },
    isAuthenticated(): boolean {
      return sessionState !== null;
    },
    getSession(): SessionState | null {
      return sessionState;
    },
    hasPermission(permission: string): boolean {
      return sessionState?.permissions.includes(permission) ?? false;
    },
    hasRole(role: string): boolean {
      return sessionState?.roles.includes(role) ?? false;
    },
    lock(): void {
      publishLock();
    },
    isLocked(): boolean {
      return locked;
    },
    shutdown(): void {
      publishShutdown();
    },
    isShutdown(): boolean {
      return shutdownState;
    },
    async reunlock(passphrase: string): Promise<void> {
      if (!options.keyStore) {
        throw new Error('keyStore is required for reunlock');
      }

      await reunlockCore(passphrase, options.keyStore, keyHolder, {
        onTimerReset: () => activityLock.touch(),
        onBroadcast: () => broadcast.publish('unlock'),
      });
    },
    unlock(): void {
      // Without this a key-free session that auto-locked is stranded: login()
      // refuses while locked, and reunlock() needs a keyStore these signers
      // have no reason to configure.
      if (evictable) {
        throw new Error('this session holds a key of its own: use reunlock(passphrase)');
      }

      locked = false;
      shutdownState = false;
      activityLock.touch();
      options.onUnlock?.();
      broadcast.publish('unlock');
    },
    destroy(): void {
      activityLock.stop();
      broadcast.close();
      // Tearing down the session must not leave the key alive in the closure.
      evictKey();
    },
  };
}
