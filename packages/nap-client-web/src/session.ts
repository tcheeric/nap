import { nip19 } from 'nostr-tools';
import { buildAuthCompleteRequest } from '@imani/nap-client-http';
import type { AuthSuccessResponse } from '@imani/nap-core';
import { createActivityLock } from './activityLock.js';
import { createBroadcastBus } from './broadcast.js';
import { AuthRequestError, SessionLockedError, fetchJson } from './httpClient.js';
import { reunlock as reunlockCore } from './reunlock.js';
import type { KeyHolder } from './keyStore.js';
import { IdentityMismatchError, isEvictableSigner } from './types.js';
import type { LockRecovery, NapClientOptions, NapSession, SessionState } from './types.js';

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

  /**
   * The signer decides first. A `keyStore` only breaks the tie for a signer that
   * actually holds a key here — for a NIP-07 or NIP-46 session there is nothing
   * to decrypt, so a store configured for the app's *other* login mode must not
   * drag it into a passphrase prompt it can never satisfy.
   */
  const lockRecovery = (): LockRecovery => {
    if (!evictable) {
      return 'unlock';
    }

    return options.keyStore ? 'passphrase' : 'reauthenticate';
  };

  // Refused at construction only. An idle timer that zeroes the key minutes
  // after a call that returned cleanly, leaving no way back, is a wiring error
  // worth failing on. `lock()` and `shutdown()` deliberately do NOT refuse:
  // zeroing the key is the whole point of RFC §28.6, and a user who asks for it
  // explicitly must get it. Needing a fresh login afterwards is the honest cost
  // of not configuring a store; a key left live in the page is not.
  if ((options.autoLock?.enabled ?? false) && lockRecovery() === 'reauthenticate') {
    throw new Error(
      'autoLock with a key-holding signer requires a keyStore: the lock evicts the key and reunlock() is the only way back'
    );
  }

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
   * A refusal the same signer cannot argue with clears the remembered choice.
   *
   * Nothing else does it: the store is written by the app (only the app knows
   * *which kind* of signer it built), so without this a login the server has
   * stopped accepting is re-offered on every visit and 401s forever. The rule is
   * "terminal", not "unknown npub" — anti-enumeration means the client is never
   * told which it was — and it deliberately excludes anything a retry fixes: a
   * dropped relay, a 5xx, a rate limit, a `getNpub()` that threw before any of
   * this ran.
   *
   * Clearing costs one extra click on the next visit. Not clearing costs a login
   * screen that only knows how to fail.
   */
  const failAuth = (phase: 'init' | 'complete', status: number): AuthRequestError => {
    const error = new AuthRequestError(phase, status);

    if (error.terminal) {
      options.signerPreference?.clear();
    }

    return error;
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
    // The kind is still right — it is the same extension or bunker — but the
    // npub in the record is now somebody else's, and a "Continue as npub1old…"
    // button that signs as whoever holds the signer now is the carry-over this
    // guard exists to prevent. `logout()` deliberately does not do this: logging
    // out is not evidence the signer changed, and re-offering it is the point.
    options.signerPreference?.clear();
    options.onIdentityChanged?.({ expectedPubkey, actualPubkey });
    broadcast.publish('identity-changed', { expectedPubkey, actualPubkey });
    return new IdentityMismatchError(expectedPubkey, actualPubkey);
  };

  /**
   * There is nothing to lock without a session, and pretending otherwise is a
   * dead end rather than a harmless no-op: `locked` gates `authenticate()`, so a
   * lock set before anyone logged in refuses the login that would clear it.
   *
   * The idle timer starts inside `createActivityLock` at construction, so a page
   * that sits on its login screen past `timeoutMs` hits exactly that. Same after
   * `logout()` and after `terminateForIdentity()` — both leave the timer running,
   * and the second one *requires* a fresh login to recover.
   */
  const hasSession = (): boolean => sessionState !== null;

  const publishLock = (): void => {
    if (!hasSession()) {
      // Rearm. The activity timers are one-shot — only `touch()` rebuilds them —
      // so returning without rescheduling would disarm autoLock for the rest of
      // the page's life. A lock timer that expires during a slow login (a NIP-46
      // approval on a phone generates no events here) would silently mean the
      // session never auto-locks once it lands.
      activityLock.touch();
      return;
    }

    keyHolder.clearKey();
    options.onLock?.();
    broadcast.publish('lock');
  };

  const publishShutdown = (): void => {
    if (!hasSession()) {
      activityLock.touch();
      return;
    }

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
          // The idle timer that locked this tab has already fired and only
          // rearms on touch() or real user activity. Without this the tab is
          // unlocked with nothing left to lock it again.
          activityLock.touch();
        }

        options.onUnlock?.();
        return;
      }

      if (type === 'shutdown') {
        // Same reason publishShutdown checks: a tab with no session that takes
        // `locked = true` from a sibling has no way to clear it, because the
        // login that would clear it is exactly what `locked` refuses.
        if (!hasSession()) {
          return;
        }

        keyHolder.clearKey();
        shutdownState = true;
        options.onShutdown?.();
        return;
      }

      // Handle incoming lock from another tab without re-broadcasting
      // to avoid ping-pong between tabs. This tab evicts its own key copy:
      // a lock in one tab that left the key live in another would not be a lock.
      if (type === 'lock') {
        // A tab still on its login screen has nothing to evict and must not take
        // the flag: `locked` gates authenticate(), and a logged-out screen shows
        // no unlock affordance, so its Sign in button would fail until reload.
        if (!hasSession()) {
          return;
        }

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

    // Compared as pubkeys, not as npubs. `pubkey` is the field the session body
    // contract actually requires — an implementation that omits `principal.npub`
    // would otherwise make every login after a resume() look like an account
    // switch, and report it with expectedPubkey === actualPubkey.
    if (sessionState && sessionState.pubkey !== pubkeyOfNpub(npub)) {
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
      throw failAuth('init', initResponse.status);
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
      throw failAuth('complete', completeResponse.status);
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
      options.onLogin?.({ via: 'login' });
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
    async resume(options_?: { verifyIdentity?: boolean }): Promise<AuthSuccessResponse | null> {
      const response = await fetchJson<AuthSuccessResponse>(
        fetchImpl,
        sessionPath(options.baseUrl, 'session'),
        { method: 'GET' }
      );

      if (response.status === 401) {
        // The remembered signer is deliberately kept. An expired or missing
        // cookie says nothing about whether that signer is still accepted, and
        // rebuilding it to log in again is exactly what it is remembered for.
        sessionState = null;
        options.onSessionExpired?.();
        return null;
      }

      if (response.status !== 200 || !response.body) {
        throw new Error(`NAP session lookup failed with status ${response.status}`);
      }

      const restored = toSessionState(response.body);

      // Opt-in, because `resume()` not touching the signer is the property that
      // makes returning to a session prompt-free (FR-024), and for NIP-46 a
      // `get_public_key` is a relay round trip. But the cookie outlives the page
      // and the signer does not: rebuilding a signer from a remembered choice
      // and resuming would otherwise restore the *previous* account's principal
      // while every later signature came from whoever the signer is now. Ask
      // when the signer might have changed while you were gone.
      //
      // Terminating goes through the same `terminateForIdentity` as the login
      // guard — one mechanism, called from a second place, not a second guard.
      // Assigned before verifying, not after. The server has already said this
      // session is valid, so a signer that cannot answer — `getNpub()` is a live
      // relay round trip on NIP-46, and a dropped relay throws — must not cost
      // the user their session. A transport failure is not a mismatch: it
      // propagates so the caller can retry or log out, with the session left
      // intact. Only a genuine mismatch terminates.
      sessionState = restored;

      if (options_?.verifyIdentity) {
        const actual = pubkeyOfNpub(await options.signer.getNpub());

        if (restored.pubkey !== actual) {
          throw terminateForIdentity(restored.pubkey, actual);
        }
      }

      // `locked` is deliberately not cleared. Restoring the server session says
      // nothing about the key: for an evictable signer it is still evicted, and
      // reporting unlocked would skip the passphrase prompt and then fail the
      // signature. A key-free session stays locked too — clearing it here would
      // be an unlock with no `onUnlock` and no broadcast, leaving sibling tabs
      // locked while this one is not.
      options.onLogin?.({ via: 'resume' });
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
    lockRecovery,
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
