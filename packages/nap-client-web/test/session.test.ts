import { describe, expect, it, vi } from 'vitest';
import {
  createNapSession,
  createPrivateKeySessionSigner,
  isEvictableSigner,
} from '../src/index.js';
import { SessionLockedError } from '../src/httpClient.js';
import type { SessionSigner } from '../src/types.js';

function createSigner(): SessionSigner {
  return {
    getNpub() {
      return 'npub1example';
    },
    async signEvent() {
      return {
        id: 'event-id',
        pubkey: 'pubkey-1',
        created_at: 1_710_000_000,
        kind: 27235,
        tags: [],
        content: '',
        sig: 'sig',
      };
    },
  };
}

/**
 * A fetch that answers the whole auth handshake, so a test can reach the
 * authenticated state before exercising lock behaviour.
 *
 * Locking an unauthenticated session is a no-op by design — `locked` gates
 * `authenticate()`, so a lock set before anyone logged in would refuse the login
 * that clears it. Tests that lock therefore have to log in first, or they assert
 * against a state real apps never reach.
 */
function authFetch(pubkey = 'pubkey-1'): ReturnType<typeof vi.fn<typeof fetch>> {
  return vi.fn<typeof fetch>(async (input) => {
    if (String(input).endsWith('/auth/init')) {
      return new Response(
        JSON.stringify({
          challenge_id: 'challenge-1',
          challenge: 'challenge',
          auth_url: 'https://merchant.example.com/auth/complete',
          auth_method: 'POST',
          issued_at: 1_710_000_000,
          expires_at: 1_710_000_060,
        }),
        { status: 200 }
      );
    }

    return new Response(
      JSON.stringify({
        status: 'ok',
        access_token: 'token',
        token_type: 'Bearer',
        expires_at: 1_710_000_900,
        principal: { npub: 'npub1example', pubkey },
        roles: [],
        permissions: [],
      }),
      { status: 200 }
    );
  });
}

describe('nap-client-web', () => {
  it('ignores a lock on a session nobody has logged into', async () => {
    // The idle timer starts at construction, so a login page left open past
    // timeoutMs used to lock itself and then refuse the login that would clear
    // it. Same after logout() and after an identity change, both of which leave
    // the timer running and require a fresh login to recover.
    const fetchMock = authFetch();
    const session = createNapSession({
      baseUrl: 'https://merchant.example.com',
      signer: createSigner(),
      fetch: fetchMock,
    });

    session.lock();

    expect(session.isLocked()).toBe(false);
    await expect(session.login()).resolves.toMatchObject({ status: 'ok' });
  });

  it('still evicts on an explicit lock it cannot undo', async () => {
    // Evictable signer, no keyStore. There is no way back from this lock — the
    // key is gone, no store can restore it — but lock() must still zero it
    // (RFC §28.6). Refusing would leave a live nsec in the page in answer to a
    // user asking for it to be wiped, which is a strictly worse trade than
    // making them sign in again. `lockRecovery()` is how the UI is told.
    const signer = createPrivateKeySessionSigner('1'.repeat(64));
    const session = createNapSession({
      baseUrl: 'https://merchant.example.com',
      signer,
      fetch: authFetch(),
    });

    await session.login();
    expect(session.lockRecovery()).toBe('reauthenticate');
    expect(signer.hasKey()).toBe(true);

    session.lock();

    expect(signer.hasKey()).toBe(false);
    expect(session.isLocked()).toBe(true);
  });

  it('refuses autoLock it could never clear, at construction', () => {
    // The automatic path has no user intent behind it, so a timer that zeroes
    // the key minutes later with no way back is a wiring error worth failing on.
    expect(() =>
      createNapSession({
        baseUrl: 'https://merchant.example.com',
        signer: createPrivateKeySessionSigner('1'.repeat(64)),
        fetch: authFetch(),
        autoLock: { enabled: true, timeoutMs: 60_000 },
      })
    ).toThrow(/keyStore/);
  });

  it('logs in, resumes, and exposes permission helpers', async () => {
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(new Response(JSON.stringify({
        challenge_id: 'challenge-1',
        challenge: 'challenge',
        auth_url: 'https://merchant.example.com/auth/complete',
        auth_method: 'POST',
        issued_at: 1_710_000_000,
        expires_at: 1_710_000_060,
      }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        status: 'ok',
        access_token: 'token',
        token_type: 'Bearer',
        expires_at: 1_710_000_900,
        principal: {
          npub: 'npub1example',
          pubkey: 'pubkey-1',
        },
        roles: ['merchant'],
        permissions: ['voucher:create'],
      }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        status: 'ok',
        access_token: 'token',
        token_type: 'Bearer',
        expires_at: 1_710_000_900,
        principal: {
          npub: 'npub1example',
          pubkey: 'pubkey-1',
        },
        roles: ['merchant'],
        permissions: ['voucher:create'],
      }), { status: 200 }));
    const session = createNapSession({
      baseUrl: 'https://merchant.example.com',
      signer: createSigner(),
      fetch: fetchMock,
    });

    const login = await session.login();
    const resumed = await session.resume();

    expect(login.principal.npub).toBe('npub1example');
    expect(resumed?.principal.pubkey).toBe('pubkey-1');
    expect(session.hasPermission('voucher:create')).toBe(true);
    expect(session.hasRole('merchant')).toBe(true);
  });

  it('locks locally and logs out', async () => {
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(new Response(JSON.stringify({
        challenge_id: 'challenge-1',
        challenge: 'challenge',
        auth_url: 'https://merchant.example.com/auth/complete',
        auth_method: 'POST',
        issued_at: 1_710_000_000,
        expires_at: 1_710_000_060,
      }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        status: 'ok',
        access_token: 'token',
        token_type: 'Bearer',
        expires_at: 1_710_000_900,
        principal: {
          npub: 'npub1example',
          pubkey: 'pubkey-1',
        },
        roles: ['merchant'],
        permissions: ['voucher:create'],
      }), { status: 200 }))
      .mockResolvedValueOnce(new Response(null, { status: 204 }));
    const session = createNapSession({
      baseUrl: 'https://merchant.example.com',
      signer: createSigner(),
      fetch: fetchMock,
    });

    await session.login();
    session.lock();
    await session.logout();

    expect(session.isLocked()).toBe(false);
    expect(session.isAuthenticated()).toBe(false);
  });

  it('evicts key material on lock and restores it on reunlock', async () => {
    const KEY = '1111111111111111111111111111111111111111111111111111111111111111';
    const signer = createPrivateKeySessionSigner(KEY);
    const npubBefore = signer.getNpub();

    const session = createNapSession({
      baseUrl: 'https://merchant.example.com',
      signer,
      fetch: authFetch(),
      keyStore: {
        hasKey: async () => true,
        loadKey: async () => KEY,
      },
    });

    await session.login();
    expect(signer.hasKey()).toBe(true);

    session.lock();

    // The lock must remove the key, not merely mark state (RFC §28.6).
    expect(signer.hasKey()).toBe(false);
    expect(session.isLocked()).toBe(true);
    await expect(signer.signEvent({
      kind: 27235, tags: [], content: '', created_at: 0,
    })).rejects.toThrow(SessionLockedError);

    // A public key is not a secret; identity must survive eviction.
    expect(signer.getNpub()).toBe(npubBefore);

    await session.reunlock('passphrase');

    expect(signer.hasKey()).toBe(true);
    expect(session.isLocked()).toBe(false);
  });

  it('refuses to authenticate while the key is evicted', async () => {
    const KEY = '1111111111111111111111111111111111111111111111111111111111111111';
    const fetchMock = authFetch();
    const signer = createPrivateKeySessionSigner(KEY);
    const session = createNapSession({
      baseUrl: 'https://merchant.example.com',
      signer,
      fetch: fetchMock,
      keyStore: { hasKey: async () => true, loadKey: async () => KEY },
    });

    await session.login();
    fetchMock.mockClear();
    session.lock();

    await expect(session.login()).rejects.toThrow(SessionLockedError);
    // Must fail before touching the network, or the session would claim to be
    // unlocked while signing was impossible.
    expect(fetchMock).not.toHaveBeenCalled();
    expect(session.isLocked()).toBe(true);
  });

  it('unlocks a key-free session, which has nothing to restore', async () => {
    // A NIP-07 or NIP-46 session holds no key of ours, so reunlock() — which
    // requires a keyStore these signers have no reason to configure — is not the
    // way back. Without unlock() an idle lock would be permanent (FR-023).
    const session = createNapSession({
      baseUrl: 'https://merchant.example.com',
      signer: createSigner(),
      // This test logs in twice, so the identity guard runs on the second one.
      // `npub1example` is not decodable bech32, so `pubkeyOfNpub` falls back to
      // the npub verbatim — the stub has to answer with that to be a consistent
      // fixture rather than look like an account switch.
      fetch: authFetch('npub1example'),
    });

    await session.login();
    session.lock();
    await expect(session.login()).rejects.toThrow(SessionLockedError);

    session.unlock();

    expect(session.isLocked()).toBe(false);
    await expect(session.login()).resolves.toMatchObject({ status: 'ok' });
  });

  it('clears a key-free lock in the other tab too', async () => {
    const tabOptions = {
      baseUrl: 'https://merchant.example.com',
      signer: createSigner(),
      fetch: authFetch(),
      broadcast: { enabled: true, channelName: 'nap-unlock-test' },
    };

    const tabA = createNapSession(tabOptions);
    const tabB = createNapSession(tabOptions);

    try {
      // Both tabs have to be authenticated: a lock means nothing without a
      // session, in the tab that publishes it or the one that receives it.
      await tabA.login();
      await tabB.login();

      // Waiting on the state rather than on a tick: BroadcastChannel delivery
      // is not bounded by one macrotask, and a fixed `setTimeout(0)` held on its
      // own but flaked under the full suite.
      tabA.lock();
      await vi.waitFor(() => expect(tabB.isLocked()).toBe(true));

      tabA.unlock();

      // An evictable session would stay locked here — its own key copy is gone
      // until it reunlocks in this tab. A key-free one has nothing to restore.
      await vi.waitFor(() => expect(tabB.isLocked()).toBe(false));
    } finally {
      tabA.destroy();
      tabB.destroy();
    }
  });

  it('refuses unlock() for a session holding a key of its own', async () => {
    const KEY = '1111111111111111111111111111111111111111111111111111111111111111';
    const session = createNapSession({
      baseUrl: 'https://merchant.example.com',
      signer: createPrivateKeySessionSigner(KEY),
      fetch: authFetch(),
      keyStore: { hasKey: async () => true, loadKey: async () => KEY },
    });

    await session.login();
    session.lock();

    // The key is evicted; only reunlock() can put it back. Clearing the flag
    // would report an unlocked session that cannot sign.
    expect(() => session.unlock()).toThrow(/reunlock/);
    expect(session.isLocked()).toBe(true);
  });

  it('rejects a reunlock that restores a different identity', async () => {
    const signer = createPrivateKeySessionSigner(
      '1111111111111111111111111111111111111111111111111111111111111111'
    );

    signer.clearKey();

    expect(() =>
      signer.setKey('2222222222222222222222222222222222222222222222222222222222222222')
    ).toThrow('does not match this signer identity');
    expect(signer.hasKey()).toBe(false);
  });

  it('evicts the key on logout and on destroy', async () => {
    const KEY = '1111111111111111111111111111111111111111111111111111111111111111';

    const logoutSigner = createPrivateKeySessionSigner(KEY);
    const logoutSession = createNapSession({
      baseUrl: 'https://merchant.example.com',
      signer: logoutSigner,
      fetch: vi.fn<typeof fetch>().mockResolvedValue(new Response(null, { status: 204 })),
    });

    await logoutSession.logout();

    expect(logoutSigner.hasKey()).toBe(false);
    // Logged out is not locked — eviction and lock state are separate.
    expect(logoutSession.isLocked()).toBe(false);

    const destroySigner = createPrivateKeySessionSigner(KEY);
    const destroySession = createNapSession({
      baseUrl: 'https://merchant.example.com',
      signer: destroySigner,
      fetch: vi.fn<typeof fetch>(),
    });

    destroySession.destroy();

    expect(destroySigner.hasKey()).toBe(false);
  });

  it('treats a signer with no key in the page as nothing to evict', async () => {
    const nip07 = {
      getNpub: () => 'npub1example',
      async signEvent() {
        return {
          id: 'event-id', pubkey: 'pubkey-1', created_at: 0,
          kind: 27235, tags: [], content: '', sig: 'sig',
        };
      },
    };

    expect(isEvictableSigner(nip07)).toBe(false);

    const session = createNapSession({
      baseUrl: 'https://merchant.example.com',
      signer: nip07,
      fetch: authFetch(),
    });

    await session.login();

    // Lock still works as session state; there is simply no key in reach.
    session.lock();
    expect(session.isLocked()).toBe(true);
  });

  it('fires onLogin on login and on a resume that restores a session', async () => {
    const authSuccess = () => new Response(JSON.stringify({
      status: 'ok',
      access_token: 'token',
      token_type: 'Bearer',
      expires_at: 1_710_000_900,
      principal: { npub: 'npub1example', pubkey: 'pubkey-1' },
      roles: ['merchant'],
      permissions: ['voucher:create'],
    }), { status: 200 });

    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(new Response(JSON.stringify({
        challenge_id: 'challenge-1',
        challenge: 'challenge',
        auth_url: 'https://merchant.example.com/auth/complete',
        auth_method: 'POST',
        issued_at: 1_710_000_000,
        expires_at: 1_710_000_060,
      }), { status: 200 }))
      .mockResolvedValueOnce(authSuccess())
      .mockResolvedValueOnce(authSuccess())
      .mockResolvedValueOnce(new Response(null, { status: 401 }));

    const onLogin = vi.fn();
    const session = createNapSession({
      baseUrl: 'https://merchant.example.com',
      signer: createSigner(),
      fetch: fetchMock,
      onLogin,
    });

    await session.login();
    expect(onLogin).toHaveBeenCalledTimes(1);
    // `via` separates a fresh signature from a still-valid cookie. Anything
    // treating authentication as evidence about *who is signing* — clearing an
    // identity-changed banner above all — must act on 'login' only.
    expect(onLogin).toHaveBeenLastCalledWith({ via: 'login' });

    await session.resume();
    expect(onLogin).toHaveBeenCalledTimes(2);
    expect(onLogin).toHaveBeenLastCalledWith({ via: 'resume' });

    // A resume that finds no session must not report a login.
    await session.resume();
    expect(onLogin).toHaveBeenCalledTimes(2);
  });

  it('verifies identity on resume when asked, and terminates on a mismatch', async () => {
    // The cookie outlives the page; the signer does not. Rebuilding a signer
    // from a remembered choice and resuming would otherwise restore the
    // previous account's principal while every signature came from whoever the
    // signer is now — and resume() never consults the signer on its own.
    const onIdentityChanged = vi.fn();
    const session = createNapSession({
      baseUrl: 'https://merchant.example.com',
      // Server says the session belongs to pubkey-1; the signer says otherwise.
      signer: createSigner(),
      fetch: authFetch('pubkey-1'),
      onIdentityChanged,
      broadcast: { enabled: false },
    });

    await expect(session.resume({ verifyIdentity: true })).rejects.toMatchObject({
      code: 'IDENTITY_MISMATCH',
    });

    expect(session.isAuthenticated()).toBe(false);
    expect(onIdentityChanged).toHaveBeenCalledWith({
      expectedPubkey: 'pubkey-1',
      actualPubkey: 'npub1example',
    });
  });

  it('returns a stable getSession() reference until the session changes', async () => {
    // nap-react's provider polls getSession() twice a second and feeds it to
    // setState. That is only cheap because the reference is stable between
    // mutations, letting React bail out; returning a fresh object per call
    // would re-render every consumer on every tick.
    const session = createNapSession({
      baseUrl: 'https://merchant.example.com',
      signer: createSigner(),
      fetch: authFetch('npub1example'),
    });

    expect(session.getSession()).toBeNull();

    await session.login();
    const first = session.getSession();

    expect(first).not.toBeNull();
    expect(session.getSession()).toBe(first);

    await session.login();
    expect(session.getSession()).not.toBe(first);
  });

  it('leaves a locked session locked across a resume', async () => {
    // Restoring the server session says nothing about the key. Reporting
    // unlocked here skipped the passphrase prompt — isLocked() is exactly what
    // useReunlock's default key check reads — and then failed the signature.
    const KEY = '1111111111111111111111111111111111111111111111111111111111111111';
    const session = createNapSession({
      baseUrl: 'https://merchant.example.com',
      signer: createPrivateKeySessionSigner(KEY),
      fetch: authFetch(),
      keyStore: { hasKey: async () => true, loadKey: async () => KEY },
    });

    await session.login();
    session.lock();
    expect(session.isLocked()).toBe(true);

    await session.resume();

    expect(session.isLocked()).toBe(true);
  });
});
