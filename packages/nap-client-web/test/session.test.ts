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

describe('nap-client-web', () => {
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
      fetch: vi.fn<typeof fetch>(),
      keyStore: {
        hasKey: async () => true,
        loadKey: async () => KEY,
      },
    });

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
    const fetchMock = vi.fn<typeof fetch>();
    const signer = createPrivateKeySessionSigner(
      '1111111111111111111111111111111111111111111111111111111111111111'
    );
    const session = createNapSession({
      baseUrl: 'https://merchant.example.com',
      signer,
      fetch: fetchMock,
    });

    session.lock();

    await expect(session.login()).rejects.toThrow(SessionLockedError);
    // Must fail before touching the network, or the session would claim to be
    // unlocked while signing was impossible.
    expect(fetchMock).not.toHaveBeenCalled();
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

  it('treats a signer with no key in the page as nothing to evict', () => {
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
      fetch: vi.fn<typeof fetch>(),
    });

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

    await session.resume();
    expect(onLogin).toHaveBeenCalledTimes(2);

    // A resume that finds no session must not report a login.
    await session.resume();
    expect(onLogin).toHaveBeenCalledTimes(2);
  });
});
