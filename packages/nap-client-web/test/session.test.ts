import { describe, expect, it, vi } from 'vitest';
import { createNapSession } from '../src/index.js';
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
});
