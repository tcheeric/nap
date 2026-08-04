import { describe, expect, it, vi } from 'vitest';
import { nip19 } from 'nostr-tools';
import { createNapSession } from '../src/session.js';
import { IdentityMismatchError } from '../src/types.js';
import type { SessionSigner } from '../src/types.js';

const PUBKEY_A = 'a'.repeat(64);
const PUBKEY_B = 'b'.repeat(64);
const NPUB_A = nip19.npubEncode(PUBKEY_A);
const NPUB_B = nip19.npubEncode(PUBKEY_B);

function signerFor(read: () => string): SessionSigner {
  return {
    async getNpub() {
      return read();
    },
    async signEvent(event) {
      return { ...event, id: 'event-id', pubkey: PUBKEY_A, sig: 'sig' };
    },
  };
}

function challenge(): Response {
  return new Response(JSON.stringify({
    challenge_id: 'challenge-1',
    challenge: 'challenge',
    auth_url: 'https://merchant.example.com/auth/complete',
    auth_method: 'POST',
    issued_at: 1_710_000_000,
    expires_at: 1_710_000_060,
  }), { status: 200 });
}

function authSuccess(npub: string, pubkey: string): Response {
  return new Response(JSON.stringify({
    status: 'ok',
    expires_at: 1_710_000_900,
    principal: { npub, pubkey },
    roles: ['merchant'],
    permissions: ['voucher:create'],
  }), { status: 200 });
}

describe('identity guard', () => {
  it('rejects a signer that switched accounts before spending a challenge', async () => {
    let npub = NPUB_A;
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(challenge())
      .mockResolvedValueOnce(authSuccess(NPUB_A, PUBKEY_A));

    const session = createNapSession({
      baseUrl: 'https://merchant.example.com',
      signer: signerFor(() => npub),
      fetch: fetchMock,
      broadcast: { enabled: false },
    });

    await session.login();
    expect(fetchMock).toHaveBeenCalledTimes(2);

    npub = NPUB_B;

    await expect(session.login()).rejects.toThrow(IdentityMismatchError);

    // The guard must fire before /auth/init — no challenge is issued for an
    // identity the session is about to refuse.
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('carries the expected and actual pubkeys on the error', async () => {
    let npub = NPUB_A;
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(challenge())
      .mockResolvedValueOnce(authSuccess(NPUB_A, PUBKEY_A));

    const session = createNapSession({
      baseUrl: 'https://merchant.example.com',
      signer: signerFor(() => npub),
      fetch: fetchMock,
      broadcast: { enabled: false },
    });

    await session.login();
    npub = NPUB_B;

    await expect(session.login()).rejects.toMatchObject({
      code: 'IDENTITY_MISMATCH',
      expectedPubkey: PUBKEY_A,
      actualPubkey: PUBKEY_B,
    });
  });

  it('terminates the session when the server reports a different pubkey', async () => {
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(challenge())
      .mockResolvedValueOnce(authSuccess(NPUB_A, PUBKEY_A))
      .mockResolvedValueOnce(challenge())
      // Same npub claimed, different key actually signed.
      .mockResolvedValueOnce(authSuccess(NPUB_A, PUBKEY_B));

    const session = createNapSession({
      baseUrl: 'https://merchant.example.com',
      signer: signerFor(() => NPUB_A),
      fetch: fetchMock,
      broadcast: { enabled: false },
    });

    await session.login();

    await expect(session.login()).rejects.toThrow(IdentityMismatchError);
    expect(session.getSession()).toBeNull();
    expect(session.isAuthenticated()).toBe(false);
  });

  it('clears state, notifies, and issues no logout request', async () => {
    let npub = NPUB_A;
    const onIdentityChanged = vi.fn();
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(challenge())
      .mockResolvedValueOnce(authSuccess(NPUB_A, PUBKEY_A));

    const session = createNapSession({
      baseUrl: 'https://merchant.example.com',
      signer: signerFor(() => npub),
      fetch: fetchMock,
      onIdentityChanged,
      broadcast: { enabled: false },
    });

    await session.login();
    npub = NPUB_B;
    await expect(session.login()).rejects.toThrow(IdentityMismatchError);

    expect(session.getSession()).toBeNull();
    expect(session.isAuthenticated()).toBe(false);
    expect(onIdentityChanged).toHaveBeenCalledWith({
      expectedPubkey: PUBKEY_A,
      actualPubkey: PUBKEY_B,
    });

    // The server session belongs to the old identity and the cookie is
    // HttpOnly; a round trip that can fail must not gate local teardown.
    const urls = fetchMock.mock.calls.map(([input]) => String(input));
    expect(urls.some((url) => url.endsWith('/auth/logout'))).toBe(false);
  });

  it('does not trip on a first login', async () => {
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(challenge())
      .mockResolvedValueOnce(authSuccess(NPUB_B, PUBKEY_B));

    const session = createNapSession({
      baseUrl: 'https://merchant.example.com',
      signer: signerFor(() => NPUB_B),
      fetch: fetchMock,
      broadcast: { enabled: false },
    });

    // No established session means no identity to contradict.
    await expect(session.login()).resolves.toMatchObject({
      principal: { pubkey: PUBKEY_B },
    });
  });

  it('propagates a mismatch to other tabs', async () => {
    const channelName = `nap-identity-${Math.floor(Math.random() * 1e9)}`;
    let npub = NPUB_A;

    const firstFetch = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(challenge())
      .mockResolvedValueOnce(authSuccess(NPUB_A, PUBKEY_A));
    const secondFetch = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(challenge())
      .mockResolvedValueOnce(authSuccess(NPUB_A, PUBKEY_A));

    let notifyOtherTab: (detail: { expectedPubkey: string }) => void = () => {};
    const otherTabNotified = new Promise<{ expectedPubkey: string }>((resolve) => {
      notifyOtherTab = resolve;
    });

    const firstTab = createNapSession({
      baseUrl: 'https://merchant.example.com',
      signer: signerFor(() => npub),
      fetch: firstFetch,
      broadcast: { enabled: true, channelName },
    });
    const secondTab = createNapSession({
      baseUrl: 'https://merchant.example.com',
      signer: signerFor(() => NPUB_A),
      fetch: secondFetch,
      broadcast: { enabled: true, channelName },
      onIdentityChanged: (detail) => notifyOtherTab(detail),
    });

    try {
      await firstTab.login();
      await secondTab.login();
      expect(secondTab.isAuthenticated()).toBe(true);

      npub = NPUB_B;
      await expect(firstTab.login()).rejects.toThrow(IdentityMismatchError);

      await expect(otherTabNotified).resolves.toMatchObject({
        expectedPubkey: PUBKEY_A,
      });
      expect(secondTab.isAuthenticated()).toBe(false);
    } finally {
      firstTab.destroy();
      secondTab.destroy();
    }
  });
});
