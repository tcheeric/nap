import { describe, expect, it, vi } from 'vitest';
import { nip19 } from 'nostr-tools';
import { createNapSession } from '../src/index.js';
import { AuthRequestError } from '../src/httpClient.js';
import type { SignerPreference, SignerPreferenceStore } from '../src/signerPreference.js';
import { IdentityMismatchError, type SessionSigner } from '../src/types.js';

const PUBKEY = 'a'.repeat(64);
const NPUB = nip19.npubEncode(PUBKEY);
const NPUB_OTHER = nip19.npubEncode('b'.repeat(64));

function createSigner(read: () => string = () => NPUB): SessionSigner {
  return {
    getNpub: read,
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

function preferenceStore(): SignerPreferenceStore & { cleared: number } {
  let record: SignerPreference | null = { kind: 'nip07', npub: NPUB, savedAt: 1 };

  return {
    cleared: 0,
    read: () => record,
    write: (kind, npub) => (record = { kind, npub, savedAt: 1 }),
    clear() {
      record = null;
      this.cleared += 1;
    },
  };
}

/** `status` applies to /auth/complete; /auth/init always succeeds. */
function completeWith(status: number, body: unknown = { status: 'error' }) {
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

    return new Response(JSON.stringify(body), { status });
  });
}

function sessionWith(
  fetchMock: ReturnType<typeof completeWith>,
  signerPreference: SignerPreferenceStore
) {
  return createNapSession({
    baseUrl: 'https://merchant.example.com',
    signer: createSigner(),
    signerPreference,
    fetch: fetchMock,
  });
}

describe('signer preference clearing', () => {
  it('clears the remembered signer when the server refuses the completion', async () => {
    const store = preferenceStore();
    const session = sessionWith(completeWith(401), store);

    await expect(session.login()).rejects.toMatchObject({
      name: 'AuthRequestError',
      phase: 'complete',
      status: 401,
      terminal: true,
    });
    expect(store.read()).toBeNull();
  });

  it('keeps it when a retry could still succeed', async () => {
    // A 5xx and a rate limit are the flaky-relay and the busy-server cases. The
    // login is still the right one to offer; forgetting it here would send a
    // user who did nothing wrong back to the signer picker.
    for (const status of [429, 500, 503]) {
      const store = preferenceStore();
      const session = sessionWith(completeWith(status), store);

      await expect(session.login()).rejects.toBeInstanceOf(AuthRequestError);
      expect(store.read(), `status ${status}`).not.toBeNull();
      expect(store.cleared, `status ${status}`).toBe(0);
    }
  });

  it('keeps it when the signer never answered', async () => {
    // getNpub() throwing is a bunker that did not reply. Nothing reached the
    // server, so nothing rejected this identity.
    const store = preferenceStore();
    const session = createNapSession({
      baseUrl: 'https://merchant.example.com',
      signer: {
        getNpub: () => Promise.reject(new Error('relay timeout')),
        signEvent: () => Promise.reject(new Error('unreachable')),
      },
      signerPreference: store,
      fetch: completeWith(200),
    });

    await expect(session.login()).rejects.toThrow('relay timeout');
    expect(store.cleared).toBe(0);
  });

  it('clears a terminal /auth/init failure too', async () => {
    const store = preferenceStore();
    const fetchMock = vi.fn<typeof fetch>(
      async () => new Response(JSON.stringify({ status: 'error' }), { status: 400 })
    );

    await expect(sessionWith(fetchMock, store).login()).rejects.toMatchObject({
      phase: 'init',
      terminal: true,
    });
    expect(store.read()).toBeNull();
  });

  it('clears when the identity guard terminates the session', async () => {
    // The kind is still right, but the npub in the record is now somebody
    // else's — and an account switch is exactly when the page must stop
    // offering "continue as" the previous identity.
    const store = preferenceStore();
    let npub = NPUB;
    const session = createNapSession({
      baseUrl: 'https://merchant.example.com',
      signer: createSigner(() => npub),
      signerPreference: store,
      broadcast: { enabled: false },
      fetch: completeWith(200, {
        status: 'ok',
        expires_at: 1_710_000_900,
        principal: { npub: NPUB, pubkey: PUBKEY },
        roles: [],
        permissions: [],
      }),
    });

    await session.login();
    expect(store.read()).not.toBeNull();

    npub = NPUB_OTHER;
    await expect(session.login()).rejects.toThrow(IdentityMismatchError);
    expect(store.read()).toBeNull();
  });

  it('survives a session wired without a preference store', async () => {
    const session = createNapSession({
      baseUrl: 'https://merchant.example.com',
      signer: createSigner(),
      fetch: completeWith(401),
    });

    await expect(session.login()).rejects.toBeInstanceOf(AuthRequestError);
  });
});
