import { describe, expect, it, vi } from 'vitest';
import { nip19 } from 'nostr-tools';
import { createNapSession } from '../src/session.js';
import {
  createNip07Signer,
  createNip07SignerFromWindow,
  type Nip07Provider,
} from '../src/nip07.js';

const PUBKEY = 'b'.repeat(64);
const NPUB = nip19.npubEncode(PUBKEY);

function authSuccess(): Response {
  return new Response(JSON.stringify({
    status: 'ok',
    expires_at: 1_710_000_900,
    principal: { npub: NPUB, pubkey: PUBKEY },
    roles: [],
    permissions: [],
  }), { status: 200 });
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

describe('createNip07Signer', () => {
  it('forwards the template to the provider untouched', async () => {
    const signEvent = vi.fn(async (event) => ({
      ...event,
      id: 'event-id',
      pubkey: PUBKEY,
      sig: 'sig',
    }));
    const signer = createNip07Signer({ getPublicKey: async () => PUBKEY, signEvent });

    const template = {
      kind: 27235,
      tags: [['u', 'https://merchant.example.com/auth/complete'], ['method', 'POST']],
      content: '',
      created_at: 1_710_000_000,
    };

    await signer.signEvent(template);

    expect(signEvent).toHaveBeenCalledWith(template);
  });

  it('touches only getPublicKey and signEvent on the provider', async () => {
    const calls: string[] = [];
    const nostr = new Proxy({
      getPublicKey: async () => PUBKEY,
      signEvent: async (event: { kind: number }) => ({
        ...event, id: 'event-id', pubkey: PUBKEY, sig: 'sig', tags: [], content: '', created_at: 0,
      }),
    } as unknown as Nip07Provider, {
      get(target, property, receiver) {
        calls.push(String(property));
        return Reflect.get(target, property, receiver);
      },
    });

    const signer = createNip07Signer(nostr);
    await signer.getNpub();
    await signer.signEvent({ kind: 27235, tags: [], content: '', created_at: 0 });

    expect(new Set(calls)).toEqual(new Set(['getPublicKey', 'signEvent']));
  });

  it('reads the provider on every getNpub so an account switch is visible', async () => {
    let pubkey = PUBKEY;
    const signer = createNip07Signer({
      getPublicKey: async () => pubkey,
      signEvent: async (event) => ({ ...event, id: 'id', pubkey, sig: 'sig' }),
    });

    expect(await signer.getNpub()).toBe(NPUB);

    pubkey = 'c'.repeat(64);

    // Caching here would make the identity guard blind to a switched account.
    expect(await signer.getNpub()).toBe(nip19.npubEncode('c'.repeat(64)));
  });
});

describe('createNip07SignerFromWindow', () => {
  it('throws NOT_AVAILABLE when no provider appears', async () => {
    await expect(
      createNip07SignerFromWindow({ window: {}, timeoutMs: 30, pollIntervalMs: 5 })
    ).rejects.toMatchObject({ code: 'NOT_AVAILABLE' });
  });

  it('wraps a provider that is present', async () => {
    const signer = await createNip07SignerFromWindow({
      window: {
        nostr: {
          getPublicKey: async () => PUBKEY,
          signEvent: async (event) => ({ ...event, id: 'id', pubkey: PUBKEY, sig: 'sig' }),
        },
      },
      timeoutMs: 30,
    });

    await expect(signer.getNpub()).resolves.toBe(NPUB);
  });
});

describe('NIP-07 prompt count', () => {
  it('prompts exactly once for a login and not at all for a resume', async () => {
    const signEvent = vi.fn(async (event) => ({
      ...event, id: 'event-id', pubkey: PUBKEY, sig: 'sig',
    }));
    const fetchMock = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(challenge())
      .mockResolvedValueOnce(authSuccess())
      .mockResolvedValueOnce(authSuccess());

    const session = createNapSession({
      baseUrl: 'https://merchant.example.com',
      signer: createNip07Signer({ getPublicKey: async () => PUBKEY, signEvent }),
      fetch: fetchMock,
    });

    await session.login();
    expect(signEvent).toHaveBeenCalledTimes(1);

    // FR-024: resuming an existing session must not reach the signer at all.
    await session.resume();
    expect(signEvent).toHaveBeenCalledTimes(1);
  });
});
