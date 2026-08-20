import { describe, expect, it, vi } from 'vitest';
import { nip19 } from 'nostr-tools';
import {
  Nip07Error,
  createNip07Signer,
  detectNip07Provider,
  type Nip07Provider,
} from '../src/nip07.js';

const PUBKEY = 'a'.repeat(64);

function provider(overrides: Partial<Nip07Provider> = {}): Nip07Provider {
  return {
    getPublicKey: async () => PUBKEY,
    signEvent: async (event) => ({
      ...event,
      id: 'event-id',
      pubkey: PUBKEY,
      sig: 'sig',
    }),
    ...overrides,
  };
}

describe('detectNip07Provider', () => {
  it('finds a provider injected after the call', async () => {
    const target: { nostr?: Nip07Provider } = {};
    const injected = provider();

    setTimeout(() => {
      target.nostr = injected;
    }, 300);

    const started = Date.now();
    const found = await detectNip07Provider({ window: target, timeoutMs: 3_000, pollIntervalMs: 10 });

    expect(found).toBe(injected);
    // Resolving the moment the provider appears, not at the deadline, is the
    // whole point — a page that waits the full budget feels broken.
    expect(Date.now() - started).toBeLessThan(1_500);
  });

  it('resolves immediately when a provider is already present', async () => {
    const injected = provider();

    await expect(
      detectNip07Provider({ window: { nostr: injected }, timeoutMs: 3_000 })
    ).resolves.toBe(injected);
  });

  it('resolves null when nothing appears, without throwing', async () => {
    await expect(
      detectNip07Provider({ window: {}, timeoutMs: 30, pollIntervalMs: 5 })
    ).resolves.toBeNull();
  });

  it('ignores a window.nostr that is not a usable provider', async () => {
    const target = { nostr: { getPublicKey: 'nope' } as unknown as Nip07Provider };

    await expect(
      detectNip07Provider({ window: target, timeoutMs: 30, pollIntervalMs: 5 })
    ).resolves.toBeNull();
  });
});

describe('NIP-07 failure classification', () => {
  it('reports a rejected prompt as DECLINED', async () => {
    const signer = createNip07Signer(provider({
      signEvent: async () => {
        throw new Error('User rejected the request');
      },
    }));

    await expect(
      signer.signEvent({ kind: 27235, tags: [], content: '', created_at: 0 })
    ).rejects.toMatchObject({ code: 'DECLINED' });
  });

  it('reports an unrecognised failure as PROVIDER_ERROR', async () => {
    const signer = createNip07Signer(provider({
      signEvent: async () => {
        throw new Error('something went sideways');
      },
    }));

    await expect(
      signer.signEvent({ kind: 27235, tags: [], content: '', created_at: 0 })
    ).rejects.toMatchObject({ code: 'PROVIDER_ERROR' });
  });

  it('lets classifyError override the heuristic', async () => {
    const signer = createNip07Signer(
      provider({
        signEvent: async () => {
          throw new Error('nope');
        },
      }),
      { classifyError: () => 'DECLINED' }
    );

    await expect(
      signer.signEvent({ kind: 27235, tags: [], content: '', created_at: 0 })
    ).rejects.toMatchObject({ code: 'DECLINED' });
  });

  it('falls back to the heuristic when classifyError returns undefined', async () => {
    const classifyError = vi.fn(() => undefined);
    const signer = createNip07Signer(
      provider({
        signEvent: async () => {
          throw new Error('User denied');
        },
      }),
      { classifyError }
    );

    await expect(
      signer.signEvent({ kind: 27235, tags: [], content: '', created_at: 0 })
    ).rejects.toMatchObject({ code: 'DECLINED' });
    expect(classifyError).toHaveBeenCalled();
  });

  it('reports a prompt that is never answered as TIMEOUT', async () => {
    const signer = createNip07Signer(
      provider({ signEvent: () => new Promise<never>(() => {}) }),
      { requestTimeoutMs: 20 }
    );

    await expect(
      signer.signEvent({ kind: 27235, tags: [], content: '', created_at: 0 })
    ).rejects.toMatchObject({ code: 'TIMEOUT' });
  });

  it('distinguishes a locked extension from an absent one', async () => {
    const signer = createNip07Signer(provider({
      getPublicKey: async () => {
        throw new Error('extension is locked');
      },
    }));

    // Present but unusable is PROVIDER_ERROR — "unlock your extension" is a
    // different instruction from "install one" (NOT_AVAILABLE).
    await expect(signer.getNpub()).rejects.toMatchObject({ code: 'PROVIDER_ERROR' });
  });

  it('raises Nip07Error, carrying the original as cause', async () => {
    const cause = new Error('boom');
    const signer = createNip07Signer(provider({
      getPublicKey: async () => {
        throw cause;
      },
    }));

    await expect(signer.getNpub()).rejects.toThrow(Nip07Error);
    await expect(signer.getNpub()).rejects.toMatchObject({ cause });
  });
});

describe('createNip07Signer', () => {
  it('encodes the provider pubkey as an npub', async () => {
    const signer = createNip07Signer(provider());

    await expect(signer.getNpub()).resolves.toBe(nip19.npubEncode(PUBKEY));
  });
});
