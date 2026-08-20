import { describe, expect, it } from 'vitest';
import { getSignerCapabilities } from '../src/signerCapabilities.js';
import type { Nip07Provider } from '../src/nip07.js';
import type { KeyStore } from '../src/keyStore.js';

const provider: Nip07Provider = {
  getPublicKey: async () => 'a'.repeat(64),
  signEvent: async (event) => ({ ...event, id: 'id', pubkey: 'a'.repeat(64), sig: 'sig' }),
};

const keyStore: KeyStore = {
  loadKey: async () => 'f'.repeat(64),
  hasKey: async () => true,
};

describe('getSignerCapabilities', () => {
  it('reports nip07 from detection and the other two from what the app declared', async () => {
    expect(
      await getSignerCapabilities({ window: { nostr: provider }, nip46: true, keyStore })
    ).toEqual({ nip07: true, nip46: true, localKey: true });
  });

  it('an absent extension does not mean no signer', async () => {
    expect(
      await getSignerCapabilities({
        window: {},
        timeoutMs: 20,
        pollIntervalMs: 5,
        nip46: true,
      })
    ).toEqual({ nip07: false, nip46: true, localKey: false });
  });

  it('defaults every undeclared capability to false', async () => {
    expect(await getSignerCapabilities({ window: {}, timeoutMs: 20, pollIntervalMs: 5 })).toEqual({
      nip07: false,
      nip46: false,
      localKey: false,
    });
  });
});
