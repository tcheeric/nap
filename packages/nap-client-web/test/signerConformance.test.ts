import { describe, expect, it, vi } from 'vitest';
import { generateSecretKey, getPublicKey, finalizeEvent, nip19 } from 'nostr-tools';
import { bytesToHex } from '@imani/nap-core';
import { createNip07Signer } from '../src/nip07.js';
import { createPrivateKeySessionSigner } from '../src/signers.js';
import { createNapSession } from '../src/session.js';
import { runSignerConformance } from './signerConformance.js';

const PRIVATE_KEY = generateSecretKey();

// Mutable: the extension is free to switch accounts under a signer that already
// exists, which is the whole point of the freshness case below.
let extensionKey = generateSecretKey();

runSignerConformance({
  name: 'private key in the page',
  keyFree: false,
  create: () => createPrivateKeySessionSigner(bytesToHex(PRIVATE_KEY)),
  // No rotateIdentity: setKey() rejects a key that is not this signer's, so the
  // identity behind it cannot change without constructing a new signer.
});

runSignerConformance({
  name: 'NIP-07 extension',
  keyFree: true,
  create: () =>
    createNip07Signer({
      getPublicKey: async () => getPublicKey(extensionKey),
      signEvent: async (event) => finalizeEvent(event, extensionKey),
    }),
  rotateIdentity: () => {
    extensionKey = generateSecretKey();
  },
});

describe('resume never reaches the signer', () => {
  it('restores a session without a signature (FR-024)', async () => {
    const pubkey = getPublicKey(extensionKey);
    const signEvent = vi.fn(async (event) => finalizeEvent(event, extensionKey));
    const getNpub = vi.fn(async () => nip19.npubEncode(pubkey));

    const session = createNapSession({
      baseUrl: 'https://merchant.example.com',
      signer: { getNpub, signEvent },
      fetch: vi.fn<typeof fetch>().mockResolvedValue(new Response(JSON.stringify({
        status: 'ok',
        expires_at: 1_710_000_900,
        principal: { npub: nip19.npubEncode(pubkey), pubkey },
        roles: [],
        permissions: [],
      }), { status: 200 })),
    });

    await session.resume();

    expect(session.isAuthenticated()).toBe(true);
    expect(signEvent).not.toHaveBeenCalled();
    expect(getNpub).not.toHaveBeenCalled();
  });
});
