import { describe, expect, it } from 'vitest';
import { runSignerConformance } from '../../nap-client-web/test/signerConformance.js';
import { createNip46Signer, type Nip46Signer } from '../src/signer.js';
import { FakeBunker } from './fakeBunker.js';

const RELAY = 'wss://relay.example';

async function connectedSigner(): Promise<Nip46Signer> {
  const bunker = new FakeBunker();
  const signer = createNip46Signer({
    connectionToken: `bunker://${bunker.pubkey}?relay=${RELAY}&secret=pairing-secret`,
    pool: bunker.pool,
    connectTimeoutMs: 500,
    signTimeoutMs: 500,
  });

  await signer.connect();
  return signer;
}

runSignerConformance({
  name: 'NIP-46 remote signer',
  keyFree: true,
  create: connectedSigner,
});

describe('signers are interchangeable', () => {
  it('exposes nothing beyond SessionSigner that the session depends on', async () => {
    const signer = await connectedSigner();

    // The session only ever reaches for these two. Everything else on the
    // NIP-46 signer is pairing lifecycle the application drives (FR-010).
    expect(typeof signer.getNpub).toBe('function');
    expect(typeof signer.signEvent).toBe('function');
  });

  it('prompts the remote signer exactly once per login', async () => {
    const bunker = new FakeBunker();
    const signer = createNip46Signer({
      connectionToken: `bunker://${bunker.pubkey}?relay=${RELAY}&secret=pairing-secret`,
      pool: bunker.pool,
      connectTimeoutMs: 500,
      signTimeoutMs: 500,
    });

    await signer.connect();
    await signer.getNpub();
    await signer.signEvent({
      kind: 27235,
      tags: [['u', 'https://merchant.example.com/auth/complete'], ['method', 'POST']],
      content: '',
      created_at: 1_710_000_000,
    });

    // SC-008: one signature request, however many times the npub was read.
    const signRequests = bunker.requests.filter((request) => request.method === 'sign_event');
    expect(signRequests).toHaveLength(1);
  });
});
