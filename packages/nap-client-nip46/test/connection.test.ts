import { describe, expect, it } from 'vitest';
import {
  DEFAULT_PERMISSIONS,
  connectWithBunkerToken,
  connectWithNostrConnect,
} from '../src/connection.js';
import { FakeBunker } from './fakeBunker.js';

const RELAY = 'wss://relay.example';

function bunkerUrl(bunker: FakeBunker, secret = 'pairing-secret'): string {
  return `bunker://${bunker.pubkey}?relay=${RELAY}&secret=${secret}`;
}

function options(bunker: FakeBunker, connectTimeoutMs = 500) {
  return { pool: bunker.pool, permissions: DEFAULT_PERMISSIONS, connectTimeoutMs };
}

function parseNostrConnect(uri: string): { clientPubkey: string; secret: string } {
  const url = new URL(uri);
  return {
    clientPubkey: url.hostname,
    secret: url.searchParams.get('secret') ?? '',
  };
}

describe('bunker:// pairing', () => {
  it('sends connect with the secret and the scoped permission list', async () => {
    const bunker = new FakeBunker();

    const connection = await connectWithBunkerToken(bunkerUrl(bunker), options(bunker));

    expect(connection.pointer.pubkey).toBe(bunker.pubkey);
    expect(bunker.requests[0]).toEqual({
      method: 'connect',
      params: [bunker.pubkey, 'pairing-secret', 'sign_event:27235'],
    });
  });

  it('asks for nothing beyond signing the NIP-98 challenge', () => {
    // FR-015: a wider grant would be a permission the protocol never spends.
    expect(DEFAULT_PERMISSIONS).toEqual(['sign_event:27235']);
  });

  it('rejects a token that is not a bunker URL', async () => {
    const bunker = new FakeBunker();

    await expect(
      connectWithBunkerToken('https://example.com/not-a-bunker', options(bunker))
    ).rejects.toMatchObject({ code: 'INVALID_TOKEN' });
  });

  it('rejects a token that names no relay', async () => {
    const bunker = new FakeBunker();

    // Without a relay there is nowhere to send the request; failing now beats a
    // connect timeout fifteen seconds later.
    await expect(
      connectWithBunkerToken(`bunker://${bunker.pubkey}`, options(bunker))
    ).rejects.toMatchObject({ code: 'INVALID_TOKEN' });
  });

  it('reports a bunker that does not echo the pairing as SECRET_MISMATCH', async () => {
    const bunker = new FakeBunker({ mode: 'wrongSecret' });

    await expect(
      connectWithBunkerToken(bunkerUrl(bunker), options(bunker))
    ).rejects.toMatchObject({ code: 'SECRET_MISMATCH' });
  });

  it('reports a dead relay as UNREACHABLE', async () => {
    const bunker = new FakeBunker({ mode: 'unreachable' });

    await expect(
      connectWithBunkerToken(bunkerUrl(bunker), options(bunker))
    ).rejects.toMatchObject({ code: 'UNREACHABLE' });
  });

  it('reports a silent bunker as TIMEOUT', async () => {
    const bunker = new FakeBunker({ mode: 'silent' });

    await expect(
      connectWithBunkerToken(bunkerUrl(bunker), options(bunker, 20))
    ).rejects.toMatchObject({ code: 'TIMEOUT' });
  });
});

describe('nostrconnect:// pairing', () => {
  function nostrConnectOptions(bunker: FakeBunker) {
    return { ...options(bunker), relays: [RELAY] };
  }

  it('surfaces the URI before waiting and pairs with the signer that answers', async () => {
    const bunker = new FakeBunker();
    let seen: string | null = null;

    const connection = await connectWithNostrConnect({
      ...nostrConnectOptions(bunker),
      onUri: (uri) => {
        seen = uri;
        const { clientPubkey, secret } = parseNostrConnect(uri);
        bunker.announceNostrConnect(clientPubkey, secret);
      },
    });

    expect(seen).toMatch(/^nostrconnect:\/\//);
    expect(connection.pointer.pubkey).toBe(bunker.pubkey);
  });

  it('carries the scoped permissions in the URI', async () => {
    const bunker = new FakeBunker();
    let seen = '';

    await connectWithNostrConnect({
      ...nostrConnectOptions(bunker),
      onUri: (uri) => {
        seen = uri;
        const { clientPubkey, secret } = parseNostrConnect(uri);
        bunker.announceNostrConnect(clientPubkey, secret);
      },
    });

    expect(new URL(seen).searchParams.get('perms')).toBe('sign_event:27235');
  });

  it('distinguishes a wrong secret from silence', async () => {
    const bunker = new FakeBunker();

    // A signer that answers without the secret is not the one we invited, and
    // saying so beats reporting the same timeout as an absent signer.
    await expect(
      connectWithNostrConnect({
        ...nostrConnectOptions(bunker),
        connectTimeoutMs: 50,
        onUri: (uri) => {
          const { clientPubkey } = parseNostrConnect(uri);
          bunker.announceNostrConnect(clientPubkey, 'not-the-secret');
        },
      })
    ).rejects.toMatchObject({ code: 'SECRET_MISMATCH' });
  });

  it('classifies a decline as DECLINED rather than SECRET_MISMATCH', async () => {
    const bunker = new FakeBunker();

    await expect(
      connectWithNostrConnect({
        ...nostrConnectOptions(bunker),
        connectTimeoutMs: 60,
        onUri: (uri) => {
          const { clientPubkey } = parseNostrConnect(uri);
          bunker.declineNostrConnect(clientPubkey, 'user rejected');
        },
      })
    ).rejects.toMatchObject({ code: 'DECLINED', message: 'user rejected' });
  });

  it('does not let an unauthenticated error abort a pairing that then succeeds', async () => {
    const bunker = new FakeBunker();

    // The client pubkey is public — it is in the #p filter every relay sees and
    // in the URI the user scans — and NIP-44 conversation keys are ECDH, so any
    // party can send us something that decrypts. Settling on {error} therefore
    // handed every relay operator a kill switch on every pairing: reject, close
    // the subscription, and the real signer's ack lands on nothing.
    await expect(
      connectWithNostrConnect({
        ...nostrConnectOptions(bunker),
        connectTimeoutMs: 5_000,
        onUri: (uri) => {
          const { clientPubkey, secret } = parseNostrConnect(uri);
          bunker.declineNostrConnect(clientPubkey, 'denied by an impostor');
          bunker.announceNostrConnect(clientPubkey, secret);
        },
      })
    ).resolves.toBeTruthy();
  });

  it('times out when no signer answers', async () => {
    const bunker = new FakeBunker();

    await expect(
      connectWithNostrConnect({ ...nostrConnectOptions(bunker), connectTimeoutMs: 20 })
    ).rejects.toMatchObject({ code: 'TIMEOUT' });
  });

  it('refuses to generate a URI with no relay to listen on', async () => {
    const bunker = new FakeBunker();

    await expect(
      connectWithNostrConnect({ ...options(bunker), relays: [] })
    ).rejects.toMatchObject({ code: 'INVALID_TOKEN' });
  });
});
