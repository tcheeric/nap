import { describe, expect, it } from 'vitest';
import { DEFAULT_PERMISSIONS, connectWithNostrConnect } from '../src/connection.js';
import { toNip46Error } from '../src/errors.js';
import { createWebCryptoSecretStore } from '../src/webCryptoSecretStore.js';
import { FakeBunker } from './fakeBunker.js';

const RELAY = 'wss://relay.example';

function parseNostrConnect(uri: string): { clientPubkey: string; secret: string } {
  const url = new URL(uri);
  return { clientPubkey: url.hostname, secret: url.searchParams.get('secret') ?? '' };
}

function memoryStorage(): Pick<Storage, 'getItem' | 'setItem' | 'removeItem'> {
  const entries = new Map<string, string>();

  return {
    getItem: (key) => entries.get(key) ?? null,
    setItem: (key, value) => {
      entries.set(key, value);
    },
    removeItem: (key) => {
      entries.delete(key);
    },
  };
}

describe('nostrconnect:// approval challenge', () => {
  it('hands over an auth_url and keeps waiting for the real answer', async () => {
    // A signer that approves in a browser tab (nsec.app and friends) answers the
    // URI with `auth_url` first. There is no BunkerSigner yet to route that
    // through `onauth`, so the wait itself has to.
    const bunker = new FakeBunker();
    const seen: string[] = [];

    const connection = await connectWithNostrConnect({
      pool: bunker.pool,
      permissions: DEFAULT_PERMISSIONS,
      connectTimeoutMs: 500,
      relays: [RELAY],
      onAuthUrl: (url) => {
        seen.push(url);
      },
      onUri: (uri) => {
        const { clientPubkey, secret } = parseNostrConnect(uri);
        bunker.announceAuthUrl(clientPubkey, 'https://signer.example/approve');
        bunker.announceNostrConnect(clientPubkey, secret);
      },
    });

    expect(seen).toEqual(['https://signer.example/approve']);
    expect(connection.pointer.pubkey).toBe(bunker.pubkey);
  });

  it('does not mistake an approval challenge for a wrong secret', async () => {
    const bunker = new FakeBunker();

    await expect(
      connectWithNostrConnect({
        pool: bunker.pool,
        permissions: DEFAULT_PERMISSIONS,
        connectTimeoutMs: 20,
        relays: [RELAY],
        onUri: (uri) => {
          bunker.announceAuthUrl(
            parseNostrConnect(uri).clientPubkey,
            'https://signer.example/approve'
          );
        },
      })
      // The user simply never approved: that is silence, not a hostile signer.
    ).rejects.toMatchObject({ code: 'TIMEOUT' });
  });

  it('pairs even when the pool delivers from inside subscribe()', async () => {
    // Reading the subscription handle from the settle path before subscribe()
    // returns is a ReferenceError, and it lands inside a catch that treats every
    // throw as an undecryptable event — so the symptom is a spurious timeout.
    const bunker = new FakeBunker({ synchronousDelivery: true });

    const connection = await connectWithNostrConnect({
      pool: bunker.pool,
      permissions: DEFAULT_PERMISSIONS,
      connectTimeoutMs: 500,
      relays: [RELAY],
      onUri: (uri) => {
        const { clientPubkey, secret } = parseNostrConnect(uri);
        bunker.announceNostrConnect(clientPubkey, secret);
      },
    });

    expect(connection.pointer.pubkey).toBe(bunker.pubkey);
  });
});

describe('stored envelope hardening', () => {
  it('refuses a record whose iteration count would hang the tab', async () => {
    const storage = memoryStorage();
    const store = createWebCryptoSecretStore('nap-nip46', { storage, iterations: 1_000 });

    await store.save('the pairing', 'passphrase');
    await expect(store.load('passphrase')).resolves.toBe('the pairing');

    // Anything that can write this key chooses the KDF cost on our next load.
    const poisoned = JSON.parse(storage.getItem('nap-nip46') as string) as {
      kdf: { iterations: number };
    };
    poisoned.kdf.iterations = 2_000_000_000;
    storage.setItem('nap-nip46', JSON.stringify(poisoned));

    await expect(store.load('passphrase')).resolves.toBeNull();
  });
});

describe('error classification', () => {
  it('reads a refusal that mentions the connection as a decline', () => {
    expect(toNip46Error(new Error('user denied the connection'), 'fallback')).toMatchObject({
      code: 'DECLINED',
    });
    expect(toNip46Error(new Error('connection refused'), 'fallback')).toMatchObject({
      code: 'UNREACHABLE',
    });
  });
});
