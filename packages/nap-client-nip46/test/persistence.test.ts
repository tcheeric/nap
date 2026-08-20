import { describe, expect, it } from 'vitest';
import { generateSecretKey } from 'nostr-tools';
import { bytesToHex } from '@imani/nap-core';
import { createWebCryptoSecretStore } from '@imani/nap-client-web';
import {
  CONNECTION_RECORD_VERSION,
  loadConnection,
  saveConnection,
  toPointer,
} from '../src/persistence.js';

const KEY = 'nap-nip46-connection';

function memoryStorage(): Pick<Storage, 'getItem' | 'setItem' | 'removeItem'> & {
  raw(): string | null;
} {
  const entries = new Map<string, string>();

  return {
    getItem: (key) => entries.get(key) ?? null,
    setItem: (key, value) => {
      entries.set(key, value);
    },
    removeItem: (key) => {
      entries.delete(key);
    },
    raw: () => entries.get(KEY) ?? null,
  };
}

function store(storage: ReturnType<typeof memoryStorage>) {
  // A low iteration count keeps the suite fast; the default is asserted below.
  return createWebCryptoSecretStore(KEY, { storage, iterations: 1_000 });
}

describe('web crypto secret store', () => {
  it('round-trips a value through a passphrase', async () => {
    const storage = memoryStorage();
    const secretStore = store(storage);

    await secretStore.save('the-plaintext', 'correct horse');

    await expect(secretStore.load('correct horse')).resolves.toBe('the-plaintext');
  });

  it('returns null for a wrong passphrase rather than throwing', async () => {
    const storage = memoryStorage();
    const secretStore = store(storage);

    await secretStore.save('the-plaintext', 'correct horse');

    // A forgotten passphrase must degrade to "pair again", not to an exception
    // the caller has to know about (FR-011a).
    await expect(secretStore.load('wrong horse')).resolves.toBeNull();
  });

  it('writes no plaintext to storage', async () => {
    const storage = memoryStorage();
    const clientSecretKey = bytesToHex(generateSecretKey());

    await store(storage).save(clientSecretKey, 'passphrase');

    const written = storage.raw() ?? '';
    expect(written).not.toContain(clientSecretKey);
    expect(written).not.toContain('passphrase');
  });

  it('uses a fresh salt and IV per write', async () => {
    const storage = memoryStorage();
    const secretStore = store(storage);

    await secretStore.save('same', 'passphrase');
    const first = JSON.parse(storage.raw() ?? '{}');
    await secretStore.save('same', 'passphrase');
    const second = JSON.parse(storage.raw() ?? '{}');

    expect(second.kdf.salt).not.toBe(first.kdf.salt);
    expect(second.iv).not.toBe(first.iv);
    expect(second.ciphertext).not.toBe(first.ciphertext);
  });

  it('records the derivation parameters so they can be raised later', async () => {
    const storage = memoryStorage();

    await createWebCryptoSecretStore(KEY, { storage }).save('value', 'passphrase');

    expect(JSON.parse(storage.raw() ?? '{}').kdf).toMatchObject({
      name: 'PBKDF2',
      hash: 'SHA-256',
      iterations: 310_000,
    });
  });

  it('reports and clears presence', async () => {
    const storage = memoryStorage();
    const secretStore = store(storage);

    await expect(secretStore.has()).resolves.toBe(false);

    await secretStore.save('value', 'passphrase');
    await expect(secretStore.has()).resolves.toBe(true);

    await secretStore.clear();
    await expect(secretStore.has()).resolves.toBe(false);
    await expect(secretStore.load('passphrase')).resolves.toBeNull();
  });

  it('survives a corrupt record', async () => {
    const storage = memoryStorage();
    storage.setItem(KEY, 'not json');

    await expect(store(storage).load('passphrase')).resolves.toBeNull();
  });
});

describe('connection record', () => {
  const record = {
    bunkerPubkey: 'b'.repeat(64),
    relays: ['wss://relay.example'],
    secret: 'pairing-secret',
    clientSecretKey: bytesToHex(generateSecretKey()),
  };

  it('round-trips through the secret store', async () => {
    const storage = memoryStorage();
    const secretStore = store(storage);

    await saveConnection(secretStore, 'passphrase', record);
    const loaded = await loadConnection(secretStore, 'passphrase');

    expect(loaded).toMatchObject({ version: CONNECTION_RECORD_VERSION, ...record });
    expect(toPointer(loaded!)).toEqual({
      pubkey: record.bunkerPubkey,
      relays: record.relays,
      secret: record.secret,
    });
  });

  it('treats a record from an unknown version as absent', async () => {
    const storage = memoryStorage();
    const secretStore = store(storage);

    await secretStore.save(JSON.stringify({ ...record, version: 99 }), 'passphrase');

    await expect(loadConnection(secretStore, 'passphrase')).resolves.toBeNull();
  });

  it('treats an undecryptable record as absent', async () => {
    const storage = memoryStorage();
    const secretStore = store(storage);

    await saveConnection(secretStore, 'passphrase', record);

    await expect(loadConnection(secretStore, 'other passphrase')).resolves.toBeNull();
  });
});
