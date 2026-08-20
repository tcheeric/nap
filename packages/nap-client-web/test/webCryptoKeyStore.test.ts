import { describe, expect, it } from 'vitest';
import { createWebCryptoKeyStore } from '../src/webCryptoSecretStore.js';
import { reunlock } from '../src/reunlock.js';
import type { KeyHolder } from '../src/keyStore.js';

function memoryStorage() {
  const data = new Map<string, string>();
  return {
    getItem: (k: string) => data.get(k) ?? null,
    setItem: (k: string, v: string) => void data.set(k, v),
    removeItem: (k: string) => void data.delete(k),
    data,
  };
}

const KEY = 'a'.repeat(64);

function store() {
  // Low iterations: this exercises the wiring, not PBKDF2's cost.
  return createWebCryptoKeyStore('nap-key', { storage: memoryStorage(), iterations: 1_000 });
}

function holder(): KeyHolder & { key: string | null } {
  return {
    key: null,
    setKey(k: string) {
      this.key = k;
    },
    clearKey() {
      this.key = null;
    },
    hasKey() {
      return this.key !== null;
    },
  };
}

describe('createWebCryptoKeyStore', () => {
  it('round-trips a key through the passphrase', async () => {
    const s = store();
    await s.save(KEY, 'correct horse');

    expect(await s.hasKey()).toBe(true);
    expect(await s.loadKey('correct horse')).toBe(KEY);
  });

  it('reports no key before enrolment', async () => {
    expect(await store().hasKey()).toBe(false);
  });

  it('never stores the key in plaintext', async () => {
    const storage = memoryStorage();
    const s = createWebCryptoKeyStore('nap-key', { storage, iterations: 1_000 });
    await s.save(KEY, 'pw');

    // RFC 1181: no plaintext key material at rest, localStorage included.
    expect(storage.data.get('nap-key')).not.toContain(KEY);
  });

  // The reason this is an adapter and not a cast. SecretStore.load() answers
  // null for a wrong passphrase, but reunlock() classifies by thrown error, and
  // anything it does not recognise becomes STORAGE_UNAVAILABLE — telling a user
  // who mistyped that their browser storage is broken.
  it('surfaces a wrong passphrase as INVALID_PASSPHRASE through reunlock', async () => {
    const s = store();
    await s.save(KEY, 'right');

    await expect(reunlock('wrong', s, holder())).rejects.toMatchObject({
      code: 'INVALID_PASSPHRASE',
    });
  });

  it('surfaces an empty store as NO_STORED_KEY through reunlock', async () => {
    await expect(reunlock('anything', store(), holder())).rejects.toMatchObject({
      code: 'NO_STORED_KEY',
    });
  });

  it('restores the key into the holder on the happy path', async () => {
    const s = store();
    const h = holder();
    await s.save(KEY, 'right');
    h.clearKey();

    await reunlock('right', s, h);

    expect(h.key).toBe(KEY);
  });

  // A record this build cannot read is neither "absent" nor "wrong passphrase",
  // and both wrong answers do harm: NO_STORED_KEY routes the app into
  // re-enrolment, whose save() overwrites the only copy of the ciphertext, and
  // INVALID_PASSPHRASE has the user retyping a passphrase that is correct.
  it.each([
    ['a newer envelope version', { version: 99 }],
    [
      'an out-of-band iteration count',
      { kdf: { name: 'PBKDF2', hash: 'SHA-256', iterations: 2e9, salt: 'AA==' } },
    ],
  ])('reports %s without discarding the record', async (_label, overrides) => {
    const storage = memoryStorage();
    const s = createWebCryptoKeyStore('nap-key', { storage, iterations: 1_000 });
    await s.save(KEY, 'pw');

    const envelope = JSON.parse(storage.data.get('nap-key')!);
    const unreadable = JSON.stringify({ ...envelope, ...overrides });
    storage.data.set('nap-key', unreadable);

    // Still present, so nothing routes the app into an overwriting re-enrolment.
    expect(await s.hasKey()).toBe(true);
    await expect(reunlock('pw', s, holder())).rejects.toMatchObject({
      code: 'STORAGE_UNAVAILABLE',
    });
    expect(storage.data.get('nap-key')).toBe(unreadable);
  });

  it('clears', async () => {
    const s = store();
    await s.save(KEY, 'pw');
    await s.clear();

    expect(await s.hasKey()).toBe(false);
  });
});
