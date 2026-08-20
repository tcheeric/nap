import { describe, expect, it, vi } from 'vitest';
import { createSignerPreferenceStore } from '../src/signerPreference.js';

function memoryStorage(seed: Record<string, string> = {}) {
  const data = new Map(Object.entries(seed));
  return {
    getItem: (k: string) => data.get(k) ?? null,
    setItem: (k: string, v: string) => void data.set(k, v),
    removeItem: (k: string) => void data.delete(k),
    data,
  };
}

const NPUB = 'npub1w0rakxc1pn2xqzjfnfr6nq5s8sq7ghpxq9v9dqxfhq4dq0zqzqqsn9rc0q';

describe('signer preference store', () => {
  it('round-trips a choice', () => {
    const storage = memoryStorage();
    const store = createSignerPreferenceStore('k', { storage, now: () => 1000 });

    store.write('nip46', NPUB);

    expect(store.read()).toEqual({ kind: 'nip46', npub: NPUB, savedAt: 1000 });
  });

  it('clears', () => {
    const storage = memoryStorage();
    const store = createSignerPreferenceStore('k', { storage });

    store.write('nip07', NPUB);
    store.clear();

    expect(store.read()).toBeNull();
  });

  // Anything able to write this key gets to put junk in it, and a newer build
  // may write a shape this one does not know. Neither is worth an exception on
  // a login screen — they mean "ask which signer", same as absent.
  it.each([
    ['not json', 'not json at all'],
    ['unknown kind', JSON.stringify({ kind: 'yubikey', npub: NPUB, savedAt: 1 })],
    ['missing npub', JSON.stringify({ kind: 'nip07', savedAt: 1 })],
    ['non-npub identity', JSON.stringify({ kind: 'nip07', npub: 'nsec1abc', savedAt: 1 })],
    ['null', 'null'],
  ])('reads null for a %s record', (_label, raw) => {
    const store = createSignerPreferenceStore('k', { storage: memoryStorage({ k: raw }) });
    expect(store.read()).toBeNull();
  });

  // Safari private mode has thrown on setItem; a partitioned frame can be denied
  // storage outright. Losing the preference costs one click, not the login page.
  it('survives a storage that throws on every operation', () => {
    const hostile = {
      getItem: () => {
        throw new Error('denied');
      },
      setItem: () => {
        throw new Error('denied');
      },
      removeItem: () => {
        throw new Error('denied');
      },
    };
    const store = createSignerPreferenceStore('k', { storage: hostile });

    expect(() => store.write('key', NPUB)).not.toThrow();
    expect(() => store.clear()).not.toThrow();
    expect(store.read()).toBeNull();
  });

  it('never writes anything but the kind, npub and timestamp', () => {
    const storage = memoryStorage();
    createSignerPreferenceStore('k', { storage }).write('key', NPUB);

    // This file must not become where somebody puts key material.
    expect(Object.keys(JSON.parse(storage.data.get('k')!)).sort()).toEqual([
      'kind',
      'npub',
      'savedAt',
    ]);
  });

  it('defaults the clock to Date.now', () => {
    const storage = memoryStorage();
    const before = Date.now();
    createSignerPreferenceStore('k', { storage }).write('nip07', NPUB);

    expect(vi.isMockFunction(Date.now)).toBe(false);
    expect(JSON.parse(storage.data.get('k')!).savedAt).toBeGreaterThanOrEqual(before);
  });
});
