import { describe, it, expect, vi } from 'vitest';
import { reunlock, ReunlockError } from '../src/reunlock.js';
import type { KeyStore, KeyHolder } from '../src/keyStore.js';

function mockKeyStore(key: string | null, passphrase: string): KeyStore {
  return {
    loadKey: async (p: string) => {
      if (!key) throw new Error('No stored key found');
      if (p !== passphrase) throw new Error('Invalid passphrase');
      return key;
    },
    hasKey: async () => key !== null,
  };
}

function mockKeyHolder(): KeyHolder & { getKey: () => string | null } {
  let held: string | null = null;
  return {
    setKey: (k: string) => { held = k; },
    clearKey: () => { held = null; },
    hasKey: () => held !== null,
    getKey: () => held,
  };
}

describe('reunlock', () => {
  it('decrypts and restores key to holder on success', async () => {
    const store = mockKeyStore('deadbeef', 'correct-pass');
    const holder = mockKeyHolder();

    const result = await reunlock('correct-pass', store, holder);

    expect(result).toEqual({ success: true });
    expect(holder.getKey()).toBe('deadbeef');
  });

  it('throws INVALID_PASSPHRASE on wrong passphrase', async () => {
    const store = mockKeyStore('deadbeef', 'correct-pass');
    const holder = mockKeyHolder();

    await expect(reunlock('wrong-pass', store, holder)).rejects.toThrow(ReunlockError);
    await expect(reunlock('wrong-pass', store, holder)).rejects.toMatchObject({
      code: 'INVALID_PASSPHRASE',
    });
    expect(holder.getKey()).toBeNull();
  });

  it('throws NO_STORED_KEY when store is empty', async () => {
    const store = mockKeyStore(null, 'any-pass');
    const holder = mockKeyHolder();

    await expect(reunlock('any-pass', store, holder)).rejects.toThrow(ReunlockError);
    await expect(reunlock('any-pass', store, holder)).rejects.toMatchObject({
      code: 'NO_STORED_KEY',
    });
    expect(holder.getKey()).toBeNull();
  });

  it('throws STORAGE_UNAVAILABLE when hasKey rejects', async () => {
    const store: KeyStore = {
      loadKey: async () => 'key',
      hasKey: async () => { throw new Error('IndexedDB unavailable'); },
    };
    const holder = mockKeyHolder();

    await expect(reunlock('pass', store, holder)).rejects.toThrow(ReunlockError);
    await expect(reunlock('pass', store, holder)).rejects.toMatchObject({
      code: 'STORAGE_UNAVAILABLE',
    });
  });

  it('throws STORAGE_UNAVAILABLE when loadKey throws non-decryption error', async () => {
    const store: KeyStore = {
      loadKey: async () => { throw new TypeError('Cannot read properties of null'); },
      hasKey: async () => true,
    };
    const holder = mockKeyHolder();

    await expect(reunlock('pass', store, holder)).rejects.toThrow(ReunlockError);
    await expect(reunlock('pass', store, holder)).rejects.toMatchObject({
      code: 'STORAGE_UNAVAILABLE',
    });
  });

  it('throws INVALID_PASSPHRASE when loadKey throws DOMException', async () => {
    const store: KeyStore = {
      loadKey: async () => { throw new DOMException('The operation failed', 'OperationError'); },
      hasKey: async () => true,
    };
    const holder = mockKeyHolder();

    await expect(reunlock('pass', store, holder)).rejects.toThrow(ReunlockError);
    await expect(reunlock('pass', store, holder)).rejects.toMatchObject({
      code: 'INVALID_PASSPHRASE',
    });
  });

  it('invokes onTimerReset callback on success', async () => {
    const store = mockKeyStore('deadbeef', 'pass');
    const holder = mockKeyHolder();
    const onTimerReset = vi.fn();

    await reunlock('pass', store, holder, { onTimerReset });

    expect(onTimerReset).toHaveBeenCalledTimes(1);
  });

  it('invokes onBroadcast callback on success', async () => {
    const store = mockKeyStore('deadbeef', 'pass');
    const holder = mockKeyHolder();
    const onBroadcast = vi.fn();

    await reunlock('pass', store, holder, { onBroadcast });

    expect(onBroadcast).toHaveBeenCalledTimes(1);
  });

  it('does not invoke callbacks on failure', async () => {
    const store = mockKeyStore('deadbeef', 'correct');
    const holder = mockKeyHolder();
    const onTimerReset = vi.fn();
    const onBroadcast = vi.fn();

    await expect(reunlock('wrong', store, holder, { onTimerReset, onBroadcast })).rejects.toThrow();

    expect(onTimerReset).not.toHaveBeenCalled();
    expect(onBroadcast).not.toHaveBeenCalled();
  });

  it('succeeds even if onBroadcast throws (FR-11a)', async () => {
    const store = mockKeyStore('deadbeef', 'pass');
    const holder = mockKeyHolder();
    const onBroadcast = vi.fn(() => { throw new Error('BroadcastChannel failed'); });

    const result = await reunlock('pass', store, holder, { onBroadcast });

    expect(result).toEqual({ success: true });
    expect(holder.getKey()).toBe('deadbeef');
  });

  it('throws NO_STORED_KEY when loadKey returns empty string', async () => {
    const store: KeyStore = {
      loadKey: async () => '',
      hasKey: async () => true,
    };
    const holder = mockKeyHolder();

    await expect(reunlock('pass', store, holder)).rejects.toMatchObject({
      code: 'NO_STORED_KEY',
    });
  });
});
