import { describe, expect, it, vi } from 'vitest';
import type { LockRecovery } from '@imani/nap-client-web';
import { acquireSigningAccess } from '../src/signingAccess.js';
import { ReunlockCancelledError } from '../src/types.js';

function deps(overrides: {
  isKeyAvailable: boolean;
  lockRecovery: LockRecovery;
  isShutdown?: boolean;
  identityChanged?: boolean;
}) {
  const prompt = vi.fn(async () => {});
  return {
    prompt,
    run: () =>
      acquireSigningAccess({
        isKeyAvailable: () => overrides.isKeyAvailable,
        identityChanged: () => overrides.identityChanged ?? false,
        isShutdown: () => overrides.isShutdown ?? false,
        lockRecovery: () => overrides.lockRecovery,
        prompt,
      }),
  };
}

function reasonOf(run: () => unknown): string {
  try {
    run();
  } catch (error) {
    return (error as ReunlockCancelledError).reason;
  }
  throw new Error('expected a refusal');
}

describe('acquireSigningAccess', () => {
  it('does nothing when the key is already available', () => {
    const d = deps({ isKeyAvailable: true, lockRecovery: 'passphrase' });
    expect(d.run()).toBeUndefined();
    expect(d.prompt).not.toHaveBeenCalled();
  });

  // terminateForIdentity sets locked = false on its way out, so the default
  // isKeyAvailable reports the key available on a session that no longer exists.
  // Checking identity after the fast path let a background save sign with the
  // new account under the old identity's cookie.
  it('refuses after an identity change even when the key looks available', () => {
    const d = deps({ isKeyAvailable: true, lockRecovery: 'unlock', identityChanged: true });
    expect(reasonOf(d.run)).toBe('identity_changed');
    expect(d.prompt).not.toHaveBeenCalled();
  });

  it('prompts a locked session whose passphrase can restore the key', () => {
    const d = deps({ isKeyAvailable: false, lockRecovery: 'passphrase' });
    expect(d.run()).toBeInstanceOf(Promise);
    expect(d.prompt).toHaveBeenCalledOnce();
  });

  // Typing the passphrase is itself the gesture, so shutdown needs no extra gate.
  it('still prompts when shut down and a passphrase can clear it', () => {
    const d = deps({ isKeyAvailable: false, lockRecovery: 'passphrase', isShutdown: true });
    d.run();
    expect(d.prompt).toHaveBeenCalledOnce();
  });

  // It used to call session.unlock() here. That assumed the signer always
  // re-prompts, and a NIP-46 bunker with pre-granted permissions does not — so a
  // background autosave cleared the lock in every tab and signed, unattended.
  it('refuses a key-free lock instead of clearing it unattended', () => {
    const d = deps({ isKeyAvailable: false, lockRecovery: 'unlock' });
    expect(reasonOf(d.run)).toBe('locked');
    expect(d.prompt).not.toHaveBeenCalled();
  });

  it('reports a shutdown distinctly from an ordinary key-free lock', () => {
    const d = deps({ isKeyAvailable: false, lockRecovery: 'unlock', isShutdown: true });
    expect(reasonOf(d.run)).toBe('shutdown');
  });

  // The arm the old boolean could not express: key zeroed, no store to restore
  // it from. Prompting cannot work and unlock() would report a session that
  // still cannot sign.
  it('reports an unrecoverable lock as needing a fresh login', () => {
    const d = deps({ isKeyAvailable: false, lockRecovery: 'reauthenticate' });
    expect(reasonOf(d.run)).toBe('reauthenticate_required');
    expect(d.prompt).not.toHaveBeenCalled();
  });

  // Awaiting the already-granted path would put fn() a microtask after the click
  // that started it, losing transient user activation and getting a signer's
  // approval window blocked.
  it('returns synchronously unless it has to wait for a prompt', () => {
    expect(deps({ isKeyAvailable: true, lockRecovery: 'unlock' }).run()).toBeUndefined();
    expect(deps({ isKeyAvailable: false, lockRecovery: 'passphrase' }).run()).toBeInstanceOf(
      Promise
    );
  });

  it('propagates a cancelled prompt', async () => {
    const boom = new Error('cancelled');
    await expect(
      acquireSigningAccess({
        isKeyAvailable: () => false,
        identityChanged: () => false,
        isShutdown: () => false,
        lockRecovery: () => 'passphrase',
        prompt: () => Promise.reject(boom),
      })
    ).rejects.toBe(boom);
  });
});
