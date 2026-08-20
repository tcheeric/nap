import type { LockRecovery } from '@imani/nap-client-web';
import { ReunlockCancelledError } from './types.js';

/**
 * Decide how a locked session gets back to signing. Extracted from `useReunlock`
 * so the branch is testable without a DOM — it is the one piece of that hook
 * that is neither React nor UI.
 *
 * It is deliberately *total* over {@link LockRecovery}. The predicate this
 * replaced was a boolean answering a three-way question, and every arm it failed
 * to model turned into a stranded user: a NIP-07 session sent to a passphrase
 * modal it could never satisfy, or an unrecoverable one sent to an `unlock()`
 * that throws. Adding a case to `LockRecovery` should break this switch.
 */
export interface SigningAccessDeps {
  /** Synchronous check for whether the signing key is usable right now. */
  isKeyAvailable(): boolean;
  /** Whether the signer has become someone else and the session was terminated. */
  identityChanged(): boolean;
  /** `session.isShutdown()` — extended inactivity, not the ordinary idle lock. */
  isShutdown(): boolean;
  /** `session.lockRecovery()` — constant for the session's lifetime. */
  lockRecovery(): LockRecovery;
  /** Show the passphrase prompt. Resolves once the modal reports success. */
  prompt(): Promise<void>;
}

/**
 * Returns `undefined` when access is already granted and a promise only when it
 * has to wait for a prompt. That is deliberate, not a micro-optimisation: an
 * `async` function would put every caller behind an await, and `fn()` running a
 * microtask later has lost the transient user activation from the click that
 * started it. A signer that opens a window for approval — the NIP-46 auth URL,
 * some extensions — gets that window blocked, and the action hangs with no
 * error. Refusals throw synchronously for the same reason; `withSigningGuard`
 * converts them to a rejected promise.
 */
export function acquireSigningAccess(deps: SigningAccessDeps): void | Promise<void> {
  // Before the key check, not after. `terminateForIdentity` sets `locked = false`
  // on its way out, so the default `isKeyAvailable` — `!session.isLocked()` —
  // reports the key available on a session that no longer exists. Checking this
  // second let a background save sign with the *new* account under the old
  // identity's cookie, which is the silent retry the identity guard exists to
  // stop.
  if (deps.identityChanged()) {
    throw new ReunlockCancelledError('identity_changed');
  }

  if (deps.isKeyAvailable()) {
    return;
  }

  // Typing a passphrase is itself the user gesture, so this path needs no
  // separate shutdown gate — the shutdown overlay collects the same passphrase.
  if (deps.lockRecovery() === 'passphrase') {
    return deps.prompt();
  }

  if (deps.isShutdown()) {
    throw new ReunlockCancelledError('shutdown');
  }

  if (deps.lockRecovery() === 'unlock') {
    // Refuses rather than calling `session.unlock()` itself. Auto-unlocking
    // assumed the signer always re-prompts, and it does not: a NIP-46 bunker
    // with DEFAULT_PERMISSIONS already granted signs silently, so a background
    // autosave would clear the lock in every tab and sign, with nobody at the
    // machine. A lock any timer can clear is not a lock. Render an unlock
    // affordance and let the click call `session.unlock()`.
    throw new ReunlockCancelledError('locked');
  }

  // 'reauthenticate': the key was zeroed and nothing can restore it — no store
  // to decrypt from, and `unlock()` would report a session that still cannot
  // sign. Only a fresh signer and a new login will do.
  throw new ReunlockCancelledError('reauthenticate_required');
}
