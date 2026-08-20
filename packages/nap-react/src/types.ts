import type { IdentityChangedDetail, LockRecovery, NapSession } from '@imani/nap-client-web';

/**
 * Session state exposed by the NapProvider context.
 * Derived from the NapSession instance + React state tracking.
 */
export interface NapSessionState {
  /** The underlying NapSession instance. */
  session: NapSession;
  /** Whether the user is authenticated (has a valid session). */
  isAuthenticated: boolean;
  /** Whether the signing key is locked (cleared from memory after inactivity). */
  isLocked: boolean;
  /** Whether the session is shut down (extended inactivity). */
  isShutdown: boolean;
  /**
   * How a lock on this session clears: `'unlock'` for NIP-07/NIP-46,
   * `'passphrase'` for an in-page key with a `keyStore`, `'reauthenticate'` for
   * one without. Branch your unlock UI on this — a passphrase field shown to a
   * NIP-46 user cannot succeed, and neither can an Unlock button for a key that
   * was zeroed with nothing to restore it from.
   */
  lockRecovery: LockRecovery;
  /**
   * Set when the signer presented a different identity and the session was
   * terminated as a result — an extension account switch, a re-paired bunker.
   * Distinct from a logout, and the distinction matters: prompt for a fresh
   * login, do not retry silently.
   *
   * Null unless the `onIdentityChanged` callback from `useNapCallbacks()` was
   * wired into `createNapSession()`. The provider cannot detect this on its own;
   * from outside the session an identity change and a logout look identical.
   */
  identityChange: IdentityChangedDetail | null;
  /**
   * Roles and permissions from the session body, kept in sync so a render can
   * branch on them. Empty arrays when unauthenticated — never null, so a
   * component can check them without first checking `isAuthenticated`.
   *
   * **These decide what the UI offers, never what the user may do.** The
   * authorization boundary is server-side: `requirePermission`, `requireRole`
   * and `requireSession` in the adapters. Hiding a button changes nothing about
   * what a request is allowed to do, and anything that treats this as
   * enforcement is a vulnerability rather than a feature.
   *
   * They are also the login-time snapshot, so a permission revoked mid-session
   * stays listed here until the session is renewed. The server behaves the same
   * way unless you pass `aclResolver` to the guards — see the ACL trap in
   * CLAUDE.md — so this is not uniquely stale, just not live.
   */
  roles: readonly string[];
  permissions: readonly string[];
  /** Reactive `permissions.includes(...)`. Affordance only, as above. */
  hasPermission: (permission: string) => boolean;
  /** Reactive `roles.includes(...)`. Affordance only, as above. */
  hasRole: (role: string) => boolean;
}

/**
 * Return type of the useReunlock hook.
 */
export interface UseReunlockReturn {
  /** Whether the re-unlock modal should be visible. */
  isPrompting: boolean;
  /** Show the re-unlock prompt. Resolves when the user unlocks, rejects on cancel/expiry/unmount. */
  promptReunlock: () => Promise<void>;
  /** Guard an async function that requires signing. Prompts re-unlock if the key is locked. */
  withSigningGuard: <T>(fn: () => Promise<T>) => Promise<T>;
  /** Dismiss the modal without unlocking. Rejects all pending promises. */
  cancel: () => void;
  /** Called by the modal on successful re-unlock. Resolves all pending promises. */
  handleSuccess: () => void;
}

/**
 * Reason for re-unlock cancellation.
 */
export type ReunlockCancelledReason =
  | 'user_cancelled'
  | 'session_expired'
  | 'logout'
  | 'unmounted'
  /** The signer became someone else mid-prompt. A fresh login, not a retry. */
  | 'identity_changed'
  /**
   * The session is shut down and has no passphrase to prompt for. Clearing it
   * is the user's gesture on the shutdown overlay, not a guarded action's.
   */
  | 'shutdown'
  /**
   * Idle-locked with no passphrase to collect. Render an unlock affordance and
   * let the click call `session.unlock()` — the guard will not clear the lock on
   * the user's behalf, because a signer with pre-granted permissions would then
   * sign with nobody at the machine.
   */
  | 'locked'
  /**
   * The key was zeroed and nothing can restore it: an in-page key with no
   * `keyStore`. Build a fresh signer and log in again.
   */
  | 'reauthenticate_required';

/**
 * Thrown when a re-unlock prompt is cancelled or interrupted.
 * Callers should catch this to silently stop loading spinners.
 */
export class ReunlockCancelledError extends Error {
  readonly reason: ReunlockCancelledReason;

  constructor(reason: ReunlockCancelledReason) {
    super(`Re-unlock cancelled: ${reason}`);
    this.name = 'ReunlockCancelledError';
    this.reason = reason;
  }
}
