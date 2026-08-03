import type { NapSession } from '@imani/nap-client-web';

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
  /** Whether the session is shut down (extended inactivity — requires passphrase to resume). */
  isShutdown: boolean;
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
export type ReunlockCancelledReason = 'user_cancelled' | 'session_expired' | 'logout' | 'unmounted';

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
