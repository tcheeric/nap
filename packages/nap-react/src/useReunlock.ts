import { useState, useRef, useCallback, useEffect } from 'react';
import { useNapSession } from './NapProvider.js';
import { acquireSigningAccess } from './signingAccess.js';
import { ReunlockCancelledError } from './types.js';
import type { UseReunlockReturn } from './types.js';

interface PendingPromise {
  resolve: () => void;
  reject: (err: ReunlockCancelledError) => void;
}

/**
 * Hook for managing the re-unlock flow in React.
 *
 * Provides `withSigningGuard` to wrap async functions that require a signing key.
 * If the key is locked, the hook prompts re-unlock before calling the function.
 * Multiple concurrent calls share a single prompt.
 *
 * The hook only decides *when* to prompt; unlocking is the modal's job, which is
 * what makes it signer-agnostic. An in-page key calls `session.reunlock(passphrase)`
 * from `onSuccess`. A NIP-07 or NIP-46 session has no passphrase and nothing to
 * restore — the hook calls `session.unlock()` for it directly, with no prompt at
 * all, and the signer's own approval on the next signature is the
 * re-authorization. See `acquireSigningAccess`.
 *
 * @param isKeyAvailable - Function that returns true if the signing key is in memory.
 *   Typically checks a ref or the NapSession's locked state. Must be synchronous.
 *
 * @example
 * ```tsx
 * function SaveButton() {
 *   const { isLocked } = useNapSession();
 *   const reunlock = useReunlock(() => !isLocked);
 *
 *   const handleSave = () => reunlock.withSigningGuard(async () => {
 *     await saveToRelay(signedEvent);
 *   });
 *
 *   return (
 *     <>
 *       <button onClick={handleSave}>Save</button>
 *       {reunlock.isPrompting && (
 *         <ReunlockModal
 *           onSuccess={reunlock.handleSuccess}
 *           onCancel={reunlock.cancel}
 *         />
 *       )}
 *     </>
 *   );
 * }
 * ```
 */
export function useReunlock(isKeyAvailable?: () => boolean): UseReunlockReturn {
  const { session, isAuthenticated, identityChange } = useNapSession();
  const [isPrompting, setIsPrompting] = useState(false);
  const pendingRef = useRef<PendingPromise[]>([]);

  // Latest-value refs, read only from imperative handlers. Taking these as
  // `useCallback` deps instead would defeat the memoization outright: the
  // documented call is `useReunlock(() => !isLocked)`, a fresh closure on every
  // render, so `withSigningGuard` would get a new identity every render and any
  // effect or memoized child keyed on it would re-fire — re-issuing the signing
  // request, and the bunker approval prompt with it.
  const isKeyAvailableRef = useRef(isKeyAvailable);
  isKeyAvailableRef.current = isKeyAvailable;

  const identityChangeRef = useRef(identityChange);
  identityChangeRef.current = identityChange;

  const checkKeyAvailable = useCallback(
    // `??` and not `||`: an `isKeyAvailable` that returns false must be honoured,
    // not fall through to the session's own view.
    () => isKeyAvailableRef.current?.() ?? !session.isLocked(),
    [session]
  );

  useEffect(() => {
    return () => {
      const pending = pendingRef.current;
      pendingRef.current = [];
      for (const p of pending) {
        p.reject(new ReunlockCancelledError('unmounted'));
      }
    };
  }, []);

  // Watch for session loss during a prompt. An identity change also drops the
  // session, so it would otherwise surface as 'session_expired' — the reasons
  // are not interchangeable, and it is checked first because the provider learns
  // of it from a callback while `isAuthenticated` catches up on the next poll.
  const prevAuthRef = useRef(isAuthenticated);
  useEffect(() => {
    const lostSession = prevAuthRef.current && !isAuthenticated;
    prevAuthRef.current = isAuthenticated;

    if (!identityChange && !lostSession) {
      return;
    }
    if (pendingRef.current.length === 0) {
      return;
    }

    const reason = identityChange ? 'identity_changed' : 'session_expired';
    const pending = pendingRef.current;
    pendingRef.current = [];
    setIsPrompting(false);
    for (const p of pending) {
      p.reject(new ReunlockCancelledError(reason));
    }
  }, [isAuthenticated, identityChange]);

  const promptReunlock = useCallback((): Promise<void> => {
    // The effect above only fires when `identityChange` *changes*, and it stays
    // set until the next login or logout. A prompt opened after that transition
    // would never be rejected by it: the modal would sit open over a dead
    // session, and submitting it would call reunlock() against nothing. Refuse
    // at the source instead of opening a prompt that cannot succeed.
    if (identityChangeRef.current) {
      return Promise.reject(new ReunlockCancelledError('identity_changed'));
    }

    return new Promise<void>((resolve, reject) => {
      pendingRef.current.push({ resolve, reject });
      setIsPrompting(true);
    });
  }, []);

  const cancel = useCallback(() => {
    const pending = pendingRef.current;
    pendingRef.current = [];
    setIsPrompting(false);
    for (const p of pending) {
      p.reject(new ReunlockCancelledError('user_cancelled'));
    }
  }, []);

  const handleSuccess = useCallback(() => {
    const pending = pendingRef.current;
    pendingRef.current = [];
    setIsPrompting(false);
    for (const p of pending) {
      p.resolve();
    }
  }, []);

  // Not `async`. When access is already granted — the common case, and the
  // key-free unlock too — `fn()` must be reached inside the caller's own call
  // stack, or the click's transient user activation is gone by the time it runs
  // and a signer that opens a window for approval has it blocked.
  const withSigningGuard = useCallback(
    <T,>(fn: () => Promise<T>): Promise<T> => {
      let pending: void | Promise<void>;
      try {
        pending = acquireSigningAccess({
          isKeyAvailable: checkKeyAvailable,
          identityChanged: () => identityChangeRef.current !== null,
          isShutdown: () => session.isShutdown(),
          lockRecovery: () => session.lockRecovery(),
          prompt: promptReunlock,
        });
      } catch (err) {
        // A synchronous refusal (shutdown) is still a rejected guard, not a
        // throw the caller has to handle differently from every other one.
        return Promise.reject(err);
      }

      return pending ? pending.then(() => fn()) : fn();
    },
    [checkKeyAvailable, promptReunlock, session]
  );

  return {
    isPrompting,
    promptReunlock,
    withSigningGuard,
    cancel,
    handleSuccess,
  };
}
