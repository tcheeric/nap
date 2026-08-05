import { useState, useRef, useCallback, useEffect } from 'react';
import { useNapSession } from './NapProvider.js';
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
 * restore — it calls `session.unlock()` instead, with no prompt at all, and the
 * signer's own approval on the next signature is the re-authorization.
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
  const { session, isAuthenticated } = useNapSession();
  const [isPrompting, setIsPrompting] = useState(false);
  const pendingRef = useRef<PendingPromise[]>([]);

  const checkKeyAvailable = isKeyAvailable ?? (() => !session.isLocked());

  useEffect(() => {
    return () => {
      const pending = pendingRef.current;
      pendingRef.current = [];
      for (const p of pending) {
        p.reject(new ReunlockCancelledError('unmounted'));
      }
    };
  }, []);

  // Watch for session loss during prompt
  const prevAuthRef = useRef(isAuthenticated);
  useEffect(() => {
    if (prevAuthRef.current && !isAuthenticated && pendingRef.current.length > 0) {
      const pending = pendingRef.current;
      pendingRef.current = [];
      setIsPrompting(false);
      for (const p of pending) {
        p.reject(new ReunlockCancelledError('session_expired'));
      }
    }
    prevAuthRef.current = isAuthenticated;
  }, [isAuthenticated]);

  const promptReunlock = useCallback((): Promise<void> => {
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

  const withSigningGuard = useCallback(<T,>(fn: () => Promise<T>): Promise<T> => {
    if (checkKeyAvailable()) {
      return fn();
    }
    return promptReunlock().then(() => fn());
  }, [checkKeyAvailable, promptReunlock]);

  return {
    isPrompting,
    promptReunlock,
    withSigningGuard,
    cancel,
    handleSuccess,
  };
}
