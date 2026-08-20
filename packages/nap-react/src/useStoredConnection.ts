import { useCallback, useEffect, useRef, useState } from 'react';

export type StoredConnectionStatus =
  /** Asking the store whether a record exists. */
  | 'checking'
  /** Nothing stored — pair from scratch. */
  | 'none'
  /** A record exists and is waiting for a passphrase. */
  | 'available'
  /** A passphrase was submitted and is being tried. */
  | 'restoring'
  /** Restored. `value` holds whatever `restore()` returned. */
  | 'restored'
  /** Wrong passphrase, or a record this build cannot read. Pair again. */
  | 'unavailable';

/**
 * The two operations this hook drives, supplied by the caller.
 *
 * Injected rather than imported so `nap-react` keeps no dependency on
 * `@imani/nap-client-nip46`. That package is opt-in and nothing else in the
 * workspace depends on it; importing it here would put a relay client in the
 * bundle of every React app that only ever uses a browser extension.
 */
export interface StoredConnectionSource<T> {
  /** `SecretStore.has()` — is there a record at all? */
  has(): Promise<boolean>;
  /**
   * Decrypt and rebuild. Return `null` for a wrong passphrase or a record that
   * cannot be read, matching `SecretStore.load()`; both mean "pair again", and
   * neither should throw. A forgotten passphrase must not be a dead app.
   */
  restore(passphrase: string): Promise<T | null>;
}

export interface UseStoredConnectionReturn<T> {
  status: StoredConnectionStatus;
  /** Non-null exactly when `status` is `'restored'`. */
  value: T | null;
  /** Try a passphrase. Resolves to the restored value, or null on failure. */
  restore: (passphrase: string) => Promise<T | null>;
  /** Back to `'available'` after a failure, so the user can retype. */
  reset: () => void;
}

/**
 * Drive a passphrase-gated restore of something persisted in the browser —
 * in practice a NIP-46 bunker pairing held as an encrypted `SecretStore` record.
 *
 * The point of the stored record is that re-pairing a bunker otherwise means
 * pasting a connection URI again on every reload. The point of the passphrase is
 * that the record contains the NIP-46 client secret key, which is why it is
 * encrypted at rest rather than merely stored.
 *
 * Failure is deliberately not an error state you can retry into forever: a
 * `null` from `restore()` means the passphrase was wrong *or* the record is
 * unreadable, and the two are indistinguishable by design (see `SecretStore`).
 * Offer "try again" and "pair from scratch" side by side.
 *
 * @example
 * ```tsx
 * const source = useMemo(() => ({
 *   has: () => store.has(),
 *   restore: async (passphrase: string) => {
 *     const record = await loadConnection(store, passphrase);
 *     return record ? createNip46Signer({ ...record }) : null;
 *   },
 * }), [store]);
 *
 * const { status, value: signer, restore } = useStoredConnection(source);
 * ```
 */
export function useStoredConnection<T>(
  source: StoredConnectionSource<T>
): UseStoredConnectionReturn<T> {
  const [status, setStatus] = useState<StoredConnectionStatus>('checking');
  const [value, setValue] = useState<T | null>(null);

  // Callers build `source` inline as often as not. As an effect dep that would
  // re-probe the store on every render; as a ref it is read when actually used.
  const sourceRef = useRef(source);
  sourceRef.current = source;

  useEffect(() => {
    let cancelled = false;

    sourceRef.current.has().then(
      (present) => {
        if (!cancelled) {
          setStatus(present ? 'available' : 'none');
        }
      },
      () => {
        // A store that cannot even be probed is a store with nothing usable in
        // it. Same answer as empty: pair from scratch.
        if (!cancelled) {
          setStatus('none');
        }
      }
    );

    return () => {
      cancelled = true;
    };
  }, []);

  const restore = useCallback(async (passphrase: string): Promise<T | null> => {
    setStatus('restoring');

    let restored: T | null;
    try {
      restored = await sourceRef.current.restore(passphrase);
    } catch {
      // Contract says restore() should not throw, but a caller's own bug must
      // not strand the UI in 'restoring' with no way forward.
      restored = null;
    }

    setValue(restored);
    setStatus(restored === null ? 'unavailable' : 'restored');
    return restored;
  }, []);

  const reset = useCallback(() => {
    setValue(null);
    setStatus('available');
  }, []);

  return { status, value, restore, reset };
}
