import { useCallback, useEffect, useRef, useState } from 'react';
import { detectNip07Provider } from '@imani/nap-client-web';
import type { Nip07DetectOptions, Nip07Provider } from '@imani/nap-client-web';

export type Nip07Status = 'detecting' | 'present' | 'absent';

export interface Nip07Detection {
  status: Nip07Status;
  /** Non-null exactly when `status` is `'present'`. */
  provider: Nip07Provider | null;
  /** Detect again — after the user installs an extension and comes back. */
  retry: () => void;
}

/**
 * Wait for a NIP-07 provider, as React state.
 *
 * Extensions inject `window.nostr` on their own schedule, so the answer is not
 * available on first render and a component that checks once tells users with an
 * extension that they have none. `detectNip07Provider()` polls to a deadline;
 * this is the tri-state that render needs while it does.
 *
 * `'detecting'` is a real state, not a formality — render a spinner or nothing,
 * never the "install an extension" copy. Showing that and then swapping it for a
 * login button is the flicker this hook exists to prevent.
 *
 * @example
 * ```tsx
 * function SignInWithExtension() {
 *   const { status, provider } = useNip07();
 *   const signer = useMemo(
 *     () => (provider ? createNip07Signer(provider) : null),
 *     [provider]
 *   );
 *
 *   if (status === 'detecting') return <Spinner />;
 *   if (status === 'absent') return <InstallPrompt />;
 *   return <button onClick={() => void login(signer!)}>Sign in</button>;
 * }
 * ```
 */
export function useNip07(options: Nip07DetectOptions = {}): Nip07Detection {
  const [detection, setDetection] = useState<Omit<Nip07Detection, 'retry'>>({
    status: 'detecting',
    provider: null,
  });
  const [attempt, setAttempt] = useState(0);

  // Held in a ref, not a dep. Callers pass this object inline — `useNip07({
  // timeoutMs: 2000 })` — so as a dep it would be a new identity every render
  // and restart detection on each one, resetting the state to 'detecting'
  // forever. Options are read once per attempt.
  const optionsRef = useRef(options);
  optionsRef.current = options;

  useEffect(() => {
    let cancelled = false;
    setDetection({ status: 'detecting', provider: null });

    // Never rejects: absence is an answer, so there is no error branch here.
    void detectNip07Provider(optionsRef.current).then((provider) => {
      if (cancelled) {
        return;
      }
      setDetection(
        provider ? { status: 'present', provider } : { status: 'absent', provider: null }
      );
    });

    return () => {
      // The deadline outlives a fast unmount, and the poll keeps running inside
      // the promise either way; this just stops it setting state afterwards.
      cancelled = true;
    };
  }, [attempt]);

  const retry = useCallback(() => setAttempt((n) => n + 1), []);

  return { status: detection.status, provider: detection.provider, retry };
}
