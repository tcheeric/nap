import { useEffect, useMemo, useState } from 'react';
import {
  createNapSession,
  type IdentityChangedDetail,
  type NapSession,
  type SessionSigner,
} from '@imani/nap-client-web';
import { useNapCallbacks } from '@imani/nap-react';

export type BootstrapPhase = 'resuming' | 'ready';

/**
 * Builds the session once and tries to restore an existing one.
 *
 * Two things here are not decoration:
 *
 * 1. `useNapCallbacks()` returns a `callbacks` object with a stable identity.
 *    Spread it — do not name a subset. Leaving out `onIdentityChanged` makes
 *    every signer account switch look like an ordinary expiry, and the retry
 *    that follows is the privilege carry-over the identity guard exists to stop.
 * 2. `resume()` runs once on mount, and until it answers the app does not know
 *    whether it is logged in. Rendering a login screen during that gap is the
 *    single most common way to lose the prompt-free reload NAP is built for.
 */
export function useNapBootstrap(signer: SessionSigner | null): {
  session: NapSession | null;
  phase: BootstrapPhase;
  identityChange: IdentityChangedDetail | null;
} {
  const [state, callbacks] = useNapCallbacks();
  const [phase, setPhase] = useState<BootstrapPhase>('resuming');

  const session = useMemo(
    () =>
      signer
        ? createNapSession({
            // Same origin as the page. The server's pinned audience must equal
            // this, or every completion fails as an indistinguishable 401.
            baseUrl: window.location.origin,
            signer,
            ...callbacks,
          })
        : null,
    [signer, callbacks]
  );

  useEffect(() => {
    if (!session) {
      setPhase('ready');
      return;
    }

    let cancelled = false;
    setPhase('resuming');

    // No `verifyIdentity` here: this page rebuilds no signer from storage, so
    // whatever signer just went into createNapSession is the one the user
    // picked in this tab. Tutorial 08, which does remember a choice across a
    // reload, must pass `resume({ verifyIdentity: true })` instead.
    session
      .resume()
      .catch(() => undefined)
      .finally(() => {
        if (!cancelled) {
          setPhase('ready');
        }
      });

    return () => {
      cancelled = true;
      // Stops the idle timer and closes the BroadcastChannel. Without it a
      // hot reload leaves a fleet of orphaned sessions racing each other.
      session.destroy();
    };
  }, [session]);

  return { session, phase: state.isAuthenticated ? 'ready' : phase, identityChange: state.identityChange };
}
