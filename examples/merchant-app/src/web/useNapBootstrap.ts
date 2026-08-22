import { useEffect, useMemo, useState } from 'react';
import {
  createNapSession,
  type IdentityChangedDetail,
  type NapSession,
  type SessionSigner,
} from '@imani/nap-client-web';
import { useNapCallbacks } from '@imani/nap-react';
import { keyStore, signerPreference } from './storage.js';

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
export function useNapBootstrap(
  signer: SessionSigner | null,
  options: { verifyIdentity?: boolean } = {}
): {
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
            // Passed for every signer kind, not just the key one. For NIP-07
            // and NIP-46 it is inert — `lockRecovery()` asks the signer first
            // and only consults the store for a signer that holds a key here,
            // so an extension user is never sent to a passphrase prompt.
            //
            // Wiring it is also what makes the next option safe. `autoLock`
            // with a key-holding signer and no `keyStore` throws right here:
            // the first idle timeout would evict the key, `reunlock()` would
            // throw for the missing store, and the session would be bricked
            // minutes after a call that returned cleanly.
            keyStore,
            // Never written here — only the app knows which kind of signer it
            // built. Passing it lets the session *clear* it, on a terminal
            // `/auth/init` or `/auth/complete` failure and when the identity
            // guard terminates. Omit it and a login the server has stopped
            // accepting stays on the screen, offered on every reload.
            signerPreference,
            autoLock: {
              enabled: true,
              // Short so the tutorial is watchable. The library default is
              // 15 minutes and that is the right order of magnitude for a
              // real product.
              timeoutMs: 60_000,
            },
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

    // `resume()` never invokes the signer, which is what makes a reload
    // prompt-free — and also what makes it unable to notice that the signer
    // is now somebody else. The cookie outlives the page; the signer does
    // not. So whoever hands us a signer rebuilt from storage rather than
    // freshly picked in this tab asks for the check, and pays one `getNpub()`
    // for it. See `KeyLogin`.
    session
      .resume({ verifyIdentity: options.verifyIdentity ?? false })
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
  }, [session, options.verifyIdentity]);

  return { session, phase: state.isAuthenticated ? 'ready' : phase, identityChange: state.identityChange };
}
