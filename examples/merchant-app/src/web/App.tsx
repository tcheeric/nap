import { useCallback, useMemo, useState, type ReactNode } from 'react';
import type { SignerKind } from '@imani/nap-client-web';
import { NapProvider, useNapSession, useSignerPreference } from '@imani/nap-react';
import { createRefreshLoop } from './refreshLoop.js';
import { LockScreen } from './LockScreen.js';
import type { SignerChoice } from './signerChoice.js';
import { SignerPicker, describe } from './SignerPicker.js';
import { useNapBootstrap } from './useNapBootstrap.js';
import { Payouts } from './Payouts.js';
import { Vouchers } from './Vouchers.js';

export function App() {
  const [picked, setPicked] = useState<SignerChoice | null>(null);
  const { session, phase, identityChange } = useNapBootstrap(picked?.signer ?? null, {
    verifyIdentity: picked?.verifyIdentity ?? false,
  });

  // Stable, because `SignerPicker` restores a remembered extension signer from
  // an effect keyed on it. A fresh arrow every render would re-run that effect
  // every render.
  const onSigner = useCallback((choice: SignerChoice) => setPicked(choice), []);

  if (!session) {
    return (
      <Shell>
        <SignerPicker onSigner={onSigner} />
      </Shell>
    );
  }

  if (phase === 'resuming') {
    // Required, not cosmetic. `resume()` is a round trip, and rendering the
    // signed-out screen underneath it makes every reload flash a login prompt
    // at a user who is already signed in.
    return <Shell><p>Restoring your session…</p></Shell>;
  }

  return (
    <NapProvider session={session} identityChange={identityChange}>
      <Shell><Account signerKind={picked?.kind ?? null} /></Shell>
    </NapProvider>
  );
}

function Shell({ children }: { children: ReactNode }) {
  return (
    <main style={{ fontFamily: 'system-ui', maxWidth: '40rem', margin: '3rem auto' }}>
      <h1>Merchant app</h1>
      {children}
    </main>
  );
}

function Account({ signerKind }: { signerKind: SignerKind | null }) {
  const { session, isAuthenticated, isLocked, isShutdown, roles, permissions } = useNapSession();
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const { remember, forget } = useSignerPreference();

  const refresh = useMemo(
    () =>
      createRefreshLoop({
        baseUrl: window.location.origin,
        // Not `logout()`. The loop cannot tell a dead session from a dead
        // network, and only the server can. A `resume()` asks: a 401 fires
        // onSessionExpired and this component re-renders signed out, while a
        // session that is somehow still good simply stays.
        onLost: () => void session.resume().catch(() => undefined),
      }),
    [session]
  );

  const run = async (action: () => Promise<unknown>) => {
    setError(null);
    setBusy(true);
    try {
      await action();
    } catch (cause) {
      setError(describe(cause));
    } finally {
      setBusy(false);
    }
  };

  // Before the authentication branch, not after. A lock that arrived from a
  // sibling tab before this one logged in would otherwise render a Sign in
  // button that `authenticate()` refuses, with no affordance to clear the
  // lock that is doing the refusing.
  if (isLocked || isShutdown) {
    return <LockScreen />;
  }

  if (!isAuthenticated) {
    return (
      <section>
        <p>Signing in asks your extension for one signature.</p>
        <button
          disabled={busy}
          onClick={() =>
            run(async () => {
              // login() returns the raw completion body, which is the only
              // place the refresh token appears. `/auth/session` never carries
              // one, so a resume() cannot re-arm this — tutorial 05 §6.
              const success = await session.login();
              refresh.arm(success);

              // After the login, not on the click that started it. Recording a
              // choice that then fails sends the next visit down a path the
              // user cannot complete.
              if (signerKind) {
                remember(signerKind, success.principal.npub);
              }
            })
          }
        >
          Sign in
        </button>
        {error ? <p role="alert">{error}</p> : null}
      </section>
    );
  }

  // Read the identity off the session state at render time. It is stable for
  // the life of the session — the identity guard terminates rather than swaps.
  const npub = session.getSession()?.npub ?? '(unknown)';

  return (
    <section>
      <p>
        Signed in as <code>{npub}</code>
      </p>
      {/* Affordance only. The boundary is the server's guards; these two lists
          are the login-time snapshot and exist so a render can hide a button. */}
      <p>
        Roles: {roles.join(', ') || '(none)'} · Permissions:{' '}
        {permissions.join(', ') || '(none)'}
      </p>
      <button
        disabled={busy}
        onClick={() =>
          run(async () => {
            refresh.disarm();
            await session.logout();
            // A deliberate sign-out is the one case where the remembered
            // choice should not survive: the next visitor to this browser may
            // not be the same person.
            forget();
          })
        }
      >
        Sign out
      </button>

      {/* Always evicts, even where recovery is awkward. Zeroing the key is
          the point of a lock; refusing an explicit one to spare the user a
          passphrase leaves a live key in the page, which is the worse trade.
          Open a second tab and press it: both lock. */}
      <button
        onClick={() => {
          session.lock();
        }}
      >
        Lock now
      </button>

      {error ? <p role="alert">{error}</p> : null}
      <Vouchers />
      <Payouts />
    </section>
  );
}
