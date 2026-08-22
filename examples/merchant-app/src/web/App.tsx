import { useMemo, useState, type ReactNode } from 'react';
import type { SessionSigner } from '@imani/nap-client-web';
import { NapProvider, useNapSession } from '@imani/nap-react';
import { createRefreshLoop } from './refreshLoop.js';
import { SignerPicker, describe } from './SignerPicker.js';
import { useNapBootstrap } from './useNapBootstrap.js';
import { Vouchers } from './Vouchers.js';

export function App() {
  const [signer, setSigner] = useState<SessionSigner | null>(null);
  const { session, phase, identityChange } = useNapBootstrap(signer);

  if (!session) {
    return <Shell><SignerPicker onSigner={setSigner} /></Shell>;
  }

  if (phase === 'resuming') {
    // Required, not cosmetic. `resume()` is a round trip, and rendering the
    // signed-out screen underneath it makes every reload flash a login prompt
    // at a user who is already signed in.
    return <Shell><p>Restoring your session…</p></Shell>;
  }

  return (
    <NapProvider session={session} identityChange={identityChange}>
      <Shell><Account /></Shell>
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

function Account() {
  const { session, isAuthenticated, roles, permissions } = useNapSession();
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

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
              refresh.arm(await session.login());
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
          })
        }
      >
        Sign out
      </button>
      {error ? <p role="alert">{error}</p> : null}
      <Vouchers />
    </section>
  );
}
