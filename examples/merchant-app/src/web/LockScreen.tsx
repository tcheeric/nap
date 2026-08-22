import { useState } from 'react';
import { ReunlockError } from '@imani/nap-client-web';
import { useNapSession } from '@imani/nap-react';

/**
 * The lock overlay. Rendered instead of the account, not over it — a locked
 * session cannot sign, so every control underneath would fail on click.
 *
 * The whole component is a switch over `lockRecovery`, which is the point.
 * The three arms need three different affordances and two of them cannot
 * satisfy the other's: a passphrase field is unanswerable for a NIP-07 user
 * who has no stored key, and an Unlock button is a lie to a session whose key
 * was zeroed with nothing to restore it from. Asking *after* locking is too
 * late, so `lockRecovery()` answers without mutating anything and is constant
 * for the session's lifetime — read it whenever you like, including while
 * still unlocked, to decide what the overlay will say.
 */
export function LockScreen() {
  const { session, isLocked, isShutdown, lockRecovery } = useNapSession();
  const [passphrase, setPassphrase] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  if (!isLocked && !isShutdown) {
    return null;
  }

  const heading = isShutdown ? 'Session shut down' : 'Locked';

  switch (lockRecovery) {
    case 'unlock':
      // NIP-07 and NIP-46. Nothing was evicted, because the key was never
      // here. `unlock()` just clears the flag; the signer's own approval on
      // the next signature is the re-authorization.
      //
      // A button, and not something the app does for the user. A bunker that
      // pre-granted `sign_event:27235` signs silently, so an app that cleared
      // its own lock would sign with nobody at the machine — and the lock
      // would mean nothing.
      return (
        <section>
          <h2>{heading}</h2>
          <p>Your signer still holds the key. Unlocking asks it for nothing.</p>
          <button
            onClick={() => {
              session.unlock();
            }}
          >
            Unlock
          </button>
        </section>
      );

    case 'passphrase':
      // An in-page key plus a `keyStore`. The key is genuinely gone from
      // memory and the passphrase is what decrypts it back out. Typing it is
      // itself the user gesture, which is why this is the one arm that may
      // prompt.
      return (
        <section>
          <h2>{heading}</h2>
          <p>Your key was cleared from memory. Your passphrase brings it back.</p>
          <label>
            Passphrase
            <input
              type="password"
              value={passphrase}
              onChange={(event) => setPassphrase(event.target.value)}
              autoComplete="current-password"
            />
          </label>
          <button
            disabled={busy || !passphrase}
            onClick={() => {
              setError(null);
              setBusy(true);
              session
                .reunlock(passphrase)
                .catch((cause: unknown) => setError(describeReunlock(cause)))
                .finally(() => {
                  setPassphrase('');
                  setBusy(false);
                });
            }}
          >
            Unlock
          </button>
          {error ? <p role="alert">{error}</p> : null}
        </section>
      );

    case 'reauthenticate':
      // An in-page key with no `keyStore`. The lock zeroed it and nothing can
      // put it back: `unlock()` would clear the flag and report a session
      // that still cannot sign, and `reunlock()` has no store to read. The
      // only way on is a fresh signer and a fresh login.
      //
      // Wiring the `keyStore` above is what keeps this arm unreachable — but
      // it stays rendered, because `lock()` and `shutdown()` evict whether or
      // not recovery is graceful. Zeroing the key is the point.
      return (
        <section>
          <h2>{heading}</h2>
          <p>Your key was cleared and this app kept no copy. Sign in again to continue.</p>
          <button
            onClick={() => {
              void session.logout();
            }}
          >
            Sign in again
          </button>
        </section>
      );
  }
}

function describeReunlock(cause: unknown): string {
  if (!(cause instanceof ReunlockError)) {
    return 'Could not unlock. Try again.';
  }

  switch (cause.code) {
    case 'INVALID_PASSPHRASE':
      return 'Wrong passphrase. Try again.';
    case 'NO_STORED_KEY':
      // Reachable: another tab pressed "Forget this key" while this one was
      // idle. There is nothing left to decrypt, so stop offering the field.
      return 'There is no stored key any more. Sign out and sign in again.';
    case 'STORAGE_UNAVAILABLE':
      return 'This browser will not let the page read its storage.';
  }
}
