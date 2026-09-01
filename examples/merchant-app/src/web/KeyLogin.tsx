import { useEffect, useState } from 'react';
import { nip19 } from 'nostr-tools';
import { createPrivateKeySessionSigner } from '@imani/nap-client-web';
import { keyStore } from './storage.js';
import type { OnSigner } from './signerChoice.js';

/**
 * Login with a key the page itself holds. The last resort of the three, and
 * the one the RFC likes least (§28.2) — an extension or a bunker never puts
 * key material in reach of this origin's JavaScript at all.
 *
 * It ships anyway because "install an extension first" is not a viable first
 * screen for every product, and the alternative apps reach for unprompted is
 * an nsec in `localStorage` in the clear.
 */
export function KeyLogin({ onSigner }: { onSigner: OnSigner }) {
  const [enrolled, setEnrolled] = useState<boolean | null>(null);
  const [nsec, setNsec] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Which of the two forms to render is a storage question, and storage is
  // async here, so there is a third state before either. Rendering the
  // enrolment form while the answer is outstanding asks a returning user for
  // an nsec they already gave you.
  useEffect(() => {
    let cancelled = false;
    keyStore.hasKey().then(
      (has) => {
        if (!cancelled) setEnrolled(has);
      },
      () => {
        if (!cancelled) setEnrolled(false);
      }
    );
    return () => {
      cancelled = true;
    };
  }, []);

  if (enrolled === null) {
    return <p>Checking for a stored key…</p>;
  }

  const submit = async () => {
    setError(null);
    setBusy(true);
    try {
      const hex = enrolled ? await keyStore.loadKey(passphrase) : await enrol(nsec, passphrase);

      // `verifyIdentity` because this signer did not come from a choice the
      // user just made in this tab — it came out of storage, or it is a key
      // they enrolled over the top of a live session belonging to somebody
      // else. `resume()` would otherwise hand that session's roles to
      // whoever this key is.
      onSigner({
        signer: createPrivateKeySessionSigner(hex),
        kind: 'key',
        verifyIdentity: true,
      });
    } catch (cause) {
      setError(describeKeyLogin(cause));
    } finally {
      // The hex string is an immutable JS string and cannot be zeroed; only
      // the signer's `Uint8Array` can. Dropping the passphrase from state at
      // least keeps that out of a React devtools tree.
      setPassphrase('');
      setNsec('');
      setBusy(false);
    }
  };

  return (
    <section>
      <h3>{enrolled ? 'Unlock your stored key' : 'Sign in with a key'}</h3>

      {enrolled ? null : (
        <p>
          Your key is encrypted with the passphrase before it touches storage, and evicted from
          memory when this tab goes idle. Neither measure survives a hostile script on this origin
          — see tutorial 08.
        </p>
      )}

      {enrolled ? null : (
        <label>
          Private key (nsec)
          <input
            type="password"
            value={nsec}
            onChange={(event) => setNsec(event.target.value)}
            placeholder="nsec1…"
          />
        </label>
      )}

      <label>
        Passphrase
        <input
          type="password"
          value={passphrase}
          onChange={(event) => setPassphrase(event.target.value)}
          autoComplete={enrolled ? 'current-password' : 'new-password'}
        />
      </label>

      <button disabled={busy || !passphrase || (!enrolled && !nsec)} onClick={() => void submit()}>
        {enrolled ? 'Unlock' : 'Encrypt and sign in'}
      </button>

      {enrolled ? (
        <button
          disabled={busy}
          onClick={() => {
            void keyStore.clear().then(() => setEnrolled(false));
          }}
        >
          Forget this key
        </button>
      ) : null}

      {error ? <p role="alert">{error}</p> : null}
    </section>
  );
}

async function enrol(nsec: string, passphrase: string): Promise<string> {
  // `decode` throws on anything malformed and returns a non-nsec type on a
  // well-formed npub, and both are the same mistake from the user's side.
  let decoded: ReturnType<typeof nip19.decode>;
  try {
    decoded = nip19.decode(nsec.trim());
  } catch {
    throw new Error('not-an-nsec');
  }
  if (decoded.type !== 'nsec') {
    throw new Error('not-an-nsec');
  }

  const hex = Array.from(decoded.data, (byte) => byte.toString(16).padStart(2, '0')).join('');
  await keyStore.save(hex, passphrase);
  return hex;
}

function describeKeyLogin(cause: unknown): string {
  const message = cause instanceof Error ? cause.message : '';

  // `createWebCryptoKeyStore` throws these two apart deliberately: a wrong
  // passphrase is retryable and a record this build cannot read is not, and
  // reporting both as "could not read your key" sends half the users into a
  // retry loop that can never succeed.
  if (message === 'Invalid passphrase') {
    return 'Wrong passphrase. Try again.';
  }
  if (message === 'stored key cannot be read by this version') {
    return 'Your stored key was written by an older version. Choose “Forget this key” and enrol it again.';
  }
  if (message === 'not-an-nsec') {
    return 'That does not look like an nsec. It starts with “nsec1”.';
  }
  return 'Could not read your key. Check the passphrase and try again.';
}
