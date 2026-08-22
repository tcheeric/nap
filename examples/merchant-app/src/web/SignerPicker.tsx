import { useEffect, useState } from 'react';
import { Nip07Error, createNip07Signer } from '@imani/nap-client-web';
import { useNip07, useSignerPreference } from '@imani/nap-react';
import { KeyLogin } from './KeyLogin.js';
import type { OnSigner } from './signerChoice.js';
import { RemoteSigner, describeNip46 } from './RemoteSigner.js';

/**
 * The four NIP-07 outcomes, each rendered as itself.
 *
 * Collapsing them into "login failed" is the mistake the error codes exist to
 * prevent: `NOT_AVAILABLE` is an onboarding step, not a failure, and telling a
 * user with no extension that their login failed sends them looking for a
 * problem that is not there.
 */
export function SignerPicker({ onSigner }: { onSigner: OnSigner }) {
  const { status, provider, retry } = useNip07();
  const { preference } = useSignerPreference();

  // Rebuild a remembered extension signer without asking. This is the whole
  // point of the preference store: the cookie is still good, so the only
  // thing standing between a reload and a restored session is an object the
  // page can reconstruct for free.
  //
  // Only this kind auto-restores. A stored bunker pairing and a stored key
  // are both ciphertext, and the passphrase that opens them is the user's.
  useEffect(() => {
    if (preference?.kind !== 'nip07' || !provider) {
      return;
    }
    try {
      onSigner({ signer: createNip07Signer(provider), kind: 'nip07', verifyIdentity: true });
    } catch {
      // Fall through to the picker. A remembered choice that cannot be
      // rebuilt is not an error worth a banner — it is a login screen.
    }
  }, [preference, provider, onSigner]);
  const [error, setError] = useState<string | null>(null);

  if (status === 'detecting') {
    // A real state, not a formality. Extensions inject `window.nostr` on their
    // own schedule, so a component that checks once on first render tells half
    // its users they have no extension.
    return <p>Looking for a signing extension…</p>;
  }

  if (status === 'absent' || !provider) {
    return (
      <section>
        <h2>No signing extension found</h2>
        <p>
          NAP signs you in with a Nostr key. Install a NIP-07 extension — Alby or nos2x —
          then come back.
        </p>
        <button onClick={retry}>I have installed one</button>
        {/* Not a dead end. A user with a key on their phone needs no extension
            at all, and this is the branch where that matters most. */}
        <RemoteSigner onSigner={onSigner} />
      <KeyLogin onSigner={onSigner} />

        {/* And a user with neither an extension nor a second device still has
            a key. Offered last, and deliberately: it is the only one of the
            three that puts key material inside this origin. */}
        <KeyLogin onSigner={onSigner} />
      </section>
    );
  }

  return (
    <section>
      <h2>Sign in</h2>
      <button
        onClick={() => {
          setError(null);
          try {
            onSigner({
              signer: createNip07Signer(provider),
              kind: 'nip07',
              // Freshly picked in this tab, so there is nothing to verify
              // against: the signer is by construction the one just chosen.
              verifyIdentity: false,
            });
          } catch (cause) {
            setError(describe(cause));
          }
        }}
      >
        Continue with extension
      </button>
      {error ? <p role="alert">{error}</p> : null}
      <RemoteSigner onSigner={onSigner} />
      <KeyLogin onSigner={onSigner} />
    </section>
  );
}

export function describe(cause: unknown): string {
  if (!(cause instanceof Nip07Error)) {
    // `login()` and `stepUp()` surface whichever signer is behind the session,
    // so the same handler has to speak both taxonomies. Collapsing a NIP-46
    // TIMEOUT into "something went wrong" throws away the only thing that
    // tells the user their phone is asleep.
    return describeNip46(cause);
  }

  switch (cause.code) {
    case 'NOT_AVAILABLE':
      return 'The extension disappeared. Reload the page and try again.';
    case 'DECLINED':
      // Not an error condition. The user made a choice; offer it again calmly.
      return 'You declined the signature. Nothing happened — try again when ready.';
    case 'TIMEOUT':
      return 'The extension never answered. Check for an approval window behind this one.';
    case 'PROVIDER_ERROR':
      return 'Your extension reported an error. It may be locked — unlock it and retry.';
  }
}
