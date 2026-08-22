import { useState } from 'react';
import {
  Nip07Error,
  createNip07Signer,
  type SessionSigner,
} from '@imani/nap-client-web';
import { useNip07 } from '@imani/nap-react';
import { RemoteSigner, describeNip46 } from './RemoteSigner.js';

/**
 * The four NIP-07 outcomes, each rendered as itself.
 *
 * Collapsing them into "login failed" is the mistake the error codes exist to
 * prevent: `NOT_AVAILABLE` is an onboarding step, not a failure, and telling a
 * user with no extension that their login failed sends them looking for a
 * problem that is not there.
 */
export function SignerPicker({ onSigner }: { onSigner: (signer: SessionSigner) => void }) {
  const { status, provider, retry } = useNip07();
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
            onSigner(createNip07Signer(provider));
          } catch (cause) {
            setError(describe(cause));
          }
        }}
      >
        Continue with extension
      </button>
      {error ? <p role="alert">{error}</p> : null}
      <RemoteSigner onSigner={onSigner} />
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
