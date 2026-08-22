import { useState } from 'react';
import { Nip46Error, createNip46Signer } from '@imani/nap-client-nip46';
import { createWebCryptoSecretStore } from '@imani/nap-client-web';
import type { OnSigner } from './signerChoice.js';

/**
 * A key that never comes near this page.
 *
 * Two ways in, and the difference is who initiates. Paste a `bunker://` URL and
 * the browser reaches out to the signer; leave it blank and the browser emits a
 * `nostrconnect://` URI for the signer to scan. Either way the private key stays
 * on the phone and every signature is a relay round trip — see tutorial 07 for
 * what that costs.
 */
export function RemoteSigner({ onSigner }: { onSigner: OnSigner }) {
  const [token, setToken] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [uri, setUri] = useState<string | null>(null);
  const [authUrl, setAuthUrl] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function connect() {
    setError(null);
    setUri(null);
    setAuthUrl(null);
    setBusy(true);

    const signer = createNip46Signer({
      ...(token.trim() ? { connectionToken: token.trim() } : {}),
      // Only used for the nostrconnect:// direction. Pick relays the user's
      // signer is actually listening on; a bunker:// URL carries its own.
      relays: ['wss://relay.nsec.app'],
      // Optional, and the difference between pairing once and pairing on every
      // reload. What is stored is an AES-GCM ciphertext of this pairing's own
      // client key — never the user's key, which this page never sees.
      ...(passphrase
        ? { secretStore: createWebCryptoSecretStore('merchant.nip46'), passphrase }
        : {}),
      // The signer wants the user to visit a page — approve a new client,
      // unlock, top up. Not an error; not a decline either.
      onAuthUrl: setAuthUrl,
      onConnectionUri: setUri,
      metadata: { name: 'Merchant app', url: window.location.origin },
    });

    try {
      // Restores a stored pairing if there is one, and pairs afresh if not.
      // The same call covers both, so the UI does not have to know which.
      await signer.connect();
      // `verifyIdentity` unconditionally, because `connect()` deliberately
      // does not tell us whether it restored a stored pairing or made a fresh
      // one — and a restored pairing may point at a different key than the
      // live cookie belongs to. It costs one more relay round trip on a path
      // that has just made several.
      onSigner({ signer, kind: 'nip46', verifyIdentity: true });
    } catch (cause) {
      setError(describeNip46(cause));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section>
      <h3>Or use a remote signer</h3>
      <p>
        <label>
          Bunker URL{' '}
          <input
            value={token}
            placeholder="bunker://… — or leave blank to be scanned"
            onChange={(event) => setToken(event.target.value)}
            size={40}
          />
        </label>
      </p>
      <p>
        <label>
          Passphrase (optional, remembers this pairing){' '}
          <input
            type="password"
            value={passphrase}
            onChange={(event) => setPassphrase(event.target.value)}
          />
        </label>
      </p>
      <button disabled={busy} onClick={() => void connect()}>
        {busy ? 'Waiting for your signer…' : 'Connect remote signer'}
      </button>

      {uri ? (
        <p>
          Scan this with your signer:
          <br />
          {/* Plain text rather than a QR code: rendering one needs a dependency,
              and every mobile signer accepts a pasted URI. */}
          <code style={{ overflowWrap: 'anywhere' }}>{uri}</code>
        </p>
      ) : null}

      {authUrl ? (
        <p>
          Your signer needs you first:{' '}
          <a href={authUrl} target="_blank" rel="noreferrer noopener">
            open it
          </a>
        </p>
      ) : null}

      {error ? <p role="alert">{error}</p> : null}
    </section>
  );
}

/**
 * Six outcomes, and only two of them are the user's fault.
 *
 * `SECRET_MISMATCH` is the one worth reading twice: something answered our
 * pairing URI without the secret that was in it. That is not a wrong password,
 * it is somebody else on the relay.
 */
export function describeNip46(cause: unknown): string {
  if (!(cause instanceof Nip46Error)) {
    return cause instanceof Error ? cause.message : 'Something went wrong.';
  }

  switch (cause.code) {
    case 'INVALID_TOKEN':
      return 'That bunker URL could not be read. Copy it again from your signer.';
    case 'UNREACHABLE':
      return 'Could not reach your signer. Is it online, and on the same relay?';
    case 'TIMEOUT':
      return 'Your signer never answered. It may be asleep — open it and try again.';
    case 'DECLINED':
      return 'Your signer declined. Nothing happened — try again when ready.';
    case 'SECRET_MISMATCH':
      return 'Something answered without the pairing secret. Start a new pairing.';
    case 'PROVIDER_ERROR':
      return 'Your signer reported an error. Check it, then retry.';
  }
}
