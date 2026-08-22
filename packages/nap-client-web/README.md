# @imani/nap-client-web

Browser session client for NAP. Runs the init/complete exchange, holds the session, and
manages the signer's lifecycle.

## Includes

- `createNapSession()` — login, resume, logout, step-up
- `SessionSigner` implementations for NIP-07 and an in-page private key
- idle lock, shutdown, and cross-tab broadcast
- `createWebCryptoKeyStore()` / `createWebCryptoSecretStore()` — AES-GCM over PBKDF2
- `createSignerPreferenceStore()` — remembers *which kind* of signer to rebuild after a reload
- `getSignerCapabilities()` and `lockRecovery()` — ask what a signer can do before prompting

## Example

```ts
import { createNapSession, createNip07SignerFromWindow } from '@imani/nap-client-web';

const session = createNapSession({
  baseUrl: 'https://api.example.com',
  signer: await createNip07SignerFromWindow(),
  onIdentityChanged: () => promptForFreshLogin(),
});

await session.resume();          // prompt-free; the session id is an HttpOnly cookie
await session.login();           // one signature, once per session
```

## Notes

- A reload keeps the session but not the signer. Rebuild the signer, then call
  `resume({ verifyIdentity: true })` — a plain `resume()` would restore the previous
  account's principal under whoever is signing now.
- `roles` and `permissions` on the session are the login-time snapshot, and they are
  affordance rather than authorization. The boundary is the server's guards.
- Wire `onIdentityChanged`. Without it, a signer account switch is indistinguishable from
  a logout, and the correct response is the opposite.
