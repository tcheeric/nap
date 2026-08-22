# @imani/nap-client-nip46

NIP-46 remote signer for NAP. Implements `SessionSigner` over a bunker, so it is
interchangeable with a NIP-07 extension or an in-page key.

Opt-in: nothing else in the workspace depends on it.

## Includes

- `createNip46Signer()` — pair via `bunker://`, NIP-05, or `nostrconnect://`
- persistence of an established pairing through a `SecretStore`
- `Nip46Error` with a `code` for each distinguishable failure
- connect / sign / ping timeouts, each configurable

## Example

```ts
import { createNip46Signer } from '@imani/nap-client-nip46';
import { createWebCryptoSecretStore } from '@imani/nap-client-web';

const signer = createNip46Signer({
  connectionToken: 'bunker://…',
  secretStore: createWebCryptoSecretStore(),
  passphrase,
  onAuthUrl: (url) => window.open(url),
});

await signer.connect();
```

Omit `connectionToken` to pair the other way round: the signer emits a `nostrconnect://`
URI through `onConnectionUri` for the user to scan.

## Notes

- Requires `nostr-tools` `^2.23.0`, and it must be deduped with every other copy in the
  tree — version skew shows up as confusing `verifyEvent` failures.
- Every signature is a relay round trip. Budget for latency and for network-shaped
  failures that have nothing to do with the user.
- The `SecretStore` persists only an AES-GCM ciphertext of the client secret key, PBKDF2
  over a passphrase the store never holds.
