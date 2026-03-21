# @imani/nap-core

Pure protocol helpers for the NAP HTTP profile.

## Includes

- wire types
- deterministic error codes
- base64 helpers
- SHA-256 payload hashing
- `Authorization: Nostr ...` parsing
- NIP-98 completion validation

## Example

```ts
import { verifyNip98Completion } from '@imani/nap-core';

const result = verifyNip98Completion({
  authorization,
  method: 'POST',
  url: 'https://api.example.com/auth/complete',
  body: { challenge_id: 'chlg_123' },
  rawBody,
  now: Math.floor(Date.now() / 1000),
});
```

