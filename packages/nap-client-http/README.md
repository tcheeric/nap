# @imani/nap-client-http

HTTP client helpers for the NAP login flow.

## Includes

- completion-body serialization
- payload hash generation
- NIP-98 completion request builder
- signer abstraction
- private-key signer helper for tests and local tooling

## Example

```ts
import {
  buildAuthCompleteRequest,
  createPrivateKeySigner,
} from '@imani/nap-client-http';
```

