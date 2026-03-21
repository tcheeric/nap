# NAP

Standalone TypeScript implementation of the NAP HTTP profile described in
[docs/NAP-v2-RFC.md](/home/eric/IdeaProjects/imani-apps/docs/NAP-v2-RFC.md).

## Packages

- `@imani/nap-core`: protocol types, hashing, header parsing, NIP-98 completion validation
- `@imani/nap-server`: challenge issuance, retry-safe completion verification, session flow
- `@imani/nap-client-http`: client-side request building for `/auth/init` and `/auth/complete`
- `@imani/nap-adapter-express`: Express router and helpers
- `@imani/nap-adapter-fastify`: Fastify plugin and helpers

## Commands

```bash
npm install
npm run typecheck
npm test
```

## Current Scope

- HTTP profile only
- NIP-98 completion proof
- opaque session issuance on the server side
- in-memory stores for local testing

## Recommended Entry Points

- `@imani/nap-core`: low-level protocol validation
- `@imani/nap-server`: `createNapServer()` for most backend use
- `@imani/nap-client-http`: `buildAuthCompleteRequest()` for client proof construction
- `@imani/nap-adapter-express`: `createNapExpressRouter()`
- `@imani/nap-adapter-fastify`: `napFastifyPlugin`

## Next Work

- richer store adapters
- better proxy/trust-policy helpers
- package publishing polish
