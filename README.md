# NAP

Standalone TypeScript implementation of the NAP HTTP profile described in
[docs/NAP-v2-RFC.md](docs/NAP-v2-RFC.md).

See [docs/NAP-INTEGRATION-GUIDE.md](docs/NAP-INTEGRATION-GUIDE.md) for a full
walkthrough of the protocol and how to integrate it into an existing app —
including where this implementation currently diverges from the RFC.

`nap-java` is the JVM implementation of the same protocol; the two are
wire-compatible and must stay that way.

## Packages

- `@imani/nap-core`: protocol types, hashing, header parsing, NIP-98 completion validation
- `@imani/nap-server`: challenge issuance, retry-safe completion verification, session flow
- `@imani/nap-client-http`: client-side request building for `/auth/init` and `/auth/complete`
- `@imani/nap-client-web`: browser session lifecycle, signers, idle lock, cross-tab sync
- `@imani/nap-react`: React provider and hooks over `nap-client-web`
- `@imani/nap-adapter-express`: Express router and helpers
- `@imani/nap-adapter-fastify`: Fastify plugin and helpers
- `@imani/nap-store-postgres`: Postgres challenge, session, and ACL stores

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
- role/permission ACL layer with per-app principal records
- in-memory stores for local testing; Postgres stores via `@imani/nap-store-postgres`

## Recommended Entry Points

- `@imani/nap-core`: low-level protocol validation
- `@imani/nap-server`: `createNapServer()` for most backend use
- `@imani/nap-client-http`: `buildAuthCompleteRequest()` for client proof construction
- `@imani/nap-client-web`: `createNapSession()` and `createNip07Signer()` for browser apps
- `@imani/nap-react`: `NapProvider`, `useNapSession()`
- `@imani/nap-adapter-express`: `createNapExpressRouter()`
- `@imani/nap-adapter-fastify`: `napFastifyPlugin`
- `@imani/nap-store-postgres`: `PostgresChallengeStore`, `PostgresSessionStore`, `PostgresAclStore`

## Documentation

- [docs/NAP-v2-RFC.md](docs/NAP-v2-RFC.md) — the protocol specification
- [docs/NAP-INTEGRATION-GUIDE.md](docs/NAP-INTEGRATION-GUIDE.md) — protocol
  walkthrough, integration guide (TypeScript, browser, and Java), security notes
- [docs/NAP-IMPLEMENTATION-BEST-PRACTICES.md](docs/NAP-IMPLEMENTATION-BEST-PRACTICES.md)
  — operational guidance

## Next Work

- more store adapters (Redis, etc.)
- better proxy/trust-policy helpers
- packaging: there is no build step — every package points `exports` at
  `./src/index.ts`, so these are not npm-publishable as-is

Known gaps against the RFC, and features that are present but incomplete, are
catalogued in §11 of the integration guide.
