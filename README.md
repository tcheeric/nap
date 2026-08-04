# NAP

TypeScript implementation of the **Nostr Authentication Protocol (NAP) v2** — challenge/response
login with a NIP-98 signed event, opaque server-side sessions, optional rotating refresh tokens,
and a role/permission ACL layer. Server, browser, and React packages in one npm workspace.

The protocol is specified in [docs/NAP-v2-RFC.md](docs/NAP-v2-RFC.md). `nap-java` is the JVM
implementation of the same protocol; the two are wire-compatible and must stay that way.

npm workspace, all packages on `0.6.0`.

> **There is no build step.** Every package points `exports` and `types` at `./src/index.ts`,
> so there is no `dist/` and nothing to compile — and these are **not npm-publishable as-is**.
> Consume them from the workspace.

## Packages

| Package | What's in it |
| --- | --- |
| `@imani/nap-core` | Protocol types, hashing, base64/hex codecs, header parsing, NIP-98 completion validation. Runs in browser and server. |
| `@imani/nap-server` | `createNapServer()` — challenge issuance, retry-safe completion verification, refresh rotation, ACL resolution, in-memory stores, rate limiter, metrics. |
| `@imani/nap-client-http` | Request building for `/auth/init` and `/auth/complete`. |
| `@imani/nap-client-web` | Browser session lifecycle: `createNapSession()`, NIP-07 detection and signers, identity guard, idle lock, re-unlock, cross-tab sync. |
| `@imani/nap-client-nip46` | NIP-46 remote-signer (`bunker://` / `nostrconnect://`) `SessionSigner`, with encrypted reconnection. **Opt-in** — install it only if you want remote signers; it is the only package that talks to relays. |
| `@imani/nap-react` | `NapProvider`, `useNapSession()`, `useReunlock()` over `nap-client-web`. |
| `@imani/nap-adapter-express` | `createNapExpressRouter()`, guards, raw-body-safe JSON parser. |
| `@imani/nap-adapter-fastify` | `napFastifyPlugin`, same surface for Fastify. |
| `@imani/nap-store-postgres` | `PostgresChallengeStore`, `PostgresSessionStore`, `PostgresAclStore`. |

## HTTP surface

Mounted by `createNapExpressRouter()` / `napFastifyPlugin` under whatever prefix you choose:

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/init` | Issue a challenge for an `npub`. |
| `POST` | `/complete` | Verify the NIP-98 proof, establish the session. |
| `GET` | `/session` | Return the session view: `status`, `expires_at`, `principal`, `roles`, `permissions`. |
| `POST` | `/logout` | Revoke the session and clear the cookie. |
| `POST` | `/refresh` | Rotate a refresh token (`Authorization: Bearer …`). **Only registered when `server.refreshTtlSeconds` is set.** |

`createPermissionsRouter()` / `permissionsFastifyPlugin` separately expose `GET /permissions`
for the registry.

Every auth failure is an identical `401` by design — no hint as to which check failed. Rate
limiting is the exception: `429` with `Retry-After`.

## Server setup

```ts
import {
  createNapServer, createRegistryAclResolver,
  InMemoryAclStore, InMemoryChallengeStore, InMemorySessionStore,
} from '@imani/nap-server';
import { createNapExpressRouter, writeNapCookieSuccess } from '@imani/nap-adapter-express';

const server = createNapServer({
  challengeStore: new InMemoryChallengeStore(),
  sessionStore: new InMemorySessionStore(),
  aclResolver: createRegistryAclResolver(REGISTRY, new InMemoryAclStore()),
});

const COOKIE = 'nap_session';

app.use('/auth', createNapExpressRouter({
  server,
  cookieName: COOKIE,
  // Exactly one of getExternalBaseUrl or audienceResolver — it sets the NIP-98 audience.
  getExternalBaseUrl: () => 'https://api.example.com',
  // A factory: the name it writes must be the name cookieName reads, or wiring throws.
  writeSuccess: writeNapCookieSuccess(COOKIE, { httpOnly: true, secure: true, sameSite: 'lax', path: '/' }),
}));
```

Guard routes with `requirePermission()` (preferred), `requireRole()`, `requireStepUp()`, or
`requireSession()` when the route is for signed-in users generally and no permission
distinguishes them. Passing `aclResolver` to any guard re-reads the ACL per request, so a
principal suspended mid-session is denied rather than lasting until their session expires.

**Misconfiguration fails at startup, not at request time.** Building the router throws if the
cookie name the success writer uses is not the one `/session`, the guards, and logout read; and
if `refreshTtlSeconds` is set without a store implementing `getByRefreshToken` /
`rotateRefreshToken`, or with a `writeSuccess` that discards the token body. Each of these was
previously a silent, mute failure.

## Commands

```bash
npm install
npm run typecheck
npm test          # vitest run
```

## Documentation

- [docs/NAP-v2-RFC.md](docs/NAP-v2-RFC.md) — the protocol specification. The authority.
- [docs/NAP-INTEGRATION-GUIDE.md](docs/NAP-INTEGRATION-GUIDE.md) — protocol walkthrough and
  integration guide (TypeScript, browser, and Java), security notes, and a section-by-section
  record of where each implementation diverges from the RFC.
- [docs/NAP-IMPLEMENTATION-BEST-PRACTICES.md](docs/NAP-IMPLEMENTATION-BEST-PRACTICES.md) —
  operational guidance.

## Known gaps and next work

§11 of the integration guide catalogues what is RFC-specified but unimplemented, and what is
implemented but incomplete. Beyond that:

- packaging — no build step, so nothing is publishable (see the note above)
- more store adapters (Redis, etc.)
- better proxy/trust-policy helpers for `createRequestDerivedBaseUrlResolver()`
- no sliding idle window or `absolute_expiry_at`; the Java implementation has both
