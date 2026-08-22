# NAP

TypeScript implementation of the **Nostr Authentication Protocol (NAP) v2** — challenge/response
login with a NIP-98 signed event, opaque server-side sessions, optional rotating refresh tokens,
and a role/permission ACL layer. Server, browser, and React packages in one npm workspace.

The protocol is specified in [docs/NAP-v2-RFC.md](docs/NAP-v2-RFC.md). `nap-java` is the JVM
implementation of the same protocol; the two are wire-compatible and must stay that way.

npm workspace. Every package shares one version — a release bumps all of them together, so
the root `package.json` is the single place to read it.

> **There is no build step.** Every package points `exports` and `types` at `./src/index.ts`,
> so there is no `dist/` and nothing to compile — and these are **not npm-publishable as-is**.
> Consume them from the workspace: `examples/merchant-app` is a workspace package that
> depends on them at the shared version and npm links them from `packages/`. That is the
> arrangement the tutorials assume.

## Start here

**[docs/tutorials/](docs/tutorials/README.md)** — a ten-part series from an empty directory to
an Express + React app doing NIP-07, NIP-46 and in-page-key logins, roles and permissions,
Postgres sessions, refresh tokens, step-up, and the caps a deployment needs. It builds
`examples/merchant-app`, which is in the workspace and covered by CI, so the code in it cannot
quietly go stale.

Already know Nostr and want the reference instead? Start at
[integration guide §1–§3](docs/NAP-INTEGRATION-GUIDE.md#1-what-nap-is-and-the-problem-it-solves).

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

## Requirements

**TypeScript >= 5.7 in the consuming project.** There is no build step — every package points
`exports` and `types` at `./src/index.ts`, so it is *your* compiler that compiles NAP's source,
and NAP's source uses the generic `Uint8Array<ArrayBuffer>` that TypeScript models only from 5.7
(`webCryptoSecretStore.ts`, where WebCrypto refuses a possibly-`SharedArrayBuffer`-backed view).
On an older compiler this surfaces as `TS2315: Type 'Uint8Array' is not generic` pointing into
`node_modules`, which reads as a bug in NAP rather than a compiler floor. Each package declares
it as an optional peer dependency, so npm says so at install time instead.

CI tests Node 20.19.0 and 22.x. `nostr-tools` is `^2.23.0` — dedupe it, four packages depend
on it and version skew surfaces as confusing `verifyEvent` failures.

## Documentation

- [docs/tutorials/](docs/tutorials/README.md) — the tutorial series, in order, with what each
  one gets you.
- [docs/NAP-v2-RFC.md](docs/NAP-v2-RFC.md) — the protocol specification. The authority.
- [docs/NAP-INTEGRATION-GUIDE.md](docs/NAP-INTEGRATION-GUIDE.md) — protocol walkthrough and
  integration guide (TypeScript, browser, and Java), security notes, and a section-by-section
  record of where each implementation diverges from the RFC.
- [docs/NAP-IMPLEMENTATION-BEST-PRACTICES.md](docs/NAP-IMPLEMENTATION-BEST-PRACTICES.md) —
  operational guidance.
- [docs/comparisons/webauthn.md](docs/comparisons/webauthn.md) — NAP against WebAuthn.
- [docs/comparisons/oauth.md](docs/comparisons/oauth.md) — NAP against OAuth 2.0.

## Known gaps and next work

§11 of the integration guide catalogues what is RFC-specified but unimplemented, and what is
implemented but incomplete. Beyond that:

- packaging — no build step, so nothing is publishable (see the note above)
- more store adapters (Redis, etc.)
- scheme trust for `createRequestDerivedBaseUrlResolver()` — the host is allowlisted, the
  scheme is still the framework's `trust proxy` decision unless the entry pins it
- no sliding idle window or `absolute_expiry_at`; the Java implementation has both
