# CLAUDE.md

Guidance for Claude Code in this repository. Read `README.md` first for the package list, HTTP
surface, and setup — this file only covers what that doesn't.

## Commands

```bash
npm test        # vitest run
npm run typecheck
```

**There is no build step.** Every package points `exports` and `types` at `./src/index.ts`, so
there is no `dist/` and nothing to compile. Don't go looking for a `build` script — it doesn't
exist, and the packages are not npm-publishable in this state.

## Repository structure

```text
nap/
├── packages/*      9 npm workspaces, all on one shared version
├── docs/           RFC, integration guide, best practices
└── specs/          feature specs (untracked)
```

All packages share a single version; a release bumps every one of them together.

## Key documents

- `docs/NAP-v2-RFC.md` — the protocol specification. **The authority.** Any behaviour question
  is settled here, not by the code.
- `docs/NAP-INTEGRATION-GUIDE.md` — how the protocol works end to end and how to integrate it.
  Also records, section by section, where the code diverges from the RFC.
- `docs/NAP-IMPLEMENTATION-BEST-PRACTICES.md` — operational guidance.

## Cross-implementation compatibility

`nap-java` (sibling repo at `../nap-java`, `xyz.tcheeric:nap-*`) is the JVM implementation of
the same protocol. **A protocol change here needs the matching change there, or interop breaks.**
`nap-java/nap-it` runs interop tests against this implementation's client.

Current deltas — Java has these, TypeScript does not:

| Feature | Note |
| --- | --- |
| Sliding idle window | Java's `GET /auth/session` advances `last_activity_at` and pushes `expires_at` forward. |
| `absolute_expiry_at` | Extra field in Java's session body. Additive, safe to ignore. |
| Typed 401 reasons | Java returns `{error, reason}` with `reason=expired\|invalid`. The web client branches on the 401 status, not the body — keep it that way. |

The session body is the contract that actually binds: `createNapSession()`'s `toSessionState()`
dereferences `response.principal.pubkey`, so `principal`, `roles`, and `permissions` must be
present on both sides. Extra fields are fine; missing ones break clients. And never put an
access token in the `/session` body — the session id is an HttpOnly cookie, and echoing a
credential into JSON makes it readable by script.

## Traps

These have each cost real debugging time. Check them before changing the relevant area.

- **Never reserialize the request body.** The NIP-98 `payload` tag is `sha256(rawBody)`. A
  global `express.json()` running before the NAP router, or any middleware that re-stringifies
  JSON, breaks every completion with `NAP_COMPLETE_PAYLOAD_MISMATCH`. The adapters capture raw
  bytes deliberately.
- **The audience is an adapter option and it is security-relevant.** Exactly one of
  `getExternalBaseUrl` or `audienceResolver` must be passed to the router/plugin — not to
  `createNapServer` — and it sets the NIP-98 audience.
  `createRequestDerivedBaseUrlResolver()` derives it from the request and contains **no trust
  policy**: it reads `Host` raw and leaves `X-Forwarded-Proto` to Express's `trust proxy`.
  Prefer a pinned constant or a Host allowlist. See §9.4 of the integration guide.
- **Dedupe `nostr-tools`.** Four packages depend on it. Version skew between the app's copy and
  NAP's surfaces as confusing `verifyEvent` failures.
- **Every auth failure is an identical 401.** That is deliberate. Debugging is impossible
  without wiring an `AuditLogger` and reading the `code`.
- **Guards default to the login-time ACL snapshot.** `requirePermission` / `requireRole` /
  `requireSession` only re-read the ACL when `aclResolver` is passed in the guard options;
  without it a suspension lands when the session expires, not when it happens. Pass the same
  resolver you gave `NapServerOptions`.
- **The default rate limiter is per-process.** It is on by default, but
  `createInMemoryRateLimiter()` counts in one process, so behind N instances the effective rate
  is N× what you configured. Anything production-facing wants a shared backend behind the same
  `RateLimiter` interface.
- **A signer that changes identity terminates the session.** An extension account
  switch or a re-paired bunker means the next `login()` would silently authenticate as
  someone else. `session.ts` guards this in exactly one place — before `/auth/init`
  against `signer.getNpub()`, and after completion against `principal.pubkey` — clears
  state, broadcasts, and throws `IdentityMismatchError`. It deliberately sends **no**
  `/auth/logout`: the cookie belongs to the old identity and is HttpOnly, so a round
  trip that can fail must not gate local teardown. Don't add a second check elsewhere,
  and don't cache `getNpub()` in a signer — a cached npub blinds the guard.
- **Cookie name and cookie options must come from one source.** The success writer and the
  readers (`/session`, guards, logout) each used to take their own; a mismatch logged users out
  on every page load and left logout clearing a cookie that was never written. Both adapters now
  throw at wiring time rather than run mute. Don't reintroduce a second source of either.

## Fail-at-startup, not at request time

The adapters deliberately throw while building the router/plugin for wiring that would otherwise
be *silently inert* — the cookie-name mismatch above, and `refreshTtlSeconds` set without a
store implementing `getByRefreshToken` / `rotateRefreshToken` or with a `writeSuccess` that
replies `{status:'ok'}` and drops the token the client needs. Inert-but-quiet is the failure
mode being designed against; keep new wiring checks in the same place.

## Known gaps

§11 of the integration guide lists what is RFC-specified but unimplemented, and what is
implemented but incomplete. Update that section when you close one.

## Active Technologies
- TypeScript 5.x, ES2022 modules, `"type": "module"` + `nostr-tools` (floor raised to `^2.23.0` for `BunkerSigner.fromBunker`/`fromURI`), WebCrypto (`crypto.subtle`), `BroadcastChannel` (001-nip46-signer-support)
- Browser-provided; the new `SecretStore` persists only an AES-GCM ciphertext of the NIP-46 client secret key. No plaintext secret is written by library code. (001-nip46-signer-support)

## Recent Changes
- 001-nip46-signer-support: Added TypeScript 5.x, ES2022 modules, `"type": "module"` + `nostr-tools` (floor raised to `^2.23.0` for `BunkerSigner.fromBunker`/`fromURI`), WebCrypto (`crypto.subtle`), `BroadcastChannel`
