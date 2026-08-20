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
  `createRequestDerivedBaseUrlResolver(allowedHosts)` derives it from the request and **an
  allowlist is the only way to construct one** — no default, no empty array; it throws at
  wiring time, because an unrestricted resolver lets a request header pick the value every
  NIP-98 proof is checked against (WebAuthn L3 §13.5.9). Entries are exact hosts, optionally
  scheme-pinned (`https://api.example.com`) and optionally `*.sub` wildcards, opt-in per entry
  (§13.5.8). The scheme is still `X-Forwarded-Proto` under Express's `trust proxy` unless the
  entry pins it. A pinned constant is still simplest for a single-host deployment. See §9.4 of
  the integration guide.
- **Dedupe `nostr-tools`.** Four packages depend on it. Version skew between the app's copy and
  NAP's surfaces as confusing `verifyEvent` failures.
- **Every auth failure is an identical 401.** That is deliberate. Debugging is impossible
  without wiring an `AuditLogger` and reading the `code`.
- **A reload keeps the session but not the signer.** The session id is an `HttpOnly` cookie and
  `resume()` never invokes the signer, so returning to a live session is prompt-free — but
  `createNapSession()` needs a `SessionSigner` before `resume()` can be called at all, and that
  object died with the page. `createSignerPreferenceStore()` remembers *which kind* to rebuild
  (a `'nip07' | 'nip46' | 'key'` discriminator plus the npub — both public, no key material,
  RFC §1181). Without it the page must ask on every reload, which is the prompt `resume()`
  exists to avoid. **That reload path must pass `resume({ verifyIdentity: true })`**: the cookie
  outlived the page and the signer did not, so a plain `resume()` restores the previous
  account's principal under whoever the signer is now. It is opt-in because verifying costs a
  `getNpub()` — a relay round trip on NIP-46 — and FR-024's prompt-free property is the default.
- **`onLogin` fires for `login()` and `resume()`, and `via` separates them.** A `login()` is a
  fresh signature; a `resume()` only proves a cookie is still valid, and the identity guard
  sends no `/auth/logout` so a terminated identity's cookie outlives its session. Anything
  treating authentication as evidence about *who is signing* — clearing an identity-changed
  banner, above all — must act on `via === 'login'` only.
- **`locked` only means something for an authenticated session.** `publishLock` /
  `publishShutdown` no-op without one, **and so must the broadcast `lock` / `shutdown`
  handlers** — a tab still on its login screen that takes the flag from a sibling has no
  unlock affordance to clear it with. The idle timer starts at `createNapSession` and `locked`
  gates `authenticate()`, so a lock set before login refuses the login that would clear it.
  Same trap after `logout()` and `terminateForIdentity()`. When the no-op fires, **rearm the
  timer**: `createActivityLock`'s timers are one-shot, so returning without `touch()` disarms
  autoLock for the life of the page. And `resume()` must not clear `locked`: the server session
  says nothing about the key.
- **A NIP-46 pairing response is not authenticated by decrypting.** The client pubkey is public
  — it is in the `#p` filter every relay sees and in the `nostrconnect://` URI — and NIP-44
  conversation keys are ECDH, so anyone can send something that decrypts. Only
  `result === input.secret` proves the sender read the URI. Never settle the pairing on an
  unauthenticated payload: treating `{error}` as a decline handed every relay operator a kill
  switch on every pairing. Record it and let it classify the timeout instead.
- **`nap-react`'s `roles` / `permissions` are affordance, not authorization.** They exist so a
  render can hide a button; the boundary is the adapters' `requirePermission` / `requireRole` /
  `requireSession`. A check that exists only client-side does not exist. They are also the
  login-time snapshot, same as the guards below. Read them off `useNapSession()` rather than
  calling `session.hasPermission()` in a component — the method reads the closure and answers
  correctly without ever causing a render, which looks like it works until grants change.
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
- **A lock clears three different ways, and the UI has to know which before it
  locks.** `lockRecovery()` answers `'unlock'` (NIP-07/NIP-46 — nothing was
  evicted), `'passphrase'` (in-page key + `keyStore`), or `'reauthenticate'`
  (in-page key, no store — the key is gone and nothing restores it). It is the
  only non-mutating way to ask; `unlock()` answers by succeeding, which is too
  late. **The signer decides, the store only breaks the tie** for signers that
  hold a key here — an app wiring one `keyStore` for its nsec login must not drag
  its extension users into a passphrase prompt. This was a
  `requiresPassphrase(): boolean` for one release and produced a bug in each arm
  it could not express, in both directions; don't collapse it back. Adding a case
  should break the switch in `acquireSigningAccess`, which is total over it.
- **Nothing unlocks on the user's behalf.** `acquireSigningAccess` refuses with
  `locked` / `shutdown` / `reauthenticate_required` and leaves the gesture to the
  UI. `unlock()` clears the lock *and* a shutdown *and* broadcasts, so a
  background autosave calling it dismisses the overlay in every tab with nobody
  present — and "the signer will re-prompt anyway" is false for a NIP-46 bunker
  with pre-granted permissions. Only the passphrase path prompts, because typing
  the passphrase is itself the gesture.
- **`lock()` and `shutdown()` always evict, even when nothing can undo them.**
  Zeroing the key is the point (§28.6); refusing a user's explicit lock to avoid
  an awkward recovery leaves a live nsec in the page, which is the worse trade.
  Only `autoLock` is refused up front, and only because a timer has no user
  intent behind it.
- **`onIdentityChanged` is not recoverable by polling.** `terminateForIdentity`
  nulls the session, so from outside, an account switch and a logout are the same
  state — but the correct response is the opposite. Any state layer must wire the
  callback, and `nap-react` consumers must spread `...callbacks` rather than
  naming a subset. `NapProvider` cannot derive it and takes it as a prop.
  Resolve it by **pubkey, never by `onLogin`**: that callback fires for `resume()`
  too, and since the guard sends no `/auth/logout` the terminated identity's
  cookie still works, so a `resume()` right after a switch restores the *old*
  principal. Treating that as "resolved" hands the previous account's roles to
  whoever is signing now — the exact carry-over the guard prevents on `login()`.
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

`createNapSession` throws on the same principle for `autoLock.enabled` with an `EvictableSigner`
and no `keyStore`: the first idle timeout evicts the key, `reunlock()` throws for the missing
store, `unlock()` throws for the held key, and the session is bricked minutes after a call that
returned cleanly. `nap-react`'s `NapProvider` does the type-level version — `identityChange` is a
required prop, because an omitted one is indistinguishable at runtime from "no identity change"
and would make every account switch reject as the retryable `session_expired`.

## Known gaps

§11 of the integration guide lists what is RFC-specified but unimplemented, and what is
implemented but incomplete. Update that section when you close one.

## External signers

`@imani/nap-client-nip46` is the ninth package and the only one that talks to relays. It is
**opt-in** — nothing else depends on it — and it implements `SessionSigner` over NIP-46, so from
`createNapSession()`'s side it is interchangeable with a NIP-07 extension or an in-page key.
`packages/nap-client-web/test/signerConformance.ts` is the shared harness that keeps that claim
checked; a new signer adds a case there rather than its own bespoke tests.

Two things it constrains:

- **`nostr-tools` floor is `^2.23.0`** for `BunkerSigner.fromBunker`/`fromURI`. Combined with the
  dedupe trap above, that floor applies to the whole workspace.
- **`SecretStore` persists only an AES-GCM ciphertext** of the NIP-46 client secret key, PBKDF2
  over a caller-supplied passphrase the store never holds. Library code writes no plaintext
  secret, and nothing here should start. The implementation now lives in
  `nap-client-web/src/webCryptoSecretStore.ts` (re-exported here for compatibility) because
  nothing in it is NIP-46-specific and `createWebCryptoKeyStore` needs the same crypto —
  **one set of crypto parameters, one place to review them.** Don't add a second.

`BunkerSigner.getPublicKey()` memoises — `signer.ts` deliberately goes around it via
`sendRequest('get_public_key', [])`, for the same reason the identity-guard trap says never to
cache an npub.
