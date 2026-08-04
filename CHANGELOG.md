# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

All packages in this workspace share a single version.

## [0.6.0] - 2026-08-04

### Added

- **Both adapters refuse to start when the cookie name the writer uses is not the one
  they read.** `writeNapCookieSuccess` takes the name as its own argument, while
  `/auth/session`, the guards, and the logout clear all go through `cookieName`. Nothing
  forced the two to agree, and the failure was mute: login returned 200 and set the
  cookie, then every read looked for a different name and 401'd — `resume()` logging the
  user out on each page load, logout clearing a cookie that was never written. Building
  the router or registering the plugin now throws, naming both strings. Inert rather than
  insecure, but silently inert, which is why it fails at wiring time — same reason as the
  existing `refreshTtlSeconds` check.

### Fixed

- **`/auth/logout` now clears the cookie with the attributes it was set with** in both
  adapters. `writeNapCookieSuccess` stamps its `cookieOptions` onto the `writeSuccess`
  function it returns, and the logout handler clears with those unless
  `clearCookieOptions` overrides them. Previously the two were unrelated fields and the
  clear defaulted to `{ path: '/' }`, so a cookie set with a `domain` — which a browser
  matches a deletion against, along with name and path — survived a logout that returned
  204. The lifetime is deliberately not copied: on Express a surviving `maxAge` would be
  fed back through `res.cookie` and reissue the cookie the clear exists to remove.
  `clearCookieOptions` keeps working and still wins, so a hand-rolled `writeSuccess` is
  unaffected. `writeNapCookieSuccess` snapshots the options object it is given and both
  the set and the clear read that snapshot, so mutating the object after wiring cannot
  move one without the other.

### Removed

- **`NapClientOptions.cookie`** in `@imani/nap-client-web`. It was declared and never
  read, so setting it did nothing — and there is nothing for it to do: the cookie's
  name, attributes, and lifetime are the server's, the browser attaches it without being
  asked, and an `HttpOnly` cookie is not readable from the page even if it were named.
  Breaking at compile time only; delete the property and behaviour is unchanged. The
  interface now carries a doc comment saying the package is cookie-mode by design and
  pointing bearer-mode callers at `@imani/nap-client-http`.

## [0.5.0] - 2026-08-04

### Added

- **Rotating refresh tokens** (RFC §14.1). Set `refreshTtlSeconds` and the completion
  response carries `refresh_token` / `refresh_expires_at`, and the adapters register
  `POST /auth/refresh`. The token is read from `Authorization: Bearer`, never a cookie —
  a cookie would be attached by the browser to every request to the origin, which is what
  a long-lived credential must not be. Each call mints a new access *and* refresh token
  and retires the presented one.

  **Presenting a retired token revokes the session.** The row keeps one step of history
  (`previous_refresh_token`), which makes a replay distinguishable from a made-up token;
  the response is `NAP_REFRESH_REUSED`, returned after the revocation. A stolen token
  therefore buys one rotation and costs the legitimate holder their session — the theft
  becomes visible instead of silent. Rotation stays on the session row, so the row *is*
  the token family and no separate lineage table can drift out of step with it.

  The ACL is re-resolved on every refresh: a refresh mints a full-TTL access token, so
  trusting the login-time snapshot would let a suspended principal extend access
  indefinitely. As elsewhere, only a denial carrying `revoke_sessions` ends every session.

  Off unless configured. `SessionStore.getByRefreshToken` and `rotateRefreshToken` are
  optional members so existing stores keep compiling, but the adapters **throw at
  construction** if `refreshTtlSeconds` is set against a store lacking either, rather than
  serve a route that answers 401 to everything. The Postgres store needs three new columns
  and two indexes (integration guide §5.5).

  Two deliberate gaps: the refresh TTL slides on every rotation with **no absolute session
  lifetime cap** (RFC §14.1 specifies none — cap it in your own `rotateRefreshToken` if you
  need one), and the client packages do not refresh for you.
- **`MetricsRecorder`** (RFC §19.3, §20.2). A pluggable, no-op-by-default interface
  alongside `AuditLogger`, incrementing the ten RFC-named counters. It decorates the audit
  logger rather than scattering `increment()` calls, so every existing and future audit
  point is counted; only `auth_init_total` and `auth_complete_total` are explicit, because
  they must include requests too malformed to reach an audit point. `NAP_COMPLETE_MISSING_PAYLOAD`
  is deliberately not counted as a payload mismatch — nothing was compared.
- **Official test vectors** (RFC §20.3) under `packages/nap-core/test-vectors/`, covering
  exact URL matching, payload hash generation, duplicate tag rejection, expired challenge
  rejection, retrying the same valid completion, and pubkey/npub mismatch. Regenerated by a
  committed script from fixed inputs, so a diff in the vectors is a protocol change and the
  diff is the review. Run here by `nap-core/test/vectors.test.ts` and
  `nap-server/test/vectors.test.ts`, and shared with the JVM implementation — error codes
  are part of the vector, so a divergence shows up as a failing case rather than as a
  mapping in a consumer.
- **`AudienceResolver` and `RawBodyExtractor`** (RFC §20.2), both accepted by the Express
  and Fastify adapters. `getExternalBaseUrl` stays as the documented shorthand; supplying
  both it and `audienceResolver` throws at construction, because a wiring mistake in the
  security-relevant audience should fail at startup rather than as a uniform 401.

### Fixed

- **A `MetricsRecorder` that throws no longer fails the request.** The interface documented
  that failures are swallowed and nothing caught them, so a metrics backend merely being
  down turned the uniform 401 into a 500 on exactly one branch — the timing side channel
  the uniform failure exists to close, in a louder form. Swallowed and deliberately not
  logged either: a broken sink must not be able to flood the caller's audit logger.
- **The adapters refuse to start when `refreshTtlSeconds` is combined with the default
  `writeNapCookieSuccess` body.** It replies `{status:"ok"}`, so the refresh token was
  minted, stored, and dropped on the floor, leaving a client that could never present the
  credential `/auth/refresh` exists to accept — inert rather than insecure, but silently
  inert. A `transformBody` that returns the token is accepted; the marker is a
  `Symbol.for`, so an adapter loaded twice through different paths cannot fail the check
  open.
- **`NAP_REFRESH_REUSED` names the principal.** The pubkey was landing inside `details`,
  because `logFailure` has nowhere else to put one. It is the one event that says a
  credential leaked, so a sink alerting on `event.pubkey` must be able to name the
  principal whose session just ended.
- Integration guide: the JDBC schema section listed one migration and quoted manual DDL for
  columns `V3` now creates. It lists V1–V3 and what each adds.

## [0.4.0] - 2026-08-03

### Added

- **Pluggable rate limiting** (RFC §17.1). `RateLimiter` is `{ check(key): RateLimitDecision }`,
  where the key carries the scope (`init` / `complete`), npub, proved pubkey, and caller
  address. `createInMemoryRateLimiter()` ships a single-process fixed-window implementation;
  behind N instances the effective rate is N× the configured one, so multi-instance
  deployments want a shared backend behind the same interface. **On by default** — the
  100 ms response floor below holds every unauthenticated request open, which without a
  limiter is a concurrency amplifier rather than a timing defence. Pass `rateLimiter: null`
  to opt out deliberately. Both adapters map `NAP_INIT_RATE_LIMITED` /
  `NAP_COMPLETE_RATE_LIMITED` to **429 with `Retry-After`** and a `"rate limited"` body
  rather than the usual 401 — rate limiting is not an authentication failure, and hiding
  it behind one only makes clients retry harder.

  `/auth/complete` is checked twice: once on caller address before the proof, and again on
  the proved pubkey after it. The first check has nothing to key on when an adapter opts
  out of address reporting, which would otherwise leave the one endpoint that runs a
  Schnorr verify per call unbounded.
- **Outstanding-challenge caps** (RFC §17.4). `maxOutstandingChallengesPerNpub` (default 10)
  and `maxOutstandingChallengesPerIp` (default 30) bound how many unredeemed, unexpired
  challenges one principal or address may hold, so a caller under the rate limit still
  cannot accumulate rows. Exceeding either returns `NAP_INIT_RATE_LIMITED` — a distinct
  code would tell the caller how to spread load to evade the cap.
- **Configurable body limits** (RFC §17.4). `bodyLimit` on `NapExpressOptions` and
  `bodyLimitBytes` on `NapFastifyOptions`, both defaulting to **1 kB**. A valid
  `/auth/complete` body is ~40 bytes; the framework defaults were 100 kB and 1 MB of
  parsing an anonymous caller could buy per request.
- **Per-request permission evaluation** (RFC §15). `resolveEffectiveAcl()`, and an
  `aclResolver` option on both adapters' guards: `requirePermission()` / `requireRole()`
  re-read the ACL per request instead of trusting the login-time snapshot. Costs one ACL
  read per guarded request, so it is opt-in per guard; without it the previous snapshot
  behaviour is unchanged.
- **`AclDecision.revoke_sessions`**, gating the mass revocation above. A denial revokes
  every session the principal holds only when the resolver sets it — `createRegistryAclResolver()`
  does so for `suspended` and nothing else. A resolver that answers "denied" because it
  could not *read* the ACL (a lagging replica, a row mid-rewrite) denies the one request
  and no more; the alternative turns a transient store problem into a forced re-login for
  everyone, recoverable only by a fresh NIP-98 exchange.
- **`constantTimeEquals(a, b)`** in `@imani/nap-server`, used by both adapters to compare
  the step-up token. Guards run outside the auth endpoints' response floor, so `===`
  short-circuiting on the first differing byte had nothing smoothing it out.
- **`createRevokingAclStore(aclStore, sessionStore, clock?)`** (RFC §15), revoking active
  sessions at the point of the ACL write rather than waiting for a request. Fires on
  `suspend()` and on a role change, deliberately **not** on a permission-override edit —
  logging everyone out because a permission was *granted* is worse than the delay.
- **Response timing floor** (RFC §15). `minAuthResponseMillis` (default 100) and
  `responseJitterMillis` (default 25) hold every auth response to a fixed floor plus
  jitter, including the path where the store throws — an unpadded 500 next to padded 401s
  is itself a distinguishable response. The generic 401 hides which check failed; latency
  did not. Jitter alone would not close it — it hides samples, not the mean — so the floor
  does the work. Set `minAuthResponseMillis: 0` in tests.
- **Challenge failure budget** (RFC §13.4). `maxFailuresPerChallenge` (default 5) moves a
  challenge to `failed_terminal`, after which further attempts get
  `NAP_COMPLETE_FAILED_TERMINAL`. Counted only for proof failures after the challenge is
  loaded and matched, so a wrong `challenge_id` cannot burn down another principal's live
  challenge, and an ACL denial — deterministic, not a guessing attack — does not spend it.
- **Step-up authentication finished** (new RFC §10.3). `POST /auth/complete` accepts
  `"step_up": true`, and the resulting session carries `step_up_token` /
  `step_up_expires_at` (`stepUpTtlSeconds`, default 600). `requirePermission()` now
  enforces `stepUp: true` from the registry when passed a `registry`, rather than needing
  `requireStepUp()` remembered at every call site. `session.stepUp()` works.
- `getClientIp` on both adapters, defaulting to the framework's `req.ip`. Return
  `undefined` to opt out — the per-IP cap is then skipped rather than enforced against a
  value anyone can forge.
- `ChallengeStore.countOutstanding()` and `ChallengeStore.recordFailure()`, implemented by
  the in-memory and Postgres stores.

### Changed

- **`challengeTtlSeconds` is now validated** (RFC §10.1). `createNapServer()` throws at
  wiring time for a value outside `1..60` instead of silently issuing a non-conformant
  challenge; a longer TTL widens the window in which a captured proof is replayable.
  A deployment that had set it above 60 will now fail to start.
- **Step-up moved from `?step_up=true` to the request body.** The body is covered by the
  NIP-98 `payload` hash, so the flag can no longer be added in transit to mint a token the
  user never asked for, nor stripped to downgrade a step-up to an ordinary login. It also
  keeps the signed `u` tag query-free and therefore equal to the audience the server
  computes, which RFC §11 requires. `buildAuthCompleteRequest()` takes a `stepUp` option.
- RFC gains §10.3 (Step-up authentication); `AuthCompleteRequest.step_up` and
  `AuthSuccessResponse.step_up_token` / `step_up_expires_at` are now specified wire fields.
- **The per-npub budgets are scoped to the caller address.** Both the outstanding-challenge
  cap (RFC §17.4) and the limiter's `npub` dimension now count per address rather than
  globally. An npub is public and `/auth/init` is unauthenticated, so a global per-npub
  budget was a lockout primitive: anyone could spend a stranger's and keep them from
  logging in. The per-address cap already bounds total storage, which is what the cap is
  for. The `pubkey` dimension keeps a global budget — it only appears once a NIP-98 proof
  has established the caller holds the key.
- **`/auth/complete` spends the caller address's budget once per request.** The post-proof
  limiter check no longer repeats `clientIp`, which was halving the configured per-address
  rate and unevenly: a request rejected before the proof cost one, a request that got
  through cost two.
- **A rate-limited response is no longer padded** to `minAuthResponseMillis`. A 429 is
  already distinguishable by its status code, so the floor hid nothing there and only gave
  a caller who was over the limit a free hold on the server — the amplification the
  limiter exists to prevent. The 401 paths are padded exactly as before.

### Fixed

- **A challenge's failure budget can no longer be spent by anyone but its principal**
  (RFC §13.4). The challenge-value check ran before the principal check, so a proof signed
  by any key could burn a challenge to `failed_terminal`. A `challenge_id` is not a secret
  — it travels in the clear and the client hands it back — so anyone who had seen one
  could deny the rightful holder their login. `NAP_COMPLETE_PRINCIPAL_MISMATCH` now
  returns without touching the counter.
- **The outstanding-challenge cap now sends `Retry-After`.** It denied with a plain
  failure, so the adapter emitted a 429 with no header and a caller who legitimately hit
  the cap could only guess. It now reports the challenge TTL, which is when a slot frees.
- **An oversized npub is dropped from the rate-limit key** rather than used as a map key.
  It reaches the limiter before `decodeNpub` has looked at it, so it is still arbitrary
  caller input at that point. Dropped, not truncated: truncation would let two distinct
  npubs share one budget.

### Migration

- **Postgres users must add two columns** before deploying:

  ```sql
  ALTER TABLE nap_challenges ADD COLUMN client_ip TEXT;
  ALTER TABLE nap_challenges ADD COLUMN failure_count INTEGER NOT NULL DEFAULT 0;
  CREATE INDEX idx_nap_challenges_npub ON nap_challenges (npub) WHERE state = 'issued';
  CREATE INDEX idx_nap_challenges_ip   ON nap_challenges (client_ip) WHERE state = 'issued';
  ```

  The indexes are not optional in practice: `countOutstanding()` runs on every
  `/auth/init`.
- **Custom `ChallengeStore` implementations keep compiling** — `countOutstanding()` and
  `recordFailure()` are optional members — but a store that omits them silently skips the
  corresponding cap. A store that cannot count cannot cap.
- **Rate limiting is now on by default.** Deployments that want the previous unlimited
  behaviour must say so with `rateLimiter: null`. The default is a single-process
  in-memory limiter at 30 requests per identifier per 60 s — behind a load balancer that
  is 30 × N, so a shared-backend limiter is still the right answer for more than one
  instance.
- **Custom `AclResolver` implementations must set `revoke_sessions: true`** on denials
  that should end the principal's sessions. Without it a denial blocks the request but
  leaves sessions alive until they expire.
- **Custom `RateLimiter` implementations** see a new `pubkey` dimension on `RateLimitKey`.
  Ignoring it is safe — the caller counts the same key on `clientIp` too — but a limiter
  that keys only on `clientIp` will not bound `/auth/complete` for an adapter that reports
  no address.
- **`nap-java` carries the matching change** (its own `[Unreleased]`), so a TS client
  asking for a step-up works against a Java server. `nap-it`'s interop test drives the
  real `@imani/nap-client-http` against the JVM server and asserts the step-up token
  round-trips, which is what fails if either side moves the flag again.

## [0.3.0] - 2026-08-03

### Added

- `GET /auth/session` and `POST /auth/logout` on both the Express and Fastify adapters.
  `nap-client-web` already called both, so two of seven `NapSession` methods —
  `resume()` and `logout()` — were dead against a stock mount. Handlers are also
  exported individually (`createNapExpressSessionHandler`, `createNapExpressLogoutHandler`,
  and the Fastify equivalents) for callers wiring routes by hand.
- `toPublicSessionView()` in `@imani/nap-server`, rendering a session without credential
  fields.
- `onLogin` on `NapClientOptions`, fired by `login()` and by a `resume()` that restores a
  session. `useNapCallbacks()` returned an `onLogin` the options type did not accept, so
  the hook's `isAuthenticated` never became true.
- `requireRole(role | role[], options)` on both adapters, with any-of semantics.
  Registered role keys are checked against the registry by `validatePermissions()`, so a
  typo fails at startup rather than silently returning 403 forever.
- `EvictableSigner` and `isEvictableSigner()` in `@imani/nap-client-web`.
- `docs/NAP-INTEGRATION-GUIDE.md`, documenting the protocol and both implementations
  against their source, including where each diverges from the RFC.
- RFC §15.1 (Guarding On Permissions, Not Roles), §28 (Client Key Custody), and
  Appendix D (NAP vs OAuth 2.0).

### Changed

- **`createTrustedProxyAwareBaseUrlResolver()` renamed to
  `createRequestDerivedBaseUrlResolver()`.** The old name advertised a trust policy the
  function does not contain: it reads `Host` raw and delegates the `X-Forwarded-Proto`
  question entirely to the framework's trust-proxy setting. Behaviour is unchanged.
- **`session.logout()` now zeroes the private key** (RFC §28.3). A later `login()`
  requires the key to be supplied again, via `reunlock(passphrase)` or a fresh signer.
  Applications that logged out and back in with the same in-memory signer must adapt.
- `createPrivateKeySessionSigner()` returns `EvictableSigner` rather than `SessionSigner`.
  This widens the type; existing callers are unaffected.
- New adapter options: `cookieName` and `clearCookieOptions`. The latter must match the
  attributes the cookie was set with, or the browser keeps it after logout.

### Fixed

- Corrected nine of the integration guide's 39 RFC line citations. Six pointed at blank
  lines and three at unrelated content, having been written against a file that was being
  edited concurrently. All 39 are now verified to resolve to the claim they support.

### Security

- **`session.lock()` now evicts key material** rather than only marking session state
  (RFC §28.6). Previously the `KeyHolder` passed to `reunlock()` only flipped booleans —
  `setKey(key)` ignored its argument — while the signer closure retained the private key
  for the life of the session, so script in the page could still sign after an idle lock.
  Eviction now fires on `lock()`, the idle timeout, `shutdown()`, `logout()`, `destroy()`,
  and an incoming lock/shutdown/logout broadcast from another tab.

  This bounds the exposure window to the idle timeout. It does not defend a key that is
  unlocked while hostile script runs, since the client must be able to decrypt it, and
  only the `Uint8Array` is zeroed — the hex string passed in is an immutable JS string
  beyond this library's reach until garbage collection.
- `setKey()` rejects a key deriving a different pubkey, so a wrong re-unlock cannot
  silently swap the signing account while `getNpub()` reports the old identity.
- `GET /auth/session` omits `access_token` and the step-up fields. In cookie mode the
  token is HttpOnly; echoing it into a JSON body would hand a working bearer credential
  to any script on the page.

## [0.2.0] - 2026-03-21

The v2 package set: `nap-core`, `nap-server`, `nap-client-http`, `nap-client-web`,
`nap-react`, `nap-adapter-express`, `nap-adapter-fastify`, and `nap-store-postgres`,
with the ACL layer and the NAP v2 RFC.

[Unreleased]: https://github.com/tcheeric/nap/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/tcheeric/nap/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/tcheeric/nap/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/tcheeric/nap/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/tcheeric/nap/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/tcheeric/nap/releases/tag/v0.2.0
