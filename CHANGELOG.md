# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

All packages in this workspace share a single version.

## [Unreleased]

### Fixed

- **Guards now honour an injected `clock`.** `NapExpressGuardOptions.clock` and its Fastify
  equivalent were passed to `resolveEffectiveAcl` but ignored by session-expiry and
  step-up-expiry checks, which read `Date.now()` directly. A guard configured with the same
  clock as the server therefore agreed about the ACL and disagreed about time: a session
  minted at the injected `now` was rejected by the very next guarded request with
  `NAP_GUARD_NO_SESSION`.

  Only reachable when a clock is injected, so it affected tests and any deployment on a
  controlled clock rather than production wall time. Found by running the extension-0001
  end-to-end test, where the server clock is pinned to a fixed timestamp — no per-module test
  could surface it, because it only appears once a login and a guarded request run against one
  clock. `clock` is now also documented on both guard options interfaces and in guide §9.6.1,
  since being undocumented is part of why the mismatch went unnoticed.

  The same bug reached `POST /auth/logout` in both adapters, found by auditing the remaining
  wall-clock reads rather than by a failing test: the handler loaded the session without the
  server's clock and stamped `revoked_at` from `Date.now()`, writing a revocation timestamp
  years away from every other timestamp in the store. Both now share
  `NapServerOptions.clock`.

- **`createMintAvailabilityPolicy` also rejects destructive *roles* in a degraded grant.**
  Checking permissions alone left a hole: roles expand into permissions downstream
  (`createRegistryAclResolver` returns `role.permissions`), so a `degradedGrant` listing only
  `voucher:view` while carrying `roles: ['admin']` passed the check and would still hand a
  degraded session everything that role grants. `destructiveRoles` closes it.

- **The mint client no longer treats a 4xx as "the mint is unavailable".** Every non-2xx was
  reported as `unavailable`, which is the one reason `onMintUnavailable: 'degrade'` (§7.3) is
  allowed to act on — so a mint answering `400`, `403`, `404`, or `429` could trigger degraded
  mode, exactly the confusion the reason codes exist to prevent. A 4xx is now
  `malformed_response`; only 5xx and transport failures are `unavailable`.

- **Keyset refetch on a miss is bounded per cache entry, not per request.** The retry deleted
  the whole cache on every miss, so N unknown keyset ids cost N mint fetches — the flood the
  retry was meant to prevent. Measured at 11 fetches for 10 unknown ids, now 2. A genuine
  rotation is still picked up within one request.

### Testing

- **Integration tests against real infrastructure** (`npm run test:integration`). Boots the
  actual `cashu-mint-rest` image and a real `nostr-rs-relay` with testcontainers and points
  the shipped mint client at them.

  The existing end-to-end test drives a full NAP login, but its mint is one this repo wrote,
  so it can only confirm our own assumptions about the wire shape. These pin the one thing it
  cannot: that `parseKeysets()` agrees with what the real `/v1/keys` actually sends, that every
  published key is a point the DLEQ code can parse, and that an unroutable mint reports
  `unavailable` against a real socket. Mutation-checked — expecting a field the mint does not
  send fails three of them.

  Opt-in via `NAP_INTEGRATION=1`, so `npm test` stays fast and needs no Docker. Documented in
  `docs/INTEGRATION-TESTS.md`, including how to run the mint standalone (the compose stack has
  eight services; four settings suffice) and two upstream limits found while building this: the
  NUT-07 endpoint needs a datastore, and voucher issuance is blocked by `commons-lang3` being
  declared `<scope>test</scope>` in `cashu-mint-rest` while the voucher ledger needs it at
  runtime.

### Documentation

- **Integration guide §3.5 documents mint-backed authorisation.** §3.1–§3.4 answer "what may
  this principal do?" from a stored ACL row; §3.5 covers answering it from a Cashu voucher
  instead. Written for an operator deciding whether to adopt it, so it leads with the tradeoff
  (no pre-registration, at the cost of the mint becoming an availability dependency of login)
  and is explicit that a stored ACL is simpler and strictly more available when you already
  know your users.

  Covers the P2PK binding that makes a stolen voucher useless, why the mint and both
  allowlists are mandatory, the verification order and the three ordering constraints that are
  security properties rather than style, deny-by-default availability handling, session
  lifecycle, the failure codes, and the body-placement rule. Ends with an honest status table
  and the ADR 0003 blocker.

  Carries a status banner: the verification primitives ship, the resolver does not, so it is
  an evaluation document rather than a wiring guide. All three code samples were compiled and
  executed against the real API.

- **ADR 0003 records the voucher secret-modelling evidence** (`docs/adr/0003-voucher-secret-modelling.md`).
  The Imani mint does **not** enforce P2PK on a VOUCHER secret:
  `VerifyProofsTask.getSpendingCondition()` dispatches first-match on kind, so a VOUCHER
  secret never reaches `P2PKSpendingCondition`, and `VoucherSpendingCondition` has no witness
  check at all. Under extension 0001 §5.3 option 1 as things stand, the §3.1 binding would be
  advisory only — checkable by the NAP server, invisible to the mint.

  Status is `proposed` rather than `accepted`: what remains is an operational choice between
  adopting option 2 now and upgrading every deployed mint first. Cross-linked from the spec's
  review question B, its open-questions list, and its recommendation, so the answer is found
  rather than rediscovered.

- **The `@imani/nap-voucher` README is checked against the source.**
  `readmeTypecheck.test.ts` extracts the TypeScript blocks from the README itself and
  type-checks them against the real API, so a renamed export or a changed option name fails
  the suite instead of silently rotting the documentation. The companion
  `readmeExample.test.ts` executes the same wiring and pins the error messages the README
  quotes. A hand-copied example test cannot catch drift in the document it was copied from,
  which is the gap this closes.

- **Extension 0001 is linked from RFC §22.** The RFC listed five open extensions but pointed
  at no document, leaving the drafted extension unreachable from the spec it extends.

- **`AclDecision` is re-exported from `@imani/nap-server`.** `AclResolver.resolve()` returns
  it, so implementing that interface previously meant importing one type from
  `@imani/nap-core` — a seam that reads as a mistake.

### Added

- **Mint-availability policy for `@imani/nap-voucher` (§7.3).**
  `createMintAvailabilityPolicy()` decides what a mint failure means, and **defaults to
  `deny`**, including when the option is omitted entirely.

  That default is a security property, not a preference. Degraded mode accepts an
  already-spent voucher: DLEQ proves the mint signed the proof but cannot tell a live one
  from a burned one, and the NUT-07 check that could is exactly what is unavailable.

  `degrade` therefore requires an explicit `degradedGrant`. There is no sensible default —
  "the full grant" is the vulnerability, and "nothing" is a session that silently does
  nothing while reading as though it works. The optional `destructivePermissions` list is
  the only mechanical check that the grant is genuinely reduced, and overlap throws at
  wiring time; without it "reduced" is a promise in a comment, and a degraded session
  quietly carrying `voucher:redeem` is the outcome §7.3 forbids.

  Only `unavailable` degrades. `mint_not_allowed`, `unknown_keyset`, and
  `malformed_response` are a mint that answered clearly, and degrading on those would
  treat a definite refusal as a network blip. Supplying a `degradedGrant` under `deny`
  throws too: it means the operator believes degraded mode is on when it is not, and an
  outage is the worst moment to discover that. The emitted grant is frozen, so a caller
  cannot widen every subsequent degraded session.

- **`@imani/nap-voucher` gains the Cashu verification client**: NUT-12 DLEQ, NUT-00
  `hash_to_curve`, and a mint client with a keyset TTL cache and the NUT-07 state check.
  Verified against the official NUT-12 and NUT-00 test vectors, including both DLEQ forms
  and the deterministic-nonce vector.

  `verifyProofDleq()` is the form the extension needs — a `VoucherCredential` carries a
  `Proof` rather than a `BlindSignature`, so `B'` and `C'` are reconstructed from the
  blinding factor `r`. DLEQ proves the mint signed the proof and says nothing about
  whether it is still unspent, which is why the NUT-07 check is not optional (§4.2).

  The client takes the `MintAllowlist` as a required constructor argument and resolves
  through it on every call, so an unvetted `mint_url` never reaches the network (§6's SSRF
  ordering note). `MintUnavailableError.reason` separates `unavailable` from
  `mint_not_allowed`, `malformed_response`, and `unknown_keyset`: only the first may
  trigger §7.3 degraded mode, and collapsing them would let degraded mode fire on a mint
  that answered clearly and said `SPENT`.

  Verification returns `false` for a failed proof and for malformed input alike, since
  both reach the client as the same generic 401 and must not be separable by exception
  shape or timing. Requests carry a mandatory timeout, an unknown keyset triggers exactly
  one refetch, the state check matches on `Y` rather than trusting response order, and an
  unrecognised state is refused rather than assumed `UNSPENT`.

- **New package `@imani/nap-voucher`, carrying the mint and issuer allowlists** for
  extension 0001 (voucher-bound authorization, §4.3). Deliberately dependency-free, per
  the extension's build order: the verification client is built standalone and testable
  with no NAP dependency.

  Any mint can sign a voucher whose tags claim `issuer: acme` and whose metadata implies
  `role: admin`. A valid signature says the mint signed it and nothing about whether that
  mint has authority to make claims this server honours. Since `mint_url` arrives in the
  request, a field choosing the mint a credential is then verified against is the same
  vulnerability class as a header choosing the NIP-98 audience — the flaw
  `createAudienceHostAllowlist()` exists to prevent. `resolve()` therefore matches the
  supplied value against the list and returns the *configured* origin, so nothing
  downstream holds a value that arrived in the request.

  `createMintAllowlist()` and `createIssuerAllowlist()` both throw on an empty list at
  wiring time: an allowlist that allows every mint is the state they exist to make
  unrepresentable. Entries are `https` only with no opt-out — unlike the audience, this is
  an outbound call to a third party whose answer decides an authorization, and over
  plaintext anyone on the path can forge an `UNSPENT` state check — and wildcards are
  refused, since these entries are third parties rather than hosts this deployment answers
  on. `resolve()` never throws and never fetches, so a malformed `mint_url` produces the
  same generic 401 as every other voucher failure and an unvetted URL is never reached.

  Issuers are keyed on the `(mint, issuerPubkey)` pair: trusting a mint is not trusting
  everyone who ever used it. A pair naming a mint outside the mint allowlist is refused,
  because it is dead configuration that reads as though it grants something.

  Nothing consumes this yet. The keyset cache, DLEQ, and NUT-07 check are #20; the
  resolver is #23, blocked on the secret-modelling decision in #13.

- **Guard denials now reach the `AuditLogger`.** `requirePermission()`,
  `requireRole()`, `requireStepUp()`, and `requireSession()` in both adapters accept an
  `auditLogger` (and an optional `metrics`) and emit one `NAP_GUARD_*` code per refusal:
  `NAP_GUARD_NO_SESSION`, `NAP_GUARD_ACL_DENIED`, `NAP_GUARD_PERMISSION_DENIED`,
  `NAP_GUARD_ROLE_DENIED`, `NAP_GUARD_STEP_UP_REQUIRED`.

  The guards are the authorization boundary — `/auth/complete` decides who you are once,
  the guards decide what you may do on every request after — and until now a refusal
  there produced no record at all. An operator running the whole tutorial-06 sequence
  against a logging server got exactly two events out, both `NAP_COMPLETE_SUCCESS`, with
  every 401 and 403 in between invisible. CLAUDE.md's "wire an `AuditLogger` and read the
  `code`" therefore did not help on the half of the surface that most needs it
  (CONTEXT.md finding 12).

  Three properties are deliberate. `NAP_GUARD_NO_SESSION` carries no `pubkey`, because
  there is no principal to name, and that absence is the signal: principal-less denials
  in bulk are unauthenticated traffic, a burst naming one principal is a permission
  problem for that user. `NAP_GUARD_ACL_DENIED` is distinct from the existing
  `NAP_COMPLETE_ACL_DENIED` — a denial at login and a denial at a guard have different
  remedies, and collapsing them makes "was this user suspended mid-session?"
  unanswerable. And a throwing audit sink costs a log line and nothing else: the denial
  goes out byte-identical, because a 500 on exactly one branch tells an attacker which
  branch they hit, and the guards run outside the `minAuthResponseMillis` floor that
  smooths the auth endpoints.

  Purely additive. Guards wired without an `auditLogger` behave exactly as before.
  `GUARD_DENIAL_CODES` and `logGuardDenial()` are exported from `@imani/nap-server` for
  anyone writing their own guard.

## [0.10.1] - 2026-08-20

No behaviour change. Declares a requirement that already existed and was only discoverable by
hitting it.

### Changed

- **Every package declares `typescript >=5.7` as an optional peer dependency.** There is no
  build step — `exports` and `types` point at `./src/index.ts` — so the *consumer's* compiler
  compiles NAP's source, and since 0.9.0 that source has used the generic
  `Uint8Array<ArrayBuffer>` (`webCryptoSecretStore.ts`, where WebCrypto refuses a
  possibly-`SharedArrayBuffer`-backed view). TypeScript models that only from 5.7. Below it the
  failure is `TS2315: Type 'Uint8Array' is not generic` pointing into `node_modules`, which
  reads as a bug in NAP rather than a compiler floor, and this repo's own `npm run typecheck`
  cannot catch it because it devDepends `typescript ^5.7.2`. npm now says so at install time.
  Optional because the case worth failing on is present-but-older; a non-optional peer would
  auto-install a compiler into consumers that pinned their own. README gains a Requirements
  section.

## [0.10.0] - 2026-08-20

Breaking, but pre-1.0, so a minor.
`createRequestDerivedBaseUrlResolver()` now requires a host allowlist; see **Changed**.
Nothing on the wire moved, so the JVM implementation interoperates unmodified. `nap-java`
has no request-derived resolver of its own — an application binds an `AudienceResolver`
bean or pins `nap.external-base-url` — so there is no code to change there. The same
advice applies to a bean that reads `Host`, and `AudienceResolver`'s javadoc now carries
it (`nap-java` 6eb4027), including the part an allowlist alone does not fix: behind a
proxy `request.getScheme()` is whatever `X-Forwarded-Proto` claimed.

### Added

- **`getSignerCapabilities()` — which signers this page could use at all.**
  `detectNip07Provider()` answers one question, "is `window.nostr` here", and a login screen
  built on it alone tells a user with no extension that there is no way in — on a desktop
  that could pair a bunker or take an nsec. This returns
  `{ nip07, nip46, localKey }`. Only `nip07` is detected: NIP-46 and an in-page key are not
  browser features, they are things your bundle contains, so the app declares them.
  `nip46: true` means pairing is offerable, never that a bunker will answer.
  `detectNip07Provider()` is unchanged and still exported — it returns the provider
  `createNip07Signer()` needs.
- **`AuthRequestError`.** `login()` and `stepUp()` threw a bare `Error` carrying the status
  in its message. This carries `{ phase, status, terminal }`, where `terminal` is any 4xx
  except 429 — the failures retrying cannot fix.
- **`NapClientOptions.signerPreference`.** Hand `createNapSession()` the preference store and
  it clears it on a terminal `/auth/init` or `/auth/complete` failure, and when the identity
  guard terminates the session. Nothing cleared it before, so an npub removed from the ACL
  (§15) left a login screen re-offering a login that 401s forever. It is never *written*
  here: only the app knows which kind of signer it built. Deliberately not cleared on
  `logout()` (not evidence about the signer), on a `resume()` that 401s (an expired cookie
  says nothing about the signer), or on anything a retry fixes. The rule is "terminal", not
  "unknown npub", because §10.1 and §15 make every auth failure the same uniform 401 — the
  client is never told which it was.

### Changed

- **`createRequestDerivedBaseUrlResolver()` requires a host allowlist.** **Breaking.** It
  read `Host` raw and contained no trust policy, which let a request header choose the
  audience every NIP-98 proof is checked against — the thing WebAuthn L3 §13.5.9 makes it
  normative for an RP not to do. Pass the hosts you answer on:
  `createRequestDerivedBaseUrlResolver(['api.example.com'])`. Entries may pin the scheme
  (`https://api.example.com`, which ignores `X-Forwarded-Proto` entirely) and may opt into
  subdomains one at a time (`*.example.com`, matching `a.example.com` but not the apex —
  §13.5.8's default is no). A missing or empty list throws at wiring time, in both adapters,
  alongside the cookie-name and `refreshTtlSeconds` checks. Migration: pass your hosts, or
  switch to the pinned constant `getExternalBaseUrl: () => 'https://api.example.com'`, which
  remains the simplest correct answer for a single-host deployment. The shared matching lives
  in `@imani/nap-server`'s `createAudienceHostAllowlist()`.

## [0.9.0] - 2026-08-20

Breaking, but pre-1.0, so a minor. `NapSession.requiresPassphrase()` and the shape of
`nap-react`'s context both changed; see **Removed** and **Changed**. Nothing on the server
or the wire moved, so the JVM implementation interoperates unmodified and `nap-java` needs
no matching change.

### Added

- **`createWebCryptoKeyStore()` — the reference `KeyStore`.** The interface shipped in
  0.8.0 with no implementation, because the application owns key enrolment. That left
  every in-page-key app writing its own, and the predictable failure of writing your own
  is a plaintext nsec in `localStorage`, which RFC §1181 forbids outright. It is an
  adapter over the existing `SecretStore` rather than a second implementation — PBKDF2
  over a caller-supplied passphrase, AES-GCM, fresh salt and IV per write, one set of
  crypto parameters in one place to review.
- **`createSignerPreferenceStore()` — which signer to rebuild after a reload.** A reload
  keeps the session, because the session id is an `HttpOnly` cookie and `resume()` never
  invokes the signer, but it does not keep the signer object, and `createNapSession()`
  needs one before `resume()` can be called at all. The store holds a
  `'nip07' | 'nip46' | 'key'` discriminator and the npub, both public — never key
  material. Without it the page has to ask on every reload, which is the exact prompt
  `resume()` exists to avoid (FR-024).
- **`resume({ verifyIdentity: true })`.** The reload path needs it: the cookie outlived
  the page and the signer did not, so a plain `resume()` restores the previous account's
  principal under whoever is signing now. Opt-in, because verifying costs a `getNpub()` —
  a relay round trip on NIP-46 — and the prompt-free property is the default.
- **`onLogin` now receives `{ via: 'login' | 'resume' }`.** A `login()` is a fresh
  signature; a `resume()` only proves a cookie is still valid. Since the identity guard
  deliberately sends no `/auth/logout`, a terminated identity's cookie outlives its
  session, so anything treating authentication as evidence about *who is signing* —
  clearing an identity-changed banner, above all — must act on `'login'` only.
- **`nap-react` catches up with 0.8.0's external signers**, which never touched it:
  `useNip07` (tri-state `'detecting' | 'present' | 'absent'` with a `retry()`, because an
  extension can inject late and a one-shot `window.nostr` check reports "no extension" to
  users who have one), `useSignerPreference`, `useStoredConnection`, and
  `acquireSigningAccess`. `useStoredConnection` takes `{has, restore}` injected, so
  `nap-react` keeps zero dependency on `@imani/nap-client-nip46` and that package stays
  opt-in.
- **Reactive `roles`, `permissions`, `hasRole` and `hasPermission` on `useNapSession()`.**
  Affordance only — they exist so a render can hide a button. The authorization boundary
  is the adapters' `requirePermission` / `requireRole` / `requireSession`, and a check
  that exists only client-side does not exist. They are the login-time snapshot, same as
  the server-side guards without an `aclResolver`. Read them off the state rather than
  calling `session.hasPermission()` in a component: the method reads the closure and
  answers correctly without ever causing a render, which looks like it works until grants
  change.

### Changed

- **BREAKING — `NapSession.requiresPassphrase(): boolean` is now
  `lockRecovery(): LockRecovery`**, answering `'unlock' | 'passphrase' |
  'reauthenticate'`. The boolean was a two-way answer to a three-way question and produced
  a bug in each arm it could not express, in both directions: a NIP-46 user shown a
  passphrase field that cannot succeed, and an in-page-key user shown an Unlock button for
  a key that was zeroed with nothing to restore it from. **The signer decides and the
  store only breaks the tie** — an app wiring one `keyStore` for its nsec login must not
  drag its extension users into a passphrase prompt. `acquireSigningAccess` is total over
  the union, so adding a case breaks the switch rather than falling through.
- **BREAKING — `NapProvider` requires an `identityChange` prop.** An omitted one is
  indistinguishable at runtime from "no identity change", which would make every account
  switch reject as the retryable `session_expired`. The provider cannot derive it: from
  outside the session, an account switch and a logout are the same state.
- **BREAKING — `ReunlockCancelledReason` gained `identity_changed`, `shutdown`, `locked`
  and `reauthenticate_required`.** An exhaustive switch over the old four values will no
  longer compile.
- **`acquireSigningAccess` no longer unlocks on the user's behalf.** It refuses with
  `locked` / `shutdown` / `reauthenticate_required` and leaves the gesture to the UI.
  `unlock()` clears the lock *and* a shutdown *and* broadcasts, so a background autosave
  calling it would dismiss the overlay in every tab with nobody present — and "the signer
  will re-prompt anyway" is false for a NIP-46 bunker with pre-granted permissions. Only
  the passphrase path prompts, because typing the passphrase is itself the gesture.
- **`autoLock` with a key-holding signer and no `keyStore` now throws at
  `createNapSession()`** instead of bricking the session minutes later, when the first idle
  timeout evicts the key, `reunlock()` throws for the missing store and `unlock()` throws
  for the held key. Same principle as the adapters' wiring checks: inert-but-quiet is the
  failure mode being designed against.
- **`createWebCryptoSecretStore` moved from `@imani/nap-client-nip46` to
  `@imani/nap-client-web`.** Nothing in it was NIP-46-specific and the new `KeyStore`
  needs the same crypto. Re-exported from the old path, so existing imports keep working.
- **The cross-tab bus posts a bare string when there is no detail**, which is the pre-0.8
  wire format the receiver already accepted. Only `identity-changed` carries a payload,
  and that is a type older tabs do not know regardless, so the object form bought nothing.
- `lock()` and `shutdown()` still evict even when nothing can undo them. Zeroing the key
  is the point of §28.6, and refusing a user's explicit lock to avoid an awkward recovery
  leaves a live nsec in the page, which is the worse trade.

### Removed

- `NapSession.requiresPassphrase()`. Replaced by `lockRecovery()`, above.

### Fixed

- **A NIP-46 pairing could be killed by any relay operator.** An `{error}` payload was
  treated as a decline, but decrypting authenticates nobody: the client pubkey is public —
  it is in the `#p` filter every relay sees and in the `nostrconnect://` URI — and NIP-44
  conversation keys are ECDH, so anyone can send something that decrypts. Only
  `result === input.secret` proves the sender read the URI. The error is now recorded and
  used only to classify the eventual timeout. An attacker can change which error a failing
  pairing ends with; they can no longer abort a live one.
- **A locked tab could keep a live key.** `lock` and `shutdown` broadcasts were acted on
  by tabs with no session — a tab still on its login screen has no unlock affordance to
  clear the flag with, and the flag gates the `authenticate()` that would clear it. The
  publishers and the receivers now both no-op without a session, and rearm the idle timer
  on the way out: the timers are one-shot, so returning early would otherwise disarm
  `autoLock` for the life of the page.
- **`resume()` no longer clears `locked`.** The server session says nothing about whether
  the key is in memory.
- **`resume()` assigns session state before verifying identity**, so a relay hiccup during
  `verifyIdentity` no longer discards an otherwise valid session.
- **`acquireSigningAccess` checks identity before the key-available fast path.**
  `terminateForIdentity` clears `locked` on its way out, which made the key look available
  on a session that no longer existed.
- **A `KeyStore` record written by a newer build is no longer reported absent.** `has()`
  answers on presence and `load()` on readability; conflating them routed the app into
  re-enrolment, whose `save()` overwrites the only copy of a ciphertext the newer build
  could still read. A present-but-unreadable record now raises its own error rather than
  `Invalid passphrase`, which would have told a user with the right passphrase to keep
  retyping.
- **A pre-0.8 tab no longer misses `lock` / `logout` / `shutdown` broadcasts.** Dropping a
  `lock` left its decrypted in-page key live after the session was locked everywhere else,
  which is the entire point of the broadcast.
- `createSignerPreferenceStore().write()` returns what it persisted, rather than making
  callers read it back through JSON and the validator to recover an object already in
  hand.

### Security

- The pairing-decline and cross-tab-broadcast fixes above are both security-relevant: the
  first was a denial-of-service any relay operator could mount on every pairing, the
  second left key material resident in a tab that should have zeroed it.
- Nothing added here writes plaintext key material at rest. The new `KeyStore` persists an
  AES-GCM ciphertext under PBKDF2 over a passphrase it never holds, and the signer
  preference stores only a kind discriminator and an npub, both public by construction.

## [0.8.0] - 2026-08-05

### Added

- **External signers: NIP-07 browser extensions and NIP-46 remote signers.** A browser
  session can now authenticate against a key the page never holds. `SessionSigner` is the
  seam, and all three implementations — in-page key, extension, remote signer — go through
  one shared conformance suite, which is what makes them substitutable. The server is
  untouched: a NIP-98 proof carries no trace of which signer produced it, so no adapter,
  store, or wire format changed, and the JVM implementation interoperates unmodified.

- **NIP-07 support in `@imani/nap-client-web`.** `detectNip07Provider()` polls up to a
  second for a late-injecting extension and resolves the moment one appears — a page that
  checks `window.nostr` once on load reports "no extension" to users who have one. It
  returns `null` rather than throwing, because absence is an answer. `createNip07Signer()`
  wraps a provider and maps refusals onto `Nip07Error` codes — `NOT_AVAILABLE`,
  `DECLINED`, `TIMEOUT`, `PROVIDER_ERROR` — since "install an extension", "you clicked
  reject", and "your extension is locked" want three different messages. Extensions phrase
  refusals differently, so the classifier is a heuristic with `classifyError` as the
  documented escape hatch.

- **`@imani/nap-client-nip46`, a new opt-in package** — the only one in the workspace that
  talks to relays, which is why it does not ship inside the browser client. It pairs in
  both directions (`bunker://` pasted by the user, or a `nostrconnect://` URI you render as
  a QR code), requests exactly `sign_event:27235`, and surfaces the signer's `auth_url` web
  approval through `onAuthUrl` during pairing as well as on later requests. The pairing is
  persisted encrypted whole — PBKDF2 (310 000, SHA-256) then AES-GCM — so a reload restores
  it instead of re-prompting; `createWebCryptoSecretStore()` is the browser implementation.
  Timeouts are per operation, sized to the fact that a remote signer is a human holding a
  phone. The relay pool is owned only when the package created it: a caller-supplied pool is
  never destroyed, and one this package opened is closed on `disconnect()` and on a pairing
  that never establishes.

- **`session.unlock()` for sessions that hold no key of their own.** `reunlock(passphrase)`
  restores an evicted key, which NIP-07 and NIP-46 sessions do not have — so without this an
  idle lock stranded them: `login()` refuses while locked, and `reunlock()` needs a
  `keyStore` those signers have no reason to configure. It throws for a session with an
  in-page key, where clearing the flag would report an unlocked session that cannot sign. It
  broadcasts, and a receiving tab honours it only when key-free, for the same reason.

### Changed

- **`nostr-tools` floor raised to `^2.23.0`** across the packages that depend on it, for
  `BunkerSigner.fromBunker`. Keep the app's copy deduped with this one — version skew
  surfaces as confusing `verifyEvent` failures.

## [0.7.0] - 2026-08-04

### Added

- **`requireSession()`** in both adapters, an authentication-only guard.
  `requirePermission`, `requireRole` and `requireStepUp` all answer "which principal", so the
  only way to say "any logged-in user" was a placeholder permission granted to everyone — a key
  in the registry that gates nothing and reads, to the next person, as though it does.

  It resolves through `loadGuardContext` rather than only the session, so a caller who passes
  `aclResolver` also has a principal the ACL has since suspended denied here. Without a resolver
  `resolveEffectiveAcl` returns the login-time snapshot, so the guard behaves identically for
  callers who have not opted in and strictly better for those who have. Resolving only the
  session would have let "logged in" survive a suspension for the full session TTL, which is the
  one thing a session guard should not do.

### Changed

- `README.md` and `CLAUDE.md` rewritten against the current code: package table, the
  `/init` `/complete` `/session` `/logout` `/refresh` surface the adapters mount, a working
  Express setup, and the wiring that fails at startup rather than at request time. Two errors in
  the old setup guidance are corrected — `getExternalBaseUrl` is an adapter option, not a
  `createNapServer` one, and `writeNapCookieSuccess` is a factory taking the cookie name.

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

[Unreleased]: https://github.com/tcheeric/nap/compare/v0.10.1...HEAD
[0.10.1]: https://github.com/tcheeric/nap/compare/v0.10.0...v0.10.1
[0.10.0]: https://github.com/tcheeric/nap/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/tcheeric/nap/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/tcheeric/nap/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/tcheeric/nap/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/tcheeric/nap/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/tcheeric/nap/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/tcheeric/nap/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/tcheeric/nap/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/tcheeric/nap/releases/tag/v0.2.0
