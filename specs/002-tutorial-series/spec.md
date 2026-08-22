# Spec — NAP tutorial series

- **Status:** ready for agent
- **Date:** 2026-08-22
- **Context:** `../../CONTEXT.md`
- **ADR:** `../../docs/adr/0001-tutorial-series-shape.md`

## Problem Statement

A developer who wants passwordless Nostr login in their application arrives at this
repository and finds three substantial documents: a protocol RFC, a 3,264-line integration
guide, and a best-practices file. All three describe surfaces. None of them is a path.

There is no document that says "start here, then do this, and here is how you know it
worked." The integration guide comes closest — §0.4 lays out a five-phase build order where
each phase is independently verifiable — but it is a table inside a reference manual, and
the reader has to assemble the actual steps from §5, §6, §9 and the RFC.

The consequences are concrete and already visible:

- The reader cannot tell which of the three signers to pick, or what picking one costs,
  without reading §0.1, §6.2 and RFC §28.
- The reader has nothing to run. Every code sample is a fragment to be retyped into a
  project that does not exist yet, against packages that cannot be `npm install`ed because
  there is no build step.
- The documentation drifts, because nothing executes it. Four defects were found in the
  first hour of reading: a stale version in the README, two contradictory accounts of
  whether `stepUp()` works, and a claim that consumers must implement a `KeyStore` that
  the library now ships.
- Three of the nine packages have no README at all, including `nap-client-web`, which is
  where every frontend integrator starts.

A reader who is new to Nostr has an additional problem: they must learn keys, npub,
NIP-07, NIP-46 and NIP-98 before any of the above makes sense, and that material is
distributed across the RFC and the guide as prerequisites rather than taught.

## Solution

A ten-document tutorial series in `docs/tutorials/`, backed by a single runnable example
application that the series builds up step by step, plus two provisional comparison pages
in `docs/comparisons/`.

The series is a genre the repository currently lacks. It does not replace or restructure
the guide or the RFC — both stay as they are, and the tutorials cross-link into them for
depth. What the series adds is a walked path with a verifiable end state at every stage.

The example application, `examples/merchant-app`, joins the npm workspace. It is
typechecked by `npm run typecheck` and covered by one HTTP-level integration test in CI,
so a breaking change to any package fails the build rather than quietly making a tutorial
wrong. This is the direct answer to the drift that produced the four known defects.

Reader routing works from a single fork. A primer, `00-nostr-for-nap`, owns every Nostr
concept the series needs. A reader who already knows the NIPs skips it and is signposted
to guide §1–§3, which is already the right document for them. No concept is taught twice.

The series covers all three signers, but not equally: NIP-07 carries the main line because
it is the recommendation, and NIP-46 and in-page keys get dedicated tutorials placed after
the reader has seen the session and lock machinery work.

Defects found while reviewing the existing documentation are fixed as part of this work,
not merely reported.

## User Stories

### Getting oriented

1. As a web developer who has heard of Nostr, I want a single page that explains keys,
   npub, NIP-07, NIP-46 and what NIP-98 signs, so that I can read everything else without
   guessing at vocabulary.
2. As a developer who already knows Nostr, I want to be told immediately that I can skip
   the primer and where to go instead, so that I do not read three pages of material I
   know.
3. As a developer evaluating NAP, I want to know within one screen what problem it solves
   and what it costs me, so that I can decide whether to keep reading.
4. As a developer, I want an index of the tutorials with what each one achieves, so that I
   can see the shape of the whole journey before starting it.
5. As a developer, I want to be told honestly on page one that these packages are not
   npm-publishable as they stand, so that I do not discover it after writing code.
6. As a developer arriving from the README, I want a link to the tutorials, so that I do
   not have to find them by browsing the repository.

### Standing a server up

7. As a backend developer, I want to get a NAP server answering `/auth/init` and
   `/auth/complete` before touching any frontend, so that a failure tells me which layer
   broke.
8. As a backend developer, I want to complete the whole exchange with `curl` and a small
   signing script, so that I see the protocol work without a browser in the way.
9. As a backend developer, I want an `AuditLogger` wired in the very first tutorial, so
   that when a request fails I can see which check rejected it.
10. As a backend developer, I want to be told why every auth failure is an identical 401
    before I hit one, so that I do not spend an afternoon assuming it is a bug.
11. As a backend developer, I want the NAP router mounted before any global body parser
    and to know why, so that I never see `NAP_COMPLETE_PAYLOAD_MISMATCH`.
12. As a backend developer, I want the audience set as a pinned constant with an
    explanation of what a request-derived one would cost me, so that I do not open a
    security hole for a convenience I do not need.
13. As a backend developer, I want to understand what a challenge is, how long it lives
    and why completion is retry-safe, so that I can reason about failures.

### Logging in from a browser

14. As a frontend developer, I want to add login to a React app with a NIP-07 extension,
    so that my users authenticate with a key they already control.
15. As a frontend developer, I want to know that `nap-client-web` is cookie-mode only
    before I wire it, so that I configure the server to match.
16. As a frontend developer, I want `credentials: 'include'` explained once, prominently,
    so that my API calls do not silently fail to authenticate.
17. As a frontend developer, I want `resume()` on mount with a loading state, so that a
    page reload does not prompt my user to sign again.
18. As a frontend developer, I want to know that a reload keeps the session but not the
    signer, so that I understand why the signer preference store exists.
19. As a frontend developer, I want the four distinguishable NIP-07 failure modes shown in
    real UI, so that "install an extension" is never rendered as "login failed".
20. As a frontend developer, I want `destroy()` called on unmount, so that I do not leak
    timers and broadcast channels.
21. As a user of the example app, I want to see whether I am logged in and as whom, so
    that the tutorial's success condition is visible rather than asserted.

### Roles and permissions

22. As a backend developer, I want to define a permission registry with roles, so that
    authorization is declared in one place rather than scattered through routes.
23. As a backend developer, I want a typo in a permission key to fail at startup, so that
    it is not discovered by a user hitting a route.
24. As a backend developer, I want `requirePermission` and `requireRole` guards on my
    routes, so that authorization is enforced at the boundary.
25. As a frontend developer, I want to hide UI a user cannot use, so that the interface
    matches their access.
26. As a frontend developer, I want to be told plainly that client-side role checks are
    affordance and not authorization, so that I do not mistake a hidden button for a
    protected endpoint.
27. As a backend developer, I want to know that permissions are a login-time snapshot and
    what passing an `aclResolver` to the guards changes, so that I can decide how fast a
    revocation must take effect.

### Persistence and session lifetime

28. As a backend developer, I want to swap in-memory stores for Postgres, so that sessions
    survive a server restart.
29. As a backend developer, I want a `docker compose` file so that I can run the database
    without a separate setup guide.
30. As a backend developer, I want to know that `markExpired()` marks but never deletes,
    so that I plan for sweeping expired rows instead of discovering unbounded growth.
31. As a backend developer, I want to see logout actually clear the cookie, so that I know
    the cookie name and options are coming from one source.
32. As a developer, I want to feel sessions *not* survive a restart before I fix it, so
    that I understand what the durable store buys me.

### Staying logged in

33. As a developer, I want to know that the default session TTL is 900 seconds and that
    refresh tokens are off by default, so that I am not surprised by a signing prompt
    every fifteen minutes.
34. As a backend developer, I want to enable rotating refresh tokens, so that my users are
    not re-prompted at every session expiry.
35. As a frontend developer, I want to know that neither `nap-client-web` nor `nap-react`
    stores the refresh token or calls the refresh endpoint, so that I wire it myself
    rather than assuming it is handled.
36. As a backend developer, I want to know that refresh rotation has no absolute lifetime
    cap in this implementation, so that I can add one if my threat model needs it.

### High-value actions

37. As a backend developer, I want to mark a destructive permission `stepUp: true`, so
    that reaching it requires evidence of present key control.
38. As a developer, I want to see an ordinary permission pass and a step-up permission
    demand a fresh signature in the same running app, so that the difference is concrete.
39. As a security-conscious developer, I want to be told that step-up proves key control
    and *not* user consent, so that I do not build a confirmation flow on top of something
    that can complete without a prompt.
40. As a backend developer, I want to know why the step-up flag lives in the request body
    rather than a query parameter, so that I do not helpfully "improve" it.

### Other signers

41. As a developer whose users will not install an extension, I want to support NIP-46
    remote signers, so that a phone-held key can authenticate.
42. As a developer wiring NIP-46, I want the pairing flow shown end to end including the
    `nostrconnect://` URI, so that I know what the user actually does.
43. As a developer wiring NIP-46, I want to know that a decryptable response does not
    authenticate the sender and only the secret match does, so that I do not hand every
    relay operator a kill switch on my pairings.
44. As a developer wiring NIP-46, I want encrypted reconnection explained, so that my
    users do not re-pair on every page load.
45. As a developer, I want to know that swapping signers is a small change at the wiring
    point, so that I am not locked in by tutorial 02.
46. As a developer, I want to know that `nap-client-nip46` is the only package that talks
    to relays and is opt-in, so that I do not pull relay code into an app that does not
    need it.

### Holding a key in the page

47. As a developer whose product cannot require an extension, I want to hold a key in the
    page using the shipped WebCrypto key store, so that I do not implement encryption
    myself.
48. As a developer, I want idle auto-lock configured and demonstrated, so that an
    unattended tab does not leave a usable key in memory.
49. As a developer, I want to know that a lock clears in three different ways and how to
    ask which one applies before locking, so that my UI shows the right recovery
    affordance.
50. As a developer, I want to know that nothing unlocks on the user's behalf, so that I
    build the gesture rather than waiting for the library to.
51. As a developer, I want cross-tab lock and logout behaviour demonstrated, so that two
    open tabs do not disagree about session state.
52. As a security-conscious developer, I want to be told plainly what in-page key custody
    does *not* protect against, so that I choose it with open eyes.
53. As a developer, I want in-page keys taught last, after I have seen the lock machinery
    work, so that I understand the cost before I take it on.

### Identity changes

54. As a developer, I want to know that a signer changing identity terminates the session,
    so that my users are never silently authenticated as someone else.
55. As a developer using React, I want to know that the identity-change callback must be
    wired and cannot be derived, so that an account switch is not mistaken for a routine
    expiry.
56. As a developer, I want to know that an identity change and a logout look identical
    from outside, so that I resolve it by pubkey rather than by a login callback.

### Shipping

57. As a developer about to deploy, I want a single closing tutorial covering what must be
    true before production, so that I am not assembling it from §9 under time pressure.
58. As an operator, I want to know that the default rate limiter counts per process, so
    that I do not run N instances at N times the rate I configured.
59. As a developer, I want body size limits, challenge caps and cookie flags reviewed
    explicitly, so that the defaults are a decision rather than an accident.
60. As a developer, I want `nostr-tools` deduping called out, so that I do not debug
    confusing signature verification failures caused by version skew.
61. As a developer, I want clock skew tolerance explained, so that I know why a correct
    proof can be rejected.

### Fastify and comparisons

62. As a Fastify developer, I want an appendix showing the same wiring for my framework,
    so that I can follow the series without translating every step.
63. As an architect, I want a page comparing NAP to WebAuthn, so that I can place it
    against a standard I already know.
64. As an architect, I want that page to state where NAP is structurally weaker than
    WebAuthn, so that I can trust the rest of it.
65. As an architect, I want a page comparing NAP to OAuth 2.0 that tells me which question
    each protocol answers, so that I can tell whether I need one, the other, or both.

### Maintenance

66. As a maintainer, I want the example application typechecked and integration-tested in
    CI, so that a breaking change fails the build instead of rotting a tutorial.
67. As a maintainer, I want the known stale statements in the existing docs corrected as
    part of this work, so that the tutorials do not link into text that is wrong.
68. As a developer, I want a README for every package, so that the package I land on first
    tells me what it is for.
69. As a maintainer, I want the comparison pages entangled with nothing, so that dropping
    them is deleting two files and two links.

## Implementation Decisions

### Documentation structure

- A new `docs/tutorials/` directory holds the series: a primer (`00`) plus nine numbered
  tutorials, and an index page. A new `docs/comparisons/` directory holds two pages.
- The integration guide and the RFC are **not restructured**. They remain the reference
  and the authority respectively. Tutorials link into them for depth; they gain
  cross-links back to the tutorials.
- Guide §0.4's five-phase build order is the spine of the series. Each phase's existing
  "done when" becomes the corresponding tutorial's stated success condition. Guide §0.3
  (the four expensive mistakes) and §0.5 (the checklist) are distributed into the
  tutorials at the point where each item first matters.
- The tutorial sequence is: `00` Nostr primer; `01` a server you can `curl`; `02` a React
  frontend that logs in; `03` roles and permissions; `04` sessions that survive a restart;
  `05` refresh tokens; `06` step-up for destructive actions; `07` remote signers (NIP-46);
  `08` holding a key in the page; `09` before you ship. A Fastify appendix accompanies the
  server-side material.
- Ordering constraints that are not free to change: `01` signs with a script-held key
  because no browser exists yet and it is the one context where an in-page key cannot be
  mistaken for production guidance; `08` is last so the reader has watched the lock state
  machine operate before owning a key it can evict; `04` follows `02` rather than
  preceding it so the reader experiences sessions failing to survive a restart.

### Reader routing

- Exactly one fork, at the primer. `00` owns every Nostr concept the series uses; no
  tutorial re-teaches one. Tutorials reference the primer by anchor.
- Nostr-literate readers are routed from the tutorial index to guide §1–§3. No fourth
  orientation document is written, because §1–§3 already is that document and a copy would
  drift.

### The example application

- `examples/merchant-app` is added as an npm workspace package. This requires adding
  `examples/*` to the root `workspaces` array, to the Vitest `include` glob, and to the
  root TypeScript `include` array — all three are currently scoped to `packages/*`.
- Stack: Express and React, per ADR 0001. Fastify is covered by an appendix derived from
  RFC Appendix C, not by a second example.
- Domain: merchant and vouchers, per ADR 0001. Permission registry contains
  `merchant:read`, `voucher:create`, and `stripe:manage`, the last carrying `stepUp: true`.
  Roles compose these.
- The application exports an app factory so the integration test can construct it with
  injected stores and a fixed clock, matching the pattern the Express adapter's own tests
  already use.
- Store progression: in-memory through `03`; `@imani/nap-store-postgres` with a
  `docker compose` file introduced in `04`. The application retains the ability to run on
  in-memory stores, which is what CI exercises.
- Mode progression: bearer mode in `01` (headless, `curl`-driven); cookie mode from `02`
  onward, because `nap-client-web` is cookie-mode only. The cookie is written by the
  adapter's cookie success writer so that the logout clear matches it.
- Signer progression: a script-held private key signer in `01`; NIP-07 from `02`; NIP-46
  added as an alternative in `07`; the shipped WebCrypto key store with auto-lock and
  re-unlock in `08`. All three remain selectable in the finished application.
- The audience is a pinned constant. The request-derived resolver is explained in `09` as
  the multi-domain case, with its allowlist requirement stated as the reason it cannot be
  constructed without one.
- An `AuditLogger` is wired in `01` and never removed.

### Comparison pages

- `docs/comparisons/webauthn.md` leads with precedent rather than a feature table: NAP's
  audience binding is WebAuthn's origin binding, and the allowlist requirement follows
  WebAuthn L3 §13.5.9. It then states three places NAP is structurally weaker — no clone
  detection (WebAuthn's signature counter has no NAP analogue), no multi-credential
  recovery, and no signed user-presence or user-verification bit. These are not optional
  content; the page's value depends on them. Source material for all of it already exists
  as scattered asides in the RFC, the guide and the best-practices file, and collecting it
  is most of the work.
- `docs/comparisons/oauth.md` is a short page that links to RFC Appendix D rather than
  restating it. Appendix D is already a complete NAP-versus-OAuth comparison. The new page
  adds only the practical angle Appendix D lacks: what a reader who has OAuth today should
  expect, drawing on guide §10.
- Both pages are provisional. Nothing in the series may depend on them, so that removal is
  deleting two files and their inbound links.
- RFC Appendix A is already a NAP-versus-NIP-46 comparison. Tutorial `07` links to it
  rather than re-explaining the distinction, consistent with the Appendix D decision.

### Documentation defects to fix

These were found during a partial review and are corrected as part of this work. The
review is not complete and is expected to surface more; the same standard applies to
anything else found.

- The README states that all packages are on `0.8.0`; the workspace version is `0.10.1`.
- Guide §0.6 and §12 state that `stepUp()` always throws and cannot work; §6.1 states it
  has worked since 0.4.0, and the client implementation mints and returns the token. §6.1
  is correct; §0.6 and §12 are stale.
- Guide §0.1 states that a local key requires implementing a `KeyStore` yourself and that
  NAP ships the interface but not an implementation. A WebCrypto key store is now exported
  from `nap-client-web`.
- `nap-client-web`, `nap-client-nip46` and `nap-store-postgres` have no README.
  `nap-client-web` is the frontend integrator's first stop.
- The README gains a tutorial index link; the guide gains cross-links to the tutorials.

### Scope boundary on the packages

No library code changes. If writing a tutorial reveals that something the docs describe
does not work, that is filed as a separate issue rather than fixed inline — with one
expected candidate: tutorial `05` will establish how much of the refresh-token gap
described in guide §11.3 is a documentation problem versus a missing client feature.

## Testing Decisions

A good test here exercises the behaviour the tutorial instructs the reader to produce, at
the level the reader observes it, and is blind to internals no tutorial mentions. It fails
when the *instructions* stop working — not when an implementation detail moves.

### The seam

**One test seam: HTTP, via supertest, against the example application's exported app
factory.** A single integration test walks the arc the series teaches — challenge issuance,
completion with a signed proof, a guarded route succeeding, a permission denial, step-up on
the `stepUp: true` permission, refresh rotation, and logout.

This is the highest seam available. It is the level the reader operates at in tutorial `01`
with `curl`, and it is the level at which every later tutorial's server-side claim is
observable.

**Prior art:** the Express adapter's own test suite is near-exact. It builds a real Express
application, drives it with supertest, signs with the private-key signer from
`@imani/nap-client-http`, and runs against in-memory stores with a fixed clock. The new
test follows that structure and imports. The best-practices file's full-flow integration
test section is the second reference.

**Typecheck is the second, compile-time seam.** Extending the root TypeScript `include` to
`examples/*` catches the class of failure that actually produces stale tutorials: the docs
describing an API that changed. All four known defects are of this class.

### Deliberately not given a seam

- **The React frontend.** No jsdom or component-testing seam. `nap-client-web` already has
  its own suites covering session lifecycle, signer conformance, re-unlock, cross-tab
  broadcast, signer preference and the identity guard. The example's frontend is wiring,
  and wiring drift is an API-shape failure that typecheck catches.
- **Intermediate tutorial states.** The test covers the finished application. Tutorial
  `01`'s bearer mode and in-memory stores never appear in the final state, but the server
  package's own tests already cover both. Maintaining one application per tutorial stage
  is the "parallel tracks" mistake in another form.
- **Prose and links.** Extracting tutorial code blocks from real source is the correct end
  state and a build-tooling project in its own right.

### Known hole

Tutorial `04` (Postgres) sits outside the seam. CI runs on in-memory stores and will not
require Docker for a documentation example, and `nap-store-postgres` currently has no test
directory. That tutorial's code is verified by typecheck only. This is an accepted trade,
recorded so that it is known rather than discovered.

## Out of Scope

- **Any change to library code in `packages/`.** Findings are filed, not fixed.
- **Making the packages npm-publishable.** The absence of a build step means a reader
  cannot install these from a registry. The series works around it by living inside the
  workspace and saying so plainly. Fixing it is a build-system project and blocking the
  series on it means neither ships.
- **Restructuring the integration guide or the RFC.** Stale statements are corrected;
  organisation is left alone.
- **A Java or JVM track.** Guide §7 serves that reader. Doubling the surface doubles the
  drift risk against an implementation this repository already tracks by hand.
- **A Fastify example application.** Appendix only.
- **Extracting tutorial code blocks from real source.** Correct end state, separate
  project.
- **Docker-backed CI for the Postgres tutorial.**
- **A hosted documentation site, navigation chrome, or search.** Markdown in the
  repository.
- **Translations.**

## Further Notes

A large fraction of this work is assembly rather than authorship, and the spine should be
built from what exists rather than written fresh:

- Guide §0.4 is the series outline, with acceptance criteria already attached.
- Guide §0.3 and §0.5 are the traps and the pre-flight checklist, ready to distribute.
- RFC Appendix A is NAP versus NIP-46 — material for `07`.
- RFC Appendix B contains web-app integration diagrams covering injected signers, the
  cookie-mode boundary, and NIP-46 — material for `02` and `07`.
- RFC Appendix C contains example Express and Fastify adapter APIs — the Fastify appendix.
- RFC Appendix D is the OAuth comparison, complete.
- The best-practices file's testing section contains a full-flow integration test — the
  seed for the CI test.
- WebAuthn precedent is cited throughout the RFC, the guide and the best-practices file
  but has no home; collecting those citations is most of the WebAuthn page.

Two observations worth carrying into implementation. First, the repository's existing
pattern is comparisons-as-RFC-appendices, which is why both comparison pages link into the
RFC rather than restating it. Second, every one of the four known defects is drift in a
document that nothing executes — which is the entire argument for the CI decision, and the
reason the example application is not optional decoration on a prose series.
