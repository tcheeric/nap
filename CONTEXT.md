# CONTEXT — NAP tutorial series

Working context for the documentation effort started 2026-08-22. Scope: a step-by-step
tutorial series for developers integrating NAP, plus a review of the existing docs in
support of it. Settled by interview; see `docs/adr/0001-tutorial-series-shape.md` for the
decisions that are expensive to reverse.

## Vocabulary

- **The guide** — `docs/NAP-INTEGRATION-GUIDE.md`. 3,264 lines. Reference and explanation.
  Not being restructured.
- **The RFC** — `docs/NAP-v2-RFC.md`. The authority on protocol behaviour (CLAUDE.md).
  Not being edited except where it is factually stale.
- **The series** — the ten documents in `docs/tutorials/`. A genre the repo currently has
  none of: tutorial, in the Diátaxis sense — a path the reader walks, not a surface
  described.
- **The example** — `examples/merchant-app`, a workspace package the series builds up.
  Runnable at every stage.
- **The primer** — `docs/tutorials/00-nostr-for-nap.md`. The single home for Nostr
  concepts, and the only place the beginner/expert fork happens.
- **The comparisons** — `docs/comparisons/`. Explanation, not tutorial. Provisional: the
  user may drop them, so nothing else may depend on them.

## Settled decisions

| # | Decision |
|---|---|
| Q1 | Runnable example app, not prose-only |
| Q2 | Both audiences (Nostr-naive and Nostr-literate), served by a skip-fork |
| Q3 | New `docs/tutorials/`; the guide is untouched and cross-linked |
| Q4 | The example lives inside this workspace and uses workspace deps; non-publishability stated honestly on page one |
| Q5 | Doc defects found during review get fixed as part of this work |
| Q6 | TypeScript only; no Java track |
| Q7 | One primer owns the Nostr concepts; tutorials link back rather than re-teach |
| Q8 | Nostr-literate readers are signposted to guide §1–§3; no fourth document written |
| Q9 | All three signers covered: NIP-07, NIP-46, local nsec |
| Q10 | NIP-07 carries the main line; NIP-46 and nsec get dedicated tutorials; nsec last |
| Q11 | Merchant/vouchers domain — it is the only candidate with a credible destructive action for `stepUp` |
| Q12 | Express + React; Fastify as a short appendix, not a track |
| Q13 | In-memory stores first; Postgres in its own tutorial with `docker compose` |
| Q14 | The example is a workspace package: typechecked, one integration test in CI |
| Q15 | Production hardening is the closing tutorial, not reference-only |
| Q16 | Refresh tokens get their own tutorial, including the client wiring NAP does not do |
| Q17 | The WebAuthn page leads with precedent and states the three structural weaknesses |
| Q18 | OAuth: promote and link RFC Appendix D; do not fork it |
| Q19 | Comparisons live in `docs/comparisons/`, entangled with nothing |

## The series

| # | Tutorial | §0.4 phase | Done when |
|---|---|---|---|
| 00 | Nostr for NAP | — | Fork target; Nostr-literate readers skip to guide §1–§3 |
| 01 | A NAP server you can `curl` | 0 | `/auth/init` → `/auth/complete` returns a session |
| 02 | A React frontend that logs in | 2 | Reload keeps you logged in, no signing prompt |
| 03 | Roles and permissions | 3 | A typo'd permission key fails the build |
| 04 | Sessions that survive a restart | 1 | Restart the server, stay logged in |
| 05 | Refresh tokens | — | No signing prompt at the 15-minute mark |
| 06 | Step-up for destructive actions | — | `stripe:manage` demands a fresh signature |
| 07 | Remote signers (NIP-46) | — | Log in from a phone-held key, no extension |
| 08 | Holding a key in the page | — | Idle out, return with a passphrase |
| 09 | Before you ship | 4 | The Phase 4 checklist passes |

Plus a Fastify appendix, and `docs/comparisons/{webauthn,oauth}.md`.

Ordering constraints worth not losing:

- **01 signs with a script-held key.** No browser exists yet, and it is the one context
  where an in-page key cannot be mistaken for production advice.
- **08 is last.** The reader watches the lock state machine work before owning a key it
  can evict.
- **06 settles a contradiction.** Writing it proves which of guide §0.6 and §6.1 is right.

## Raw material already in the repo

Reuse rather than rewrite:

- **Guide §0.4** ("Build in this order") is the series outline. Each phase already carries
  a "done when", which becomes the tutorial's acceptance criterion.
- **Guide §0.3 and §0.5** are the traps and the checklist. §0.5's four groups map onto
  tutorials 01, 02, 03 and 09.
- **RFC Appendix A** is NAP vs NIP-46 — material for tutorial 07.
- **RFC Appendix B** has web-app integration diagrams (B.1 injected signer, B.2 BFF cookie,
  B.3 NIP-46, B.4 recommended boundary) — material for 02, 07.
- **RFC Appendix C** has example Express and Fastify adapter APIs — material for the
  Fastify appendix.
- **RFC Appendix D** is NAP vs OAuth 2.0 — the OAuth comparison, already written.
- **Best-practices §6.4** is a full-flow integration test — the seed for the CI test in Q14.
- **WebAuthn precedent** is cited but scattered: RFC:121 (L3 §13.4.1 trust model), RFC:158
  (UP/UV bits), RFC:163 (clone detection), RFC:171 (multi-credential recovery), RFC:569,
  guide:2565 (§13.5.9 audience binding), guide:2844, guide:2853, best-practices:455
  (§13.5.8 RP allowlists). Collecting these is most of the WebAuthn page.

## Doc defects found so far

Not a complete review — found while reading §0, §6.1, §11 and §12 of a 3,264-line guide.
A systematic pass is part of the work and will surface more.

1. `README.md` says all packages are on `0.8.0`; `package.json` is `0.10.1`.
2. Guide §0.6 and §12 say `stepUp()` always throws / "cannot work in 0.2.0"; §6.1 says it
   has worked since 0.4.0, and `packages/nap-client-web/src/session.ts:434` mints the token.
3. Guide §0.1 says a local key means implementing a `KeyStore` yourself, "NAP ships the
   interface, not an implementation" — `createWebCryptoKeyStore` is exported from
   `packages/nap-client-web/src/index.ts:31`.
4. No README for `nap-client-web`, `nap-client-nip46`, `nap-store-postgres`.
   `nap-client-web` is where every frontend integrator starts.
5. `README.md` needs a tutorial index; the guide needs cross-links back.

All of 1–4 are drift. Drift is the reason for the Q14 CI decision. 1–4 are **fixed**
(ticket 2); 5 is ticket 15.

## Library findings — filed, not fixed

Out of scope per the spec ("any change to library code in `packages/`"), but each one
cost time while building `examples/merchant-app` and each is worth a ticket of its own.

6. **The Express guards authorise but do not expose the principal.** `requireSession` /
   `requirePermission` / `requireRole` load the session, check it, and hand the route
   nothing — so any handler that needs the caller's pubkey reloads it. The example carries
   `src/principal.ts` to do exactly that. Attaching the loaded `SessionRecord` to the
   request would delete that file and the same helper in every consumer.
7. **`NapExpressGuardOptions.clock` is only half honoured.** It reaches
   `resolveEffectiveAcl`, but the guard's own `expires_at` check calls the module-level
   system clock (`packages/nap-adapter-express/src/adapter.ts`, `loadSession`). An injected
   clock therefore cannot move a guarded request in time, and a test pinned to a constant
   instant 401s on every guarded route with no indication why. The example's test anchors
   its clock to `Date.now()` and says so.
8. **`@types/express` must be deduped like `nostr-tools`.** `nap-adapter-express` declares
   `@types/express@^5.0.0` against `express@^4`. A consumer declaring `^4.17` gets a nested
   copy and every handler fails to typecheck against the adapter's — a structural type
   mismatch that reads as a bug in NAP. Worth adding to the CLAUDE.md dedupe trap.
9. **`nap-react` declares no `react` peer dependency.** It has `@types/react@^19` as a
   *dev* dependency and nothing else, so a consumer on React 18 installs cleanly, gets a
   nested `@types/react@18`, and every `ReactNode` fails to typecheck against the
   package's — finding 8 again, in a second package. A React library should declare
   `react` (and `react-dom` where it needs one) as a peer. The example pins React 19 to
   dodge it.

10. **`PostgresSessionStore` returns `expires_at` / `issued_at` as strings.** `pg` parses
    BIGINT as a string to protect precision; `mapSessionRecord` casts it to `number`
    without converting, so the `/auth/session` body ships `"expires_at":"1787407576"` on
    Postgres and `1787407576` in memory. Comparisons coerce and appear to work; arithmetic
    does not (`expiresAt + 60` concatenates), and the session body is the
    cross-implementation contract, so a field whose JSON type depends on the store backend
    is an interop bug. Verified against Postgres 16. The store should convert in the mapper
    or register the INT8 parser itself; the example works around it with a pool-scoped
    `getTypeParser`.

11. **Cookie mode's default body makes `nap-client-web.login()` throw.**
    `writeNapCookieSuccess` without a `transformBody` replies `{"status":"ok"}`, and
    `session.ts`'s `toSessionState()` dereferences `response.principal.pubkey` — so the
    first browser login against a stock cookie-mode backend dies on a bare
    `TypeError: Cannot read properties of undefined (reading 'pubkey')`, before there is
    a session, with nothing naming the cause. The integration guide framed
    `transformBody` as a render optimisation ("so the SPA can render without a second
    round trip"); it is mandatory for every `nap-client-web` consumer. Verified by
    probing the example in cookie mode. The library should either throw a named error
    naming `transformBody`, or fall back to `resume()` when the completion body carries
    no principal. Guide text corrected in the tutorial-05 commit; the library is
    untouched.

12. **Guard denials reach no `AuditLogger`.** `NapExpressGuardOptions` has no
    `auditLogger` field, and neither does the Fastify equivalent, so every
    `requirePermission` / `requireRole` / `requireSession` refusal is invisible: no
    code, no principal, no record. Verified by running the whole tutorial-06 sequence
    — a plain-session 403, a step-up completion, a success, and a cross-paired 403 —
    against a logging server and getting exactly two records out, both
    `NAP_COMPLETE_SUCCESS`. The `/auth/*` endpoints are well covered; the guards, which
    are the actual authorization boundary, are not covered at all. CLAUDE.md's "wire an
    `AuditLogger` and read the `code`" trap therefore does not help for the half of the
    surface an operator most needs to see. The guards should accept the same
    `AuditLogger` and log a denial code per refusal reason.

## Open

Nothing. Frontier was emptied over five rounds. Next step is `/to-spec`.
