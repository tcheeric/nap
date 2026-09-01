# ADR 0001 — Shape of the NAP tutorial series

- **Status:** accepted
- **Date:** 2026-08-22
- **Context doc:** `../../CONTEXT.md`

## Context

The repository has three substantial documents — an RFC, a 3,264-line integration guide,
and a best-practices file — and no tutorials. In Diátaxis terms it has reference,
explanation and how-to, and nothing a reader walks step by step. The gap is additive, not
a defect in what exists.

Most decisions taken for the series are cheap to revisit. Three are not, because
everything written downstream depends on them. This ADR records those three.

## Decision 1 — The series is backed by a runnable example, not prose alone

`examples/merchant-app` is a workspace package that the series builds up. The reader can
run it at every stage.

**Why:** guide §0.4 already prescribes a five-phase build order in which each phase is
independently verifiable and carries a "done when". That is a tutorial series in reference
clothing — the outline exists, and each phase's "done when" becomes the tutorial's
acceptance criterion at no cost.

**Cost accepted:** several times the work of prose, and a second thing to keep alive. This
is mitigated by making the example a workspace package covered by `npm run typecheck` and
one integration test in CI, so a breaking change fails the build rather than quietly
making a tutorial wrong. Every existing doc in this repo is kept in sync by hand, and four
drift defects were found in the first hour of reading — that is the evidence for paying
this cost.

**Reversing it** means deleting the example and rewriting every tutorial's code blocks as
untested quotations. Cheap mechanically, but it discards the drift protection, which is
the main reason for the decision.

## Decision 2 — The example is a merchant/vouchers app

Permissions: `merchant:read`, `voucher:create`, `stripe:manage` (the last with
`stepUp: true`).

**Why:** the series must cover step-up authentication, and step-up is only honest when
demonstrated on an action a user would genuinely want a fresh signature for. A notes app —
the other candidate, and the one guide §5 uses for its registry examples — has no credible
destructive action, so its step-up tutorial would be a contrivance. This matters more than
usual because step-up is the surface the docs currently contradict themselves about
(guide §0.6 and §12 versus §6.1), so the tutorial has to actually exercise it.

**Cost accepted:** the domain is slightly larger than the minimum, and it diverges from the
`notes:read`/`notes:write` examples in guide §5. Guide §3 already uses the merchant
vocabulary, so the divergence is against one section, not the document.

**Reversing it** means rewriting the example's routes and the registry in every tutorial
from 03 onward. Expensive, and the reason it is recorded here.

## Decision 3 — Express and React, with Fastify as an appendix

**Why:** the raw-body trap — the single most expensive mistake in the integration, per
guide §0.3 — is documented in most depth for Express, and `nap-react` is the
best-documented client package (a 25KB README against no README at all for
`nap-client-web`). Covering both backends fully would double the example surface to
demonstrate an adapter difference of roughly twenty lines. RFC Appendix C already carries
example APIs for both, which is enough to write the appendix from.

**Cost accepted:** Fastify integrators get an appendix rather than a path. If that proves
wrong, the appendix is the natural place to grow a track from.

**Reversing it** means a second example package and a parallel set of server-side
tutorials.

## Consequences

- The series is ten documents in `docs/tutorials/`, plus two provisional comparison pages
  in `docs/comparisons/` that nothing else may depend on.
- The integration guide and the RFC are not restructured. Stale statements in them are
  fixed; their organisation is left alone.
- `examples/merchant-app` joins the npm workspace and CI.
