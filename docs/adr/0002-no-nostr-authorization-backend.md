# ADR 0002 — No Nostr backend for session roles and permissions

- **Status:** accepted (decision is "do not build")
- **Date:** 2026-09-01
- **Related:** `../extensions/0001-voucher-bound-authorization.md`

## Context

NAP resolves a session's roles and permissions through one seam,
`AclResolver.resolve(npub, pubkey)` (`packages/nap-server/src/types.ts:193`), called at
three sites: login (`server.ts:684`), refresh, and per-request re-resolution at the guards
(`server.ts:901`). Today the only implementation is `createRegistryAclResolver`, backed by
an `AclStore` over Postgres. Extension 0001 proposes a second implementation backed by a
Cashu voucher.

A third was proposed: a Nostr backend, where authorization is supplied by signed Nostr
events rather than a stored row. This ADR records why it was not built, so the idea is not
rediscovered from scratch.

## What was considered

Four distinct things travel under the name "Nostr backend", and they are not variations of
one design:

1. **Replicated ACL rows** — NIP-33 parameterised-replaceable events, one per principal,
   published by an app authority key. The Postgres table with relays as transport.
2. **Self-attested claims** — the principal publishes their own roles. Worthless without a
   countersignature; ruled out immediately.
3. **Issuer-signed capability events** — an issuer publishes "npub X holds role Y until Z",
   the server holds an issuer allowlist. The voucher model with a Nostr event in place of a
   Cashu proof.
4. **Revocation channel only** — relays carry status transitions, not grants.

Option 4 was already the recommendation in extension 0001 §7.1 (the ledger watcher) and is
being built there, so it was out of scope for this discussion. Option 3 was selected as the
candidate and interviewed.

## Positions reached before the decision

Recorded because they were settled, and they are the starting point if this is ever
reopened:

| Question | Position |
| --- | --- |
| Issuer trust | A bounded delegation chain, root → issuer → grant, depth exactly 2 |
| Grant scope | `d = <app_id>:<pubkey>` — scoped and replaceable, not cross-app |
| Fetch model | Subscribe and materialise a local view; no relay round trip in `resolve()` |
| Absence of a grant | Denied |
| Cold start | An explicit readiness gate: deny *uncertainly* (never setting `revoke_sessions`) until initial sync completes |
| View storage | In-memory, rebuilt from relays on every boot |
| Multiple backends | Mutually exclusive; a deployment configures exactly one |
| Motivation | An alternative to Postgres |

Note that NIP-26 delegated event signing is deprecated and largely unimplemented, so
"delegation" here could not mean reusing an ecosystem feature. It meant NAP verifying a
bespoke chain itself.

## Decision

**Do not build a Nostr authorization backend.** The seam stays as it is; anyone who wants
one can implement `AclResolver` outside the library.

## Why

The design collapsed on a contradiction between two of the positions above.

The stale-grant problem — NIP-33 replacement is ordered by `created_at`, which the issuer
chooses and relays do not police, so a relay serving an older, more permissive grant is
indistinguishable from a slow one — was answered with "NAP is coming with its own relay".
The motivation was separately given as "an alternative to Postgres".

These cannot both hold:

1. **A relay you operate is a database.** It is an append-only event store with a query
   interface that must be backed up, replicated and kept available. That is not removing a
   stateful dependency, it is exchanging Postgres for a less mature one with a worse query
   model.
2. **The delegation chain loses its purpose.** A verifiable chain buys verification
   *without trusting the transport*. If the transport is trusted, an ACL row in your own
   store makes the same statement with no PKI to build and maintain.
3. **Nostr's value is verification across a trust boundary.** Removing the boundary means
   paying for a signature scheme that is not doing any work.

The chosen combination was also the worst available on availability. An in-memory view
(rebuilt each boot) behind a readiness gate, sourced from a single self-operated relay,
gives every deploy a window in which no one can log in, of a length proportional to the
number of grants. Postgres has no such window. This is the same availability regression
extension 0001 §7.3 identifies for the mint, but incurred at every restart rather than only
during an outage.

The deciding question was: **name a real third-party issuer** — a key signing grants that
the NAP operator does not hold. There was none. Where issuer and operator are the same
party, `createRegistryAclResolver` over Postgres already expresses the same thing, and the
no-pre-registration case that a genuine third-party issuer would want is already covered by
extension 0001.

## Cost accepted

Deployments wanting authorization without Postgres have no in-tree option. This is judged
acceptable: no such deployment exists, and the `AclResolver` interface is a public seam, so
one can be built outside the library without a change to NAP.

Building ahead of a real issuer would also have to be mirrored in `nap-java` — a protocol
change in one implementation without the other breaks interop (CLAUDE.md) — doubling the
cost of speculative work.

## Reversing it

Cheap, and the interface seam is what keeps it cheap. Nothing was built, so there is nothing
to remove. Reopening requires one new fact: **a grant signed by a key the NAP operator does
not hold, with a stated reason it cannot be a Cashu voucher instead.** Absent that, the
answer above does not change.

If it is reopened, the multi-relay adversarial design is the one to build — no NAP-operated
relay, mandatory short `expires_at` on every grant rather than reliance on NIP-33
replacement, and relay quorum on read. That version makes the delegation chain earn its
keep. The self-operated-relay version does not, and should not be revisited.
