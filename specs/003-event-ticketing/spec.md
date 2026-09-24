# Event Ticketing on Voucher-Bound Authorization

> **New to this?** Read [how NAP uses Cashu mint authorisation](../../docs/explanation/mint-backed-authorisation.md)
> and [extension 0001](../../docs/extensions/0001-voucher-bound-authorization.md) first. This
> document assumes both.

**Status:** Draft, for review. Nothing implemented.

**Depends on:** Extension 0001 (`P2PK_VOUCHER` secret, the voucher ACL resolver), NUT-07 state
check, NUT-11 P2PK, NUT-12 DLEQ.

**Applies to:** an application built *on* NAP. This is not a protocol change and adds nothing to
the RFC. Two items in §13 would be, and are called out where they arise.

**Conferencing engine:** BigBlueButton (LGPL-3.0). §6 and §8 name its API directly; every other
section is engine-agnostic.

Each requirement carries one of three markers:

- **[built]** — extension 0001 or `@imani/nap-voucher` already does this. Wire it.
- **[build]** — application code, specified here.
- **[gap]** — needs something NAP does not have yet. §13 tracks each one.

---

## 1. Summary

A paid ticket to a live online event is a `P2PK_VOUCHER` proof. Presenting it at
`/auth/complete` yields a NAP session whose permissions admit the holder to one event. The
session, not the proof, is the seat: admission does not spend the ticket, so a dropped
connection costs nothing and a rejoin is free.

Three properties fall out that no ticketing platform currently offers together:

- **No attendee record.** The organiser never learns who attended. There is no guest list to
  breach, subpoena, or sell.
- **Tickets transfer without a platform.** Resale is an ordinary Cashu swap between two
  parties. Nobody arbitrates whether a transfer is permitted, and the seat count is preserved
  because the number of live proofs is fixed.
- **Capacity is arithmetic, not policy.** *N* proofs issued means at most *N* simultaneous
  attendees, enforced by the mint's double-spend database and the conferencing engine's own
  participant cap rather than by a rule someone could misconfigure.

The one-line framing: **the ticket is the entitlement, the session is the seat, and the mint is
the turnstile.**

## 2. Terminology

| Term | Meaning |
| --- | --- |
| **Ticket** | A `P2PK_VOUCHER` proof whose tags name an event. |
| **`K`** | The keypair a ticket is P2PK-locked to. Freshly generated per ticket (§4.3). |
| **Holder** | Whoever controls `K`. Deliberately not "the buyer" — they may differ after a transfer. |
| **Admission** | The NAP login that converts a ticket into a session. |
| **Join** | The redirect from an admitted session into the conferencing engine. |
| **Seat** | One concurrent occupancy of the meeting, keyed on ticket. |
| **Organiser** | Whoever issues tickets and runs the event. Also the voucher issuer. |

## 3. Actors and trust boundaries

```
  Holder                Platform (NAP)            Mint            Conferencing engine
    │                        │                     │                      │
    │ ── admission ────────► │                     │                      │
    │    (NIP-98 by K,       │ ── state check ───► │                      │
    │     ticket in body)    │ ◄── UNSPENT ─────── │                      │
    │ ◄── session cookie ─── │                     │                      │
    │                        │                     │                      │
    │ ── GET /join ────────► │ ── create/join ───────────────────────────► │
    │ ◄── 302 ───────────────│    (shared secret, server-side)            │
    │ ─────────────────────────────── join URL ──────────────────────────► │
```

Three boundaries, and what each side is trusted for:

- **Holder → Platform.** Untrusted. Everything the holder sends is attacker-controlled,
  including `mint_url` (§5.2.1).
- **Platform → Mint.** Trusted for liveness only, and only for mints on the allowlist. The mint
  learns that *a* ticket was state-checked, and when. It does not learn who holds it.
- **Platform → Engine.** The platform holds the engine's shared secret. The engine has no user
  model of its own and trusts any correctly-checksummed call. The platform is therefore the
  entire authorization layer, and the engine's join URL is the point at which NAP's guarantees
  end (§6.2).

The organiser is **not** in the trusted path for admission. They issued the ticket; they cannot
retroactively decide who gets in, short of ending the meeting.

## 4. The ticket

### 4.1 Secret

**T-1 [built]** A ticket MUST be a NUT-10 secret of kind `P2PK_VOUCHER`, per ADR 0003. Neither
a bare `VOUCHER` secret carrying P2PK tags (the lock goes unenforced by the mint) nor a `P2PK`
secret carrying voucher tags (the issuer signature covers bytes that never appear on the wire)
is acceptable.

**T-2 [built]** The secret's `data` field MUST be the P2PK lock key `K`.

### 4.2 Tags

Extension 0001's tag vocabulary carries the ticket without extension. Nothing below is a new
tag.

| Tag | Required | Ticket meaning |
| --- | --- | --- |
| `voucher_id` | yes | Opaque unique id. Also the seat key (§6.3) and the engine `userID` seed. |
| `issuer` | yes | The organiser. |
| `issuer_pubkey`, `issuer_sig` | yes | Issuer authority. Verified locally at step (e). |
| `expires_at` | yes | Doors close, plus grace. See T-5. |
| `unit` | yes | The tier discriminator — e.g. `ga`, `speaker`, `press`. |
| `face_value` | yes | See §4.4. |
| `memo` | no | Human-readable event name, shown in wallets. Not authoritative. |
| `merchant_metadata` | yes | Carries `event_id`. Issuer-signed, therefore not forgeable. |

**T-3 [build]** `event_id` MUST live in an issuer-signed tag. `merchant_metadata` is the
designated home. It MUST NOT be inferred from the request path, the session, or anything else
the holder controls — a ticket for a €5 workshop must not admit its holder to a €500 masterclass
because the path said so.

**T-4 [build]** `unit` is the tier. The mapping from `unit` to roles is `grant()` (§7), and it
MUST be total: an unrecognised `unit` denies rather than defaulting to general admission.

**T-5 [built]** `expires_at` MUST be the event end plus an operator-chosen grace window, not the
event start. A ticket that expires at doors-open cannot readmit someone who drops at minute
three.

### 4.3 Key generation

**T-6 [build]** `K` MUST be freshly generated per ticket and MUST NOT be the holder's long-term
Nostr identity key.

This is the single requirement most likely to be quietly violated by a wallet implementation,
and violating it forfeits the entire privacy claim: a ticket locked to a personal npub is a
named attendee record, and no amount of server-side care recovers it. Extension 0001 states the
same rule and nothing enforces it there either. The platform SHOULD reject at issuance any lock
key that matches a key it has seen on another ticket, which catches the careless case without
pretending to catch the determined one.

**T-7 [build]** The platform MUST NOT retain the mapping from purchaser to `voucher_id` after
issuance settles. Retaining it reconstructs the attendee list this design exists to abolish, in
the one place best positioned to do so.

### 4.4 What `face_value` means

**T-8 [build] — decision required.** Two models, and the choice is architectural:

**(a) Ticket as entitlement (recommended).** The buyer pays through an ordinary channel; the
organiser then issues a ticket with nominal `face_value`. The organiser has their money at
issuance and never needs to redeem. Resale is a pure entitlement transfer, with payment between
the parties handled separately and invisibly to the platform. `backing_strategy` and
`issuance_ratio` document the arrangement.

**(b) Ticket as ecash.** The ticket carries real value and the organiser swaps it for settlement.
Because admission MUST NOT spend (§5.2.4), settlement is a separate batch after doors close —
which means an attendee who transfers their ticket mid-event leaves the organiser holding a proof
someone else already spent.

Model (a) unless there is a specific reason otherwise. Model (b) is not specified further here.

## 5. Lifecycle

### 5.1 Issuance

**L-1 [build]** The organiser declares `capacity`. Exactly `capacity` tickets are minted. This
number is the only capacity control that cannot be misconfigured later, because it is the count
of things that exist.

**L-2 [build]** Issuance is out of band with respect to NAP. The platform's issuance endpoint is
guarded by the organiser's own session — an ordinary stored-ACL NAP login, not a voucher one.
Ticketing does not make the organiser anonymous, and should not try to.

### 5.2 Admission

Admission is extension 0001's verification procedure, unmodified. It is restated here only for
the ordering, which is load-bearing.

**L-3 [built]** `/auth/init` issues the challenge. `/auth/complete` carries the NIP-98 event
signed by `K`, with the ticket in the body.

**L-4 [built]** Verification runs in extension 0001's order: (a) mint allowlist, (c) parse
secret, (d) P2PK key equals completion signer, (g) `expires_at`, (e) issuer signature,
(f) `(mint, issuer)` allowlist, (b) DLEQ, (h) NUT-07 state, (i) grant. Steps (a)–(i) run **only
after** RFC steps 1–12 have proven key control.

Three orderings carry weight and MUST NOT be rearranged:

**5.2.1 [built]** The mint allowlist runs before any outbound call. `mint_url` arrives in the
request; fetching it first is server-side request forgery from inside the perimeter. Both
allowlists throw at construction when empty. The mint allowlist MUST reject `http:` — an
attacker on the path can otherwise forge `UNSPENT`.

**5.2.2 [built]** The binding check (d) runs before the network call (h). It is local and free,
and running the round trip first would tell a mint that someone is probing a proof already known
to be invalid.

**5.2.3 [built]** Everything runs after key control is proven. Otherwise `/auth/complete` is a
free oracle for state-checking arbitrary proofs against a mint the caller does not control.

**5.2.4 [built]** **Admission MUST NOT spend the ticket.** NUT-07 is read-only. Spending at the
door means a dropped connection costs a ticket, and it would make NAP's retry-safe completion
path destructive — a duplicate completion is guaranteed to return the same session, which is not
possible if the first one burned the proof.

**L-5 [build]** On success the session's lifetime MUST be capped at the event duration plus
grace, via `maxSessionLifetimeSeconds`. This is the bound on §7.1 of extension 0001: a ticket
transferred mid-event leaves the transferor's session live until the ceiling, and the ceiling is
the only thing that ends it.

### 5.3 Join

**L-6 [build]** `GET /events/:id/join` MUST be guarded by `requirePermission` for the permission
`grant()` derived from *this ticket's* `event_id` (§7.1), and MUST pass the same `aclResolver`
the server was configured with. A guard without an explicit resolver reads the login-time
snapshot only.

**L-7 [build]** The join handler MUST:

1. Verify the meeting exists and is running; create it if not (§6.1).
2. Run the seat check (§6.3). Refuse if the ticket already occupies a seat.
3. Construct the engine's `join` call server-side, signed with the shared secret.
4. Respond `302` to the resulting URL.

**L-8 [build]** The join URL MUST NOT be returned to the client as data — no JSON field, no
template variable, no `fetch` response. A `302` consumed immediately is the only form in which
it leaves the server. This does not make it secret (§6.2); it removes the obvious ways it gets
copied.

### 5.4 Transfer and resale

**L-9 [built, at the mint]** Transfer is an ordinary Cashu swap and involves the platform not at
all. The holder presents the proof locked to `K`; the mint marks it spent and issues a
replacement locked to the recipient's `K'`. The old ticket is dead on its next state check.

**L-10 [build]** The platform MUST NOT offer a transfer endpoint, a transfer approval step, or a
transfer record. Every one of those reintroduces the arbitration this design removes, and none is
necessary for the swap to work.

**L-11 [build]** The transferor's live session survives the swap until the §L-5 ceiling. The
platform MUST NOT treat this as a defect to be patched with per-request mint checks; extension
0001 §7.1 establishes the ceiling as the intended bound. Operators wanting a tighter bound
shorten the ceiling, at the cost of re-admission prompts mid-event.

### 5.5 Refund and cancellation

**L-12 [gap]** There is no automatic refund path. NUT-11 `locktime` with a refund pubkey is the
mechanism — the holder can spend until `T`, after which only the organiser can, or the reverse
for a cancellation refund — and `packages/nap-voucher` implements neither tag. `expires_at` is a
local clock check on an issuer-signed value, not a mint-enforced spending condition, and cannot
substitute.

Until §13.1 closes, cancellation refunds are manual and out of band.

## 6. Seat enforcement

### 6.1 Meeting creation

**S-1 [build]** The meeting MUST be created with `maxParticipants` equal to the number of tickets
issued for the event.

This is the arithmetic cap and the most valuable single line in the integration: it is enforced
by the engine, needs no platform state, and cannot drift from the ticket count if it is derived
from it.

**S-2 [build]** The meeting SHOULD set `duration` to bound the event server-side, `logoutURL`
back into the platform, and `meta_endCallbackUrl` for end-of-meeting reconciliation.

**S-3 [build]** `create` MUST be called server-side and MUST be idempotent from the platform's
side — call it immediately before the first join rather than on a schedule, and retain the
returned `createTime`.

### 6.2 The join URL is a bearer credential

**S-4 [build] — stated so it is not discovered later.** The engine's join URL is checksummed but
bearer: it is reusable for the life of the meeting instance, it carries `role` in the clear, and
the engine will honour it from any browser. Everything NAP proves about `K` terminates at the
`302`.

This is not a defect to be fixed; it is the boundary. Defence is layered and each layer is
independently worth having:

| Layer | Stops | Does not stop |
| --- | --- | --- |
| `maxParticipants` = tickets issued | Any over-capacity attendance, however achieved | The wrong *person* attending within capacity |
| Seat check on `userID` (§6.3) | A second concurrent join on one ticket | Sequential handoff of one ticket |
| `createTime` on the join URL | A saved URL admitting to a later meeting | Reuse within the same instance |
| `302`, never data | Casual copying out of the UI | Devtools, browser history |

**S-5 [build]** The platform MUST NOT claim single-use join links to organisers. Sequential
handoff of one ticket between two people, one at a time, is not prevented by this design and
SHOULD be documented as such.

### 6.3 Seat check

**S-6 [build]** The engine `userID` MUST be `sha256(voucher_id)`, truncated to the engine's
identifier limits. It MUST be stable for the lifetime of a ticket and MUST NOT be derived from
`K`, the purchaser, or anything that survives a transfer — a transferred ticket keeps its seat,
which is correct.

**S-7 [build]** Before issuing a join, the platform MUST call `getMeetingInfo` and refuse if this
`userID` already appears among the attendees.

Polling `getMeetingInfo` at join time is deliberately chosen over the webhooks module: it needs
no additional deployment, no callback endpoint, and no delivery guarantees. It leaves a race
window of a few seconds during which two joins on one ticket could both pass. `maxParticipants`
is the backstop, and the residual harm — one ticket briefly seating two people inside an
already-capped meeting — does not justify the operational surface of webhooks.

**S-8 [build]** Refusal at the seat check MUST be distinguishable to the holder from refusal at
admission. Admission failures are deliberately uniform 401s (§10); a seat refusal is not a
security signal and the holder needs to know their ticket is in use elsewhere rather than
invalid.

## 7. Grant policy

### 7.1 `grant()`

**G-1 [build]** `grant()` maps a verified ticket to roles and permissions. It is the
application's policy and lives outside the library by design.

```ts
grant(v: VerifiedVoucher): VoucherGrant {
  const eventId = eventIdFrom(v.secret);        // merchant_metadata, issuer-signed
  const tier = TIERS[v.unit ?? ''];             // total, or deny
  if (!eventId || !tier) return { roles: [], permissions: [] };
  return { roles: [tier.role], permissions: [`event:join:${eventId}`] };
}
```

**G-2 [build]** The permission MUST name the event. A bare `event:join` admits any ticket to any
event, and the ticket's own `event_id` is then decoration.

**G-3 [build]** An empty grant MUST deny. A ticket for an unrecognised tier or a missing
`event_id` is not a general-admission ticket.

### 7.2 Tiers

**G-4 [build]** Tier maps to the engine's role:

| `unit` | NAP role | Engine role |
| --- | --- | --- |
| `ga` | `attendee` | `VIEWER` |
| `speaker` | `presenter` | `MODERATOR` |
| `press` | `attendee` | `VIEWER` |

**G-5 [build]** `MODERATOR` is a destructive capability in this engine — a moderator can end the
meeting, mute everyone, and start recording. It MUST appear in `destructivePermissions` for the
availability policy (§8) and MUST NOT be reachable from any degraded path.

### 7.3 Registry validation

**G-6 [build] — decision required.** ADR 0004 validates `grant()` output against the permission
registry at grant time. A per-event permission key (`event:join:evt_042`) means the registry must
either enumerate every event or be omitted.

Two options:

- **Enumerate.** Register `event:join:${id}` when the event is created. Keeps the typo guard;
  couples event creation to registry mutation.
- **Coarse permission plus a session claim.** Grant `event:join` and carry `event_id` in the
  session, checked in the handler. Keeps the registry static; moves one check out of the guard
  and into application code, where it is easier to forget.

Enumerate, unless events are created by an untrusted path. The typo guard is worth more than the
coupling, and G-2's failure mode — every ticket admitting to every event — is exactly what a
registry check catches.

## 8. Availability

**A-1 [build]** Admission depends on the mint. If the mint is unreachable, nobody is admitted,
and unlike recorded media the event does not wait.

**A-2 [build]** `onMintUnavailable: 'degrade'` is defensible here in a way it is not for a paid
recording. A degraded grant admits a holder whose ticket may already have been transferred;
turning away an entire audience is the larger harm for a live event that happens once.

**A-3 [build]** If degrade is enabled, the degraded grant MUST admit at `VIEWER` only.
`MODERATOR`, and every permission that can end or record the meeting, MUST be listed in
`destructivePermissions` and `destructiveRoles`, which throw at wiring time on overlap.

A degraded session is one where the platform does not know whether the ticket is live. Handing
that session the ability to end the event is the failure mode extension 0001 §7.3 forbids, in its
most literal form.

**A-4 [build]** Degrade MUST be per-event configuration, not global. A free community call and a
paid masterclass do not want the same answer.

## 9. Privacy

**P-1 [build]** The engine's `fullName` is required and is shown to every other attendee. It MUST
be a display name the attendee supplies at the door. It MUST NOT be derived from the purchase,
the mint, `K`, or `voucher_id`.

**P-2 [build]** `meta_*` parameters are retrievable from `getRecordings` indefinitely. Ticket
ids, `voucher_id`, lock keys and purchaser data MUST NOT appear in any `meta_*` value.

**P-3 [build]** The platform MUST NOT log the association between a session and a `voucher_id`
beyond the seat table's lifetime, and the seat table MUST be discarded when the meeting ends.

**P-4 [built]** Audit logging records denial codes and the completion pubkey. Because that pubkey
is a per-ticket burner (T-6), it is not an identity — provided T-6 actually holds.

**P-5 [build]** The mint learns that a ticket was state-checked, and when. Admission is once per
session rather than once per request, which bounds the pattern to roughly one observation per
attendee per event. This is the residual leak and it is not removable without blind presentation,
which is out of scope.

## 10. Failure codes

**F-1 [built]** Every admission failure MUST return a byte-identical 401 — same status, same
body, same headers. Extension 0001's ten codes exist only in the `AuditLogger`.

**F-2 [build]** Ticket-specific denials — unrecognised tier, missing `event_id`, wrong event —
MUST return through the same uniform 401. Together the codes are an oracle: they would tell a
caller whether a mint is allowlisted, whether an issuer is trusted, and, most sensitively,
whether a given proof has been spent.

**F-3 [build]** The seat check (§S-8) is the one deliberate exception, and it sits after
admission has already succeeded. It reveals nothing about ticket validity.

## 11. Interfaces

**Data.** Two tables, both discardable:

```ts
interface Event {
  id: string;
  title: string;
  startsAt: number;
  endsAt: number;
  capacity: number;          // == tickets minted, == maxParticipants
  degradeOnMintUnavailable: boolean;
  meetingId?: string;        // engine-side, set on first create
  createTime?: string;       // from create, pinned into join URLs
}

interface Seat {
  eventId: string;
  userIdHash: string;        // sha256(voucher_id)
  occupiedAt: number;
}
```

**HTTP.**

| Method | Path | Guard | Notes |
| --- | --- | --- | --- |
| `POST` | `/events` | organiser session | Creates event, mints `capacity` tickets |
| `GET` | `/events/:id` | none | Public event page. No attendee data |
| `POST` | `/auth/init` | none | NAP, unchanged |
| `POST` | `/auth/complete` | none | NAP, unchanged. Ticket rides in the body |
| `GET` | `/events/:id/join` | `requirePermission` | 302 to the engine |

No transfer endpoint (L-10). No attendee list endpoint, at any privilege level.

**Wiring trap [built].** The ticket rides in the `/auth/complete` body and the NIP-98 `payload`
tag is `sha256(rawBody)`. A global `express.json()` ahead of the NAP router breaks every
admission with `NAP_COMPLETE_PAYLOAD_MISMATCH`. The engine has its own version of the same class
of bug: its checksum covers the query string, not the POST body, and duplicating a parameter
across both throws `checksumError`.

## 12. Acceptance

The spike is §12.5. Everything before it is plumbing that obviously works.

1. **Issue.** Mint three tickets for one event, each locked to a distinct fresh `K`.
2. **Admit.** Each ticket yields a session carrying `event:join:<id>` and the tier's role.
3. **Join.** Each session receives a `302` and lands in the meeting.
4. **Cap.** A fourth ticket, minted outside `capacity`, is admitted by NAP and refused by
   `maxParticipants`. *(Both halves matter: NAP admitting it is correct — the ticket is valid;
   the engine refusing it is where capacity lives.)*
5. **Negative cases, all four:**
   - A ticket already swapped at the mint → `NAP_VOUCHER_SPENT`, uniform 401.
   - A valid ticket presented with a different keypair → `NAP_VOUCHER_BINDING_MISMATCH`,
     uniform 401, byte-identical to the above.
   - A ticket for event A used against event B's join → refused by the guard.
   - A second concurrent join on ticket #1 → refused by the seat check, with a distinguishable
     message.
6. **Degrade.** With the mint unreachable and degrade enabled, a `speaker` ticket admits at
   `VIEWER`, not `MODERATOR`.

Step 5 is the whole security claim. Steps 1–4 and 6 are configuration.

## 13. Open questions

**13.1 Locktime and refund.** §L-12. Adding `locktime` and `refund_pubkey` to the
`P2PK_VOUCHER` tag vocabulary is a protocol change: it touches extension 0001, needs the
matching change in `nap-java`, and — critically — needs the mint to enforce the composite kind's
spending condition. Mint-side behaviour for `P2PK_VOUCHER` is the least settled part of the
stack. Until then, no automatic refunds.

**13.2 Java parity.** `nap-java` has no voucher module. Extension 0001 is TypeScript-only, so
nothing here can be served by the JVM implementation. Interop is not merely untested; the feature
is absent.

**13.3 Does the platform need to know `capacity` at all?** If tickets are the only thing that
exist, `maxParticipants` could be derived by counting issued proofs at the mint rather than
stored. That removes the one number that can drift from reality, at the cost of a mint call
during meeting creation. Worth deciding before the seat table is written.

**13.4 Sequential handoff.** §S-5. One ticket used by two people in turn is not prevented. It may
not be worth preventing — it is exactly what lending a physical ticket looks like, and the
capacity guarantee holds regardless. But it should be a decision, not an omission.

**13.5 What does a recording cost?** Post-event access to a recording is the encrypted-segment
design from the DRM note, and the engine's own recording playback URLs are plain bearer links.
Turning `record=true` on without deciding this hands out a permanent, transferable, unmetered
copy to anyone who ever held a ticket.

**13.6 Interactive or broadcast?** If most attendees are passive, an SFU carries broadcast
traffic at SFU cost, and the ticket would be better gating a segment key than a conference join.
The ticketing half of this spec is unchanged either way; §6 is not.

## 14. Out of scope

- **Payment.** How the buyer pays for a ticket is model (a)'s separate channel. Admission never
  spends.
- **Anonymous credentials.** The mint learns a ticket was checked. Blind presentation is not
  attempted.
- **Single-use across servers.** Nothing prevents one ticket admitting on two platforms that both
  honour the same issuer. Extension 0001 §7.4 applies unchanged.
- **Hosting and branding of the conferencing engine.** Deliberately excluded; the integration
  surface is one base URL and one shared secret, and is swappable.
