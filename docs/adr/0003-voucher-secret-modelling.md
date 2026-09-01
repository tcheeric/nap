# ADR 0003 — Secret modelling for voucher-bound authorization

- **Status:** accepted — **option 3**: a new composite NUT-10 kind
- **Date:** 2026-09-01 (superseding an option 2 decision taken earlier the same day, see [Superseded decision](#superseded-decision))
- **Related:** `../extensions/0001-voucher-bound-authorization.md` §5.3, review question B; GitHub issue #13
- **Unblocks:** issues #22, #23, #24, #29

## Context

Extension 0001 §3.1 states the whole design in one line:

```
voucher proof --P2PK--> K <--signs-- NIP-98 completion event
```

The voucher proof carries a P2PK lock naming a public key `K`, and the completion's NIP-98
event must be signed by `K`. That equality is what makes a stolen voucher useless: holding
the proof without the key proves nothing, because the completion cannot be signed.

A Cashu proof has exactly one NUT-10 kind, so the voucher metadata and the P2PK lock must
share one secret. §5.3 gives three options and calls this "the one genuinely unresolved
modelling question" and "the highest-risk open item":

1. **`VOUCHER` kind carrying P2PK tags** — keeps `cashu-voucher`'s domain model intact, but
   the mint must be taught to enforce P2PK on a `VOUCHER` secret.
2. **`P2PK` kind carrying voucher tags** — the mint enforces the lock natively today;
   voucher metadata becomes untyped tag payload.
3. **A composite kind** — cleanest model, largest change, needs mint support that does not
   exist.

The spec is explicit about the stakes: "**If the mint does not enforce it, this extension's
security collapses** — the binding in §3.1 would be checkable by the NAP server but not by
the mint, so a thief could still swap the proof."

## Evidence

Verified against `cashu-mint`, `cashu-lib`, and `cashu-voucher` as they stand.

### The mint does not enforce P2PK on a `VOUCHER` secret

`cashu-mint-protocol/.../tasks/VerifyProofsTask.java`, `getSpendingCondition()` dispatches
**first-match on secret kind**:

```java
if (VoucherSecretDetector.isVoucherSecret(secret)) {
    return new VoucherSpendingCondition<>(mint, mintProtocolService);
}
if (secret instanceof P2PKSecret) {
    return new P2PKSpendingCondition(transaction);
}
```

A `VOUCHER` secret takes the first branch and never reaches `P2PKSpendingCondition`.
`VoucherSpendingCondition.verify()` checks expiry, the issuer signature, double-spend state,
keyset id, and BDHKE — searching it for `witness` or `p2pk` returns nothing, and its test
class has no P2PK case. `MeltTask` rejects voucher secrets outright under Model B and applies
`P2PKSpendingCondition` only `if (proof.getSecret() instanceof P2PKSecret)`.

**So under option 1 as things stand, the P2PK lock is advisory only** — checkable by the NAP
server, invisible to the mint. A thief who steals the proof can still swap it.

### `VOUCHER` is not a registered NUT kind

Only `P2PK` (NUT-11) and `HTLC` (NUT-14) are specified. `Kind.VOUCHER` is an Imani extension
in `cashu-lib`. Both NUT-10 and NUT-11 carry the same caution:

> If the mint does not support spending conditions or a specific `kind`, **proofs may be
> treated as regular anyone-can-spend tokens.**

NUT-10 itself is permissive about extension — it defines only the envelope
`[kind, {nonce, data, tags}]`, says "the specific type of spending condition is not part of
this document", and offers tags for "feature extensions". So a custom kind is **spec-legal**.
What it is not is *interoperable*: any mint that does not know the kind treats the proof as
anyone-can-spend, and the mint's `/v1/info` cannot honestly advertise the lock without a
number to advertise it under.

### Option 2 breaks issuer signing

The finding that overturned the earlier decision. `VoucherCanonicalBytes` — what
`VoucherSignatureService` signs and verifies — hardcodes the kind:

```java
sb.append("[\"").append(WellKnownSecret.Kind.VOUCHER.name()).append("\",\"");
sb.append(Hex.toHexString(secret.getData()));      // the voucher UUID
```

Under option 2 the on-wire secret is `["P2PK", K, nonce, tags]`. The issuer signature would
therefore cover a document **that never exists on the wire**: the kind differs, and `data`
differs (voucher UUID versus the lock key `K`). The signature would no longer commit to what
the mint verifies, which is the property §4.3's issuer allowlist depends on.

Option 2 was chosen on the belief that it required no changes outside NAP. It requires
changes to `cashu-voucher`'s canonical-bytes form, which is the one place a change is most
expensive: it invalidates every issuer signature already produced.

### The two kinds mean different things

The distinction that motivates option 3, and the reason collapsing them reads badly:

| | Purpose | `data` field |
| --- | --- | --- |
| `VOUCHER` | what this credential *is worth* — issuer, expiry, face value | voucher UUID |
| `P2PK` | who may *spend* it | the lock key |

Option 2 collapses these and makes `data` mean "lock key", demoting the voucher id to a tag.
Anyone reading a proof would see a P2PK secret and have no signal that its tags carry
authorization semantics an issuer signed.

## Decision

**Option 3: a new composite NUT-10 kind**, carrying both the voucher metadata and the P2PK
lock as first-class parts of one secret, enforced by the mint as a single spending condition.

**The kind is named `P2PK_VOUCHER`.** The placement of `K` (a `data` field versus a dedicated
tag) and the canonical-bytes form remain implementation details for the `cashu-lib` change.
What this ADR fixes is the name, and that the two concerns stay **distinct and both
enforced** rather than one being smuggled into the other's tags.

### On the name

The enum name *is* the wire string — `WellKnownSecretSerializer` writes `getKind().name()`
and the deserializer reads `Kind.valueOf(...)` — so this names a permanent public format, not
just a Java identifier. Worth getting right once.

`P2PK_VOUCHER` follows the convention the existing kinds already set: `P2PK` and `HTLC` name
the **spending mechanism**, not the use case. (`VOUCHER` breaks that pattern by naming the
payload, which is arguably part of how the enforcement gap arose — nothing in the name
suggests a witness is involved.) A mint implementer reading `P2PK_VOUCHER` knows immediately
that a witness is required, which is exactly the property option 1 failed to convey.

It also degrades correctly: an unaware mint hits `Kind.valueOf("P2PK_VOUCHER")` and throws,
rather than parsing it and falling through to NUT-10's "may be treated as regular
anyone-can-spend tokens".

**`BEARER` was considered and rejected.** It reads as the opposite of what this is. A bearer
instrument is one where possession alone authorises; here possession is useless without the
private key for `K`, which is the whole §3.1 binding. Extension 0001 uses "bearer" twice to
describe what the design *rejects* — "bearer over the wire… anything that sees the request
can reuse it" and "a bearer token yields nothing to key on". The accurate sense is its third
use, "the credential is bearer-**issued**", meaning no pre-registration; but "bearer-issued"
and "bearer-redeemable" are different claims and `BEARER` collapses them into the wrong one.
Since the name is the permanent wire string, that misreading would ship forever.

### Why

- **Option 1** leaves the lock unenforced by the mint. Its only advantage is that
  `cashu-voucher` needs no change, and the enforcement gap is exactly what extension 0001
  §5.3 warns collapses the security argument.
- **Option 2** requires changing `VoucherCanonicalBytes`, invalidating existing issuer
  signatures, *and* conflates two distinct meanings. It buys nothing that option 3 does not,
  once its true cost is counted.
- **Option 3** is the only shape where the mint enforces both the lock and the voucher
  conditions, and where a reader can tell what a proof is by its kind.

Every option needs a mint change except option 2, and option 2's apparent cheapness was an
error in the earlier analysis. Given that, pay for the honest model.

## Consequences

### Work this implies, outside NAP

- **`cashu-lib`**: `Kind.P2PK_VOUCHER`; `WellKnownSecretDeserializer` handling for it (three
  call sites: spec, flattened, and object forms); a secret class exposing both the voucher
  accessors and the P2PK lock. Note that `Kind.valueOf()` means the enum name is the wire
  string, so the member name is a public format decision.
- **`cashu-voucher`**: `VoucherCanonicalBytes` must emit the new kind, and
  `VoucherSignatureService` must sign and verify over it. **This invalidates issuer
  signatures produced under the old form**, so it needs either a migration window or a
  version tag in the canonical bytes.
- **`cashu-mint`**: `VerifyProofsTask.getSpendingCondition()` must dispatch `P2PK_VOUCHER` to
  a condition that runs *both* the voucher checks and `P2PKSpendingCondition`. Ordering
  matters: it must be matched before the existing `isVoucherSecret` branch, or a
  `P2PK_VOUCHER` secret could fall into the voucher-only path that has no witness check. `MeltTask`'s
  Model B rejection needs the same treatment. `/v1/info` should advertise the new kind so a
  wallet can tell whether the lock is real.

### For NAP

- **#22 is unblocked**: `VoucherCredential.secret` carries the new composite kind, and the
  resolver reads the lock key and the voucher metadata through its accessors rather than
  through untyped tags.
- **The §6 step-13 procedure is unchanged in shape.** Step (d) — extract `K` and compare it
  to the completion pubkey — differs only in where `K` is read from, and it stays before the
  mint round trip.
- **NAP must not ship ahead of the mint.** Until the mint enforces the new kind, the §3.1
  binding holds only as far as NAP checks it, which is the same position option 1 was
  rejected for. Extension 0001 §11 already couples the TypeScript and Java releases; this
  adds the mint to that set.

### Where the new kind lives

Asked twice during review, in two forms — "should the new type get its own sister repo?" and
"should `cashu-voucher` be renamed to something not voucher-specific?" — so the answer is
recorded rather than left to be re-derived.

**The new kind goes in `cashu-lib`, beside `P2PKSecret` and `VoucherSecret`. Its meaning
stays in `cashu-voucher`. Neither a new repo nor a rename.**

The existing split is already the right seam, and it is not the one the question assumes:

| Repo | Owns | Evidence |
| --- | --- | --- |
| `cashu-lib` | **What a secret is on the wire** — kinds, parsing, serialisation | `cashu-lib-common/.../nut10`, `nut11`, `nut18`; packages organised by NUT number |
| `cashu-voucher` | **What a voucher means** — signing, validation, lifecycle, ledger, passes | `VoucherSignatureService`, `VoucherValidator`, `VoucherStatus`, `VoucherIssuanceService` |

`cashu-voucher` contains no secret type at all. `VoucherSecret` lives in `cashu-lib` next to
`P2PKSecret`, because that is where wire formats belong.

- **A sister repo would split the wrong seam.** A NUT-10 kind is a wire format, so it belongs
  where the other kinds are. Putting one kind elsewhere would leave
  `WellKnownSecretDeserializer` either depending on the new repo or duplicating its parsing.
- **A rename would misdescribe the contents.** The domain genuinely is voucher-specific:
  `VoucherTags` carries `face_value`, `face_decimals`, `backing_strategy`, `issuance_ratio`,
  and `merchant_metadata` — stored-value concepts, not credential concepts — and the app
  module is issuance, redemption, and merchant verification, with a `-pass` module producing
  branded wallet passes. A "generic credential" library whose core type has a face value and
  a backing strategy would be a name the contents do not honour.
- **The generic layer already exists.** `WellKnownSecret`, its `Kind` enum, and the tag
  system are in `cashu-lib` and are already shared by `P2PK`, `HTLC`, and `VOUCHER`. A
  future non-voucher credential has a home without any restructuring.

The real question underneath both framings is **"is this new kind a voucher?"** It is: it has
an issuer, a face value, an expiry, a redemption lifecycle, and a Nostr status ledger. The
P2PK lock adds *who may spend it*, not a new category of thing. If a genuinely non-voucher
credential appears later, it gets its own domain module or repo and the shared parts will be
visible rather than guessed at — which is the cheaper order to discover them in.

### Reversing it

Expensive, and the reason it is settled now. The options differ in wire form, so vouchers
issued under one shape are not verifiable under another, and there is no in-place migration
for a bearer credential already in circulation — the practical path would be letting
outstanding vouchers expire, making `expires_at` the migration window. Nothing has issued a
voucher yet, which is what makes this cheap today and not tomorrow.

## Superseded decision

Option 2 was accepted earlier on 2026-09-01 and reverted the same day. It was chosen because
it appeared to need no changes outside NAP, and because a `P2PK` secret with extra tags is
enforced by every conformant mint today.

That reasoning was sound as far as it went and is retained above under
[option 2 breaks issuer signing](#option-2-breaks-issuer-signing) — but the analysis had not
checked `VoucherCanonicalBytes`, which hardcodes `"VOUCHER"` into the signed form. Once that
surfaced, option 2's distinguishing advantage disappeared: it needs an upstream change like
the others, and unlike the others it also conflates two meanings.

Recorded rather than rewritten, because "the cheap option was not cheap" is the kind of thing
worth being able to find later.
