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

The kind name, the placement of `K` (a `data` field versus a dedicated tag), and the
canonical-bytes form are implementation details to settle in the `cashu-lib` change, not
here. What this ADR fixes is that the two concerns stay **distinct and both enforced**,
rather than one being smuggled into the other's tags.

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

- **`cashu-lib`**: a new `Kind` enum member; `WellKnownSecretDeserializer` handling for it
  (three call sites: spec, flattened, and object forms); a secret class exposing both the
  voucher accessors and the P2PK lock.
- **`cashu-voucher`**: `VoucherCanonicalBytes` must emit the new kind, and
  `VoucherSignatureService` must sign and verify over it. **This invalidates issuer
  signatures produced under the old form**, so it needs either a migration window or a
  version tag in the canonical bytes.
- **`cashu-mint`**: `VerifyProofsTask.getSpendingCondition()` must dispatch the new kind to a
  condition that runs *both* the voucher checks and `P2PKSpendingCondition`. `MeltTask`'s
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
