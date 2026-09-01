# ADR 0003 — Secret modelling for voucher-bound authorization

- **Status:** proposed — awaiting a decision the maintainer must make (see [Decision required](#decision-required))
- **Date:** 2026-09-01
- **Related:** `../extensions/0001-voucher-bound-authorization.md` §5.3, review question B; GitHub issue #13
- **Blocks:** issues #22, #23, #24, #27, #29, and the remaining half of #30

## Context

Extension 0001 §3.1 states the whole design in one line:

```
voucher proof --P2PK--> K <--signs-- NIP-98 completion event
```

The voucher proof carries a NUT-11 P2PK lock naming a public key `K`, and the completion's
NIP-98 event must be signed by `K`. That equality is what makes a stolen voucher useless:
holding the proof without the key proves nothing, because the completion cannot be signed.

A Cashu proof has exactly one NUT-10 kind, so the voucher metadata and the P2PK lock must
somehow share one secret. §5.3 gives three options and calls this "the one genuinely
unresolved modelling question" and "the highest-risk open item":

1. **VOUCHER kind carrying P2PK tags** — keeps `cashu-voucher`'s domain model intact, but
   the mint must be taught to enforce P2PK on a VOUCHER secret.
2. **P2PK kind carrying voucher tags** — the mint enforces the lock natively today; voucher
   metadata becomes untyped tag payload and `VoucherSecret`'s accessors no longer apply.
3. **A composite kind** — cleanest model, largest change, needs mint support that does not
   exist.

The spec is explicit about the stakes: "**If the mint does not enforce it, this extension's
security collapses** — the binding in §3.1 would be checkable by the NAP server but not by
the mint, so a thief could still swap the proof."

So the question is not which option is most elegant. It is a question of fact about the
deployed mint, and it was answered by reading the mint rather than by argument.

## Evidence

Verified against `cashu-mint`, `cashu-lib`, and `cashu-voucher` as they stand.

### The mint does not enforce P2PK on a VOUCHER secret

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

A VOUCHER secret takes the first branch and never reaches `P2PKSpendingCondition`.

`VoucherSpendingCondition.verify()` checks exactly five things: voucher expiry, the issuer's
Schnorr signature, double-spend state, keyset id, and BDHKE. Searching that class for
`witness`, `Witness`, or `p2pk` returns nothing, and its test class
(`VoucherSpendingConditionTest`) has no P2PK or witness case.

Melt does not help. `MeltTask` rejects voucher secrets outright under Model B
(`voucher_not_accepted`, "Please redeem with issuing merchant") and applies
`P2PKSpendingCondition` only `if (proof.getSecret() instanceof P2PKSecret)`.

**Consequence:** under option 1 as the mint stands, the P2PK lock is advisory only —
checkable by the NAP server, invisible to the mint. A thief who steals the proof can still
swap it. That is precisely the collapse §5.3 warns about.

### Option 2 works against the mint as deployed

- `P2PKSecret extends WellKnownSecret` with `Kind.P2PK`, so it reaches
  `P2PKSpendingCondition`, which enforces the n-of-m multisig, locktime, and refund pathway
  natively today.
- `WellKnownSecret.addTag(String key, List<Object> values)` is public and unrestricted, so
  voucher metadata (`issuer`, `expires_at`, `issuer_sig`, `issuer_pubkey`, …) can ride as
  tags on a P2PK secret with no mint change.
- The cost is exactly what §5.3 predicted: `VoucherSecret`'s typed accessors no longer
  apply, and the NAP resolver reads tags directly.

### On the existing analysis document

`cashu-voucher/project/VOUCHER-SPENDING-CONDITIONS-ANALYSIS.md` recommends option 1. That
recommendation is not wrong on its own terms — it weighs flexibility, type safety, and code
size for *voucher features generally*. It is not answering this question. Its own comparison
matrix rates option 1 "Mint Enforcement: Strong" only on the assumption that the mint is
taught to enforce it, and its "Implementation Steps" section is a sketch of that change.
That change has not been made.

## Decision required

This ADR does not settle the question, because the two viable paths differ in operational
cost rather than in correctness, and that is a maintainer's call:

**Path A — adopt option 2 now.** No mint change. NAP ships against the mint as deployed.
Voucher metadata becomes untyped tag payload on a P2PK secret.

**Path B — teach the mint, then adopt option 1.** Have `VoucherSpendingCondition` delegate
to `P2PKSpendingCondition` when P2PK tags are present, exactly as the analysis document
sketches. Cost: a mint release, and **every deployed mint must be upgraded before the §3.1
binding can be relied on**. Until then the extension's security argument does not hold.

**Recommendation: Path A.** The mint is a separately deployed artifact, and extension 0001
§11 already insists the TypeScript and Java sides ship together; adding "and every mint must
be upgraded first" widens a release that is already coupled across two repositories. Option
1's benefit is a cleaner domain model, which is real but does not outweigh shipping against
a mint that enforces nothing.

Whoever decides should record it on issue #13 and update this ADR's status.

## Consequences either way

- **Option 3 is out.** It needs mint support that does not exist, and would incur Path B's
  upgrade cost with strictly more work.
- **`VoucherCredential.secret` (#22) cannot be finalised until this is settled**, since its
  contents are exactly what is in question. Every downstream issue inherits that block.
- **The verification client is unaffected.** DLEQ, the keyset cache, and the NUT-07 state
  check (#20) operate on the proof, not on the secret's kind, and are already built and
  verified end to end. Whichever path is chosen, that work stands.
- **Step (d) of the §6 procedure changes shape, not position.** Extracting `K` differs
  between the options, but it stays before the mint round trip either way.

## Reversing it

Moderate. Switching between options 1 and 2 later changes the secret's wire form, so
vouchers issued under one shape are not verifiable under the other. There is no in-place
migration for a bearer credential already in circulation: the practical path is to let
outstanding vouchers expire, which makes `expires_at` the effective migration window.

This is the strongest reason to settle it before shipping anything that issues vouchers.
