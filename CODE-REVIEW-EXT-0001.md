# Code review: extension 0001 changes in `nap`

Self-review of everything landed this session (`31626bd`..`5175834`), after the work was
already committed. Four findings, all reproduced before being fixed and all now closed.

**Status: all four addressed.** Each fix was mutation-verified — the guard was disabled and the
corresponding test observed to fail. Two of the fixes initially had no test at all (findings 2
and 3): the code was correct but nothing would have caught a regression, which the mutation runs
exposed. Tests were added until every fix failed under its own mutation.

The bias worth naming up front: I reviewed my own code, so I looked hardest at the places
where I had made a judgement call and moved on — the paths that skip the main flow, and the
parser I wrote against a Java implementation I could not run inline.

---

## Finding 1 — Duplicate tags are accepted, and the mint rejects them (security, interop)

**Severity: high.** `parseVoucherSecret` accepts a secret carrying the same tag twice and reads
the first occurrence. `cashu-lib` refuses the same bytes outright:

```
TypeScript: duplicate expires_at -> parsed: 2000000000
Java:       REJECTED: MalformedP2PKSecretException tag 'expires_at' appears more than once
```

This is not merely a parity nit. The issuer signature covers *both* tags, so a doctored secret
verifies on the NAP side while being unspendable at the mint. NAP would grant a session from a
document with two answers, and `grant()` would derive roles from whichever the parser happened
to read first. The golden-vector work exists precisely so both sides agree about the same
bytes; this is a case where they parse identical bytes to different verdicts.

NUT-11 is explicit that a repeated tag makes the secret malformed, so rejecting is also the
conformant reading.

**Fix:** reject a secret with a repeated tag key, matching `requireEachTagAtMostOnce()`.

## Finding 2 — The degraded path skips the registry check and the expiry clamp (correctness)

**Severity: medium.** `onMintUnavailable: 'degrade'` returns early, before the
`permissionRegistry` validation added for #17 and before the `expires_at` clamp added for #27.
Reproduced with a registry that declares neither degraded key:

```
degraded decision: {"allowed":true,"roles":["typo-role"],"permissions":["voucher:veiw"],...}
registry check on degraded path: SKIPPED
voucher expiry clamp           : MISSING
```

The registry check is the more serious half: a typo in `degradedGrant` is exactly the mistake
ADR 0004 exists to catch, and degraded mode is the configuration an operator exercises least
and can least afford to get wrong. The missing clamp means a degraded session can outlive the
voucher that justified it, which is the staleness bound #15 was about.

**Fix:** apply both to the degraded grant.

## Finding 3 — `grant` is checked for presence but not for being callable (robustness)

**Severity: low.** The constructor rejects a missing `grant` but accepts
`grant: 'not a function'`, which then throws on the first login that presents a voucher. Every
other wiring mistake in this package fails at construction; this one waits for a user.

**Fix:** check the type, not just presence.

## Finding 4 — Extension spec §5.2 documents an interface that does not exist (docs)

**Severity: low, but misleading.** §5.2 still shows the pre-implementation sketch: `allowedMints`
and `allowedIssuers` as raw arrays, plus `keysetCacheTtlSeconds` and `onMintUnavailable` as
resolver options. What shipped takes constructed collaborators (`mintAllowlist`,
`issuerAllowlist`, `mintClient`, `availability`) and has four options the spec never mentions.
Every field name in the block is wrong.

This is the same class of defect as the RFC §25 drift found earlier, and for the same reason:
nothing checked it. Guide §3.5.11 has a wiring example that *is* type-checked and executed;
§5.2 has one that is neither.

**Fix:** replace the sketch with the real interface, and say why the shape changed.

---

## Checked and found sound

- `clampTtlToDecision` against `Infinity`, `-Infinity`, `NaN`, `1e300`, fractional and zero
  bounds — all clamp sensibly, none produce a negative or absurd TTL.
- `__proto__` as a tag key does not pollute `Object.prototype`.
- `AclDecision.reason` reaches only the audit log, never a client response.
- Construction-time rejection of a missing `mintAllowlist`, `issuerAllowlist`, `mintClient`,
  `availability`, or `grant`.
- `supported_extensions` is copied on the way out, so a later mutation of the operator's array
  cannot change what was advertised.

## Noted, deliberately not changed

- **No cap on tag count.** 50,000 tags parse fine. The completion body is already bounded by the
  adapter's `bodyLimit`, and the parse is linear, so this is bounded by the same limit that
  bounds every other request. A separate cap would be a second, weaker limit with its own
  failure mode.
