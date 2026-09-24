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

---

# Round 2

A second pass, deliberately over what round 1 did **not** look at: `server.ts`, the client
builder, `parseVoucherCredential`, the availability guard, and the new tests themselves. Round 1
had reviewed the resolver and the parser and stopped there, which is why its finding count says
more about where I looked than about what was wrong.

Three findings.

## Finding 5 — The session ceiling was an estimate, not a wall (security)

**Severity: medium.** `maxSessionLifetimeSeconds` gated the *decision* to refresh but not the
token that refresh minted. A refresh one second before the ceiling issued a full-length access
token, and guarded requests kept succeeding past the limit:

```
refresh at cap-1        : allowed
guarded req at cap+1    : 200 <- past the ceiling
guarded req at cap+898  : 200 <- still past the ceiling
```

The overshoot is bounded by `sessionTtlSeconds`, so the real guarantee was `cap + sessionTtl`
rather than `cap`. That gap is exactly the interval #15 exists to bound — time during which a
redeemed voucher still authorises — so an approximate ceiling undercuts the reason it was added.

**Fix:** clamp both the access and refresh windows to the ceiling, so a rotation near the limit
produces a token that expires *at* it. A resolver's own bound still narrows it further; whichever
is sooner wins.

One existing test had to change: it asserted the rotated refresh token outlived the ceiling,
which was the bug written down as an expectation.

## Finding 6 — A "login never spends" test that could not detect a spend (test quality)

**Severity: low.** `expect(Object.keys(harness().resolver)).toEqual(['resolve'])` inspects the
**resolver**, which has only ever had one method. A spending operation would be added to the
*mint client*, which that assertion never touches, so it passes regardless. It read as a second
safeguard beside `noSpend.test.ts` and was none.

**Fix:** replaced with a call-count assertion that says something true about the resolver's
behaviour, and a comment pointing at `noSpend.test.ts` for the real property.

## Checked and found sound

- **Client key order does not affect verification.** The same bytes are hashed and sent, so
  ordering varies between requests but never within one. Confirmed the server hashes raw bytes:
  added whitespace and reordered voucher keys both fail with 401.
- **`parseVoucherCredential`** rejects a non-object, an array, a string, an empty object and a
  string `amount` with 400, and strips unknown fields at both the top level and inside `dleq`.
- **The availability guard's exact-match overlap check** accepts `Voucher:Redeem` alongside
  `voucher:redeem`. That is correct rather than a gap: guards compare permissions exactly, so
  those are genuinely different keys and a case-insensitive check would reject legitimate ones.
- Every new test file contains assertions; none is a no-op.

## The pattern across both rounds

Six findings, and the count tracked how hard I looked rather than how much was wrong. Round 1
found four by reviewing the code I had written most recently; round 2 found three more by
reviewing what round 1 had skipped. Two findings in each round were *tests that could not fail* —
which is the failure mode that survives review most easily, because a passing test looks like
evidence.
