# ADR 0004: `grant()` output is validated at grant time, not at wiring time

- **Status:** Accepted
- **Date:** 2026-09-01
- **Context:** Extension 0001 §5.2, §10 question E ([#17](https://github.com/tcheeric/nap/issues/17))

## Context

`createVoucherAclResolver` takes a `grant(voucher) -> { roles, permissions }` callback. It is
application policy and deliberately lives outside the library: what a `unit: 'sat'` voucher of
face value 1000 is *worth* is not something a protocol library can know.

Nothing checks that what `grant()` returns exists in the `PermissionRegistry`. The failure mode
is silent, and was reproduced before deciding:

```
wiring-time validation           : passed
grant() returns                  : ["voucher:veiw"]
is the typo in the registry?     : false
```

The session is issued. It carries a permission key no guard will ever match, so the holder is
denied at some unrelated route later, with nothing in the audit log connecting that denial to a
typo in the wiring. Tutorial 03 establishes the opposite property for the registry — a typo'd
key fails at wiring time — and the extension's §5.2 asks whether that should extend here.

## Decision

**Validate, but at grant time**, via an optional `permissionRegistry` option. An undeclared role
or permission denies the login and logs `NAP_VOUCHER_GRANT_NOT_IN_REGISTRY` with the offending
keys.

## Why not wiring time, as the issue proposed

The issue assumed the cost was "a construction-order constraint". It is not; wiring-time
validation is **not possible** for this callback, and the constraint would have bought nothing.

`grant()` takes a *verified voucher*. A realistic policy derives keys from the voucher's own
tags, so it has no output at all until a real voucher arrives. Probing it at construction with a
synthetic voucher was tried:

```
with a synthetic probe voucher   : ["voucher:view:PROBE:0"]
with the real voucher at login   : ["voucher:view:sat:1000"]
```

Validating that first set would report success for a policy that fails on every real login, and
would fail for policies that are correct. That is worse than no check: it manufactures
confidence in the wrong direction. The only honest options were grant-time validation or none.

## Why deny rather than filter

An undeclared key could be dropped, granting the remainder. That was rejected. A
partially-applied policy is one nobody wrote — the operator meant the login to carry
`voucher:view`, and a session carrying everything *except* that is not a safer version of their
intent, just a differently-broken one that is harder to diagnose.

Roles are checked alongside permissions. Checking permissions alone would miss the worse case:
roles expand into permissions downstream (`createRegistryAclResolver` returns
`role.permissions`), so an undeclared role is an empty grant wearing the name of a real one.

## Consequences

- The wiring-time guarantee tutorial 03 gives is **not** available here, and this ADR is the
  record of why. What is gained is the conversion of a silent failure into a loud, audited one.
- The option is optional and additive. An application without a registry, or one validating
  elsewhere, is unaffected.
- A typo is caught on the first login rather than the first *guarded request by a holder of that
  permission*, which in practice is the difference between finding out in a smoke test and
  finding out from a user.
