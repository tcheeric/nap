# @imani/nap-voucher

Verification primitives for **NAP Extension 0001 — Voucher-Bound Authorization**
(`docs/extensions/0001-voucher-bound-authorization.md`).

**Status: incomplete.** This package currently ships the two allowlists (§4.3).
The keyset cache, DLEQ verification, and NUT-07 state check (#20) are not built
yet, and the resolver that consumes them (#23) is blocked on decision #13.

Deliberately dependency-free, per the extension's build order: the verification
client is built standalone and testable with no NAP dependency, so this package
imports neither `@imani/nap-server` nor `@imani/nap-core`.

## Why there are two allowlists

Any mint can sign a voucher whose tags claim `issuer: acme` and whose metadata
implies `role: admin`. A valid signature says the mint signed it, and nothing at
all about whether that mint has authority to make claims this server honours.

The credential carries `mint_url`, and it is **client-supplied**. A request
field choosing the mint that a credential is then verified against is the same
vulnerability class as a request header choosing the NIP-98 audience — the flaw
`createAudienceHostAllowlist()` exists to prevent. So the supplied `mint_url` is
*matched against* the list, never trusted to select from it.

The second list is keyed on the `(mint, issuerPubkey)` **pair**, because
trusting a mint is not trusting everyone who ever used it, and an issuer trusted
on one mint should not thereby be trusted on another.

```ts
import { createMintAllowlist, createIssuerAllowlist } from '@imani/nap-voucher';

const mints = createMintAllowlist(['https://mint.example.com']);
const issuers = createIssuerAllowlist(
  [{ mint: 'https://mint.example.com', issuerPubkey: '<64 hex chars>' }],
  mints
);

// Returns the *configured* origin, or null. Never throws, never fetches.
const mint = mints.resolve(credential.mint_url);

if (!mint) {
  // NAP_VOUCHER_MINT_NOT_ALLOWED — audit it, then fail as a generic 401.
}
```

## Properties worth knowing

- **No default and no empty-list escape hatch.** An allowlist that allows every
  mint is the state this exists to make unrepresentable, so both constructors
  throw at wiring time rather than producing a uniform 401 per request.
- **`https` only, with no opt-out.** The audience allowlist permits `http`
  because a deployment may terminate TLS elsewhere and speak plaintext on a
  trusted internal hop. Nothing analogous applies here: this is an outbound call
  to a third party, carrying a credential, whose answer decides an
  authorization. Over plaintext anyone on the path can forge an `UNSPENT` state
  check.
- **No wildcards.** A wildcard would mean "trust any subdomain to mint
  authorization claims". Unlike the audience case, where a wildcard names hosts
  *this* deployment answers on, these entries are third parties.
- **`resolve()` never throws and never fetches.** A malformed `mint_url` is a
  client error that must produce the same generic 401 as every other voucher
  failure, and step (a) of the §6 procedure runs before any outbound request, so
  an unvetted URL is never reached. Both are asserted by tests.
- **`resolve()` returns the configured origin, not the caller's string.**
  Nothing downstream should ever hold a value that arrived in the request.
- **Entries with a path, query, fragment, userinfo, or a duplicate after
  normalization are refused.** Each is a case where the operator believes they
  configured something narrower than they did.
