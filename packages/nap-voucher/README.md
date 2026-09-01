# @imani/nap-voucher

Verification primitives for **NAP Extension 0001 — Voucher-Bound Authorization**
(`docs/extensions/0001-voucher-bound-authorization.md`).

**Status: incomplete.** This package ships the two allowlists (§4.3), NUT-12
DLEQ verification, NUT-00 `hash_to_curve`, and a mint client with a keyset TTL
cache and the NUT-07 state check. The resolver that consumes them (#23) is
blocked on decision #13.

Deliberately dependency-free apart from `@noble/curves` and `@noble/hashes`, per
the extension's build order: the verification client is built standalone and
testable with no NAP dependency, so this package imports neither
`@imani/nap-server` nor `@imani/nap-core`.

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

## DLEQ and the state check

```ts
import { createMintClient, verifyProofDleq } from '@imani/nap-voucher';

const mint = createMintClient({ allowlist: mints, keysetCacheTtlSeconds: 3600 });

// The client resolves through the allowlist itself, so an unvetted mint_url
// never reaches the network.
const A = await mint.getKey(credential.mint_url, credential.keyset_id, credential.amount);

if (!verifyProofDleq({ A, secret, C, dleq })) {
  // NAP_VOUCHER_DLEQ_INVALID
}

if ((await mint.checkState(credential.mint_url, secret)) !== 'UNSPENT') {
  // NAP_VOUCHER_SPENT
}
```

`verifyProofDleq` is the form the extension needs: a `VoucherCredential` carries
a `Proof`, not a `BlindSignature`, so `B'` and `C'` are reconstructed from the
blinding factor `r`. Both forms are verified against the official NUT-12 test
vectors, and `hash_to_curve` against the NUT-00 vectors.

**DLEQ is necessary but not sufficient.** It proves the mint signed this proof.
It says nothing about whether the proof is still unspent — a burned voucher
carries a perfectly valid DLEQ. Only the NUT-07 state check answers liveness,
which is why §4.2 makes the mint mandatory.

### Failure modes are distinguished on purpose

`MintUnavailableError.reason` is one of `mint_not_allowed`, `unavailable`,
`malformed_response`, or `unknown_keyset`. Only `unavailable` may trigger §7.3
degraded mode: collapsing "the mint is down" into "the check failed" would let
degraded mode fire on a mint that answered clearly and said `SPENT`.

Verification functions return `false` rather than throwing, for a failed proof
*and* for malformed input alike. Every voucher failure reaches the client as the
same generic 401, so the two must not be separable by exception shape or timing.

Other properties: requests carry a mandatory timeout, since an unresponsive mint
would otherwise pin the login path until the platform default and turn a slow
third party into resource exhaustion. An unknown keyset triggers exactly one
refetch, so an attacker supplying random keyset ids cannot drive one mint request
per attempt. The state check matches on `Y` rather than trusting response order.
An unrecognised state is refused rather than assumed `UNSPENT`.
