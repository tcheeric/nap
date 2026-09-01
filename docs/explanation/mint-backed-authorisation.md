# How NAP uses a Cashu mint for authorisation

NAP's core protocol answers *who are you* with a Nostr signature. It answers *what may
you do* with a stored ACL row: a table keyed by public key, listing roles and
permissions.

Extension 0001 replaces that second answer with a Cashu voucher. The user presents a
cryptographic bearer token at login, and the token itself carries the authorisation. No
row, no prior registration.

This document explains why a mint is involved at all, what the design buys, and what it
costs. It is not a specification and not a how-to. For the normative rules read
[extension 0001](../extensions/0001-voucher-bound-authorization.md); for wiring code read
[integration guide §3.5.11](../NAP-INTEGRATION-GUIDE.md#3511-wiring-it-up).

---

## The problem

Stored-ACL authorisation has a registration step. Before a user can do anything, somebody
must create a row saying what they may do. That is fine when your users are your users:
they sign up, you provision them, the row exists.

It fails in three situations:

**Bearer authorisation.** A gift card, a conference pass, a prepaid API allowance. The
issuer does not know who will present it, and often should not: whoever holds it is
entitled to it. A row keyed by public key cannot express "whoever turns up with this".

**Cross-organisation trust.** A merchant issues something a *different* server honours.
With stored ACLs, the second server needs a synchronised copy of the first server's user
table, which is a federation problem nobody wants.

**Transferable rights.** The holder passes it on. Stored ACLs make this a write to the
provisioning system, with all the auditing and revocation that implies.

The Cashu ecosystem already solves the underlying problem. A Cashu proof is a bearer
token the mint signed blindly, and NUT-11 lets that proof be *locked* to a public key.
Extension 0001's claim is that a locked proof is a usable authorisation credential.

## The naive design, and why it is unsafe

The obvious version: put the roles in a token, sign it, let the server read them.

```
{ "roles": ["merchant"], "signature": "..." }
```

This fails on four counts, and they are worth naming because each one shapes part of the
real design.

**No freshness.** The token carries no challenge, so a captured token replays forever.

**No binding.** Possession alone authorises, so a stolen token is a working credential.

**No revocation.** A signature stays valid until its expiry, whatever the issuer decides
afterwards.

**No issuer authority.** Signature validity says nothing about *whose* signature it is.
Anyone can sign a token claiming `roles: ["admin"]`; the question is whether you trust
the signer, and a signature cannot answer that about itself.

## The approach: bind the credential to the login key

The design's centre is one equality:

```
voucher proof --P2PK--> K <--signs-- NIP-98 completion event
```

The voucher carries a NUT-11 P2PK lock naming a public key `K`. The NIP-98 event that
completes the login must be signed by `K`. The server checks that they match.

That single check answers two of the four failures at once:

- **Holding the voucher without `K` proves nothing.** The completion cannot be signed, so
  a stolen or copied voucher is inert.
- **Holding `K` without the voucher proves nothing.** There is no authorisation to
  resolve, and the resolver denies.

Freshness comes from NAP's existing challenge, unchanged: the NIP-98 event is bound to a
server-issued challenge that expires. The extension adds no new replay surface, because
the credential rides inside a request that was already replay-protected.

Issuer authority is the one the cryptography cannot supply, and it is handled by
configuration instead. See *Two allowlists* below.

## Why the mint is mandatory

A NAP server verifying a voucher must talk to the mint. Three independent reasons, each
sufficient on its own:

**A keyset id is not a locator.** A Cashu proof carries `id`, identifying which keyset
signed it, but not where that mint lives. Without a mint URL the server cannot fetch
`/v1/keys` and cannot verify anything.

**Liveness is mint-local state.** NUT-12 DLEQ proves *the mint signed this proof*. It
says nothing about whether the proof is still unspent, because a redeemed voucher carries
a perfectly valid DLEQ. Only a NUT-07 state check distinguishes a live credential from a
burned one.

**Trust is per-mint.** Any mint can sign a voucher whose tags claim `issuer: acme` and
imply `role: admin`. The signature will verify. **Signature validity says nothing about
issuer authority**, which is the fourth failure above, and it is why the next section
exists.

## Two allowlists

`mint_url` arrives *in the request*. A request field that chooses which mint a credential
is verified against is the same vulnerability class as a request header choosing the
NIP-98 audience: the caller picks their own authority.

So the server holds two allowlists, and neither is optional.

**The mint allowlist** pins exact `https` origins. No wildcards: a wildcard would mean
"trust any subdomain to mint authorisation claims", and unlike the audience case these
are third parties rather than hosts your own deployment answers on. No `http`: this is an
outbound call carrying a credential, whose answer decides an authorisation, and over
plaintext anyone on the path can forge `UNSPENT`.

**The issuer allowlist** is keyed on the `(mint, issuer_pubkey)` *pair*. Trusting a mint
is not trusting everyone who ever used it, and an issuer trusted on one mint should not
thereby be trusted on another.

Both throw at construction when empty. A server that would honour any mint is the state
these exist to make unrepresentable, so the failure belongs at startup rather than as a
uniform 401 in production.

## Verification order is a security property

The checks do not run in a convenient order. They run in an order chosen so that each one
protects the next.

```
  login request
       │
       ├── RFC steps 1-12: challenge, NIP-98 signature, payload hash
       │   ▲ everything below happens only after key control is proven
       │
       ├── (a) mint_url in the allowlist?          local   ← before any network call
       ├── (c) parse the NUT-10 secret             local
       ├── (d) P2PK key == completion pubkey?      local   ← the binding
       ├── (g) expires_at in the future?           local
       ├── (e) issuer signature valid?             local
       ├── (f) (mint, issuer) allowlisted?         local
       │
       ├── (b) NUT-12 DLEQ against the keyset      NETWORK ← first outbound request
       ├── (h) NUT-07 state == UNSPENT?            NETWORK
       │
       └── (i) grant(voucher) -> roles, permissions
```

Three orderings carry weight:

**Everything after key control.** If the mint were contacted before the NIP-98 signature
was verified, `/auth/complete` would be a free oracle: an unauthenticated caller submits
somebody else's proof, and the server's outbound state check reports whether it is spent.
That is a privacy break against the mint's users and turns the endpoint into a laundering
service for probing arbitrary proofs.

**The allowlist before anything.** `mint_url` is attacker-supplied. Fetching it before
checking it is server-side request forgery, with the request originating inside your
network perimeter.

**The binding before the network call.** Step (d) is local and free. Running the round
trip first would spend it on a credential already known bad, and would tell the mint that
somebody is probing that proof.

## Login must never spend

The NUT-07 state check is read-only. Login does not swap, melt, or otherwise consume the
proof.

Redemption is a business action. In this repository's own example it is the destructive
operation sitting behind step-up authentication, and conflating it with login would burn a
voucher on every sign-in. It would also make the retry-safe completion path destructive:
NAP guarantees that a duplicate completion returns the same session, and a spending login
would violate that on the first retry.

## What it costs

Three costs, all real, none hidden.

**The mint becomes an availability dependency of login.** If the mint is unreachable,
nobody logs in. That is a genuine regression against stored ACLs, where login depends only
on your own datastore. The `onMintUnavailable: 'degrade'` policy can issue a reduced
session on DLEQ alone, but the default is `deny`, because degraded mode accepts a voucher
that may already have been spent.

**A session can outlive its credential.** A voucher redeemed or revoked mid-session leaves
a live NAP session behind it. Per-request mint checks would fix this and are a trap at any
real request rate, so the bound is a session ceiling instead:
`maxSessionLifetimeSeconds` caps a session's total life, and a resolver can additionally
clamp the session to the voucher's own expiry. The honest guarantee is *the ceiling*, not
*immediately*.

**One voucher works at several servers.** Nothing stops the holder logging in at two
places at once. Because the P2PK binding means only the holder of `K` can present it, this
is one legitimate holder opening several sessions rather than a replayed credential — but
it does mean this extension issues *multi-use* credentials. Single-use across servers
needs shared state that does not exist.

## Every failure is the same 401

The verification steps produce ten distinct audit codes. The client sees one response.

| Code | Cause |
| --- | --- |
| `NAP_VOUCHER_MINT_NOT_ALLOWED` | `mint_url` not in the allowlist |
| `NAP_VOUCHER_MALFORMED` | the credential or its secret would not parse |
| `NAP_VOUCHER_DLEQ_INVALID` | NUT-12 verification failed |
| `NAP_VOUCHER_BINDING_MISMATCH` | P2PK key is not the completion's signer |
| `NAP_VOUCHER_ISSUER_UNTRUSTED` | issuer signature invalid, or pair not allowlisted |
| `NAP_VOUCHER_EXPIRED` | `expires_at` has passed |
| `NAP_VOUCHER_SPENT` | NUT-07 returned `SPENT` or `PENDING` |
| `NAP_VOUCHER_MINT_UNAVAILABLE` | mint unreachable and the mode is `deny` |
| `NAP_VOUCHER_ABSENT` | no credential, and no fallback resolver wired |
| `NAP_VOUCHER_GRANT_NOT_IN_REGISTRY` | `grant()` returned an undeclared role or permission |

The distinctions live only in the `AuditLogger`. Together the codes are an oracle: they
would tell a caller whether a mint is allowlisted, whether an issuer is trusted, and —
most sensitive — whether a given proof has been spent. So the HTTP response is
byte-identical across all of them, status, body, and headers.

That uniformity is what forces the capability signal to live elsewhere. A client holding a
credential that gets a 401 cannot tell "this server has no voucher support" from "your
voucher was refused", and those call for opposite actions: retry without the credential,
or do not retry at all. So `/auth/init` advertises `supported_extensions`, before the
client has signed anything, describing the *server* rather than any principal.

## Where the credential travels

The voucher goes in the `/auth/complete` request body, not in the NIP-98 event.

That placement is load-bearing. NIP-98's `payload` tag is `sha256(rawBody)`, so putting
the credential in the body means **the signature covers it**. A credential swapped in
transit changes the hash and the completion fails — the same mechanism that already
protects the `step_up` flag.

The consequence for adapters is that the raw-body trap applies unchanged and with more at
stake. Any middleware that reparses and re-stringifies JSON breaks the hash. Previously
that broke logins; here it would break the integrity of an authorisation credential. It
fails closed and loudly, but for every user at once.

## The secret is a composite kind

A Cashu proof carries exactly one NUT-10 kind, so a voucher that is also P2PK-locked has
to pick one. Neither existing kind works, and understanding why explains the shape of the
whole extension.

A **`VOUCHER` secret carrying P2PK tags** leaves the lock unenforced. A mint dispatches on
kind, so the proof never reaches the P2PK validator and no witness is ever checked. The
binding would be checkable by NAP and invisible to the mint, so a thief could still spend
the proof.

A **`P2PK` secret carrying voucher tags** is enforced natively, but breaks issuer signing:
the canonical bytes an issuer signs commit to the kind and to the voucher id, so moving to
`P2PK` would leave the signature covering a document that never exists on the wire.

So extension 0001 uses a new composite kind, **`P2PK_VOUCHER`**, carrying both concerns and
enforced as a single spending condition. It is named for the spending mechanism, following
`P2PK` and `HTLC`, so a mint implementer reading it knows a witness is required.
[ADR 0003](../adr/0003-voucher-secret-modelling.md) records the full reasoning, including
why `BEARER` was rejected: a bearer instrument is one where possession alone authorises,
and here possession is useless without the key for `K`.

## What is deliberately not solved

- **Not a replacement for NIP-98.** A voucher presented alone authenticates nothing.
- **Not payment.** Login must not spend, swap, or melt the proof.
- **Not anonymous credentials.** The mint learns that the voucher was state-checked. Blind
  presentation is out of scope.
- **Not single-use.** See *What it costs* above.

One more property is worth stating because nothing enforces it: `K` should be freshly
generated per voucher and should not be the holder's long-term identity key. A holder who
locks a voucher to their personal npub gets today's linkability back, and no amount of
server-side checking can prevent that.

## Where to go next

- [Extension 0001](../extensions/0001-voucher-bound-authorization.md) — the normative
  specification: the verification procedure, failure codes, and the open lifecycle
  questions.
- [Integration guide §3.5](../NAP-INTEGRATION-GUIDE.md#35-mint-backed-authorisation) — the
  operator-facing account, including allowlist construction errors and the two wiring
  traps.
- [ADR 0003](../adr/0003-voucher-secret-modelling.md) — why the composite NUT-10 kind.
- [ADR 0004](../adr/0004-voucher-grant-registry-validation.md) — why `grant()` output is
  validated at grant time rather than at wiring time.
- [`packages/nap-voucher`](../../packages/nap-voucher/README.md) — the implementation and
  its API.
