# NAP Extension 0001 — Voucher-Bound Authorization

**Status:** Draft, for review. Partially implemented (verification primitives only). Not part of the core profile.
**Operator-facing summary:** [integration guide §3.5](../NAP-INTEGRATION-GUIDE.md#35-mint-backed-authorisation) — this document is the design rationale; §3.5 is what an integrator reads.
**Extends:** `docs/NAP-v2-RFC.md` §15 (ACL and Authorization), §22 (Open Extensions, items 1 and 5).
**Depends on:** `cashu-lib` NUT-10 `VoucherSecret` / NUT-11 `P2PKSecret`, `cashu-voucher` issuer signatures, NUT-07 state check, NUT-12 DLEQ.
**Applies to:** `nap` (TypeScript) and `nap-java` together. A protocol change in one without the other breaks interop (CLAUDE.md).

---

## 1. Summary

This extension lets an Imani-issued Cashu voucher supply a session's roles and permissions,
in place of a stored ACL row.

It changes **authorization only**. NAP's authentication — a challenge-bound NIP-98 Schnorr
signature (RFC §11, §12) — is untouched, byte for byte. The client still signs; the server
still verifies exactly as it does today.

What the voucher changes is the *meaning* of the key that signs. Today the completion pubkey
is a durable personal identity and the ACL is a statement about that person. Under this
extension the pubkey is an ephemeral key that a voucher was P2PK-locked to, and the
authorization statement lives in the voucher, made by its issuer.

A one-line framing: **keep the nsec, make it disposable, and let the voucher say what it can do.**

### 1.1 What this buys

| Property | Today | With this extension |
| --- | --- | --- |
| Long-term identity required to log in | Yes — the user's npub | No — a per-voucher burner key |
| Where authorization comes from | `AclStore` row, provisioned in advance | Voucher metadata, signed by the issuer |
| Pre-registration required | Yes | No — the credential is bearer-issued |
| Cross-session linkability | High — same npub every time | Low — a key per voucher |
| Offline verifiability | ACL is local | Partial: DLEQ offline, liveness needs the mint |

The pre-registration property is the practical driver. A merchant can hand out a voucher that
grants `voucher:redeem` to whoever holds it, without ever learning a customer's npub or writing
an ACL row.

### 1.2 Non-goals

1. **Not a replacement for NIP-98.** A voucher presented alone authenticates nothing (§3.1).
2. **Not payment.** Login MUST NOT spend, swap, or melt the proof (§6.1).
3. **Not anonymous credentials.** The mint learns that the voucher was state-checked. Blind
   presentation is out of scope.
4. **No change to the session body contract.** `principal.pubkey` remains present and required.
5. **Not a single-use credential.** One live voucher may open sessions at several servers at
   once. Only the holder of `K` can do so (§3.1), but nothing bounds how many. Cross-server
   single-use needs shared state that does not exist — see §7.4 for why the obvious fix does not
   work.

---

## 2. Why the naive design is unsafe

Stated so review does not have to rediscover it.

**"Send the voucher instead of signing"** fails on four counts:

1. **No freshness.** A voucher carries no challenge binding. Replay is unbounded in time.
2. **Bearer over the wire.** Anything that sees the request — a TLS-terminating proxy, an
   access log, an APM trace — can reuse it. NAP deliberately never puts a credential in a
   readable place (CLAUDE.md: "never put an access token in the `/session` body").
3. **Verification by spending destroys value.** Proving a proof is live by swapping it burns
   the voucher on every login and races the retry-safe completion path (RFC §13.2), where the
   same completion may legitimately arrive twice.
4. **No principal.** `toSessionState()` dereferences `response.principal.pubkey` and the ACL
   is keyed on a pubkey. A bearer token yields nothing to key on.

The P2PK binding in §3 fixes 1, 2 and 4 by making possession of the voucher useless without
possession of a key. §6.1 fixes 3 by never spending.

---

## 3. Design

### 3.1 The binding

The voucher proof MUST carry a NUT-11 P2PK lock naming a public key `K`. The completion's
NIP-98 event MUST be signed by `K`.

```
voucher proof --P2PK--> K <--signs-- NIP-98 completion event
```

That equality is the whole design. Everything else is plumbing.

- Holding the voucher without `K` proves nothing: the completion cannot be signed.
- Holding `K` without the voucher proves nothing: there is no authorization to resolve, and
  the ACL resolver denies.
- Replay of a captured completion is already prevented by the core profile: the challenge is
  single-use and atomically redeemed (RFC §13.1).

`K` SHOULD be freshly generated per voucher, by the issuing wallet, and SHOULD NOT be the
holder's personal identity key. Nothing enforces this, and a holder who locks a voucher to
their long-term npub simply gets today's linkability back.

### 3.2 Where it plugs in

No new endpoint. No change to `POST /auth/init` or `POST /auth/complete` semantics. The
extension is one implementation of the existing `AclResolver` interface
(`packages/nap-server/src/types.ts:193`), called at `server.ts:684` for login and `:901` for
per-request re-resolution.

```
/auth/complete  →  NIP-98 verify (unchanged, RFC §12 steps 1–12)
                →  AclResolver.resolve(...)      ← VoucherAclResolver goes here
                →  session minted (unchanged)
```

`AclResolver.resolve(npub, pubkey)` as it stands has no parameter for a voucher. §5.1 proposes
the minimal widening.

### 3.3 The credential

The client presents a `VoucherCredential` alongside the completion:

```ts
export interface VoucherCredential {
  /** Absolute HTTPS URL of the mint that signed the proof. REQUIRED. See §4. */
  mint_url: string;
  /** Keyset id from the proof. */
  keyset_id: string;
  /** NUT-10 VOUCHER secret, canonical serialization. */
  secret: string;
  /** Blind signature C, hex. */
  signature: string;
  amount: number;
  /** NUT-12 DLEQ proof. REQUIRED — see §4.2. */
  dleq: { e: string; s: string; r: string };
  /** NUT-11 P2PK witness, if the mint requires one for the state check. */
  witness?: string;
}
```

The voucher metadata the resolver reads comes from the NUT-10 tags already defined in
`cashu-lib`'s `VoucherTags`: `issuer`, `unit`, `face_value`, `expires_at`,
`backing_strategy`, `issuer_sig`, `issuer_pubkey`, `merchant_metadata`.

The P2PK lock key `K` is carried in the secret's NUT-11 tags (see §5.3 on how VOUCHER and
P2PK kinds compose — this is the one genuinely unresolved modelling question).

### 3.4 Transport

The credential is not part of the NIP-98 event. It goes in the completion body:

```ts
export interface AuthCompleteRequest {
  challenge_id: string;
  step_up?: boolean;
  voucher?: VoucherCredential;   // ← added by this extension
}
```

**This is deliberate and it is load-bearing.** The `payload` tag is
`sha256(rawBody)` (RFC §11 rule 7), so putting the credential in the body means the signature
covers it. A credential swapped in transit changes the hash and the completion fails with
`NAP_COMPLETE_PAYLOAD_MISMATCH`. This is the same mechanism that already protects `step_up`
(`server.ts:691` comment: "The flag is signed (it lives in the hashed body), so it cannot be
added in transit").

Consequence for adapters: the raw-body trap in CLAUDE.md applies unchanged and with more at
stake. Any middleware that re-stringifies JSON breaks this.

---

## 4. The mint is mandatory

Three independent reasons, each sufficient on its own.

### 4.1 The keyset id is not a locator

A Cashu proof carries `id` (keyset), not a mint URL. Without `mint_url` the server cannot
fetch `/v1/keys`, cannot resolve the keyset to public keys, and therefore cannot verify
anything at all. A keyset registry mapping id → mint would work, but that is a private
allowlist by another name, so §4.3 applies to it identically.

### 4.2 Liveness is mint-local state

NUT-12 DLEQ proves *the mint signed this proof*. It says nothing about whether the proof is
still unspent. Only a NUT-07 `POST /v1/checkstate` distinguishes a live voucher from a burned
one. DLEQ is therefore necessary but not sufficient, and is REQUIRED (§3.3) so that a server
in mint-degraded mode (§7.3) still has cryptographic footing.

### 4.3 Trust is per-mint, and the allowlist is not optional

Any mint can sign a voucher whose tags claim `issuer: acme` and whose metadata implies
`role: admin`. Signature validity says nothing about issuer authority.

The server MUST therefore hold a **mint allowlist**, and it MUST be constructed the same way
as the audience allowlist already is (CLAUDE.md; guide §9.4):

1. No default. No implicit "any mint".
2. An empty array throws at wiring time, not at request time.
3. Entries are exact origins, scheme-pinned.
4. The request-supplied `mint_url` is *matched against* the allowlist, never trusted to
   select it.

A request header choosing the mint that a credential is then verified against is the same
vulnerability class as a request header choosing the NIP-98 audience — the flaw
`createRequestDerivedBaseUrlResolver`'s mandatory allowlist exists to prevent (WebAuthn L3
§13.5.9, §13.5.8). Reviewers should treat any relaxation here as the single highest-severity
change in this document.

Issuer authority is a second, narrower allowlist: `(mint_url, issuer_pubkey)` pairs, since a
trusted mint may still carry vouchers from issuers this server does not honour.

---

## 5. Proposed interfaces

Illustrative. Names are open; the shapes are the argument.

### 5.1 Widening `AclResolver`

The existing signature has nowhere to put a credential:

```ts
export interface AclResolver {
  resolve(npub: string, pubkey: string): Promise<AclDecision>;
}
```

Minimal backward-compatible widening — a third optional parameter:

```ts
export interface AclResolutionContext {
  voucher?: VoucherCredential;
  now: number;
}

export interface AclResolver {
  resolve(npub: string, pubkey: string, context?: AclResolutionContext): Promise<AclDecision>;
}
```

Existing resolvers ignore the third argument and continue to compile and behave identically.
`createRegistryAclResolver` is untouched.

**Review question A:** an optional third parameter is the cheap route, but it makes the
credential invisible at the type level to every resolver that ought to reject it. A separate
`VoucherAclResolver` interface with its own call site in `verifyCompletion` is more honest and
more code. Which?

### 5.2 The resolver

As shipped:

```ts
export interface VoucherAclResolverOptions {
  /** REQUIRED. Built by `createMintAllowlist`, which throws on an empty list (§4.3). */
  mintAllowlist: MintAllowlist;
  /** REQUIRED. Built by `createIssuerAllowlist`, keyed on the (mint, issuer) pair. */
  issuerAllowlist: IssuerAllowlist;
  /** REQUIRED. Owns the keyset cache TTL and the NUT-07 state check. */
  mintClient: MintClient;
  /** REQUIRED. Owns the §7.3 deny/degrade decision. Default is deny. */
  availability: MintAvailabilityPolicy;
  /** REQUIRED. Maps verified voucher metadata to roles/permissions. */
  grant(voucher: VerifiedVoucher): VoucherGrant;
  /** Checks `grant()` output at grant time (ADR 0004). */
  permissionRegistry?: PermissionRegistryLike;
  /** What a *guarded request* means when there is no credential (§7.2). */
  onMissingCredential?: 'deny' | 'trust-session';
  /** Delegate for logins that present no voucher. Absent means deny. */
  fallback?: AclResolverLike;
  clock?: Clock;
  auditLogger?: VoucherAuditLogger;
}
```

**This differs from the sketch this section carried before implementation**, and the difference
is worth stating rather than quietly replacing. The original took `allowedMints: string[]`,
`keysetCacheTtlSeconds` and `onMintUnavailable` directly, which folded four separate concerns
into one options bag. What shipped takes the *constructed* collaborators instead, because each
one has wiring-time failure modes of its own: an empty allowlist, a mint URL with a path, a
`degradedGrant` overlapping a destructive permission. Passing them pre-built means those
failures surface where the operator wires them, with an error naming the specific mistake,
rather than inside this constructor as a second-hand complaint.

The three options the sketch never anticipated — `permissionRegistry`, `onMissingCredential`,
`fallback` — each exist because implementation found a problem the design had not:
respectively [ADR 0004](../adr/0004-voucher-grant-registry-validation.md), the §7.2 guard trap,
and credential-free logins.

`grant` is the application's policy and stays outside the library.

**Review question E: SETTLED — validate at grant time**, accepted 2026-09-01. See
[ADR 0004](../adr/0004-voucher-grant-registry-validation.md). Pass the optional
`permissionRegistry` and an undeclared role or permission denies the login and logs
`NAP_VOUCHER_GRANT_NOT_IN_REGISTRY`.

Wiring-time validation, which this section previously proposed, turned out to be impossible
rather than merely costly: `grant()` takes a *verified voucher*, so a policy deriving keys from
the voucher's own tags has no output until a real voucher arrives. Probing it at construction
with a synthetic voucher yields `voucher:view:PROBE:0` — validating that would report success
for a policy that fails on every real login. Grant-time validation does not give tutorial 03's
wiring-time guarantee; what it gives is the conversion of a silent failure into an audited one.

### 5.3 Secret modelling — open

`cashu-lib` has `VoucherSecret extends WellKnownSecret` with `Kind.VOUCHER`, and a separate
`P2PKSecret`. A proof has one kind. Three options, per
`cashu-voucher/project/VOUCHER-SPENDING-CONDITIONS-ANALYSIS.md`:

1. **VOUCHER kind carrying P2PK tags.** Voucher metadata stays first-class; the mint must be
   taught to enforce P2PK on a VOUCHER secret, or the lock is advisory only. **If the mint does
   not enforce it, this extension's security collapses** — the binding in §3.1 would be
   checkable by the NAP server but not by the mint, so a thief could still swap the proof.
2. **P2PK kind carrying voucher tags.** The mint enforces the lock natively today. Voucher
   metadata becomes tag payload, and `VoucherSecret`'s accessors no longer apply.
3. **A composite kind.** Cleanest model, largest change, needs mint support that does not
   exist. **Chosen** — see ADR 0003. Every option turned out to need an upstream change, so
   the deciding factor became which model is honest rather than which is cheapest.

**Review question B: SETTLED — option 3**, a new composite kind named `P2PK_VOUCHER`,
accepted 2026-09-01. See [ADR 0003](../adr/0003-voucher-secret-modelling.md).

Option 1 leaves the lock unenforced: the Imani mint dispatches first-match on kind, so a
VOUCHER secret never reaches `P2PKSpendingCondition`, and `VoucherSpendingCondition` has no
witness check. Option 2 looked free but is not — `VoucherCanonicalBytes` hardcodes the
`VOUCHER` kind and the voucher id into the bytes the issuer signs, so a P2PK-kind secret
would carry a signature over a document that never exists on the wire. It also collapses two
distinct meanings, since `data` would become the lock key and the voucher id would demote to
a tag.

Every option needs an upstream change; option 2's apparent cheapness was an error in the
earlier analysis. So pay for the model where both concerns stay first-class and both are
enforced.

Cost: `cashu-lib` (deserialiser, secret class), `cashu-voucher` (canonical bytes and issuer
signing — this invalidates signatures produced under the old form), and `cashu-mint`
(dispatch, and `/v1/info` advertising the kind). **NAP must not ship ahead of the mint.**

---

## 6. Verification procedure

Inserted at RFC §12 step 13 ("Verify ACL authorization"), which becomes:

13. If the completion body carries a `voucher`:
    - a. `mint_url` MUST match the allowlist exactly (§4.3). Reject otherwise.
    - b. Verify the NUT-12 DLEQ against the cached keyset for `keyset_id`.
    - c. Parse the NUT-10 secret. Extract voucher tags and the P2PK lock key `K`.
    - d. **`K` MUST equal the completion event's `pubkey`.** This is §3.1. Reject otherwise.
    - e. Verify `issuer_sig` over the voucher's canonical bytes using `issuer_pubkey`.
    - f. `(mint_url, issuer_pubkey)` MUST be in the issuer allowlist.
    - g. `expires_at` MUST be in the future relative to the server clock.
    - h. NUT-07 state check MUST return `UNSPENT` (subject to §7.3).
    - i. Call `grant()` and use the result as the `AclDecision`.

Ordering notes:

- All of this happens **after** steps 1–12, so a request that has not proven key control never
  reaches the mint. Otherwise an unauthenticated caller could use `/auth/complete` as a
  free oracle to state-check arbitrary proofs.
- Step (d) before (h): reject a mismatched binding locally before spending a network round
  trip, and before telling the mint anything.
- Step (a) before everything: never make an outbound request to an unvetted URL. SSRF.

### 6.1 Login MUST NOT spend

The state check is read-only. `/auth/complete` MUST NOT swap, melt, or otherwise consume the
proof. Redemption is a business action, and in this repo's own example it is precisely the
destructive action that sits behind `requireStepUp` (tutorial 06). Conflating the two would
burn a voucher on every login and make the retry-safe completion path
(RFC §13.2, where a duplicate submission MUST return the same session) destructive on retry.

### 6.2 Failure codes

Every failure remains an identical generic 401 to the client (CLAUDE.md: "Every auth failure is
an identical 401"). The distinctions exist only in the `AuditLogger`:

| Code | Cause |
| --- | --- |
| `NAP_VOUCHER_MINT_NOT_ALLOWED` | `mint_url` not in the allowlist |
| `NAP_VOUCHER_DLEQ_INVALID` | NUT-12 verification failed |
| `NAP_VOUCHER_BINDING_MISMATCH` | P2PK key ≠ completion pubkey (§3.1) |
| `NAP_VOUCHER_ISSUER_UNTRUSTED` | issuer signature invalid, or pair not allowlisted |
| `NAP_VOUCHER_EXPIRED` | `expires_at` in the past |
| `NAP_VOUCHER_SPENT` | NUT-07 returned SPENT/PENDING |
| `NAP_VOUCHER_MINT_UNAVAILABLE` | mint unreachable and mode is `deny` |

Note finding 12 in `CONTEXT.md`: guard denials currently reach no `AuditLogger` at all. If
guards re-resolve voucher authorization per request (§7.2), these codes will be invisible on
exactly the surface that matters most. **That finding should be fixed before this extension
ships, not after.**

---

## 7. Lifecycle problems

The honest hard parts.

### 7.1 Session outlives credential

A voucher redeemed, revoked, or expired mid-session leaves a live NAP session backed by a dead
credential. `VoucherStatus` has three terminal states (`REDEEMED`, `REVOKED`, `EXPIRED`) and
none of them reaches the session store.

RFC §15 rule 1 already requires permissions to be evaluated on every authorized request, and
rule 2 says removal SHOULD revoke active sessions. Options:

- **Cap the session TTL** well below the voucher's remaining life, and cap it absolutely.
  Cheap, coarse, no mint dependency.
- **Re-check on `/auth/session`**, honouring RFC §15 rule 1 properly. One mint round trip per
  session read: expensive, and it makes the mint a hard dependency of every authenticated
  request, not just login.
- **Subscribe to the Nostr ledger.** `cashu-voucher` publishes status to a NIP-33 ledger
  (kind 30078). A watcher calling `revokeByPrincipal(pubkey)` on a terminal transition is the
  right shape and adds no per-request cost.

  **Blocked upstream, on two counts found while scoping it** (#27 phase 2). The watcher needs
  to map a ledger event to a principal, and today it cannot:

  1. `SignedVoucher` holds a `VoucherSecret`, while `P2PKVoucherSecret` extends `P2PKSecret` —
     a different branch of the hierarchy. The compiler is explicit: *"incompatible types:
     P2PKVoucherSecret cannot be converted to VoucherSecret"*. **The ledger cannot represent a
     P2PK-locked voucher at all**, which is precisely the kind this extension uses.
  2. The event's tags are `status`, `amount`, `unit`, `expiry`, and a `d` tag of
     `voucher:<id>`. None carries the lock key `K` — and `K` *is* the principal pubkey. So even
     with (1) fixed, a watcher could not tell whose sessions to revoke without parsing it out
     of the embedded secret, or without `K` being added to the event.

  Neither is fixable in NAP. Both belong to `cashu-voucher`, alongside the `P2PK_VOUCHER`
  support that is already pending release there.

**Recommendation:** short TTL now, ledger watcher later. Per-request state checks are a trap.

**Review question C: SETTLED — a 24-hour ceiling, enforced**, accepted 2026-09-01.

Implementing this turned up something the section had assumed away. "Cap the session TTL" was
not sufficient, because **the cap did not exist**. Refresh sets `refresh_expires_at` to
`now + refreshTtlSeconds` on every rotation, so the window slides forward indefinitely:

```
no cap (today)          : refresh 5 at t+400000 -> 200, still alive
maxSessionLifetimeSeconds 24h : refresh 2 at t+160000 -> 401 (session ended)
```

A session refreshed regularly never ended, so the staleness window was not "long", it was
unbounded. That is tolerable for a stored-ACL decision, which `resolveEffectiveAcl` re-reads per
guarded request. It is not tolerable for a decision the server cannot re-read, which is exactly
what a voucher is once login is over.

`NapServerOptions.maxSessionLifetimeSeconds` is the fix: an absolute ceiling measured from
`issued_at`, which survives rotation. Once reached, refresh fails and the holder must log in
again, presenting the credential afresh.

**The agreed number is 24 hours (86400) as a maximum, and a voucher server SHOULD go lower.**
The reasoning is that the ceiling is the worst-case interval during which a redeemed or revoked
voucher still authorises a session, so it should be the shortest value the deployment's users
will tolerate re-authenticating at. 24 hours matches the upper end of the RFC's refresh
recommendation, so it costs nothing beyond what a deployment already accepts, and it converts
"unbounded" into a number an operator can reason about.

This is a ceiling, not a substitute for the ledger watcher. It bounds staleness; it does not
detect anything. A watcher calling `revokeByPrincipal()` on a terminal transition remains the
right shape and would reduce the window from hours to seconds.

**Guard cache TTL (§7.2) must be chosen consistently**, and it is a security parameter for the
same reason: it is the maximum staleness of a re-resolution decision. It should be well below
the session ceiling, or the ceiling is the only thing bounding anything.

### 7.2 Re-resolution at the guards

`resolveEffectiveAcl` re-resolves per guarded request, and this section assumed that meant a
mint round trip per request unless results were cached.

**As built, it does not.** The credential is not available on re-resolution at all, so the
resolver returns before reaching the mint:

```
100 guarded requests -> 0 keyset fetches, 0 state checks
```

The per-request mint dependency the section feared is structurally absent rather than avoided by
tuning, which is the better outcome: there is no cache TTL to get wrong, and no configuration
that reintroduces the problem. What replaces it is a staleness bound — `onMissingCredential:
'trust-session'` accepts the session's snapshot, so authorization is as fresh as the session,
which `maxSessionLifetimeSeconds` (§7.1) caps.

A deployment that *wants* per-request mint checks would have to cache them, and the warning
would apply again. §7.1 says why that is a trap.

**There is a sharper problem than caching, found while implementing #24.** Re-resolution holds
a *session*, never the credential — that lived in the login body and is gone. A voucher
resolver whose answer depends on a credential therefore denies **every guarded request**, and
the operator sees a login that succeeds followed by a session that can do nothing:

```
re-resolving guard, default      : login 200 -> guarded request 401
```

The credential's absence alone cannot distinguish this from a credential-free login, which must
still be denied. So `AclResolutionContext` carries `session` on re-resolution and refresh,
present exactly when `voucher` is absent, and `createVoucherAclResolver` takes
`onMissingCredential`:

- `'deny'` (default) — strict, and audits `NAP_VOUCHER_ABSENT` with a note naming the cause
  rather than leaving an operator to infer it from identical denials.
- `'trust-session'` — honours the session's snapshot on re-resolution, while a credential-free
  *login* is still denied.

`'trust-session'` means a session's authorization is only as fresh as its TTL, which is §7.1's
staleness question. That is why it is an explicit choice rather than a default.

### 7.3 The mint becomes an availability dependency of login

If the mint is down, nobody logs in. This is a real regression against today's behaviour, where
login depends only on the app's own store.

`onMintUnavailable: 'degrade'` MAY issue a session on DLEQ alone (proving the mint did sign it)
with a **reduced** permission set that excludes anything destructive or value-bearing. Default
MUST be `deny`, because degraded mode accepts an already-spent voucher.

### 7.4 Double-use across servers

Nothing stops one live voucher authenticating at several servers at once:

```
holder at server A            : 200
same voucher at server B      : 200
THIEF with the same voucher   : 401
```

**SETTLED 2026-09-01: out of scope for v1, and the accepted risk is recorded here** (#28).

The third line is why. Because §3.1 binds the voucher to `K` and login requires a NIP-98
signature by `K`, only the holder of `K` can present it anywhere. "Double-use across servers" is
therefore **one legitimate holder logging in at several servers** — not a stolen credential
being replayed. That is ordinary behaviour for an authorization credential, and it is what
holding a key already means everywhere else in NAP.

The `Y`-keyed record this section previously proposed does not solve the stated problem. It is
per-server state: server A recording `Y` prevents a second login *at A*, and does nothing about
server B, which never sees A's record. It delivers **per-server** single-use while the heading
says cross-server. Shipping it would leave the impression the problem was handled.

Genuine cross-server single-use needs shared state, and there are only two kinds:

- **Mint-side** — actually spending the proof, which §6.1 forbids at login and which would burn
  a voucher on every login and make the retry-safe completion path destructive.
- **A ledger shared between servers** — a trust federation that does not exist, and a much
  larger design than this extension.

So the honest position is that this extension issues **multi-use authorization credentials**,
and an operator who needs single-use should not model it as a voucher presented at login.

Two things bound the risk in practice. `maxSessionLifetimeSeconds` (§7.1) caps how long any one
of those sessions can live, and the NUT-07 state check (§6.h) means that once a voucher *is*
redeemed through a real business action, no further logins succeed anywhere. What is unbounded
is only the number of concurrent sessions a holder may open with a live voucher, using a key
they control.

**If single-use later becomes a requirement**, the per-server `Y` record is still worth having
as a partial measure — but it must be described as what it is, and it needs a defined retention
period, since the record has to outlive the voucher to mean anything.

---

## 8. Interop

`nap-java` implements the same protocol and `nap-java/nap-it` runs interop tests against this
implementation's client. This extension adds an optional body field, so:

- A TypeScript client sending `voucher` to a Java server without the extension: the field is
  ignored, the `payload` hash still matches (it hashes whatever bytes were sent), the ACL falls
  through to the store, and the login most likely **fails closed** with `ACL_DENIED` because
  the burner key has no row. Fail-closed is the right outcome, but it is indistinguishable
  from a real denial without an audit log.
- The reverse direction is symmetric.

**Recommendation:** a capability signal so a client can know before signing. Cheapest is an
additive field on `AuthInitResponse`, which the RFC's §24.3 constraints permit as an extension:

```ts
{ supported_extensions?: string[] }   // e.g. ["voucher-acl/1"]
```

**Review question D: SETTLED — advertise it**, accepted 2026-09-01. The extension name string
is fixed as **`voucher-acl/1`**, and `NapServerOptions.supportedExtensions` publishes it on
`/auth/init`.

Fail-closed is correct and stays correct; the problem is that it is not *actionable*. A client
holding a credential that receives a 401 faces two possibilities calling for opposite responses:

| Cause | Correct client action |
| --- | --- |
| Server has no voucher support | Retry **without** the credential — a stored-ACL login may well succeed |
| Credential dead, forged, or unbound | Do **not** retry; tell the holder their voucher is bad |

Guessing wrong costs either a login that could have worked or a wasted signing prompt and a
misleading error. Nothing in the response distinguishes them, and §6.2 requires that it never
does — so the signal has to arrive *before* the attempt, which is what makes `/auth/init` the
right place rather than a richer error.

This publishes nothing sensitive, which is why it does not undermine §6.2. The field describes
the **server**, not a principal: it names a feature anyone can read about in the documentation,
it is sent before the client has signed anything, and it says nothing about any credential,
mint, or issuer. A server that omits it still refuses everything it would have refused.

Two properties worth stating, both tested:

- **Absence means "makes no claim", not "supports nothing".** Every server shipped so far omits
  the field, and an older server may support an extension while predating the field entirely. A
  client MUST treat absence as unknown and fall back to trying, rather than as a denial.
- **The option is declarative and enables nothing.** Setting it does not turn the extension on
  and omitting it does not turn it off. A stale value is therefore a lie the server tells about
  itself rather than a security hole — but set it beside the wiring it describes.

---

## 9. What is genuinely new versus what already exists

For reviewers deciding scope.

| Piece | Status |
| --- | --- |
| NIP-98 authentication | Exists, unchanged |
| `AclResolver` seam | Exists (`types.ts:193`) |
| Signed voucher + issuer verification | Exists (`cashu-voucher-domain`) |
| NUT-10 `VoucherSecret` and tags | Exists (`cashu-lib`) |
| Nostr voucher ledger / status | Exists (`cashu-voucher-nostr`) |
| P2PK on a voucher secret | **Open — §5.3, review question B** |
| Mint allowlist + keyset cache | New |
| DLEQ + NUT-07 client in the auth path | New |
| `VoucherCredential` on the completion body | New, additive |
| Voucher→session revocation watcher | New, deferrable (§7.1) |
| Guard-level audit logging | **Pre-existing gap, blocks §6.2** (CONTEXT.md finding 12) |

The seam is genuinely already there. The new surface is a Cashu verification client and two
allowlists.

---

## 10. Open questions for review

- **A.** Widen `AclResolver` with an optional context parameter, or add a distinct interface
  and call site? (§5.1)
- **B.** ~~VOUCHER-with-P2PK-tags, P2PK-with-voucher-tags, or a composite kind?~~
  **Settled: option 3**, a new composite kind
  ([ADR 0003](../adr/0003-voucher-secret-modelling.md)). Option 1 leaves the lock unenforced
  by the mint; option 2 breaks issuer signing, because the canonical bytes hardcode the
  VOUCHER kind.
- **C.** ~~Acceptable staleness between voucher death and session death.~~ **SETTLED
  2026-09-01: a 24-hour ceiling via `maxSessionLifetimeSeconds`, and lower where tolerable**
  (§7.1). Implementing it found that the "cap the TTL" the section assumed did not exist —
  refresh slid the window forward indefinitely, so staleness was unbounded rather than long.
- **D.** ~~Capability advertisement on `/auth/init`, or fail-closed?~~ **SETTLED 2026-09-01:
  advertise `voucher-acl/1` via `supportedExtensions`** (§8). Fail-closed is correct but not
  actionable — the two causes of a 401 call for opposite client actions, and §6.2 forbids the
  response distinguishing them, so the signal must precede the attempt.
- **E.** ~~Should `grant()` be validated against the `PermissionRegistry` at wiring time?~~
  **SETTLED 2026-09-01: at grant time, not wiring time** —
  [ADR 0004](../adr/0004-voucher-grant-registry-validation.md). Wiring-time validation is not
  possible for a callback whose output depends on the voucher it is given.
- **F.** ~~Does anything here belong in the core RFC?~~ **CONFIRMED 2026-09-01: permanently an
  extension** (RFC §22.1). Confirmed after implementation rather than before, which is what
  gives it weight: nothing in the core profile changed to accommodate this, and the two core
  edits made along the way (`AclResolutionContext`, `maxSessionLifetimeSeconds`) are general
  enough to defend had this extension never existed.

---

## 11. Recommendation

Worth building, in this order:

1. **Settle question B first.** Everything downstream is contingent on how the P2PK lock and
   the voucher metadata coexist, and on whether the mint enforces it. If the mint does not
   enforce the lock in the chosen shape, stop: the security argument in §3.1 does not hold.
   *(Settled 2026-09-01: option 3, a new composite kind —
   [ADR 0003](../adr/0003-voucher-secret-modelling.md). The mint must enforce it before NAP
   ships, so §11 step 5's coupling now includes the mint.)*
2. Build the verification client (allowlist, keyset cache, DLEQ, NUT-07) standalone and
   testable, with no NAP dependency.
3. Fix CONTEXT.md finding 12 (guard audit logging), so §6.2 is observable.
4. Add the resolver and the body field, behind the extension name.
5. Mirror in `nap-java` before anything ships.

Do not ship steps 4 and 5 apart.
