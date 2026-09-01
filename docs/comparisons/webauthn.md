# NAP and WebAuthn

**Who this is for:** an architect who already knows WebAuthn and is deciding
whether to bet an auth system on NAP.

This is not a feature table with ticks in the NAP column. NAP treats
[W3C WebAuthn Level 3](https://w3c.github.io/webauthn/) as **normative
precedent** — several of NAP's rules exist because WebAuthn made the same call
first, and NAP's source cites the section numbers. The honest comparison starts
from that, and then says plainly where NAP is worse. Three of those places are
permanent and cannot be engineered away.

Everything below is already stated somewhere in this repository — the RFC, the
integration guide, the best-practices file, and a doc comment in
`packages/nap-server/src/audience.ts`. This page is where it lives together.

---

## 1. The precedent NAP follows

### Origin binding → audience binding

A WebAuthn assertion is bound to an origin, and the Relying Party is required to
check it. WebAuthn L3 §13.5.9:

> The Relying Party MUST validate the origin member of the client data. The
> Relying Party MUST NOT accept unexpected values of origin.

A NAP completion proof is bound to an **audience** — the exact absolute URL of
`POST /auth/complete`, carried in the NIP-98 `u` tag and checked byte for byte
by the server. A proof addressed to `https://api.example.com/auth/complete`
cannot be redeemed anywhere else. Wrong audience fails as
`NAP_COMPLETE_URL_MISMATCH`, behind the same generic 401 as every other
failure.

That check is only as good as the value it compares against, which is why the
audience is a **server-side deployment decision**, never a client-supplied
header. `createRequestDerivedBaseUrlResolver()` — the only way to derive the
audience from the request — **requires a host allowlist**. There is no default
and no empty-array escape hatch; an empty or missing list throws at wiring time
rather than answering 401 per request:

```
NAP audience resolution requires a non-empty host allowlist: pass the exact
hosts this deployment answers on, e.g. ["api.example.com"]
```

That refusal is §13.5.9 applied directly. `Host` is client-supplied, so an
unrestricted resolver lets the caller choose the security parameter their own
proof is validated against — the "unexpected value of origin" WebAuthn forbids,
wearing a different name. Every pattern §13.5.9 sanctions is an allowlist, so
NAP's is too.

### Subdomains are opt-in, per entry

WebAuthn L3 §13.5.8 is the reason a wildcard in that allowlist is per-entry
rather than a flag over the whole list: a Relying Party by default SHOULD NOT
accept subdomain origins, because a subdomain serving user content is inside the
credential's trust boundary. So `*.tenant.example.com` is something you write
deliberately for one entry, it matches `a.tenant.example.com` and
`deep.a.tenant.example.com`, and it never matches the apex.

### The same §13.5.8 guidance on injected script

`docs/NAP-v2-RFC.md` §28.5 is blunt that a hostile script on your origin defeats
every key-custody measure NAP has, because your own code must be able to decrypt
the key to use it. That is a ceiling, not a reason to skip the layers
underneath, and the Relying Party guidance in §13.5.8 transfers with no
translation:

- **Ship a Content Security Policy** on any origin that can reach the signer.
- **Minimise third-party script** there. An analytics tag is same-origin code
  with the same access to an unlocked key that your own bundle has.
- **Never serve user-submitted content from a host inside the credential's
  scope.** Keep it on a separate registrable domain.

### Origin substitution — §13.4.1, and NAP's version is worse

WebAuthn L3 §13.4.1 (`remoteClientDataJSON`) names the trust model where a
caller supplies the origin instead of the user agent deriving it from the
execution context:

> Origin substitution: the user agent accepts an origin supplied by the calling
> Remote desktop web client rather than deriving the current execution context.
> Any user agent granting this permission MUST therefore trust the caller to
> accurately and honestly supply the origin to the remote Relying Party.

WebAuthn permits this only as a **per-origin, explicitly configured
degradation**, and requires the user agent to indicate that a proxied operation
is in progress.

Under NIP-07 and NIP-46 this is the **default**, on **every** origin, with **no
user-visible indication**. The page composes the event, so the page writes the
`u` tag; the signer signs the audience the calling page asks for. A hostile page
can ask a victim's signer for a proof addressed to your real server and redeem
it from its own backend. NIP-07 grants are scoped by `(origin, kind)`, not by
audience, so a site the user has already approved for `kind:27235` can mint
login proofs for *every* NAP server with no further prompt.

**There is no server-side fix.** RFC §7.1 records the dead ends so nobody
re-derives them: an `origin` tag (the page writes it), an `Origin` allowlist or
strict CORS on `/auth/complete` (pushes the attacker server-side, where the
header is a string it types), a cookie planted at init and demanded at complete,
DPoP-style binding to a non-extractable WebCrypto key, IP or device
fingerprinting — all four legs run on attacker infrastructure.

The refusal has to come from the signer. A NIP-46 bunker is a separate process
the hostile page does not control, and `nostrconnect://` pairing already carries
the app's identity, so a bunker can pin the paired app's URL and refuse a
`kind:27235` event whose `u` host is outside its policy. That is the WebAuthn
refusal in the only place it can live — per-origin policy plus a prompt the page
cannot forge — and it is bunker configuration, not a protocol change on either
side.

**NIP-46 with an audience-enforcing bunker is the phishing-resistant path.
NIP-07 is the weak one.** Deployments should record which they rely on.

---

## 2. The concept mapping

| WebAuthn | NAP | Note |
| --- | --- | --- |
| RP ID / origin | audience — the absolute URL of `/auth/complete` | Checked exactly; §13.5.9 is the precedent. |
| RP-generated challenge, single use | `POST /auth/init` challenge, single-use, bounded TTL | NAP additionally bounds *outstanding* challenges per npub and per IP. |
| `clientDataJSON` + `authenticatorData`, covered by the assertion signature | NIP-98 `kind:27235` event with `u`, `method`, `payload` tags | `payload` is `sha256(rawBody)`, so the completion body is covered too. |
| Authenticator | signer — NIP-07 extension, NIP-46 bunker, or an in-page key | Substitutable; the server cannot tell which one signed. |
| Credential public key, stored at registration | the `npub` itself | No registration ceremony exists. |
| Registration ceremony | — | A NAP server can authenticate a principal it has never seen. |
| Signature counter | — | **Impossible in principle.** See §3. |
| UP / UV bits in `authenticatorData` | — | **No analogue.** See §3. |
| Attestation | — | Nothing states what kind of signer produced a proof. |
| Per-RP, non-portable credential | one key, every service | The same property that removes clone detection. |
| (out of scope) | session model, ACL, step-up, refresh rotation | WebAuthn stops at the assertion; NAP §14–§15 keep going. |

---

## 3. Where NAP is structurally weaker

These are not caveats. If any one of them is load-bearing for you, NAP is the
wrong choice and no amount of careful integration changes that.

### No clone detection, permanently

WebAuthn authenticators keep a per-credential **signature counter**. The Relying
Party compares it against the stored value on every ceremony, and a counter that
fails to increase is evidence the authenticator may have been cloned. It is
probabilistic, and it is more than nothing.

A Nostr key is *designed* to be copied between devices. That is normal use, not
compromise. There is therefore no observable difference between the user's key
and a stolen copy of it, ever — not at login, not at step-up, not at any point
afterwards. NAP cannot acquire this signal, because acquiring it would mean
giving up the portability that is the reason to use a Nostr key at all.

What you get instead: session-level controls. Short access-token lifetimes,
refresh rotation with reuse detection, and an ACL you can revoke against — all
of which detect *misuse of a session*, none of which detect *possession of the
key*.

### No multi-credential recovery

WebAuthn Relying Parties are advised to have users register several credentials
across several authenticators, precisely because the private key never leaves
its authenticator and is unrecoverable once that authenticator is lost.

NAP has no enrollment ceremony to hang that on. The npub *is* the account, so
there is no NAP-level notion of "this principal's other credential", no backup
authenticator, and no protocol-level path from a lost key back to an account. A
user who loses their key loses the account, and anything better than that is
something your application invents on its own — a second npub you accept for the
same account, a recovery contact, an out-of-band process. NAP will not help you
build it and does not specify it.

### No signed user-presence or user-verification bit

WebAuthn signs **UP** (user presence) and **UV** (user verification) as bits
inside `authenticatorData`, covered by the assertion signature, and requires the
Relying Party to check them.

A `kind:27235` event carries no evidence a human was involved. A NIP-46 bunker
with pre-granted permissions signs without prompting anyone; an extension can be
configured to auto-approve. There is no equivalent bit and NAP cannot acquire
one at this layer.

The consequence lands hardest on **step-up**. RFC §10.3 is explicit: a step-up
proves *key control at this moment*, not that a human approved anything. A
signer holding a remembered grant completes the entire ceremony — new challenge,
new signature, new `step_up_token` — with nobody present. Step-up therefore caps
what a **stolen access token** can reach, and does nothing at all against a
**hostile page that already has signer access**, which simply re-runs the
ceremony. Do not build a UI that tells the user they authorised an operation
because step-up succeeded.

And do not try to close the gap with a tag: RFC §10.3 forbids adding a
presence bit to the completion event, because the page composes the event, so
the page writes the tag, and the server cannot distinguish a signer-asserted bit
from a page-asserted one. A presence bit is worth something only if the signer
sets it and refuses to lie, which is a change to NIP-98, not to NAP.

---

## 4. Where they are not competing

Several of the differences above are the same property read in two directions,
and it is worth being clear which trade you are making.

- **Portability against clone detection.** WebAuthn's credential is per-RP and
  non-extractable, which buys clone detection and costs cross-service identity.
  NAP's key is one identity across every service that speaks Nostr, which buys
  portability and costs clone detection. You cannot have both, and neither
  protocol is confused about which it chose.
- **Registration.** WebAuthn requires an enrollment ceremony before anyone can
  log in. NAP has none: a server can authenticate a principal it has never seen
  and provision it on first sight. That is a genuine operational simplification
  and it is also why there is no multi-credential story.
- **Scope.** WebAuthn ends at a verified assertion; what happens next is yours.
  NAP specifies the session, its lifetime, refresh rotation, the ACL layer and
  step-up. If you adopt WebAuthn you will build most of NAP's §14–§15 yourself.
- **They compose.** Nothing stops a service from offering WebAuthn to accounts
  that want a phishing-resistant, RP-scoped credential and NAP to accounts that
  want to bring an identity they already own. They authenticate different
  things.

---

## 5. Choosing

- **Phishing resistance is the requirement, and you control enrollment** →
  WebAuthn. NAP's origin-substitution exposure is real, has no server-side fix,
  and its mitigation depends on which signer your users happen to have.
- **A portable, user-owned identity across services is the requirement** → NAP,
  and push users onto an audience-enforcing NIP-46 bunker rather than a NIP-07
  extension. Record which of the two your threat model assumes.
- **Key loss must be survivable** → neither protocol solves this for you.
  WebAuthn at least has a shape for it (register more than one authenticator).
  NAP does not; budget for building recovery in your application.
- **Human consent must be provable** → neither, at this layer. WebAuthn's UV bit
  is closer, but consent needs a signer that prompts per request on a device the
  page does not control.

---

## Sources

Everything above is drawn from:

| Claim | Where it is specified |
| --- | --- |
| Audience binding, and what it does not cover | `docs/NAP-v2-RFC.md` §7.1 |
| Step-up proves key control, not consent | `docs/NAP-v2-RFC.md` §10.3 |
| Session model, ACL | `docs/NAP-v2-RFC.md` §14, §15 |
| Injected script is a ceiling | `docs/NAP-v2-RFC.md` §28.5 |
| Audience allowlist rules and the wiring-time throw | `packages/nap-server/src/audience.ts`; `docs/NAP-INTEGRATION-GUIDE.md` §9.4 |
| Origin-substitution dead ends | `docs/NAP-INTEGRATION-GUIDE.md` §9.8 |
| Relying Party guidance on injected script | `docs/NAP-IMPLEMENTATION-BEST-PRACTICES.md` §5.7 |
| Practical wiring of the allowlist | [Tutorial 09 §6](../tutorials/09-before-you-ship.md) |
| What a signature proves, in plain terms | [Tutorial 00](../tutorials/00-nostr-for-nap.md) |

WebAuthn sections cited: **L3 §13.4.1** (origin substitution / `remoteClientDataJSON`),
**L3 §13.5.8** (code injection, subdomain origins), **L3 §13.5.9** (validating
the origin of a credential).
