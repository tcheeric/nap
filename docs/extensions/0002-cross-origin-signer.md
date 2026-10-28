# NAP Extension 0002: Cross-Origin Signer

**Status:** Draft, implemented in `@imani/nap-client-web` (`connectCrossOrigin`, `mountCrossOriginSigner`). Not part of the core profile.
**Registered name:** `cross-origin-signer/1` (wire tag `nap-cross-origin-signer/1`).
**Extends:** `docs/NAP-v2-RFC.md` §7.1 (origin substitution), §10.3 (step-up), §28.2 (signer preference). Relates to §22 item 5 (delegated auth), without delegating the key.
**Applies to:** browser clients only. **Servers are unchanged**, so `nap-java` needs no code change and `supported_extensions` is not used (see §9).
**Tracking:** tcheeric/nap#54.

---

## 1. Summary

A web app on one origin (the **relying origin**) gets a NAP session for a user whose key
lives on a **different origin** (the **key origin**). The key never leaves the key origin.

The relying origin opens a page of the key origin (the **signer page**) as a popup and talks
to it with `postMessage`. The signer page learns the caller's origin from the browser
(`MessageEvent.origin`), which the calling page cannot choose. It checks that origin against
a policy, asks the user once, and then signs only events addressed to that origin's own
audiences, for a bounded time.

The relying origin's server sees an ordinary NIP-98 completion proof. Nothing on the wire of
§10 or §11 changes.

### 1.1 Why

Two sister sites (say `wallet.example` and `shop.example`) want one sign-in. Each origin has
its own storage, so without this the second site needs one of:

- NIP-07: most users don't have it, and its grants are scoped by origin and kind but not by
  audience, which is the §7.1 ambient-authority problem;
- a second encrypted copy of the key, with a second passphrase: §28.2 option 3, on one more
  origin;
- a QR round trip through a phone for every sign-in.

### 1.2 What it buys

| Property | NIP-07 | Local key on each origin | This extension |
| --- | --- | --- | --- |
| Key on the relying origin | No | **Yes** | No |
| Second passphrase | No | **Yes** | No |
| Refusal comes from a signer the page doesn't control (§7.1) | No (blind, per-origin grant) | No | **Yes**: browser-reported origin + audience check |
| Works without an extension | No | Yes | Yes |
| Prompt the page cannot forge | Extension chrome | No (page DOM) | Popup on the key origin, its own URL bar |

## 2. Terminology

| Term | Meaning |
| --- | --- |
| **Key origin** | The origin that holds the key, or reaches it (in-page key per §28.3, NIP-07, or NIP-46). |
| **Relying origin** | The origin that wants a session and signatures. It never holds the key. |
| **Signer page** | A page on the key origin, `DEFAULT_SIGNER_PATH = /nap/signer` by default, that runs `mountCrossOriginSigner`. |
| **Policy** | Key-origin configuration: for each relying origin, the kinds it may have signed, the audiences those events may address, and a maximum grant lifetime. |
| **Grant** | `{grantId, pubkey, kinds, audiences, expiresAt}`, held in the signer page's memory. The relying origin holds the `grantId` only. It names the grant but does not unlock it. |

## 3. Messages

Every message is a structured-clone object with `nap: "nap-cross-origin-signer/1"`. Anything
else is ignored. **No message carries the sender's origin**: each side reads
`MessageEvent.origin`. Every post uses an explicit target origin, never `*`.

| `type` | Direction | Fields |
| --- | --- | --- |
| `ready` | signer → relying | none. Sent once on load, to each policy origin in turn. The browser delivers it only to the one that matches the opener. |
| `connect` | relying → signer | `id`, `kinds[]`, `audiences[]`, optional `expectedPubkey` |
| `connected` | signer → relying | `id`, `grant` |
| `sign` | relying → signer | `id`, `grantId`, `template` (`kind`, `created_at`, `content`, `tags`) |
| `signed` | signer → relying | `id`, `event` |
| `error` | signer → relying | optional `id`, `code` |
| `revoked` | signer → relying | `grantId` |
| `disconnect` | relying → signer | `grantId` |

Error codes: `NOT_AVAILABLE`, `POPUP_BLOCKED`, `DECLINED`, `REFUSED`, `GRANT_EXPIRED`,
`REVOKED`, `CHANNEL_CLOSED`, `TIMEOUT`, `SIGNER_ERROR`. `REFUSED` covers every "outside the
policy or grant" case (kind, audience, `u` tag, `created_at`, malformed), so a probe learns
nothing about which rule it broke.

Receivers MUST parse defensively: reject unknown types and fields of the wrong type, bound
sizes, and copy accepted values rather than keep references.

## 4. Flow

```
relying origin (shop.example)             key origin signer page (wallet.example/nap/signer)
 click → window.open(signer page)  ───▶  load; opener present, top-level, not framed
                                   ◀───  ready
 connect {kinds, audiences}        ───▶  origin in policy? request ⊆ policy?
                                         ensureUnlocked()   (unlock UI, on the key origin)
                                         consent remembered? else onConsent()
                                   ◀───  connected {grant}
 POST /auth/init (own server)
 sign {grantId, kind 27235 proof}  ───▶  grant live? same window? kind ∈ grant?
                                         single u tag, origin ∈ grant.audiences?
                                         |created_at − now| ≤ skew?
                                         first completion proof? (else onSign)
                                   ◀───  signed {event}
 verify sig, pubkey, template
 POST /auth/complete               ───▶  (relying origin's server: unchanged core NAP)
```

## 5. Normative rules

### 5.1 Signer page

1. MUST answer only `window.opener`, and only when the browser-reported `event.origin` is a
   policy key. It MUST ignore `event.source` values other than the opener.
2. MUST NOT answer at all when framed (`top !== self`), and MUST NOT show consent or unlock UI
   in a frame. The page SHOULD send `Content-Security-Policy: frame-ancestors 'none'`.
3. MUST NOT send `Cross-Origin-Opener-Policy: same-origin` (or `same-origin-allow-popups`). These
   sever `window.opener` and make the handshake impossible (verified in Chromium,
   `crossOrigin.browser.test.ts`). `unsafe-none` is required for this page. Other pages of the
   key origin may keep a stricter COOP.
4. MUST refuse an empty policy at mount time. Policy origins and audiences MUST be canonical
   bare origins.
5. On `connect`: the requested kinds and audiences MUST be subsets of the policy entry, and the
   key MUST be unlocked on the key origin before consent is asked. Consent is per
   (relying origin, pubkey, scope). A remembered consent holds no secret.
6. If `expectedPubkey` is given and differs from the signer's identity, MUST refuse, even
   after the user consented. Connecting as B when A was asked for is a privilege transfer.
7. On `sign`: the grant MUST exist, belong to this origin and this window, and be unexpired by
   the **signer page's** clock. The template's kind MUST be in the grant. It MUST carry exactly
   one `u` tag, whose origin is in the grant's audiences. `created_at` MUST be within the skew
   (default 300 s), so a live grant cannot pre-sign proofs for later use.
8. **Step-up (§10.3).** The first NAP completion proof (a template with a `challenge` tag) in a
   grant is covered by the connection consent. Every later completion proof MUST go through
   `onSign`, and is refused if `onSign` is not configured. This is what makes step-up through
   this signer a real prompt rather than a silent re-run: the gap §10.3 describes for NIP-07
   and pre-granted NIP-46.
9. The signed event's pubkey MUST equal the grant's. If it does not, the identity behind the
   signer changed, and every grant MUST be revoked.
10. Grants live in memory only. `revokeAll` MUST run on the key origin's lock, logout,
    shutdown and identity change (`mountCrossOriginSigner` listens on the session's
    `BroadcastChannel` for this). Grant lifetime MUST NOT exceed `MAX_GRANT_TTL_SECONDS` (900,
    the default session TTL, §28.4).

### 5.2 Relying origin

1. MUST call `window.open` synchronously inside a user gesture. `connectCrossOrigin` does so
   before its first `await`.
2. MUST accept messages only from the window it opened, with `event.origin` equal to the key
   origin.
3. MUST verify every returned event: the Schnorr signature, `pubkey` equals the grant's, and
   kind, `created_at`, `content` and `tags` equal what was asked. A signer page is another
   origin and is not trusted to return what it was asked for.
4. MUST treat a second `ready` after connection (the signer page reloaded) as revocation.
5. SHOULD `disconnect()` once it no longer needs fresh signatures. After login the NAP session
   cookie carries the session, and the popup can close.

## 6. Security analysis

| Threat | Outcome |
| --- | --- |
| **§7.1 origin substitution**: a hostile page asks for a proof addressed to a real NAP server | Its browser-reported origin isn't in the policy, so it gets no reply at all. An allow-listed origin can only obtain proofs for its own audiences (rule 5.1.7). |
| XSS on an allow-listed relying origin | It can sign within the grant until the TTL: the same reach as script holding that origin's session cookie. It cannot step up silently (5.1.8), cannot reach other audiences, and cannot pre-sign (skew). State this to integrators as §28.5 does. It is not a defence against script on the relying origin. |
| Message forgery by a third window | Ignored: wrong `source` or `origin` on both sides. |
| Clickjacking consent | No answer and no UI when framed. Consent is in a top-level popup with the key origin's URL bar. |
| Signer page returns a different or forged event | The relying side verifies the signature and template (5.2.3). |
| Replay of a signed proof | Unchanged: §11/§12 challenge and time window. |
| Enumeration (§10.1, §19) | Strangers get silence. Every in-policy refusal shares `REFUSED`, and unknown grants share `REVOKED`. |
| Grant outliving the unlocked key | Revoked on lock, logout and identity change, including from other tabs via `BroadcastChannel`. Expiry is enforced by the signer page's clock, not the relying page's. |

**Not addressed** (inherent, as in §7.1): there is still no user-presence bit in the event,
and a user who approves a phishing *allow-listed* origin is not protected. The policy is the
allow-list, and keeping it short is the defence.

## 7. API (`@imani/nap-client-web`)

```ts
// Key origin, on /nap/signer
import { mountCrossOriginSigner, createStorageConsentStore } from '@imani/nap-client-web';

const handle = mountCrossOriginSigner({
  policy: {
    'https://shop.example': { kinds: [27235], audiences: ['https://shop.example'], maxTtlSeconds: 900 },
  },
  signer,                                  // any SessionSigner: in-page key, NIP-07, NIP-46
  ensureUnlocked: () => ui.unlock(),       // throw to refuse
  onConsent: (request) => ui.confirm(request),
  onSign: (request) => request.reason === 'completion' ? ui.confirmStepUp(request) : Promise.resolve(true),
  consentStore: createStorageConsentStore(),
  onGrantsChanged: (grants) => ui.renderConnectedSites(grants),
});
// session.onLock / onLogout → handle.revokeAll('lock' | 'logout')   (also automatic via BroadcastChannel)

// Relying origin, in a click handler
import { connectCrossOrigin, createNapSession } from '@imani/nap-client-web';

const grant = await connectCrossOrigin({
  keyOrigin: 'https://wallet.example',
  kinds: [27235],
  audiences: [location.origin],
  expectedPubkey,                          // optional hint, e.g. from ?pubkey=
});
const session = createNapSession({ baseUrl: location.origin, signer: grant.signer });
await session.login();
grant.disconnect();                        // once fresh signatures aren't needed
```

`grant.signer` is a `SessionSigner` and passes the shared signer conformance suite as a
key-free signer (`isEvictableSigner` is false, `lockRecovery()` is `'unlock'`).

## 8. Deployment notes

- Signer page headers: `Cross-Origin-Opener-Policy: unsafe-none`,
  `Content-Security-Policy: frame-ancestors 'none'`.
- Relying page COOP: `same-origin-allow-popups` or `unsafe-none`. `same-origin` on the relying
  page also severs the popup. All four combinations are checked in Chromium by
  `crossOrigin.browser.test.ts`.
- Keep the policy in code or signed configuration on the key origin. A policy the relying
  origin can influence is no policy.
- Native apps (webviews) usually can't open a cross-origin popup with an opener. Use NIP-46
  there.
- Third-party storage partitioning doesn't matter here: the signer page is a first-party,
  top-level window on the key origin.

## 9. Why the core profile is untouched

The server receives a kind-27235 event that is byte-for-byte what any other signer would
produce. It cannot tell, and does not need to tell, that the signature was made in another
window. So:

- no new endpoint, field or tag. `supported_extensions` (§22.2) describes servers, and there is
  nothing for a server to advertise;
- `nap-java` needs no change. Interop is unaffected;
- a deployment that never uses it carries none of it.

## 10. Not in this version

- **Iframe mode** (silent re-signing without a popup). It would need the Storage Access API in
  partitioned browsers and has a clickjacking surface. It is left out until there is a need.
- **Signed, fetched policy.** Policy is code today.
- **Path/method scoping for NIP-98** beyond the `u` origin.
- **A relay transport for the same policy engine** (the key origin acting as a NIP-46 bunker),
  which would also work across devices.
