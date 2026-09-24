# Ticket-Gated Broadcast

> **Read [003 event ticketing](../003-event-ticketing/spec.md) first.** This document is a
> variant of it, not a replacement. §§1–5, 9 and 10 of 003 apply unchanged and are not restated.

**Status:** Draft, for review. Nothing implemented.

**Relationship to 003:** 003 targets a conferencing engine with a real authorization boundary
(BigBlueButton). This document targets a broadcast platform with none. The ticket, its issuance,
admission, transfer and privacy rules are identical; everything downstream of the session is
different.

**Engine:** zap.stream / `zap-stream-core` (GPL-3.0). RTMP ingest, HLS output, NIP-53 kind 30311
announcements on Nostr, NIP-98 API auth.

Requirement ids in this document use the `B-` prefix and do not collide with 003's.

---

## 1. The finding

`zap-stream-core` has **no viewer-side access control of any kind**. There is no paywall, no
allowlist, no entitlement check, no signed playback URL, and no per-viewer token anywhere in its
API. `content_warning` is descriptive metadata, not enforcement. The only access control the API
implements separates a broadcaster from an admin; it never separates one viewer from another.
Money is present, but exclusively as broadcaster billing — account balance, top-up, withdraw,
per-endpoint `cost`.

Discovery compounds it. The playback URL is published in the `streaming` tag of a NIP-53 kind
30311 event on public relays. Anyone who reads the announcement has the stream.

**B-1.** Therefore: hosted zap.stream **cannot** serve a ticketed event. A stream it ingests is
public by construction, and gating a second copy of a stream that is already free accomplishes
nothing. This document assumes self-hosted `zap-stream-core`, where the operator controls both
`overseer.nsec` (which publishes the 30311) and `overseer.advertise` (which offers the server to
zap.stream's directory).

This inverts the work relative to 003. BBB gave an authorization boundary with a bearer-URL
weakness at the end of it. Here there is no boundary, so §6 of 003 is not adapted — it is
replaced by §§4–5 below.

## 2. Inherited from 003, unchanged

The following apply verbatim. Where this document contradicts them, this document is wrong.

| 003 | Subject |
| --- | --- |
| §4, T-1 … T-8 | The ticket: `P2PK_VOUCHER` secret, tags, `event_id` in `merchant_metadata`, fresh `K` per ticket, `face_value` model |
| §5.1, L-1 … L-2 | Issuance |
| §5.2, L-3 … L-5 | Admission, verification order, **admission MUST NOT spend** |
| §5.4, L-9 … L-11 | Transfer and resale, and the session ceiling |
| §5.5, L-12 | No automatic refund path — still a gap |
| §7, G-1 … G-3, G-6 | `grant()`, event-named permissions, empty grant denies, registry validation |
| §9, P-2 … P-5 | Privacy, with P-5 amended by B-16 |
| §10, F-1 … F-3 | Uniform 401s |

**Amended:** G-4, G-5 (§6 below), A-1 … A-4 (§7), P-1 (moot — §8), and the whole of 003 §6.

## 3. Where zap.stream is the better answer

Recorded so the tradeoff is legible, because §§4–5 are a larger build than 003's.

**B-2.** The 30311 is the poster and NAP is the box office. Publish the announcement publicly —
`title`, `image`, `starts`, `status`, and a purchase link — and withhold only `streaming`. Every
Nostr client shows the event; the ticket gates the media. This is a genuine fit rather than a
workaround, and it gives a ticketed event the discovery surface that ticketing platforms
normally have to buy.

**B-3.** One auth vocabulary. `zap-stream-core` already authenticates its API with NIP-98 kind
27235, the same primitive NAP uses. Broadcaster-side only, so it does not help admission, but it
means one signing model across the stack.

**B-4.** This settles 003 §13.6. HLS from a CDN scales the way a ticketed audience needs; an SFU
does not. Broadcast is the committed answer here.

## 4. Architecture: encrypted HLS, gated key

### 4.1 Integration depth

**B-5 — decision required.** Two depths, neither requiring a fork:

**(a) Forward to your own packager (recommended).** `POST /api/v1/forward` adds an RTMP forward
target. `zap-stream-core` ingests and transcodes; a copy goes to your packager, which does the
encryption and serves the gated HLS. Requires that the operator's own output is **not** published
— `overseer.advertise` off, and the 30311 emitted without a usable `streaming` tag (B-7).

**(b) Announcement only.** Use `zap-stream-core` for nothing but the 30311, and run ingest
yourself. Fewer moving parts and no per-endpoint cost, at the price of rebuilding ingest and
transcode.

Take (a). It keeps ingest, transcode and the ABR ladder as someone else's problem, which is the
only part of this stack that is genuinely hard and genuinely solved.

**B-6.** `zap-stream-core` is GPL-3.0 — stricter than BBB's LGPL, but with no network clause.
Running a modified copy as a service is not distribution. Neither (a) nor (b) requires modifying
it at all.

### 4.2 The announcement

**B-7.** The published kind 30311 MUST NOT carry a playable `streaming` URL. It MAY carry a URL
pointing at the platform's own gateway, which requires a session and redirects or 401s.

**B-8.** The 30311 MUST NOT carry any tag that identifies ticket holders. NIP-53 `p` tags name
participants with roles; for a ticketed broadcast they name the host and speakers only. A `p` tag
per attendee would publish the attendee list to public relays — the exact artefact 003 T-7 exists
to prevent, in the most durable place available.

**B-9.** `status` and `current_participants` MAY be published. `current_participants` is an
aggregate and leaks nothing about who; it is also the only public signal that the event is
selling.

### 4.3 Encryption

**B-10.** Segments MUST be encrypted with HLS's native `#EXT-X-KEY:METHOD=AES-128`. Every player
implements it, so there is no custom player and none of the MSE work in the DRM note's §08.

**B-11.** The `URI` attribute of `#EXT-X-KEY` MUST point at the platform's own origin, at an
endpoint guarded by `requirePermission` for this event's permission.

**B-12.** The manifest itself SHOULD also be gated, but MUST NOT be relied on as the boundary. A
manifest is one request; the segments are many, and a manifest leaked after fetch names every
segment URL. The key is the boundary; the manifest is a speed bump.

### 4.4 The key endpoint

**B-13.** NAP's session id is an HttpOnly cookie, so a same-origin key request carries it with no
header plumbing on the player side. This is the whole reason the design is small.

Two paths need verifying early, because they fail differently:

- **hls.js** — key fetches go through the library's loader. `xhrSetup` sets `withCredentials`
  where the key origin differs from the page; same-origin needs nothing beyond a `SameSite` value
  that permits it.
- **Native HLS (Safari, iOS)** — the key request is issued by the platform media stack, not by
  script, and the cookie behaviour is not under the page's control. **This MUST be tested before
  the design is committed to**, because on iOS there is no fallback to hls.js.

**B-14.** The key endpoint MUST enforce the concurrency rule in §5. It is the only component that
sees every viewer continuously and therefore the only place capacity can be enforced at all.

### 4.5 The ceiling, stated

**B-15.** An AES-128 HLS key passes through the player and is reachable from script or devtools.
Extraction is not prevented, and the platform MUST NOT be described to organisers as if it were.

This is the same Widevine-L3 tier the DRM note establishes, and it is the price of not writing a
custom player: the non-extractable `CryptoKey` path in that note's §07 is not reachable through
standard HLS. Rotation (§4.6) bounds what one extracted key is worth; nothing bounds the
determined case.

### 4.6 Rotation

**B-16.** Keys MUST rotate. A new `#EXT-X-KEY` line mid-playlist rekeys every segment after it,
which is standard packager behaviour and needs no client support.

**B-17.** The rotation period is the primary tuning knob and trades three things against each
other:

| Shorter period | Longer period |
| --- | --- |
| Smaller blast radius per extracted key | Fewer key requests |
| Finer concurrency signal (§5) | Less observation of viewers (§8) |
| More load on the key endpoint | Coarser capacity enforcement |

Start at one rotation per 30–60 seconds of media. It gives a usable concurrency heartbeat without
turning the key endpoint into a per-segment request stream.

## 5. Capacity and concurrency

This section replaces 003 §6 entirely.

**B-18.** There is no `maxParticipants` equivalent. HLS has no participant cap. 003 S-1 — the
single most valuable line in the BBB integration, because capacity was enforced by the engine and
could not drift — **has no analogue here**. Capacity stops being arithmetic and becomes
application logic that can have a bug.

This is the largest single regression against 003 and MUST be stated to organisers in those
terms.

**B-19.** Concurrency MUST be derived from key requests. A viewer playing the stream requests a
key every rotation period; a viewer who has stopped does not. Therefore:

```
concurrent(event) = |{ ticket : ticket requested a key within the last 2 rotation periods }|
```

Two periods, not one, so a single dropped request does not evict a live viewer.

**B-20.** A key request from a ticket beyond `capacity` concurrent tickets MUST be refused. The
refusal MUST be distinguishable from an admission failure, per 003 S-8 — it is not a security
signal, and the holder needs to know their ticket is in use elsewhere.

**B-21.** Concurrency is a *better* seat check than 003's, and this should be recognised rather
than mourned. 003 S-7 checked only at join; a viewer who joined and left held their seat until
the meeting noticed. Key requests are continuous, so a seat is released within two rotation
periods of the viewer actually stopping, with no webhook, no callback endpoint, and no delivery
guarantees.

**B-22.** The concurrency table MUST hold only `(event_id, sha256(voucher_id), last_seen)` and
MUST be discarded when the event ends. See B-27.

## 6. Tiers

**B-23.** 003 G-4 and G-5 do not apply. zap.stream has no viewer-side role, and in particular no
destructive one — there is no `MODERATOR` equivalent, nothing a viewer can end, mute or record.

**B-24.** Tiers, if offered, map to things the packager controls rather than to engine roles:
a bitrate ceiling in the ABR ladder, early access before `starts`, or access to the recording
(§12.3). The mapping MUST still be total per 003 T-4 — an unrecognised `unit` denies.

## 7. Availability

**B-25.** 003 A-1 applies: the mint is an availability dependency of admission, and the event
does not wait.

**B-26.** 003 A-3's constraint on degraded grants largely evaporates, because B-23 leaves no
destructive role to withhold. `onMintUnavailable: 'degrade'` is therefore materially safer here
than in 003, and SHOULD be the default for a live broadcast.

`destructivePermissions` MUST still be configured, because a degraded grant must not carry
whatever tier permission unlocks the recording — that outlives the outage and is exactly the
value-bearing grant extension 0001 §7.3 forbids issuing on unknown liveness.

## 8. Privacy

003 P-2 through P-5 apply. Two changes and one collision.

**B-27 — amends 003 P-5.** The mint learns less here and the platform learns much more. Admission
is still one mint observation per session, but the key endpoint now sees each ticket **every
rotation period for the duration of the event** — a continuous attendance record of exactly the
kind this design exists to avoid, held by the one party best placed to abuse it.

Therefore: the key endpoint MUST NOT log per-request. The concurrency table (B-22) holds
`last_seen` only, overwritten in place, never appended. There MUST be no request log, access log
or metrics series keyed on `sha256(voucher_id)`.

**B-28.** 003 P-1 is moot. HLS viewers supply no name and appear in no participant list. This is
a straightforward privacy improvement over 003.

**B-29 — the collision.** NIP-53 live chat is kind 1311, published to public relays and signed by
the poster's own key. 003 T-6 gives every ticket a burner keypair precisely so attendance is
unlinkable — and the first chat message, signed with the holder's real Nostr identity, publishes
the association to a public relay, permanently, where the platform cannot retract it.

Worse, 1311 is open in both directions: anyone can read the chat and anyone can post to it,
ticket or not.

**B-30.** Therefore the platform MUST NOT present NIP-53 live chat as part of a ticketed event
without stating both properties to holders. If ticket-holders are to have a private chat, it
cannot be built on 1311 as specified, and is out of scope here (§13).

## 9. Interfaces

**Data.** Replaces 003 §11's `Seat`:

```ts
interface BroadcastEvent {
  id: string;
  title: string;
  startsAt: number;
  endsAt: number;
  capacity: number;
  rotationSeconds: number;      // B-17
  naddr: string;                // the published 30311
  degradeOnMintUnavailable: boolean;
}

interface Presence {
  eventId: string;
  userIdHash: string;           // sha256(voucher_id)
  lastSeen: number;             // overwritten in place, never appended (B-27)
}
```

**HTTP.** 003 §11's table, with the join row replaced:

| Method | Path | Guard | Notes |
| --- | --- | --- | --- |
| `GET` | `/events/:id/manifest.m3u8` | `requirePermission` | Gated, but not the boundary (B-12) |
| `GET` | `/events/:id/key/:seq` | `requirePermission` | **The boundary.** Enforces concurrency (B-14, B-19) |

Segments themselves need no guard: they are ciphertext, and per the DRM note they can sit on any
host and be mirrored freely.

No transfer endpoint. No attendee list endpoint. No per-request access log on the key path.

## 10. Acceptance

003 §12 steps 1–2 and 5 apply unchanged — issuance, admission, and the four negative cases.
Steps 3, 4 and 6 are replaced:

3. **Play.** An admitted session fetches the manifest, fetches a key, and decrypts. Verified in
   hls.js **and** in native Safari on iOS (B-13). A failure in the second is a design-level
   failure, not a bug.
4. **Capacity.** With `capacity = 3` and three tickets streaming, a fourth ticket admits
   successfully and is refused at the key endpoint, distinguishably.
5. **Release.** One of the three stops playing. Within two rotation periods the fourth ticket's
   key request succeeds.
6. **Rotation.** A key captured from rotation *n* fails to decrypt a segment from rotation
   *n + 1*.
7. **No leak.** The published 30311 is fetched from a public relay by an unauthenticated client
   and yields no playable URL and no attendee pubkeys.

Step 7 is the equivalent of 003's step 5: it is where the claim either holds or does not, because
everything else assumes the announcement is not itself the leak.

## 11. Open questions

**11.1 Does native HLS carry the cookie?** B-13. If iOS Safari will not send the session cookie
on the key request, the options are a token in the key URI — which puts a credential in the
manifest and is a different design — or no iOS support. This is the highest-risk unknown in the
document and should be tested before anything else is built.

**11.2 What is the recording worth?** 003 §13.5 was a footnote; here it is the main event. The
same key infrastructure gates a recording, but a recording is unbounded in time — an extracted
key is worth a permanent copy rather than 60 seconds. Per-title rotation on the recording, or no
recording at all, are both defensible and the choice is a product decision.

**11.3 Can the ticket gate the chat?** B-29 says not on 1311. A NIP-44 encrypted chat keyed to
ticket holders is possible in principle and is a second protocol design, not a configuration
choice.

**11.4 Is `capacity` meaningful at all for broadcast?** 003 §13.3 asked whether capacity should
be derived from the mint. Here the question is sharper: a broadcast has no physical seat limit,
so capacity is a pricing decision rather than a constraint. If the answer is "sell as many as we
like", B-18's regression stops mattering and §5 simplifies to presence-tracking with no cap.

**11.5 Does forwarding double the bill?** B-5 option (a) has `zap-stream-core` transcoding and
forwarding, and the packager transcoding again if the ladder is rebuilt. Worth measuring before
committing; a passthrough forward that reuses the existing ladder avoids it.

## 12. Out of scope

- Everything in 003 §14.
- **Private live chat.** §11.3.
- **Custom player work.** B-15 accepts the standard-HLS ceiling explicitly. The DRM note's
  non-extractable `CryptoKey` path is available only to a bespoke MSE player and is not attempted
  here.
- **Modifying `zap-stream-core`.** Neither integration depth requires it.
