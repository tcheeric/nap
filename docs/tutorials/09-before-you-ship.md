# 09 — Before you ship

**You build:** the merchant app with the caps, the audience rule, and the cookie
attributes a deployment actually needs — and a clear-eyed list of what it still
is not.

**You need:** tutorial 08 finished, or any working copy of
`examples/merchant-app`.

**On transcripts.** The captures below were taken against
`examples/merchant-app` running on port **3100** rather than the default 3000,
because 3000 was busy on the machine they were recorded on. Substitute your own
port; nothing else changes.

**This tutorial does not make the example app production-ready.** It closes
Phase 4 of the integration guide's build order (§0.4), which is a real
milestone and not the same claim. §8 at the end says what is still missing.

---

## 1. What Phase 4 actually asks for

The guide's build order gives Phase 4 one row:

> `rateLimiter` wired; outstanding-challenge caps sized; `aclResolver` passed to
> the guards; cookie flags reviewed.
>
> **Done when** `/auth/init` is no longer an uncapped write, and revoking access
> takes effect on the next request.

Two of those four are already done. Tutorial 03 passed `aclResolver` into
`guardOptions`, and tutorial 02 set the cookie attributes when it switched to
cookie mode. The other two are the subject of §2 and §3 — and the reason the
first two were done early is that they are the ones whose absence is *silent*.
A missing rate limiter shows up as a bill. A missing `aclResolver` shows up as a
revoked user who keeps working for the rest of their session and nobody notices
for a week.

Alongside the phases, the guide keeps a shorter list titled **"What you cannot
defer"**: audience correctness (§9.4), raw-body ordering (§5.2), sizing the rate
limiter (§9.5), and cookie attributes on logout (§6.1). Everything in this
tutorial is on one of those two lists.

---

## 2. Two different caps, both of which answer 429

`/auth/init` is an unauthenticated write. Anyone who can reach it can make the
server mint a challenge and store a row. There are two separate limits on that,
and they stop two different things.

```ts
const napServerOptions: NapServerOptions = {
  // …
  rateLimiter: createInMemoryRateLimiter({ windowSeconds: 60, maxPerWindow: 30 }),
  maxOutstandingChallengesPerNpub: 10,
  maxOutstandingChallengesPerIp: 30,
  ...options.server,
};
```

Every one of those is already the default. They are spelled out in
`examples/merchant-app/src/app.ts` anyway, because the numbers are the thing you
are supposed to size, and a default you never read is a number nobody chose.

**The rate limiter caps arrival.** Thirty requests a minute per identifier,
fixed window. It counts `npub`, `pubkey`, and `clientIp` separately and all
three must pass, so one principal cycling addresses is still capped and one
address cycling principals is too. The `npub` dimension is deliberately scoped
to the address it arrived from: an npub is public and `/auth/init` is
unauthenticated, so a globally counted npub budget would be a lockout primitive
— anyone could spend a stranger's budget and keep them from logging in.

**The outstanding caps limit how many challenges are alive at once.** A
challenge row lives for its full TTL, so a slow drip *under* the rate limit
still accumulates. Ten per npub, thirty per IP. Both need
`ChallengeStore.countOutstanding`, which `InMemoryChallengeStore` and
`PostgresChallengeStore` both implement — a store that cannot count silently
does not cap, with no error anywhere.

Watch both, in that order. Start the app and fire thirty-two inits:

```console
$ for i in $(seq 1 32); do
    curl -s -o /dev/null -w '%{http_code} ' -X POST http://localhost:3100/auth/init \
      -H 'content-type: application/json' -d "{\"npub\":\"$NPUB\"}"
  done
200 200 200 200 200 200 200 200 200 200 429 429 429 429 429 429 429 429 429 429
429 429 429 429 429 429 429 429 429 429 429 429
```

The wall arrives at eleven, not thirty-one. That is the outstanding cap, not the
rate limiter: ten challenges are alive and the eleventh has nowhere to go. On
the wire the two are indistinguishable. In the audit log they are not:

```json
{"code":"NAP_INIT_RATE_LIMITED","outcome":"rate_limited","details":{"npub":"npub1fu6…","cap":"npub"}}
{"code":"NAP_INIT_RATE_LIMITED","outcome":"rate_limited","details":{"npub":"npub1fu6…"}}
```

`"cap":"npub"` is the outstanding cap. The line without a `cap` field is the
rate limiter, which the same run reaches once thirty requests have arrived
inside the window. Nineteen of the refusals above were the outstanding cap and
three were the rate limiter, and without the `AuditLogger` from tutorial 01
there would be no way to know which number to change.

The 429 itself is the one auth response NAP does not disguise:

```console
$ curl -s -i -X POST http://localhost:3100/auth/init -H 'content-type: application/json' -d "{\"npub\":\"$NPUB\"}"
HTTP/1.1 429 Too Many Requests
Retry-After: 51
Content-Type: application/json; charset=utf-8

{"status":"error","message":"rate limited"}
```

Every other failure is an identical, padded 401 — the timing floor from
`minAuthResponseMillis` runs on all of them so an attacker cannot distinguish
"no such npub" from "bad signature" by clock. A 429's status code already says
it was throttled, so withholding `Retry-After` would hide nothing and would make
every client back off by guessing.

### The honest limit

`createInMemoryRateLimiter` counts **in one process**. Behind N instances the
effective rate is N × what you configured, and a restart forgets every counter.
It is a floor, not a control. Anything production-facing wants a shared backend
— Redis, your API gateway, whatever you already run — behind the same
`RateLimiter` interface, which is one `check(key)` method. The outstanding caps
do not have this problem: they count rows in the challenge store, which is
already shared once tutorial 04's Postgres is in place.

---

## 3. The body limit, and the one you inherit by accident

```ts
createNapExpressRouter({
  server: napServerOptions,
  getExternalBaseUrl: () => options.baseUrl,
  cookieName: COOKIE_NAME,
  bodyLimit: '1kb',
})
```

Again the adapter's own default, written out. An `/auth/init` body is one npub.
An `/auth/complete` body is one signed event. Nothing legitimate approaches a
kilobyte.

```console
$ curl -s -o /dev/null -w '%{http_code}\n' -X POST http://localhost:3100/auth/init \
    -H 'content-type: application/json' --data-binary @big.json
413
```

The number that matters is not 1 kB — it is that this is *the NAP router's*
limit. `express.json()`'s own default is **100 kB**, which is what you would
inherit on any route you parse yourself. The merchant app's two POST API routes
carry `express.json({ limit: '1kb' })` for exactly that reason.

The 413 comes out of `body-parser` and lands in Express's default error handler,
so it does **not** reach your `AuditLogger` — NAP never saw the request. If you
want oversize bodies in the same log as everything else, add an error handler.

---

## 4. Revocation timing, and where the guards read the ACL

`requirePermission` / `requireRole` / `requireSession` default to the ACL
snapshot taken at login. That is fast and it is wrong for anything you can
revoke: a suspension lands when the session expires, not when you make it.

```ts
const guardOptions = {
  sessionStore,
  cookieName: COOKIE_NAME,
  aclResolver: napServerOptions.aclResolver,
  registry: REGISTRY,
  // …
};
```

Pass **the same resolver** you gave `NapServerOptions`, not a second one built
the same way — a second one is a second cache and a second thing to keep in
step. With it, revoking a role takes effect on the next request. The example
app's integration test pins that behaviour directly — *applies a revocation to a
live session because the guards re-read the ACL*.

This is a per-request read against your ACL store. On Postgres that is one
indexed query per guarded route; if that becomes the hot path, cache it *inside*
your resolver where you control the TTL, rather than turning it off at the
guard where the TTL becomes "the session lifetime".

---

## 5. Cookies, HTTPS, and the proxy in front of you

Tutorial 02 set the attributes. Here is the review Phase 4 asks for.

```ts
writeNapCookieSuccess(COOKIE_NAME, {
  httpOnly: true,
  sameSite: 'lax',
  secure: options.secureCookies ?? false,
  path: '/',
})
```

- **`httpOnly: true`** is the entire reason cookie mode exists. Drop it and the
  session token is readable by script, at which point bearer mode is more honest
  about what you have.
- **`secure`** is `baseUrl.startsWith('https://')` in `server.ts`. It is off for
  the tutorials only because they run on plain-HTTP localhost. In production it
  is on, always, and if your `baseUrl` is `https://` you get it without thinking
  about it — which is the point of deriving it rather than defaulting it.
- **`sameSite: 'lax'`** suits a first-party app. Cross-site needs `'none'`,
  which requires `secure`, and it means you have a CSRF surface to think about
  that `'lax'` was covering for you.
- **`path: '/'`** must match what logout clears. It does here because the
  adapter takes the attributes and the name from one source and hands the same
  ones to the logout handler. Both adapters throw at wiring time rather than let
  a mismatch through — a cookie cleared under the wrong name is a logout the
  browser ignores, and it is invisible until a user complains.

If something else terminates TLS, tell Express:

```ts
if (options.trustProxy !== undefined) {
  app.set('trust proxy', options.trustProxy);
}
```

This decides two things NAP depends on. `req.ip` is the dimension
`maxOutstandingChallengesPerIp` counts on — without `trust proxy` behind a
proxy, every request shares the proxy's address and a per-IP cap becomes a
global cap on all your users at once. And `req.protocol` is what a
request-derived audience resolver reads. Set it to the specific value your
deployment warrants (`1` for one proxy, a subnet, a predicate) rather than
`true`; with nothing actually in front of you, `true` means both values are
whatever a header claims.

---

## 6. Two hosts, one audience

The merchant app pins its audience:

```ts
getExternalBaseUrl: () => options.baseUrl
```

For a deployment that answers on one host, that is the correct answer and the
simplest one. Keep it.

If you genuinely answer on several — `api.example.com` and `api.eu.example.com`
— derive it, from an allowlist:

```ts
createNapExpressRouter({
  server: napServerOptions,
  audienceResolver: createRequestDerivedBaseUrlResolver([
    'https://api.example.com',
    'https://api.eu.example.com',
  ]),
  cookieName: COOKIE_NAME,
})
```

Exactly one of `getExternalBaseUrl` and `audienceResolver` may be passed, and
both go on the **router**, not on `createNapServer`.

**There is no default and no empty-list escape hatch.** The value this returns
is the audience every NIP-98 proof is checked against, and `Host` is a
client-supplied header — an unrestricted resolver lets the caller pick the
security parameter their own proof is validated against. WebAuthn L3 §13.5.9 is
normative about the equivalent decision for origins, and the pattern it
sanctions is an allowlist. So an empty list throws at wiring time rather than
returning a 401 per request:

```
NAP audience resolution requires a non-empty host allowlist: pass the exact
hosts this deployment answers on, e.g. ["api.example.com"]
```

Three things about entries:

- They are **hosts**, not URLs. Include the port if it is not the scheme
  default. A path, query, or userinfo throws.
- `https://api.example.com` **pins the scheme**. Without the prefix the scheme
  comes from `req.protocol`, which under `trust proxy` is whatever
  `X-Forwarded-Proto` says — so a pin is the only way to stop a misconfigured
  proxy from downgrading your audience to `http`.
- `*.example.com` matches subdomains and is **opt-in per entry**, matching
  §13.5.8's "SHOULD NOT accept subdomain origins" default. It matches
  `a.example.com` and not `example.com`.

---

## 7. Two smaller things that cost a whole afternoon each

### Dedupe `nostr-tools`

Four NAP packages depend on it, and so does your app. Two copies in one bundle
means events signed by one and verified by the other, and the symptom is
`verifyEvent` returning `false` on a signature that is fine.

```console
$ npm ls nostr-tools
nap@0.10.1 /home/eric/IdeaProjects/nap
├─┬ @imani/nap-client-http@0.10.1 -> ./packages/nap-client-http
│ └── nostr-tools@2.23.3
├─┬ @imani/nap-client-nip46@0.10.1 -> ./packages/nap-client-nip46
│ └── nostr-tools@2.23.3 deduped
├─┬ @imani/nap-client-web@0.10.1 -> ./packages/nap-client-web
│ └── nostr-tools@2.23.3 deduped
…
```

Every line after the first says `deduped`. If yours does not, `npm dedupe`, or
an `overrides` entry if a transitive dependency is pinning an older one. The
floor is `^2.23.0`, from `BunkerSigner.fromBunker` in tutorial 07.

### Clock skew is a real 401

A NIP-98 event carries a `created_at`, and the server checks it against a
window. The defaults:

| Option | Default | What it allows |
| --- | --- | --- |
| `maxClockSkewSeconds` | 60 | how far the client's clock may be off |
| `lowerBoundGraceSeconds` | 30 | slack on the early edge |
| `upperBoundGraceSeconds` | 5 | slack on the late edge |
| `challengeTtlSeconds` | 60 | challenge lifetime — also the RFC §10.1 ceiling; higher throws |

A phone with a wrong clock fails every login with the same 401 as a forged
signature, and the user's report will be "it doesn't work". The audit code
distinguishes them; nothing else does. Widening the window trades that away
against replay resistance, so before you widen it, check the audit log to
confirm skew is what you are actually seeing.

---

## 8. What this still is not

Phase 4 passes. The example app is still an example. In rough order of how
likely each is to matter to you:

| Gap | Why it is a gap |
| --- | --- |
| The rate limiter is per-process | Fine on one instance; N× your configured rate on N. Needs a shared backend. |
| `nap_challenges` and `nap_sessions` grow forever | `markExpired()` flips a state and never deletes. `deleteExpiredRows()` in `stores.ts` is a starting point, not an ops story: no batching, no lock timeout, no metrics. |
| Auto-provisioning is on | `createRegistryAclResolver` gives any valid signature the default role. Correct for a demo; for a real app the first login should create a *pending* user. |
| The audit log is `console.log` | Structured JSON on stdout is enough to debug and nowhere near enough to alert on. |
| No CSRF story beyond `sameSite: 'lax'` | Adequate first-party. Cross-site cookie mode needs its own answer. |
| Health, readiness, metrics, graceful shutdown | None of it is here. Not NAP's job, but it is between you and production. |

§11 of the integration guide is the other list to read: what the RFC specifies
that this implementation does not yet do, and what it does incompletely. Read it
once before you commit to NAP for something that matters, not after.

---

## Try it

1. Start the app and fire thirty-two `/auth/init` requests with the same npub.
   Note that the wall arrives at eleven.
2. Read the audit lines. Count how many carry `"cap":"npub"` and how many do
   not. Those are your two different limits.
3. Wait sixty seconds and try again. The rate-limiter window has rolled; the
   outstanding challenges have expired. Both walls are gone.
4. Set `maxOutstandingChallengesPerNpub: 2` and repeat. The wall moves to three.
5. Send a 2 kB `/auth/init` body. Confirm the 413, and confirm nothing about it
   reaches your `AuditLogger`.
6. Swap `getExternalBaseUrl` for `createRequestDerivedBaseUrlResolver([])`. The
   app refuses to start. Read the message — that is the shape every wiring check
   in NAP is trying to have.
7. Now give it `['localhost:3100']` and log in. Then give it
   `['https://localhost:3100']` and watch every login fail with an
   indistinguishable 401: the scheme pin says `https`, the client called `http`,
   and the audience no longer matches. Only the audit log's
   `NAP_COMPLETE_URL_MISMATCH` tells you why.
8. Revoke your own role in the ACL store mid-session and make one more request.
   It should be a 403 immediately. Remove `aclResolver` from `guardOptions` and
   watch the same revocation do nothing for the rest of the session.

---

## Where this leaves you

Nine tutorials: a server you can curl, a browser login, roles, Postgres, refresh
tokens, step-up, remote signers, in-page keys, and the caps and cookie rules
that make the whole thing deployable. The example app in `examples/merchant-app`
is every one of those decisions in one place, with the reasoning in the
comments.

From here the integration guide is the reference — §9 for security and
operations, §11 for the gaps, §12 when something returns a 401 you cannot
explain. And the RFC settles anything the guide and the code disagree about.
