# 05 — Refresh tokens

**You build:** a session that outlives its access token, so your users stop being asked
for a signature every fifteen minutes — and a client that does the refreshing, because
nothing in NAP does it for you.

**You need:** tutorial 04 finished, or any working copy of `examples/merchant-app`.

> **On the transcripts.** Every response body, status line, and audit record below is
> copied from a real run of this example. The commands say port 3000, which is what the
> rest of the series uses; the capture machine had 3000 occupied, so it ran on a spare
> port. That number in the boot line is the only thing rewritten.

---

## 1. Fifteen minutes

A NAP session lasts `sessionTtlSeconds`, which defaults to **900**. Nothing extends it.
When it ends, the only way back is `login()` — a fresh NIP-98 event, which means a fresh
signature, which means your NIP-07 user sees an extension popup. Four times an hour.
Your NIP-46 user's phone buzzes four times an hour.

That is not a bug and the number is not timid. An access token is a bearer credential:
whoever holds it is you, until it expires. Fifteen minutes is how long a stolen one is
worth stealing.

Watch it happen. The example lets you shorten the TTL so you do not have to sit through
the real one — `NAP_SESSION_TTL` exists for this tutorial and for nothing else:

```bash
NAP_MODE=bearer NAP_SESSION_TTL=60 NAP_REFRESH_TTL=0 npm start --workspace @imani/nap-example-merchant-app
```

```
merchant-app listening on http://localhost:3000 (bearer mode, in-memory stores, session 60s, refresh off)
```

Log in with the `complete.ts` script from [tutorial 01](./01-a-server-you-can-curl.md#3-sign-the-completion),
keep the token, and spend it twice a minute apart:

```bash
TOKEN=...   # access_token from the completion response

curl -si localhost:3000/api/vouchers -H "authorization: Bearer $TOKEN" | head -1
sleep 65
curl -si localhost:3000/api/vouchers -H "authorization: Bearer $TOKEN" | head -1
```

```
HTTP/1.1 200 OK
HTTP/1.1 401 Unauthorized
```

Multiply the 65 by fifteen and that is your production default.

---

## 2. One setting turns it on

`refreshTtlSeconds` on `NapServerOptions`. Any positive value does three things: it
registers `POST /auth/refresh` on the router, it makes every login response carry a
`refresh_token`, and it starts rotating them.

In this example it comes from an environment variable so you can turn it off again
(`src/server.ts`):

```ts
const refreshTtlSeconds = Number(process.env.NAP_REFRESH_TTL ?? 7 * 24 * 60 * 60);

const { app } = createMerchantApp({
  // ...
  server: {
    sessionTtlSeconds,
    ...(refreshTtlSeconds > 0 ? { refreshTtlSeconds } : {}),
  },
});
```

Two TTLs now, doing different jobs. `sessionTtlSeconds` bounds how long a **stolen access
token** is useful — leave it short. `refreshTtlSeconds` bounds how long a user can stay
signed in **without signing anything** — that is the product decision. A week is a
reasonable place to start.

The endpoint only exists when the setting does. The adapter also refuses to start if the
`SessionStore` cannot honour it — `getByRefreshToken` and `rotateRefreshToken` are optional
methods on the interface, and a store missing them would mint tokens that every refresh
then rejects. Both bundled stores implement them.

Restart with refresh on:

```bash
NAP_MODE=bearer NAP_SESSION_TTL=60 NAP_REFRESH_TTL=3600 npm start --workspace @imani/nap-example-merchant-app
```

```
merchant-app listening on http://localhost:3000 (bearer mode, in-memory stores, session 60s, refresh 3600s)
```

The completion response has grown two fields:

```json
{
  "status": "ok",
  "access_token": "TwBGRDrrza2nnC0wyUEQAipxtB5PlcrSY0g9qZ5QmP8",
  "token_type": "Bearer",
  "expires_at": 1787408259,
  "refresh_token": "VHNBZ2AxcF0CDoVVo3alp_lB6vv4DCZzC6Yve_inPaM",
  "refresh_expires_at": 1787411799,
  "principal": {
    "npub": "npub1fu64hh9hes90w2808n8tjc2ajp5yhddjef0ctx4s7zmsgp6cwx4qgy4eg9",
    "pubkey": "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa"
  },
  "roles": ["merchant"],
  "permissions": ["merchant:read", "voucher:create"]
}
```

Wait out the minute, then spend the refresh token:

```bash
curl -si localhost:3000/api/vouchers -H "authorization: Bearer $TOKEN" | head -1
curl -s -X POST localhost:3000/auth/refresh -H "authorization: Bearer $REFRESH"
```

```
HTTP/1.1 401 Unauthorized
{"status":"ok","access_token":"D4974YgSI_Cr2O7OMNa8VdTQyjr1LLvJYP5as_PkoFs","token_type":"Bearer","expires_at":1787408324,"refresh_token":"MpYrYah9ODscceM9ITKE4Rb1QOQQROASN_pTa0qq4wU","refresh_expires_at":1787411864, ... }
```

A new access token, good for another sixty seconds, and **no signature was involved**.
That is the whole feature.

Three details in that response worth naming:

- **The refresh token is in the `Authorization` header, not a cookie.** A cookie rides
  along on every request to the origin. A week-long credential should travel on exactly
  the one request that spends it.
- **The refresh token changed.** Rotation, covered next.
- **`refresh_expires_at` moved forward too** — 1787411799 to 1787411864, the sixty-five
  seconds that elapsed. Section 5.

---

## 3. Rotation, and what a replay means

Every refresh retires the token you presented and issues a new one. The retired token is
not forgotten, though; the server keeps recognising it. Present it a second time:

```bash
curl -si -X POST localhost:3000/auth/refresh -H "authorization: Bearer $REFRESH" | head -1
```

```
HTTP/1.1 401 Unauthorized
```

Now check the session that was working a second ago:

```bash
curl -si localhost:3000/api/vouchers -H "authorization: Bearer $NEW_TOKEN" | head -1
curl -si -X POST localhost:3000/auth/refresh -H "authorization: Bearer $NEW_REFRESH" | head -1
```

```
HTTP/1.1 401 Unauthorized
HTTP/1.1 401 Unauthorized
```

The whole session is gone. That is deliberate and it is the point of rotating.

A refresh token that gets used twice means two parties hold it. The server cannot tell
which request came from the thief — the legitimate client and the attacker present the
same string. So it assumes the worse case and revokes the session, and both of them have
to sign in again. A theft costs the user one login; not revoking would cost them a
permanently renewing session in someone else's hands.

The audit log is where you see this. Wire an `AuditLogger` before you turn refresh on:

```
{"code":"NAP_REFRESH_SUCCESS","pubkey":"4f355bdc…","outcome":"success","details":{"session_id":"wzotau4TIP-DP1cLAoO49h_2ZXydh-oG"}}
{"code":"NAP_REFRESH_REUSED","pubkey":"4f355bdc…","outcome":"failure","details":{"session_id":"wzotau4TIP-DP1cLAoO49h_2ZXydh-oG"}}
{"code":"NAP_REFRESH_REVOKED","outcome":"failure","details":{"session_id":"wzotau4TIP-DP1cLAoO49h_2ZXydh-oG"}}
```

`NAP_REFRESH_REUSED` is the one to alert on. Unlike most failure codes it carries the
`pubkey`, because it says a credential leaked and whoever reads the alert needs to know
whose. On the wire it is the same 401 as everything else.

**The consequence for your client: never retry a refresh.** If a refresh fails in a way
that leaves the outcome unknown — a timeout, a dropped response, a 502 from your proxy —
the server may already have rotated. The token you are holding is then retired, and
retrying with it is indistinguishable from the theft above. You will revoke your own
user's session. One attempt; on anything other than a clean 200, stop and re-check the
session.

---

## 4. No client does this for you

Here is the honest part.

`nap-client-web` does not store the refresh token. `nap-react` does not call
`/auth/refresh`. Neither package contains the string `refresh` at all. The server side is
complete and the browser side is yours to write.

`session.login()` returns the raw completion body, so the token is reachable:

```ts
const auth = await session.login();
auth.refresh_token; // the only place it ever appears
```

`GET /auth/session` does **not** return one, so a `resume()` cannot get you one. That
matters after a reload; section 6.

### The cookie-mode wrinkle

In cookie mode the default success writer replies `{"status":"ok"}` and puts the access
token in an `HttpOnly` cookie. That body has nowhere to put a refresh token, and
`/auth/refresh` reads `Authorization: Bearer`, which a cookie-only client cannot produce.
So the adapter refuses to start:

```
NAP refreshTtlSeconds cannot be combined with the default writeNapCookieSuccess body:
it replies {status:"ok"}, so the client never receives the refresh token that
/auth/refresh requires. Pass a transformBody that returns refresh_token, or leave
refreshTtlSeconds unset.
```

The third argument to `writeNapCookieSuccess` is that `transformBody`. This example
returns everything except the two fields the cookie now carries (`src/app.ts`):

```ts
writeSuccess: writeNapCookieSuccess(
  COOKIE_NAME,
  { httpOnly: true, sameSite: 'lax', secure: options.secureCookies ?? false, path: '/' },
  ({ access_token, token_type, ...rest }) => rest
),
```

Read that trade before you copy it. The access token stays out of script's reach; the
refresh token, by necessity, does not. An XSS on your page can read a week-long
credential. That is the cost of not prompting for a signature every fifteen minutes, and
it is why `refreshTtlSeconds` is off by default rather than merely defaulted low.

You also **need** a `transformBody` for a browser client whether or not you use refresh —
`nap-client-web`'s `login()` maps the completion body into its session state and reads
`principal.pubkey`, so against the bare `{"status":"ok"}` it throws a `TypeError` before
you ever have a session. See `CONTEXT.md` finding 11.

### The loop

`examples/merchant-app/src/web/refreshLoop.ts`, in full — this is all of it:

```ts
export function createRefreshLoop({ baseUrl, onLost, leadSeconds = 60 }: RefreshLoopOptions): RefreshLoop {
  // Memory only, and deliberately. localStorage makes a week-long credential
  // readable by any script that gets into the page, and outlives the tab.
  let refreshToken: string | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;

  const arm = (auth: AuthSuccessResponse) => {
    clearTimeout(timer);
    refreshToken = auth.refresh_token;

    if (!refreshToken) {
      return; // Server has no refreshTtlSeconds. The session just ends at expires_at.
    }

    const fireAt = (auth.expires_at - leadSeconds) * 1000;
    timer = setTimeout(refresh, Math.max(0, fireAt - Date.now()));
  };

  const refresh = async () => {
    // Read before the await: the rotation retires this token the moment the
    // server sees it, so it must not still be reachable if anything re-enters.
    const spending = refreshToken;
    refreshToken = undefined;

    let response: Response;

    try {
      response = await fetch(`${baseUrl}/auth/refresh`, {
        method: 'POST',
        headers: { authorization: `Bearer ${spending}` },
        // The rotation mints a new access token, which in cookie mode arrives
        // as a Set-Cookie the response must be allowed to write.
        credentials: 'include',
      });
    } catch {
      onLost();
      return;
    }

    if (!response.ok) {
      onLost();
      return;
    }

    arm((await response.json()) as AuthSuccessResponse);
  };

  return { arm, disarm() { clearTimeout(timer); refreshToken = undefined; } };
}
```

Wiring it, in `App.tsx`:

```tsx
const refresh = useMemo(
  () =>
    createRefreshLoop({
      baseUrl: window.location.origin,
      onLost: () => void session.resume().catch(() => undefined),
    }),
  [session]
);

// Sign in
run(async () => refresh.arm(await session.login()));

// Sign out
run(async () => {
  refresh.disarm();
  await session.logout();
});
```

Four decisions in there worth stating outright:

1. **The refresh response sets a new cookie.** Rotation replaces the access token too, so
   the cookie the browser was holding is dead the moment the refresh succeeds. Without
   `credentials: 'include'` the browser neither sends nor stores it, and your client has
   logged itself out at the exact moment it tried to stay in.
2. **`onLost` calls `resume()`, not `logout()`.** The loop cannot tell a dead session from
   a dead network; only the server can. A `resume()` asks — a 401 fires `onSessionExpired`
   and the app re-renders signed out, while a session that turns out to be fine simply
   stays.
3. **The timer is scheduled from `expires_at`, not from a fixed interval.** The server owns
   the lifetime; a hardcoded 14-minute timer silently breaks the day someone changes
   `sessionTtlSeconds`.
4. **`setTimeout` in a backgrounded tab is throttled and may fire late.** If it fires past
   expiry the refresh still works — the refresh TTL is much longer — so lateness costs
   nothing here. A tab that was *asleep* for longer than the refresh TTL is genuinely
   logged out. Refreshing on `visibilitychange` as well as on the timer is a cheap
   improvement this example leaves out.

---

## 5. Nothing caps the total lifetime

Every rotation slides `refresh_expires_at` forward from *now*, so an unbroken chain of
refreshes extends the session indefinitely. You saw it in section 2: the window moved
forward by exactly the time that had passed. A tab left open for a year, refreshing every
fourteen minutes, is still signed in a year later on one signature.

The RFC specifies no absolute cap and this implementation adds none. (`nap-java` does cap
it, which is worth knowing if you run both.)

What *is* bounded is authority, not duration: the ACL is re-read on every refresh. Suspend
a principal and the next refresh returns 401 and revokes the session, rather than waiting
out the access token. A stale session cannot do more than its current grants allow — it
just does not, on its own, end.

If you need a hard cap, it goes in your own `rotateRefreshToken`: keep the session's
original `issued_at`, and refuse the rotation once `now - issued_at` exceeds your maximum.
That is the seam, and it is the reason `SessionStore` is an interface.

---

## 6. A reload still costs a signature

The refresh token lives in a JavaScript variable. Reload the page and it is gone.

The session itself survives — the access token is an `HttpOnly` cookie, and `resume()`
picks it up without touching the signer, which is exactly what tutorial 02 relies on. But
`GET /auth/session` returns no refresh token, so the loop cannot be re-armed. What you get
after a reload is the un-refreshed behaviour: a session that ends at `expires_at`, and a
signature prompt to get the next one.

The obvious fix is to persist the refresh token, and it is a genuine trade rather than an
oversight:

| | Memory | `localStorage` / `sessionStorage` |
| --- | --- | --- |
| Survives reload | No | Yes |
| Readable by injected script | While the tab lives | Whenever the script runs |
| Survives tab close | No | `localStorage` yes, `sessionStorage` no |

This example chooses memory, because a week-long credential sitting in `localStorage` is a
larger prize than one signature prompt after a reload is a cost. If you choose otherwise,
`sessionStorage` at least dies with the tab.

There is no third option that gets both — the server has nowhere else to put a credential
that must arrive in an `Authorization` header.

---

## 7. Try it

With the app running in cookie mode (`npm start` and `npm run dev:web`, per tutorial 02):

1. Start the API with a short session: `NAP_SESSION_TTL=120 NAP_REFRESH_TTL=3600 npm start`.
2. Sign in through the browser, open the network tab, and leave it.
3. At the sixty-second mark a `POST /auth/refresh` goes out on its own, with an
   `Authorization: Bearer` header and a `Set-Cookie` on the response. No extension popup.
4. Sign in again with `NAP_REFRESH_TTL=0` and watch the same two minutes pass with no
   refresh, then a 401 from the next voucher request.

---

## Where this leaves you

Your users sign once a week instead of four times an hour, and you own the sixty lines
that make that true. Next: some actions should demand a fresh signature no matter how
recently the user signed in.

**Next:** [06 — Step-up authentication](./06-step-up.md) — proving intent for the
operations where a session is not enough.
