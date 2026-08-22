# 06 — Step-up for destructive actions

**You build:** a payout-settings endpoint that a valid session is not enough to
reach. It wants a signature made *just now*.

**You need:** tutorial 05 finished, or any working copy of `examples/merchant-app`.

> **On the transcripts.** Every status line and body below is copied from a real
> run. The commands say port 3000; the capture machine had 3000 occupied, so it
> ran on a spare port. That is the only substitution.

---

## 1. One flag in the registry

Back in tutorial 03 the registry declared three permissions. One of them carries a
flag the others do not (`src/registry.ts`):

```ts
{ key: 'merchant:read',  description: 'Read vouchers and merchant profile', stepUp: false },
{ key: 'voucher:create', description: 'Issue a new voucher',                stepUp: false },
{ key: 'stripe:manage',  description: 'Change payout settings',             stepUp: true  },
```

`stepUp: true` is not documentation. `requirePermission` reads the registry, and
when the permission it is guarding is marked, it demands an `X-Step-Up-Token`
header in addition to a valid session — so the route itself says nothing special:

```ts
app.post(
  '/api/payouts',
  requirePermission('stripe:manage', guardOptions),
  express.json({ limit: '1kb' }),
  (_req, res) => res.json({ status: 'payout settings updated' })
);
```

The flag lives with the permission rather than the route, which means the decision
is made once, in the vocabulary, and every route guarding that permission inherits
it. Add a second payouts endpoint and you cannot forget.

**`guardOptions` must include `registry`.** Leave it out and there is no
enforcement — the guard has nothing to read the flag from, so `stripe:manage`
becomes an ordinary permission and the route serves anyone whose role carries it.
This is the one piece of step-up wiring that fails silently rather than loudly.

---

## 2. What it looks like from curl

Bearer mode, and the default role temporarily set to `'owner'` so the principal
actually holds `stripe:manage` (tutorial 03 §7 does the same thing in reverse):

```bash
curl -s -X POST localhost:3000/api/payouts \
  -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' -d '{}'
```

```
HTTP/1.1 403 Forbidden
{"status":"error","message":"step-up required"}
```

Note that this 403 *does* say why, unlike every 401 in NAP. It is not an
authentication failure: the caller is authenticated, and telling them what is
missing is the only way they can supply it.

Now log in again with `step_up: true` in the completion body — the same
`complete.ts` from tutorial 01, with one option added:

```ts
const completion = await buildAuthCompleteRequest({
  challenge: init,
  signer: createPrivateKeySigner(PRIVATE_KEY_HEX),
  stepUp: true,
});
```

```json
{
  "status": "ok",
  "access_token": "thwH3wDdIMNsTEkxqCtnB1ESrThZgh-xMlTtI_3YPP4",
  "token_type": "Bearer",
  "expires_at": 1787409752,
  "step_up_token": "9FmrHAGtaVmPnBEThDzGM7IQa2iUJ-iFVbgonAFlW_I",
  "step_up_expires_at": 1787409452,
  "principal": { "npub": "npub1fu64hh9…", "pubkey": "4f355bdc…" },
  "roles": ["owner"],
  "permissions": ["merchant:read", "stripe:manage", "voucher:create"]
}
```

Two expiries, and the step-up one is **earlier**: 600 seconds against the session's
900 (`stepUpTtlSeconds`, default 600). The elevation is meant to outlive the action
that needed it and not much else.

Send both:

```bash
curl -s -X POST localhost:3000/api/payouts \
  -H "authorization: Bearer $STEPPED_TOKEN" \
  -H "x-step-up-token: $STEP_UP_TOKEN" \
  -H 'content-type: application/json' -d '{}'
```

```
HTTP/1.1 200 OK
{"status":"payout settings updated"}
```

---

## 3. A step-up mints a new session

This is the part that bites, and it is not obvious from the API.

`stepUp: true` does not add a token to the session you already have. It runs the
whole init/complete exchange again, which creates a **second session** — new
session id, new access token, new cookie. The first one is untouched and still
works. The audit log shows two completions with two different `session_id`s.

The guard checks the step-up token against the session named by *the request's own
credential*. So pairing a fresh step-up token with the access token you were
already holding proves nothing:

```bash
curl -si -X POST localhost:3000/api/payouts \
  -H "authorization: Bearer $ORIGINAL_TOKEN" \
  -H "x-step-up-token: $STEP_UP_TOKEN" -d '{}' | head -1
```

```
HTTP/1.1 403 Forbidden
```

```bash
curl -si localhost:3000/api/vouchers -H "authorization: Bearer $ORIGINAL_TOKEN" | head -1
```

```
HTTP/1.1 200 OK
```

**A bearer client must adopt both halves of the step-up response** — the new access
token *and* the step-up token — or it will hold a valid elevation it can never
spend. A cookie client gets this for free: the step-up response carries a
`Set-Cookie` for the new session, so the browser swaps credentials without being
asked, which is why the retry in the next section simply works.

---

## 4. Let the 403 ask for it

`session.stepUp()` in `nap-client-web` returns the token and, in cookie mode,
leaves the browser holding the new session. `examples/merchant-app/src/web/Payouts.tsx`:

```tsx
async function save() {
  // Try without a step-up first, deliberately.
  let res = await post();

  if (res.status === 403) {
    // Only a step-up refusal is retryable. A plain 403 means the role does not
    // carry the permission, and no number of signatures fixes that.
    const body = (await res.json().catch(() => ({}))) as { message?: string };
    if (body.message !== 'step-up required') {
      setStatus('You are not allowed to change payout settings.');
      return;
    }

    res = await post(await session.stepUp());
  }

  setStatus(res.ok ? 'Payout settings updated.' : 'Could not update payout settings.');
}
```

Two things worth copying.

**Attempt first, elevate on refusal.** A client that decides for itself when a
step-up is needed has hard-coded a copy of the registry, and it will keep prompting
after the server has stopped asking — or worse, stop prompting before the server
has. The 403 is the server telling you, in the only place that actually knows.

**Distinguish the two 403s.** `"step-up required"` is retryable; a bare permission
denial is not. Retrying that one prompts the user for a signature that cannot
change the outcome.

**Declining is an ordinary outcome.** A user who dismisses the extension popup
makes `stepUp()` reject. That is them saying no, not a failure to report as one.

---

## 5. What a step-up actually proves

**Present key control. That is the whole claim.**

It says: whoever is at the other end of this session could produce a signature from
the principal's key, seconds ago. That is genuinely worth something — a stolen
access token cannot reach `stripe:manage`, because the thief has the token and not
the key.

It does **not** say a human approved this action. A NIP-46 bunker with the
permission pre-granted answers a step-up without asking anybody; so does an
in-page key that is already unlocked. Neither one showed a prompt.

So if you build a confirmation dialog on top of step-up — "you are about to move
€4,000, sign to confirm" — you have built something that can complete with nobody
present. Consent is a UI problem, and it stays a UI problem. Step-up is the
credential check underneath it.

The RFC is explicit about this and the integration guide repeats it; it is repeated
a third time here because it is the mistake the feature invites.

---

## 6. Why the flag is in the body

`{"step_up": true}` goes in the request body, not in `?step_up=true`. Three reasons,
all of which a well-meaning refactor would break.

1. **The body is signed.** The NIP-98 `payload` tag is `sha256(rawBody)`, so the
   flag is covered by the proof. It cannot be added in transit to mint an elevated
   token the user never asked for, nor stripped to silently downgrade a step-up to
   an ordinary login.
2. **It keeps the signed `u` tag query-free.** `docs/NAP-v2-RFC.md:294` requires query parameters
   to match if present, and the URL the client signs must equal the audience the
   server computes. The old query-string form did not reliably satisfy that.
3. **Anything in a URL leaks.** Query strings land in proxy logs, browser history,
   and `Referer` headers. The flag itself is not a secret, but the habit is.

---

## 7. Guard denials are not audited

Something you will notice the first time you try to debug this. The full sequence
above — one plain 403, one step-up completion, one success, one cross-paired 403 —
produced exactly two audit records, both `NAP_COMPLETE_SUCCESS`.

`NapExpressGuardOptions` has no `auditLogger` field. Every `requirePermission`,
`requireRole`, and `requireSession` denial is invisible: no code, no principal, no
record that anything was refused. The `AuditLogger` you wired on day one covers the
`/auth/*` endpoints and stops there.

Until that changes, log guard denials yourself — an error-handling middleware that
sees a 401 or 403 from a guarded route, with the path and (where you have one) the
principal. Filed as its own issue; the tutorials do not change library code.

---

## 8. Try it

1. In `src/registry.ts`, temporarily set `defaultRole: 'owner'` so your key holds
   `stripe:manage`, and restart the API.
2. Sign in through the browser and press **Update payout settings**. You get one
   extension prompt, then "Payout settings updated." — the first attempt 403'd and
   the retry carried the token, without you seeing either.
3. Press it again straight away. **No second prompt** — the step-up token is good
   for ten minutes and the component is holding a session that carries it. This is
   the strongest demonstration that step-up is not consent: nobody approved the
   second payout.
4. Now delete `registry` from `guardOptions` in `src/app.ts` and restart. The
   button works with no prompt at all, and nothing anywhere says why.

---

## Where this leaves you

Every server-side feature in NAP is now wired. The remaining tutorials are about
the other side of the seam: signers that are not a browser extension.

**Next:** [07 — Remote signers with NIP-46](./07-nip46.md) — a key that lives on a
phone, and the pairing dance that reaches it.
