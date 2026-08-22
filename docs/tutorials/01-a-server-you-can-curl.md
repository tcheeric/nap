# 01 — A NAP server you can `curl`

**You will build:** a running Express server that issues challenges, verifies signed
completions, and refuses a guarded route to anyone without a session. Then you will drive
the whole login by hand from a terminal.

**No browser, no extension, no frontend.** Those arrive in
[tutorial 02](./02-logging-in-from-a-browser.md). The point of doing it this way first is
that everything is visible: you see the challenge, you see the proof, you see the token.
When something breaks later, this is the mental model you debug against.

**Before you start:** [tutorial 00](./00-nostr-for-nap.md), or enough Nostr to know what
an npub is and what NIP-98 signs.

**Time:** about 20 minutes.

---

## 0. Get the code running

The example lives in this repository, at `examples/merchant-app`. It is a real npm
workspace package, so it resolves `@imani/nap-*` straight from `packages/`.

> **Why not `npm install @imani/nap-server`?** Because you can't yet. Every package points
> `exports` at `./src/index.ts` and there is no build step, so nothing here is publishable
> as it stands. You consume NAP from the monorepo, or you vendor it. This is a known
> limitation, not something you are doing wrong — see §11.4 of the integration guide.

```bash
git clone <this repo> && cd nap
npm install
NAP_MODE=bearer npm run dev --workspace @imani/nap-example-merchant-app
```

```
merchant-app listening on http://localhost:3000 (bearer mode)
```

`NAP_MODE=bearer` makes `/auth/complete` return the access token in the response body,
which is what you want when the client is `curl`. From tutorial 02 the server runs in its
default cookie mode instead, and the token stops being visible to anything but the browser.

Leave it running. Open a second terminal for everything below.

## 1. The shape of the server

Four files, and nothing in them is long. Open `examples/merchant-app/src/app.ts` and read
it once before you run anything — it is about 150 lines and it is the whole integration.

Three things in there are load-bearing, and each is a mistake somebody has already made.

### There is no global `express.json()`

Look at where the parser is. It is not at the top of the file:

```ts
const app = express();

app.use('/auth', createNapExpressRouter({ /* … */ }));
```

The NAP router installs **its own** JSON parser, one that keeps the raw request bytes
around. It has to: the NIP-98 `payload` tag is `sha256` of those exact bytes. A global
`express.json()` mounted above this line parses the body and throws the bytes away, the
adapter re-stringifies to compensate, key order and whitespace shift, and **every single
login fails** with `NAP_COMPLETE_PAYLOAD_MISMATCH`.

Routes that are not NAP routes can parse JSON normally. Notice `POST /api/vouchers` mounts
`express.json()` on itself. That is fine — it is downstream of the auth router, not above
it.

### The audience is pinned, and it is a security control

```ts
getExternalBaseUrl: () => options.baseUrl,
```

That value is what every NIP-98 `u` tag is compared against. Get it wrong and every login
fails with a 401 you cannot distinguish from a bad signature.

You may be wondering why it is not derived from the request — the server obviously knows
its own hostname. It knows what the *request said* its hostname is, which is not the same
thing, and a client that picks the audience picks what its own proof is checked against.
NAP does ship a request-derived resolver, and it cannot be constructed without an explicit
host allowlist for exactly this reason. [Tutorial 09](./09-before-you-ship.md) covers when
you need it. For one host, a constant is simpler and strictly safer.

### The audit logger is not optional

```ts
auditLogger: options.auditLogger ?? consoleAuditLogger,
```

**Every authentication failure returns an identical 401**, with the same body every time:

```json
{ "status": "error", "message": "authentication failed" }
```

Wrong signature, expired challenge, mismatched audience, replayed proof — all identical,
deliberately. A 401 that explains itself is an oracle for whoever is probing it. Which
means the audit log is the *only* place the reason exists:

```json
{"at":"2026-08-22T13:32:12.611Z","code":"NAP_COMPLETE_PAYLOAD_MISMATCH","outcome":"failure",
 "details":{"url":"http://localhost:3000/auth/complete"}}
```

Wire it now, before you need it. You will need it within the hour.

## 2. Ask for a challenge

`POST /auth/init` says "I am this npub, give me something to sign." Pick any npub; the
server does not care whether you can sign for it yet.

```bash
curl -s localhost:3000/auth/init \
  -H 'content-type: application/json' \
  -d '{"npub":"npub1fu64hh9hes90w2808n8tjc2ajp5yhddjef0ctx4s7zmsgp6cwx4qgy4eg9"}' | jq
```

```json
{
  "challenge_id": "6GCmUHBeM7K-HDcs",
  "challenge": "TYllLtXNpDLWdDMIG6BXS_EsteX0kImxcI6COqs42P0",
  "auth_url": "http://localhost:3000/auth/complete",
  "auth_method": "POST",
  "issued_at": 1710000000,
  "expires_at": 1710000060
}
```

Three of those matter:

- **`challenge`** is the random value your signature has to commit to. Single use.
- **`auth_url`** is the audience — the exact string that must appear in the `u` tag. The
  server is telling you what it will check against, which is why a client never has to
  guess it.
- **`expires_at`** is 60 seconds out by default, and 60 seconds is also the RFC's ceiling.
  A challenge is meant to be signed now, not stored.

Call it twice and you get two different challenges. Nothing is spent until a completion
succeeds.

## 3. Sign the completion

This is the step a real client's signer does. Doing it in `curl` alone would mean
hand-rolling a Schnorr signature, so use the same helper the tests use —
`@imani/nap-client-http`, which is the headless client and knows nothing about browsers.

Save this as `examples/merchant-app/complete.ts`:

```ts
import { buildAuthCompleteRequest, createPrivateKeySigner } from '@imani/nap-client-http';

// A throwaway key, in a script, for one tutorial. Everything from tutorial 02
// onward uses a signer that never hands the key to the application.
const PRIVATE_KEY_HEX = '1111111111111111111111111111111111111111111111111111111111111111';

const init = await fetch('http://localhost:3000/auth/init', {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({
    npub: 'npub1fu64hh9hes90w2808n8tjc2ajp5yhddjef0ctx4s7zmsgp6cwx4qgy4eg9',
  }),
}).then((r) => r.json());

const completion = await buildAuthCompleteRequest({
  challenge: init,
  signer: createPrivateKeySigner(PRIVATE_KEY_HEX),
});

const response = await fetch(completion.url, {
  method: 'POST',
  headers: {
    authorization: completion.authorization,
    'content-type': 'application/json',
  },
  // The exact bytes the payload tag hashed. Not `JSON.stringify(completion.body)`.
  body: completion.rawBody,
});

console.log(response.status, JSON.stringify(await response.json(), null, 2));
```

```bash
npx tsx examples/merchant-app/complete.ts
```

```
200 {
  "status": "ok",
  "access_token": "F3wQpUnAMKs_g03k7x9ChwfEQdRHj_9yxbYQHzCjMjo",
  "token_type": "Bearer",
  "expires_at": 1710000900,
  "principal": {
    "npub": "npub1fu64hh9hes90w2808n8tjc2ajp5yhddjef0ctx4s7zmsgp6cwx4qgy4eg9",
    "pubkey": "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa"
  },
  "roles": [
    "merchant"
  ],
  "permissions": [
    "merchant:read",
    "voucher:create"
  ]
}
```

The session lasts 900 seconds. That is the default and it is short on purpose — a session
you cannot renew without a signature should not be a day long.

The npub in your `init` call must match the key you sign with, or the completion is
rejected. If you used a different npub above, take the one the script printed.

Look at the server's terminal. The audit log has a line for it.

### What just happened

The server checked, in order: that the challenge exists and is unspent, that the signature
verifies against the pubkey, that the `u` tag equals its own audience, that `method` is
`POST`, that `payload` matches `sha256` of the bytes it received, and that `created_at` is
inside the tolerance window. Any one of those failing produces the same 401.

You did not create a user. The `roles` and `permissions` came from the permission registry
in `src/registry.ts`: no ACL row existed for this pubkey, so it got `defaultRole`, which is
`merchant`. Whatever you put there is what a stranger with a valid signature gets, so
choose it as narrowly as you can live with.

## 4. Spend the session

```bash
TOKEN=nap_at_…   # from the response above

curl -s localhost:3000/api/vouchers -H "authorization: Bearer $TOKEN" | jq
curl -s localhost:3000/api/me       -H "authorization: Bearer $TOKEN" | jq
```

Create one:

```bash
curl -s -X POST localhost:3000/api/vouchers \
  -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{"amount_cents":2500}' | jq
```

```json
{
  "voucher": {
    "id": "vch_1",
    "code": "MERCHANT-0001",
    "amountCents": 2500,
    "issuedBy": "npub1fu64hh9hes90w2808n8tjc2ajp5yhddjef0ctx4s7zmsgp6cwx4qgy4eg9",
    "issuedAt": 1710000012
  }
}
```

`issuedBy` is worth a note. NAP's guards answer "may this proceed?" and hand the route
nothing — no principal, no session object. The example carries a four-line
`src/principal.ts` to load it, mounted *after* the guard. On its own it authorises
nothing; do not mistake it for one.

Now drop the header:

```bash
curl -si localhost:3000/api/vouchers | head -1
```

```
HTTP/1.1 401 Unauthorized
```

And try a route the `merchant` role does not reach:

```bash
curl -si -X POST localhost:3000/api/payouts -H "authorization: Bearer $TOKEN" | head -1
```

```
HTTP/1.1 403 Forbidden
```

**401 and 403 are saying different things.** 401 is "I do not know who you are." 403 is "I
know exactly who you are and the answer is still no." The registry marks `stripe:manage` as
`stepUp: true`, so even the role that *does* carry it needs one more thing —
[tutorial 06](./06-high-value-actions-step-up.md).

## 4b. Where the vocabulary lives

```bash
curl -s localhost:3000/permissions | jq
```

The registry, served back. Every permission with its `stepUp` flag, every role with what
it composes. A frontend can render against this instead of hard-coding strings it might
misspell — and `validatePermissions()` runs over the same object at boot, so a
`requirePermission('vouchers:create')` typo is a startup crash rather than a 403 nobody
can account for.

## 5. Break it on purpose

Two failures, run deliberately now so you recognise them later.

**Replay the completion.** Edit the script to reuse a `challenge_id` you have already
spent, rather than fetching a fresh one. 401, and the audit code names it. Challenges are
single-use; that is what stops a captured proof from being replayed.

**Break the payload hash.** Add one space to the body:

```ts
body: new TextDecoder().decode(completion.rawBody) + ' ',
```

```
401 {"status":"error","message":"authentication failed"}
```

and in the server's terminal:

```json
{"code":"NAP_COMPLETE_PAYLOAD_MISMATCH","outcome":"failure", …}
``` Nothing about the request
looks wrong. This is precisely the failure a global `express.json()` produces, on every
request, with no clue at the call site — which is why it is worth seeing once, on purpose,
with a one-character cause.

## Where you are

You have a server that authenticates a Nostr key and authorises what that key can do, and
you have driven every step of it by hand. Nothing so far has depended on a browser.

Delete `complete.ts` — the next tutorial replaces it with a real signer.

**Next:** [02 — Logging in from a browser](./02-logging-in-from-a-browser.md). React, a
NIP-07 extension, and the switch from bearer tokens to an HttpOnly cookie.
