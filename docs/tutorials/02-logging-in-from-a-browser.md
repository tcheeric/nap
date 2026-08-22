# 02 — Logging in from a browser

**You will build:** a React frontend for the merchant app that signs in with a NIP-07
extension, shows who is signed in, signs out, and survives a page reload without asking
for a signature.

**Before you start:** [tutorial 01](./01-a-server-you-can-curl.md). You should have the
server running and know what `/auth/init` and `/auth/complete` do, because this tutorial
never shows you those requests again — the client library makes them for you.

**Time:** about 30 minutes.

---

## 0. Read this before you wire anything

**`@imani/nap-client-web` is cookie-mode only.** It has no API for reading an access token
out of a response, no API for holding one, and no API for putting one in a header. Every
request it makes sets `credentials: 'include'` and lets the browser attach the session
cookie.

That is a deliberate constraint, not an omission. A token your JavaScript can read is a
token any script on your origin can read, and "any script on your origin" includes the
dependency you added last week. The session id lives in an `HttpOnly` cookie so that the
page can *use* the session without ever *holding* the credential.

The consequence for you: `NAP_MODE=bearer` from tutorial 01 is over. The server has to run
in cookie mode from here on, and it is the default.

## 1. Switch the server to cookie mode

You already have the code — it is the branch you skipped in tutorial 01:

```ts
app.use('/auth', createNapExpressRouter({
  server: napServerOptions,
  getExternalBaseUrl: () => options.baseUrl,
  cookieName: COOKIE_NAME,
  writeSuccess: writeNapCookieSuccess(COOKIE_NAME, {
    httpOnly: true,
    sameSite: 'lax',
    secure: options.secureCookies ?? false,
    path: '/',
  }),
}));
```

`writeNapCookieSuccess` writes the cookie and replies `{"status":"ok"}` — the access token
never reaches the body. Confirm it with the completion response you drove by hand last
time:

```
complete 200 {"status":"ok"}
set-cookie: session=7_dEH19tc-EZ_QdUhdnnAsR7zU_yzL5bMtlnciUfhqs; Path=/; HttpOnly; SameSite=Lax
```

Note `cookieName` is passed **once**, to the router, and the same constant reaches the
guards. That is load-bearing. The writer and the readers each used to take their own name,
and a mismatch produced a server that logged every user out on the next page load while
logout cleared a cookie nobody had written. Both adapters now throw at wiring time rather
than run mute — but only if you give them one source. Don't introduce a second.

## 2. One origin, or nothing works

The browser has to reach the API and the frontend at the same origin. Two things depend on
it, and both fail quietly if you get it wrong:

- The session cookie is `SameSite=Lax`. A cross-origin `fetch` will not send it.
- **The NIP-98 audience is the URL the browser actually called.** The server checks each
  proof's `u` tag against the audience it was configured with. If the browser calls
  `http://localhost:5173/auth/complete` and the server was told its base URL is
  `http://localhost:3000`, every completion fails — as an indistinguishable 401.

The example solves this with a Vite dev proxy:

```ts
// examples/merchant-app/vite.config.ts
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: { '/auth': API, '/api': API, '/permissions': API },
  },
});
```

and by starting the server with its base URL pointed at the *frontend's* origin:

```bash
# terminal 1
PORT=3000 NAP_BASE_URL=http://localhost:5173 npm run start --workspace @imani/nap-example-merchant-app
# terminal 2
npm run dev:web --workspace @imani/nap-example-merchant-app
```

Check it before you write any UI. Ask for a challenge through the proxy:

```bash
curl -s -X POST http://localhost:5173/auth/init \
  -H 'content-type: application/json' \
  -d '{"npub":"npub1fu64hh9hes90w2808n8tjc2ajp5yhddjef0ctx4s7zmsgp6cwx4qgy4eg9"}'
```

```json
{"challenge_id":"RrqSe0fwSBt9okC1","challenge":"gu8WGO…","auth_url":"http://localhost:5173/auth/complete","auth_method":"POST","issued_at":1787406061,"expires_at":1787406121}
```

`auth_url` names port 5173, not 3000. That is the whole check: **the audience the server
will verify against is the origin the browser sees.** If that URL names your API's own
port, stop and fix `NAP_BASE_URL` — nothing downstream will tell you why logins fail.

In production this problem usually disappears, because the API and the app are behind one
hostname already. When they are not, §9.4 of the integration guide covers deriving the
audience from the request against an allowlist.

## 3. Getting a signer

A `SessionSigner` is the two-method object from
[the primer](./00-nostr-for-nap.md#signers): `getNpub()` and `signEvent()`. For a browser
extension, `createNip07Signer(provider)` wraps one.

Finding the provider is its own small problem, because extensions inject `window.nostr`
on their own schedule. `useNip07()` handles the polling and gives you a tri-state:

```tsx
const { status, provider, retry } = useNip07();

if (status === 'detecting') {
  return <p>Looking for a signing extension…</p>;
}
```

**`'detecting'` is a real state, not a formality.** A component that reads `window.nostr`
once during its first render tells a large share of your users they have no extension,
and they believe it.

When `status === 'absent'`, the right screen is onboarding, not an error. The user has not
failed at anything; they are missing a tool. Name the tool, and offer `retry` so they can
come back without a reload.

## 4. All four ways NIP-07 says no

`Nip07Error` carries a `code`, and the four values want four different screens. Collapsing
them into "login failed" is the mistake the codes exist to prevent:

```tsx
switch (cause.code) {
  case 'NOT_AVAILABLE':
    return 'The extension disappeared. Reload the page and try again.';
  case 'DECLINED':
    // Not an error condition. The user made a choice; offer it again calmly.
    return 'You declined the signature. Nothing happened — try again when ready.';
  case 'TIMEOUT':
    return 'The extension never answered. Check for an approval window behind this one.';
  case 'PROVIDER_ERROR':
    return 'Your extension reported an error. It may be locked — unlock it and retry.';
}
```

`DECLINED` is the one that matters most. A user who clicked "reject" and is then told
something went wrong will go looking for the fault — usually in your app.

`TIMEOUT` is the second: the approval window is often behind the browser, and telling
someone where to look is the entire fix.

The switch above is exhaustive over `Nip07ErrorCode`, with no `default`. Keep it that way.
When a fifth code arrives, you want a type error, not a silent fall-through to "something
went wrong".

## 5. Creating the session, and resuming it

```ts
const session = useMemo(
  () => signer
    ? createNapSession({ baseUrl: window.location.origin, signer, ...callbacks })
    : null,
  [signer, callbacks]
);
```

Two details in that call.

**`...callbacks`, spread — never a named subset.** `useNapCallbacks()` returns the full set
already wrapped in stable `useCallback`s. Picking three of them out by hand is how
`onIdentityChanged` goes unwired, and an unwired `onIdentityChanged` is not recoverable by
polling: `terminateForIdentity` nulls the session, so from outside, an account switch and
a plain logout look identical while demanding opposite responses.

**`baseUrl` is `window.location.origin`** — the same origin §2 went to such trouble to
establish.

Then, on mount:

```ts
useEffect(() => {
  if (!session) { setPhase('ready'); return; }
  let cancelled = false;
  setPhase('resuming');
  session.resume().catch(() => undefined).finally(() => {
    if (!cancelled) setPhase('ready');
  });
  return () => { cancelled = true; session.destroy(); };
}, [session]);
```

`resume()` asks the server whether the cookie is still good. It **never invokes the
signer**, which is the point: returning to a live session costs the user nothing.

**The loading state is required, not cosmetic.** `resume()` is a network round trip, and
rendering the signed-out screen underneath it makes every reload flash a login prompt at
someone who is already signed in. They will click it, and pay for a signature they did not
need.

**`destroy()` on unmount** stops the idle timer and closes the `BroadcastChannel`. Skip it
and each hot reload in development leaves another live channel behind, all of them
answering the same lock broadcast.

## 6. A reload keeps the session but not the signer

This is the part that surprises people, so it is worth stating flatly.

The session id is an `HttpOnly` cookie. It survives a reload. The signer is a JavaScript
object. It does not.

So after a reload, `createNapSession()` needs a `SessionSigner` before `resume()` can be
called at all — and the object that used to be there died with the page. In this tutorial
the user picks a signer again, which is honest but not free.

[Tutorial 08](./08-in-page-keys.md) fixes that with `createSignerPreferenceStore()`, which
remembers *which kind* of signer to rebuild — a `'nip07' | 'nip46' | 'key'` discriminator
plus the npub, both public, no key material.

**And when you do rebuild a signer from storage, `resume()` must become
`resume({ verifyIdentity: true })`.** The cookie outlived the page and the signer did not,
so a plain `resume()` would restore the *previous* account's principal under whoever the
extension is signed in as now. It is opt-in because verifying costs a `getNpub()`, and the
prompt-free reload is the property `resume()` exists to provide. You are not rebuilding a
signer here, so plain `resume()` is correct — for exactly one more tutorial.

## 7. Rendering the session

```tsx
<NapProvider session={session} identityChange={identityChange}>
  <Account />
</NapProvider>
```

`identityChange` is a **required** prop. `NapProvider` cannot derive it, and an omitted one
is indistinguishable at runtime from "no identity change" — which would make every account
switch reject as the retryable `session_expired`. The type system makes you supply it.

Inside:

```tsx
const { session, isAuthenticated, roles, permissions } = useNapSession();
```

**Read `roles` and `permissions` off the hook, not by calling `session.hasPermission()` in
a component.** The method reads a closure and answers correctly without ever causing a
render — which looks like it works right up until a grant changes and the button never
updates.

**And they are affordance, not authorization.** They exist so a render can hide a button.
The boundary is the server's `requirePermission` / `requireRole` / `requireSession`. A
check that exists only on the client does not exist. They are also the login-time snapshot,
which [tutorial 03](./03-roles-and-permissions.md) is about.

Login and logout are one call each:

```tsx
<button onClick={() => session.login()}>Sign in</button>
<button onClick={() => session.logout()}>Sign out</button>
```

`login()` runs the whole handshake — init, sign, complete — and produces exactly one
extension prompt.

## 8. Your own API calls need `credentials: 'include'`

NAP's own requests already set it. **Yours do not.**

```ts
await fetch('/api/vouchers', { credentials: 'include' });
```

Leave it off and `fetch` sends no cookie, the guard sees no session, and you get a 401 that
looks exactly like an expired one. Nothing in the failure points at the missing option —
which is why it is worth knowing before you meet it rather than after.

Same-origin `fetch` defaults to `credentials: 'same-origin'`, so this often works by
accident in development and breaks the first time the API moves to its own hostname. Set it
explicitly.

## 9. Try it

```
Signed in as npub1fu64hh9hes90w2808n8tjc2ajp5yhddjef0ctx4s7zmsgp6cwx4qgy4eg9
Roles: merchant · Permissions: merchant:read, voucher:create
```

Three things to do before moving on:

1. **Reload the page.** You are asked for a signer again, but not for a signature. That
   gap is §6.
2. **Decline the signature.** You should get the calm "nothing happened" message, not a
   failure.
3. **Sign out, then check the cookie in devtools.** It is gone, because logout clears the
   same name the writer wrote.

## Where you are

The merchant app has a real frontend, on a real session, with no credential anywhere your
JavaScript can reach. What it does not have is anything interesting to authorise — every
user gets `merchant` and that is the end of it.

**Next:** [03 — Roles and permissions](./03-roles-and-permissions.md). Making the two lists
above mean something, and where the client's copy of them stops being trustworthy.
