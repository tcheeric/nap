# 03 — Roles and permissions

**You will build:** guarded routes that refuse the wrong caller, a registry that turns a
typo into a boot failure, and a frontend that stops offering buttons it knows will fail.

**Before you start:** [tutorial 02](./02-logging-in-from-a-browser.md). You have a browser
session and a `Roles: merchant` line on screen that so far means nothing.

**Time:** about 25 minutes.

**Reference:** §3 of the [integration guide](../NAP-INTEGRATION-GUIDE.md) is the full ACL
model. This tutorial is the working subset. Nothing here needs new Nostr knowledge — the
principal being authorised is the pubkey from
[the primer](./00-nostr-for-nap.md#keys), and NAP has already established who it is.

---

## 1. The registry is the vocabulary

Every permission and every role the app knows about lives in one object:

```ts
export const REGISTRY: PermissionRegistry = {
  appId: 'merchant-app',
  permissions: [
    { key: 'merchant:read', description: 'Read vouchers and merchant profile', stepUp: false },
    { key: 'voucher:create', description: 'Issue a new voucher', stepUp: false },
    { key: 'stripe:manage', description: 'Change payout settings', stepUp: true },
  ],
  roles: [
    { key: 'viewer', description: 'Can look, cannot touch', permissions: ['merchant:read'] },
    { key: 'merchant', description: 'Runs a shop', permissions: ['merchant:read', 'voucher:create'] },
    { key: 'owner', description: '…', permissions: ['merchant:read', 'voucher:create', 'stripe:manage'] },
  ],
  defaultRole: 'merchant',
};
```

**`defaultRole` is the one to think hardest about.** Every principal with no ACL row lands
there, and a principal is anyone who can produce a valid signature over a challenge — which
is everyone with a Nostr key, which is everyone. Make it the least you are willing to hand
a stranger. `merchant` is generous; it is a tutorial.

Roles expand into permissions at the ACL layer. The session gets both lists, but only one
of them is what you guard on.

## 2. Guard the permission, not the role

```ts
app.get('/api/vouchers', requirePermission('merchant:read', guardOptions), handler);
app.post('/api/vouchers', requirePermission('voucher:create', guardOptions), handler);
```

Both directions work — roles are already expanded into the session's permissions, so any
role check is expressible as a permission check. They differ in which way maintenance
flows.

Guard `voucher:create`, and a new role that should be able to issue vouchers is **one
registry edit**. Guard `merchant`, and it is an edit to every guard site that should now
also accept the new role. The registry exists to hold that mapping in one place; role
guards route around it.

So `requireRole` is the exception, and the test for whether you have a real one is whether
a permission could express it. The example has exactly one:

```ts
app.get('/api/support/lookup', requireRole('support', guardOptions), handler);
```

```ts
{
  key: 'support',
  description: 'Staff. Can look up a merchant, and nothing this app offers',
  permissions: [],
}
```

`support` holds **no permissions at all**. There is no key that means "is staff", and
inventing one would put something in the merchant vocabulary that no merchant should ever
hold. That is a genuine role guard. Break-glass and staff-only routes are the pattern;
everything else is a permission.

`requireSession` is the third guard, for routes that are simply for signed-in users:

```ts
app.get('/api/me', requireSession(guardOptions), handler);
```

Use it rather than inventing a `user:basic` permission granted to everyone. A key in the
registry that gates nothing reads, to everyone after you, as though it gates something.

## 3. A typo is a boot failure

Each guard registers the string it was given. After the routes are mounted:

```ts
validatePermissions(REGISTRY);
```

**After**, deliberately — it can only check the guards it has seen.

Break one on purpose. Change `voucher:create` to `voucher:crate` in `app.ts` and start the
server:

```
Error: Permissions used in middleware but missing from registry: voucher:crate
    at validatePermissions (…/nap-adapter-express/src/adapter.ts:810:11)
    at createMerchantApp (…/examples/merchant-app/src/app.ts:183:3)
```

The server does not start. That is the whole point: without this call the route would mount
happily and 403 every caller forever, including the ones who genuinely have the permission,
and nothing in the response would say why. Every auth failure in NAP is deliberately
indistinguishable on the wire — so the failures that *can* be caught before a request has to
be.

Put it back before continuing.

## 4. Which permissions does this user have?

Two ways to ask, and they answer different questions.

`GET /permissions` publishes the registry — the app's whole vocabulary, the same for
everyone:

```json
{"appId":"merchant-app","permissions":[{"key":"merchant:read","description":"Read vouchers and merchant profile","stepUp":false}, …]}
```

Render your UI from that rather than hard-coding permission strings into a frontend that
can get them subtly wrong.

`GET /auth/session` answers for *this* caller:

```json
{"status":"ok","expires_at":1787407028,
 "principal":{"npub":"npub1fu64hh9hes90w2808n8tjc2ajp5yhddjef0ctx4s7zmsgp6cwx4qgy4eg9","pubkey":"4f355…"},
 "roles":["merchant"],"permissions":["merchant:read","voucher:create"]}
```

`nap-client-web` reads that for you. In React it arrives through the hook.

## 5. Hiding a button is not protecting a route

```tsx
const { permissions } = useNapSession();
const canCreate = permissions.includes('voucher:create');

{canCreate ? <button onClick={create}>Issue voucher</button> : null}
```

**This is affordance, not authorization.** It stops a user reaching for something that
would be refused; it does not do the refusing. `requirePermission()` on the server does the
refusing, and it does it whether or not this component exists. Delete every check in the
file and the app is exactly as secure — only ruder.

The reason to say it here, rather than in a footnote, is that the code above *looks* like a
security control. It is the shape of one. Someone reading it in six months, deciding whether
a new endpoint needs a guard, will see it and conclude the frontend has that covered.

Two consequences worth building for:

**Handle the 403 you supposedly cannot get.** The hidden button is reachable anyway — a
second tab, a stale snapshot, a revoked role, `curl`:

```tsx
if (res.status === 403) {
  setError('You are not allowed to issue vouchers.');
  return;
}
```

**Read the lists off the hook, not the session's methods.**

```tsx
const { permissions } = useNapSession();   // ✅ re-renders when it changes
if (session.hasPermission('voucher:create')) { … }   // ❌ correct answer, no render
```

`session.hasPermission()` reads a closure. It returns the right answer every time you call
it, and never causes a re-render — so a component built on it is correct on first paint and
frozen after. It looks like it works until a grant changes.

## 6. The login-time snapshot, and how to escape it

`session.permissions` is captured **at login**. Nothing refreshes it. Revoke a role
mid-session and the snapshot keeps saying what it said, right up to the session TTL.

For the guards, that is a choice you make in one place:

```ts
const guardOptions = {
  sessionStore,
  cookieName: COOKIE_NAME,
  aclResolver: napServerOptions.aclResolver,   // ← re-read per request
  registry: REGISTRY,
};
```

Pass the **same resolver you gave `NapServerOptions`**. Without it, `requirePermission`,
`requireRole`, and `requireSession` all check the snapshot, and a suspension lands when the
session expires rather than when it happens.

The example's test pins the difference down:

```ts
await grant(aclStore, 'owner');
const token = (await login(app)).body.access_token;
// … POST /api/vouchers → 201

await grant(aclStore, 'viewer');       // same session, same token
// … POST /api/vouchers → 403
```

Without `aclResolver` in the guard options, that second call is a 201.

The cost is a resolver call per guarded request, which for a database-backed ACL store is a
query. If that is too much, cache inside the resolver — the decision about *when* a
revocation should bite belongs there, where you can see it, and not in an option somebody
left off.

The client's copy stays stale regardless: it refreshes on the next `login()` or `resume()`.
Since it is only affordance, that is survivable — the button reappears a beat late, and the
server was never fooled.

## 7. Try it

The example has no admin UI, so demote yourself the blunt way: change `defaultRole` to
`'viewer'` in `registry.ts` and restart the server. Sign in again:

```
Roles: viewer · Permissions: merchant:read
```

```json
{"status":"ok","expires_at":1787407402,
 "principal":{"npub":"npub1fu64hh9hes90w2808n8tjc2ajp5yhddjef0ctx4s7zmsgp6cwx4qgy4eg9", …},
 "roles":["viewer"],"permissions":["merchant:read"]}
```

The voucher list renders; the issue-voucher form is gone. Now `curl` the route the button no
longer offers:

```bash
curl -s -X POST http://localhost:5173/api/vouchers \
  -H 'content-type: application/json' -b 'session=…' -d '{"amount_cents":2500}'
```

```json
{"status":"error","message":"forbidden"}
```

**403, not 401.** The distinction is worth keeping straight for the rest of the series: 401
means the request carried no usable session, 403 means it carried a perfectly good one
belonging to someone who may not do this. Retrying a 401 after a login can work; retrying a
403 cannot.

Put `defaultRole` back to `'merchant'` before moving on.

## Where you are

The merchant app now enforces its own vocabulary at the boundary, fails to boot on a typo'd
permission, and hides what it cannot do. Everything is still in memory, though — restart
the server and every session and every ACL row is gone.

**Next:** [04 — Sessions that survive a restart](./04-postgres.md). Swapping the in-memory
stores for Postgres.
