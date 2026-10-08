# Upgrading

## 0.11.0 to 0.12.0

No runtime behaviour changes. What changes is how you get the packages.

**1. Install from npm instead of aliasing a sibling checkout.** The packages are published as
`@398ja/nap-*` and keep their `@imani/nap-*` import names through npm aliases, so no import
changes:

```json
"@imani/nap-client-web": "npm:@398ja/nap-client-web@^0.12.0",
"@imani/nap-react": "npm:@398ja/nap-react@^0.12.0"
```

Drop any bundler or `tsconfig` `paths` alias to `../nap/packages/*/src`, and any second
Docker build context for nap.

**2. Install the peers yourself.** `nostr-tools` (`^2.23.0`), `@noble/hashes`, `@noble/curves`
(nap-voucher only) and `react` (nap-react) are peer dependencies now. npm 7+ installs a missing
peer, but declaring them is what guarantees one shared copy.

**3. You no longer compile NAP's TypeScript.** The packages ship ESM and `.d.ts`. A bundler
needs no TypeScript handling for `node_modules`, and a plain Node service can import the
server packages directly.

## 0.10.1 to 0.11.0

One change breaks a working deployment, and it is the one that sounds harmless: the session
cookie now carries `Secure` by default. Everything else is additive or a bug fix.

No data migration. All packages in the workspace share a version, so upgrade them together.

### Before you deploy

**1. If anything serves over plain `http://`, say so explicitly.**

`writeNapCookieSuccess()` used to default to a session cookie with no `HttpOnly`, no
`Secure`, and no `SameSite`. It now defaults to all three, and a browser will not send a
`Secure` cookie over `http://`. A deployment terminating TLS nowhere stops authenticating
the moment it upgrades, and it does so silently: the login succeeds, the cookie is set, and
the next request simply arrives without it.

Local development and anything genuinely behind plain http needs the escape hatch:

```ts
// Cookie options are the second argument, after the cookie name.
writeNapCookieSuccess('nap_session', { secure: false })
```

Production should terminate TLS instead. The escape hatch is per-attribute, so turning off
`secure` leaves `httpOnly` and `sameSite` in place.

**2. If you pass cookie options, re-read them.**

Partial options used to *replace* the defaults rather than merge with them, so passing
`{ maxAge }` alone silently dropped every security attribute. They now merge, which means
an option you pass explicitly still wins, but the ones you leave out are no longer discarded.

Worth an actual look: if you were compensating for the old behaviour by restating
attributes you did not otherwise care about, those restatements are now redundant rather
than load-bearing.

**3. Expect expired challenges and sessions to disappear.**

`InMemoryChallengeStore` and `InMemorySessionStore` now evict records past their retention
bound, where they previously grew without limit. Code holding a `challenge_id` past its TTL
now sees `null` where it used to see a stale record. The bound is derived from the
record itself (`result_cache_until` for a redeemed challenge, `expires_at` otherwise), so
RFC §13.3 retry safety is preserved: a redeemed challenge still inside its result-cache
window survives.

Both constructors take an optional `{ clock }`. If you inject a clock into
`NapServerOptions`, pass the same one here. A store sweeping on a different clock from the
server either keeps records the server has written off or drops ones it still considers
live.

This only affects the in-memory stores. The SQL stores still retain expired rows (nap#39),
which is tracked separately.

### Deploying alongside `nap-java`

Both implementations now put the access token in the cookie and authenticate with
`getByAccessToken()`. Before this release they disagreed, so a cookie minted by one server
could not be presented to the other.

If both run against one session store, deploy `nap` 0.11.0 and `nap-java` 0.9.0 together.
A mixed fleet mid-rollout rejects cookies issued by the other side, which presents as users
being logged out at random rather than once.

### Verifying afterwards

```bash
curl -si https://your-host/auth/session | grep -i set-cookie
```

You want `HttpOnly`, `Secure`, and `SameSite` on that line. If sessions stop working right
after the upgrade and that line is present, the likely cause is the first item above: the
cookie is being set correctly and withheld on the next request because the origin is not
`https`.
