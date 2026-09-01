# Appendix — the same series on Fastify

**Who this is for:** you are following tutorials 01–09, your backend is Fastify
5, and you would rather translate once than at every step.

**How to use it:** read the tutorials as written. When one of them wires the
Express adapter, come here for the Fastify line, then go back. The §
cross-references below say which tutorial each substitution belongs to.

**On the code below.** The snippets are illustrative — there is no Fastify
example app in this repository, deliberately (see *Why there is no second
example* at the end). They are not invented, though: they follow
`packages/nap-adapter-fastify/test/adapter.test.ts`, which runs on every commit,
and the wiring in §1 through §7 was compiled against this workspace under
`npm run typecheck` before it was written down. Option names and shapes are
real; the surrounding application is not. The adapter API itself follows RFC
Appendix C, which sketches both adapters against one shared shape.

---

## The whole substitution, at a glance

| Concern | Express | Fastify |
| --- | --- | --- |
| Mount | `app.use('/auth', createNapExpressRouter(opts))` | `await app.register(napFastifyPlugin, { routePrefix: '/auth', ...opts })` |
| Body limit | `bodyLimit: '1kb'` (string or number) | `bodyLimitBytes: 1024` (**number of bytes only**) |
| Raw body | `createNapExpressJsonParser()`, installed by the router | a scoped `addContentTypeParser`, installed by the plugin |
| Raw body override | `rawBody` symbol on the request | `rawBodyExtractor` option |
| Client IP | `getClientIp`, defaults to `req.ip` under `app.set('trust proxy', …)` | `getClientIp`, defaults to `req.ip` under `Fastify({ trustProxy: … })` |
| Guards | `app.get('/x', requirePermission(k, g), handler)` | `app.get('/x', { preHandler: requirePermission(k, g) }, handler)` |
| Permission registry route | `app.use(createPermissionsRouter(REGISTRY))` | `await app.register(permissionsFastifyPlugin(REGISTRY))` |
| Cookie writer | `writeNapCookieSuccess(name, CookieOptions, transformBody?)` | `writeNapCookieSuccess(name, SerializeOptions, transformBody?)` |
| Logout attributes | `clearCookieOptions?: CookieOptions` | `clearCookieOptions?: SerializeOptions` |
| Rate limiter | `napServerOptions.rateLimiter` | **identical** — it lives in `nap-server` |
| ACL resolver, registry, step-up | identical | identical |

Everything in the last two rows is the point: the adapters are a thin edge.
Challenge issuance, verification, rate limiting, ACL resolution, and step-up all
live in `@imani/nap-server` and do not know which framework called them.

---

## 1. Mounting the router — tutorial 01 §1

Express mounts a router. Fastify registers a plugin, and the prefix is a
**plugin option**, not Fastify's `prefix`:

```ts
import Fastify from 'fastify';
import { napFastifyPlugin } from '@imani/nap-adapter-fastify';

const app = Fastify();

await app.register(napFastifyPlugin, {
  routePrefix: '/auth',
  server: napServerOptions,
  getExternalBaseUrl: () => baseUrl,
  cookieName: 'session',
  bodyLimitBytes: 1024,
});
```

`await` the `register`. Fastify defers plugin loading, so a wiring error the
plugin throws — a cookie-name mismatch, an unwirable `refreshTtlSeconds` —
surfaces when the promise settles. Without the `await` it becomes an unhandled
rejection some time after your `listen()` reported success, which is exactly
the "fails at startup, not at request time" property the throws exist to have.

Routes registered: `POST /auth/init`, `POST /auth/complete`,
`GET /auth/session`, `POST /auth/logout`, and `POST /auth/refresh` only when
`server.refreshTtlSeconds` is set. Same set as Express, same order of
appearance in the tutorials.

## 2. The raw body — tutorial 01 §1, and the Express trap that isn't one here

Tutorial 01 opens with this and `CLAUDE.md` lists it first among the
traps: a global `express.json()` mounted before the NAP router re-stringifies
the body and fails every completion with `NAP_COMPLETE_PAYLOAD_MISMATCH`,
because the NIP-98 `payload` tag is `sha256` over the exact bytes.

**On Fastify that specific trap does not exist**, and it is worth knowing why.
The plugin installs its parser on the instance it is handed:

```ts
instance.addContentTypeParser(
  'application/json',
  { parseAs: 'buffer', bodyLimit: bodyLimitBytes },
  (req, body, done) => { /* stash raw bytes, then JSON.parse */ }
);
```

Registering a plugin creates an encapsulation context, so that parser applies to
the plugin's routes and nowhere else. Your app's other routes keep Fastify's
default JSON parser. You do not have to sequence anything.

**The inverse trap is real.** Wrap the registration in `fastify-plugin` and you
break encapsulation on purpose: NAP's raw-body parser becomes your application's
global JSON parser, with a 1 kB limit, on every route you have. Don't. Register
it plainly.

If your raw bytes genuinely come from somewhere else — an upstream plugin, a
gateway that hands you the body — supply a `rawBodyExtractor` rather than
reaching for `req.body`. Anything that re-stringifies a parsed body changes key
order or whitespace and fails every completion. When no raw body is available
the adapter throws rather than guessing:

```
nap-adapter-fastify requires raw body capture for /auth/complete
```

RFC Appendix C.1 makes that non-negotiable: an adapter must not "silently fall
back when raw body bytes are unavailable".

## 3. The body limit — tutorial 09 §3

```ts
bodyLimitBytes: 1024
```

Not `bodyLimit`, and **not a string** — `'1kb'` does not work here. The name and
the type both differ from Express, which takes `bodyLimit: string | number`.

The number matters more on Fastify than it looks. Express's `express.json()`
defaults to 100 kB; **Fastify's own default is 1 MB**. Both adapters default to
1 kB, so you inherit the safe number either way — but the thing you are being
protected from is an order of magnitude larger here.

## 4. Guards — tutorials 03 and 06

Same functions, same options object, attached as a `preHandler` rather than
positionally:

```ts
app.get(
  '/api/vouchers',
  { preHandler: requirePermission('merchant:read', guardOptions) },
  async () => ({ vouchers: vouchers.list() })
);
```

An array works for chaining, which is how an explicit step-up guard
attaches (tutorial 06 §4):

```ts
app.post(
  '/api/payouts',
  {
    preHandler: [
      requirePermission('stripe:manage', guardOptions),
      requireStepUp({ sessionStore, cookieName: 'session' }),
    ],
  },
  async () => ({ status: 'payout settings updated' })
);
```

`guardOptions` is the same object as in tutorial 03, and the same warning
applies with the same force (tutorial 03 §6): **pass `aclResolver`**, the same one you gave
`NapServerOptions`, or a revocation only lands when the session expires. The
`registry` field does the same job too — a permission marked `stepUp: true`
there is enforced by `requirePermission` itself, so the explicit `requireStepUp`
above is only needed for a route whose permission is not registry-marked.

`requireSession`, `requirePermission`, `requireRole`, and `requireStepUp` all
exist with identical signatures. So do `validatePermissions(REGISTRY)` and
`resetPermissionValidationState()`; call `validatePermissions` after your routes
register, exactly as in tutorial 03 §3, so a typo'd permission key is a boot
failure rather than a 403 nobody can explain.

One thing the Express example has that the adapter does not give you on either
framework: the merchant app's `attachPrincipal` middleware, which puts the
session on the request for handlers to read. That is example-app code, about
fifteen lines, and it ports directly to a `preHandler` that decorates the
request.

## 5. The permission registry route — tutorial 03 §4

```ts
await app.register(permissionsFastifyPlugin(REGISTRY));
```

It serves `GET /permissions`. Note the shape: `permissionsFastifyPlugin` is a
**factory** — it takes the registry and returns the plugin — whereas Express's
`createPermissionsRouter(REGISTRY)` returns a router you `app.use`. Register it
with a Fastify `prefix` if you want it somewhere other than the root.

## 6. Cookie mode — tutorial 02 §1

```ts
await app.register(napFastifyPlugin, {
  routePrefix: '/auth',
  server: napServerOptions,
  getExternalBaseUrl: () => baseUrl,
  cookieName: 'session',
  writeSuccess: writeNapCookieSuccess('session', {
    httpOnly: true,
    sameSite: 'lax',
    secure: true,
    path: '/',
  }),
});
```

Same function name, same three parameters, same defaults. The attribute type is
`SerializeOptions` from the `cookie` package rather than Express's
`CookieOptions`; in practice the fields you use are spelled the same.

Two rules carry over unchanged, and both are enforced:

- **The name must match.** Pass `cookieName` alongside `writeSuccess` or the
  plugin throws at registration:

  ```
  NAP cookie name mismatch: writeNapCookieSuccess writes 'session' but the
  adapter reads 'nap'. /auth/session and /auth/logout would look for a cookie
  that is never set.
  ```

- **Logout must clear it under the same attributes.** Leave
  `clearCookieOptions` unset and the logout handler reuses what
  `writeNapCookieSuccess` was given, which is the pairing that cannot drift. Set
  it only when your `writeSuccess` is your own function the adapter has nothing
  to copy from — otherwise you are back to a `{ path: '/' }` guess and a browser
  that keeps a cookie the server thinks it revoked.

Tutorial 05 §2's refresh-token variant ports the same way: pass the same
`transformBody` third argument, and the same wiring check fires if you don't —
the default `{status:'ok'}` body drops the refresh token the client needs, so
`refreshTtlSeconds` plus the default writer throws at registration.

## 7. Audience, proxies, and the rate limiter — tutorial 09

`getExternalBaseUrl` and `audienceResolver` are the same two mutually exclusive
options, on the plugin rather than the router, with the same throw for passing
both or neither:

```
NAP adapter requires exactly one of getExternalBaseUrl or audienceResolver
```

`createRequestDerivedBaseUrlResolver(allowedHosts)` is exported from the Fastify
package too, with the same allowlist rules and the same refusal to construct
from an empty list.

The proxy setting is where the frameworks differ in spelling only:

```ts
const app = Fastify({ trustProxy: true });   // vs. app.set('trust proxy', true)
```

It decides the same two things — `req.ip`, which
`maxOutstandingChallengesPerIp` counts on, and the protocol a request-derived
audience reads. Set it to what your deployment warrants, not `true` by reflex.

The rate limiter and both outstanding-challenge caps need **no translation at
all**. They are `NapServerOptions` fields:

```ts
const napServerOptions: NapServerOptions = {
  challengeStore,
  sessionStore,
  aclResolver,
  auditLogger,
  rateLimiter: createInMemoryRateLimiter({ windowSeconds: 60, maxPerWindow: 30 }),
  maxOutstandingChallengesPerNpub: 10,
  maxOutstandingChallengesPerIp: 30,
};
```

Everything tutorial 09 says about them — that the limiter counts per process,
that the two caps are different limits both answering 429, that only the audit
log's `cap` field separates them — is true verbatim on Fastify.

## 8. What needs no translation

Tutorials 02, 05 (client half), 06 (client half), 07, and 08 are entirely
frontend. `@imani/nap-client-web`, `@imani/nap-client-nip46`, and
`@imani/nap-react` talk HTTP to endpoints that are byte-identical across the two
adapters. Nothing on those pages changes.

Tutorial 04 is Postgres. `@imani/nap-store-postgres` knows nothing about your
HTTP framework.

---

## Why there is no second example

The difference is the table at the top of this page — roughly twenty lines. A
parallel Fastify example application would double the surface that has to stay
correct, in exchange for saving a reader those twenty lines once. `docs/adr/0001-tutorial-series-shape.md`
records that decision.

The consequence to be honest about: the Express example in
`examples/merchant-app` is exercised by an integration test on every commit, and
this page is not. What *is* exercised is
`packages/nap-adapter-fastify/test/adapter.test.ts` — it covers the init and
complete flow, cookie mode, the audience allowlist, all four guards, step-up,
refresh rotation, and the wiring throws. If a snippet here ever looks wrong, that
file is the source of truth, and it is short enough to read straight through.
