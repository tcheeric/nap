# 04 — Sessions that survive a restart

**You will build:** the same merchant app, backed by Postgres, so that restarting the
server no longer logs everybody out.

**Before you start:** [tutorial 03](./03-roles-and-permissions.md), and Docker.

**Time:** about 20 minutes.

> **A note on how this tutorial is verified.** Everything below was run against a real
> Postgres 16 before it was written, and the output is copied from those runs. But it sits
> **outside the repository's test suite** — CI runs on the in-memory stores and does not
> start a database, and `nap-store-postgres` has no tests of its own. The wiring is covered
> by typecheck; the behaviour is covered by the fact that someone ran it once. Treat the
> schema in particular as something to verify against your own database, not something the
> project guarantees.

---

## 1. Lose a session first

Do this before changing anything. Sign in, confirm you are signed in, then restart the
server and reload the page.

```bash
npm run start --workspace @imani/nap-example-merchant-app
# ^C, then start it again
```

You are signed out. Not expired — *gone*. The cookie in your browser is still there and
still valid-looking, and the server has no idea what it refers to, because
`InMemorySessionStore` was a `Map` in a process that no longer exists.

This is worth feeling once. "Sessions survive a restart" is an abstract promise until you
have watched them not.

The same is true of challenges: a login that had a challenge outstanding when the process
died completes into a 401, because the challenge it references was in the same `Map`.

## 2. Bring up a database

```bash
npm run db:up --workspace @imani/nap-example-merchant-app
```

That is `docker compose up -d --wait` against:

```yaml
services:
  db:
    image: postgres:16-alpine
    environment: { POSTGRES_USER: nap, POSTGRES_PASSWORD: nap, POSTGRES_DB: nap }
    ports: ['5433:5432']
    volumes:
      - ./db/schema.sql:/docker-entrypoint-initdb.d/schema.sql:ro
```

Port **5433**, so it does not collide with a Postgres you already run.

`/docker-entrypoint-initdb.d/` runs on an **empty data volume only**. Change `schema.sql`
later and nothing happens until `npm run db:down` (`docker compose down -v`) drops the
volume. This catches everybody once.

## 3. The schema is yours to own

**NAP ships no migration file and no DDL.** There is no `.sql` in `packages/`, and there is
no `CREATE TABLE` constant to import. The schema in `examples/merchant-app/db/schema.sql`
is derived, column by column, from the queries in `nap-store-postgres`; §5.5 of the
[integration guide](../NAP-INTEGRATION-GUIDE.md) shows which statement requires each one.

Three parts of it will bite you if you improvise:

**`nap_sessions.challenge_id` must be `UNIQUE`.** The store inserts with
`ON CONFLICT (challenge_id) DO NOTHING`, which is a *runtime* error without a matching
unique constraint — and the constraint is what makes "one session per challenge" true, so
losing it loses idempotency, not just the insert.

**`nap_acl` needs `PRIMARY KEY (app_id, pubkey)`.** Same reason, for the ACL upsert.

**The timestamp types are deliberately mixed.** `nap_challenges` and `nap_sessions` use
`BIGINT` unix seconds, compared numerically. `nap_acl.suspended_at` / `created_at` /
`updated_at` are `TIMESTAMPTZ`, written with SQL `NOW()` and read back as strings. Do not
standardise them onto one type; the row mappers expect exactly this.

Both `SELECT *` queries pick fields by name, so extra columns of your own are harmless.

## 4. The swap is a constructor call

```ts
export function createStores(databaseUrl = process.env.DATABASE_URL): Stores {
  if (!databaseUrl) {
    return {
      challengeStore: new InMemoryChallengeStore(),
      sessionStore: new InMemorySessionStore(),
      aclStore: new InMemoryAclStore(),
    };
  }

  const pool = new Pool({ connectionString: databaseUrl, types: PARSE_BIGINT_AS_NUMBER });

  return {
    challengeStore: new PostgresChallengeStore(pool),
    sessionStore: new PostgresSessionStore(pool),
    aclStore: new PostgresAclStore(pool),
    close: () => pool.end(),
  };
}
```

All three swap together. They are interfaces, and nothing else in the app can tell which
implementation it got — the routes, the guards, and the registry are untouched.

Each store takes a `Pool` **or** a `PoolClient`, so you can hand them a transaction-bound
client when you need the ACL write and your own write to land together.

Run it:

```bash
DATABASE_URL=postgres://nap:nap@localhost:5433/nap \
  npm run start --workspace @imani/nap-example-merchant-app
```

```
merchant-app listening on http://localhost:3000 (cookie mode, postgres stores)
```

Sign in. Restart the server. Reload.

```json
{"status":"ok","expires_at":1787407719,
 "principal":{"npub":"npub1fu64hh9hes90w2808n8tjc2ajp5yhddjef0ctx4s7zmsgp6cwx4qgy4eg9","pubkey":"4f355…"},
 "roles":["merchant"],"permissions":["merchant:read","voucher:create"]}
```

Still signed in. The voucher list is empty, though — `VoucherStore` is still a `Map`, and
that is deliberate: it makes the boundary visible. NAP's persistence is NAP's; your data is
yours.

## 5. `PARSE_BIGINT_AS_NUMBER`, and why it is there

That line in the `Pool` config is not decoration. Remove it and the same request returns:

```json
{"status":"ok","expires_at":"1787407576", …}
```

A **string**. In memory the same field is a number.

`pg` returns `BIGINT` as a string, because a Postgres bigint does not fit in a JS number,
and `PostgresSessionStore` casts the column straight to `number` without checking. The type
says `number`, the value is a string, and TypeScript never sees it.

It mostly appears to work — `"1787407576" <= 1787406676` coerces and compares correctly, so
expiry checks are fine — which is what makes it worth knowing about. Where it stops working
is arithmetic: `expiresAt + 60` on the client is `"178740757660"`, not a timestamp an hour
out. And the `/auth/session` body is a cross-implementation contract, so a session body
whose field type depends on which store you picked is an interop bug waiting for someone
else to hit.

```ts
const PARSE_BIGINT_AS_NUMBER = {
  getTypeParser: (oid, format) =>
    oid === pgTypes.builtins.INT8 ? Number : pgTypes.getTypeParser(oid, format),
};
```

Scoped to this pool rather than set globally with `pgTypes.setTypeParser`, so an application
bigint that genuinely exceeds 2^53 keeps its precision.

## 6. Nothing is ever deleted

This is the operational fact to leave with.

`markExpired()` is **not called for you**. Put it on a timer:

```ts
setInterval(() => {
  void challengeStore.markExpired(Math.floor(Date.now() / 1000));
}, 60_000).unref();
```

And then read what it actually did. Three challenges were issued and abandoned, and the
sweeper ran:

```
marked expired: 3
```

```
  state   | count
----------+-------
 expired  |     3
 redeemed |     2
```

Five rows, and five rows after. **`markExpired()` flips `state`; it never deletes.** And
expired *sessions* are not swept at all — `getByAccessToken()` filters on
`revoked_at IS NULL` and the adapter checks `expires_at` in application code, so an expired
session row simply stays.

Both tables grow forever. Every login is a challenge row and a session row, and every failed
login attempt is a challenge row too. On a busy app that is the kind of thing found in
production, at 2am, by a disk alert.

So write the DELETE job. Something like:

```sql
DELETE FROM nap_challenges WHERE state <> 'issued' AND expires_at < $1;
DELETE FROM nap_sessions   WHERE expires_at < $1;
```

with `$1` a retention horizon rather than "now" — you probably want a few days of expired
sessions to answer "was this person logged in on Tuesday". That retention window is a
decision, and NAP deliberately does not make it for you. Make it on purpose.

## 7. Clean up

```bash
npm run db:down --workspace @imani/nap-example-merchant-app
```

`docker compose down -v`, dropping the volume — so the next `db:up` re-runs `schema.sql`.

## Where you are

The merchant app keeps its sessions across a restart, on a schema you own, with a sweeping
policy you now know you have to write. Sessions still expire on their TTL, though, and when
they do the user signs in again from scratch.

**Next:** [05 — Refresh tokens](./05-refresh-tokens.md). Extending a session without a new
signature, and what makes rotation safe.
