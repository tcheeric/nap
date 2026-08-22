# @imani/nap-store-postgres

Postgres implementations of the `@imani/nap-server` store interfaces.

## Includes

- `PostgresChallengeStore` — single-use challenges, retry-safe redemption
- `PostgresSessionStore` — sessions and atomic refresh-token rotation
- `PostgresAclStore` — per-principal roles and permission overrides

Each takes a `pg` `Pool` or `PoolClient`, so they compose with a transaction you already
have open.

## Example

```ts
import { Pool } from 'pg';
import {
  PostgresAclStore,
  PostgresChallengeStore,
  PostgresSessionStore,
} from '@imani/nap-store-postgres';

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

const napServerOptions = {
  challengeStore: new PostgresChallengeStore(pool),
  sessionStore: new PostgresSessionStore(pool),
  aclResolver: createRegistryAclResolver(registry, new PostgresAclStore(pool)),
};
```

## Notes

- The schema is not created for you. See §5.5 of the integration guide — and note the
  `UNIQUE (challenge_id)` on `nap_sessions` and `PRIMARY KEY (app_id, pubkey)` on
  `nap_acl` are load-bearing, not hygiene: the upserts fail without them.
- `markExpired()` marks and never deletes. Nothing sweeps expired rows; schedule that
  yourself.
- Refresh rotation is atomic — the update matches on the presented token, so a replayed
  token rotates nothing.
