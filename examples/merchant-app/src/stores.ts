import {
  InMemoryAclStore,
  InMemoryChallengeStore,
  InMemorySessionStore,
  type AclStore,
  type ChallengeStore,
  type SessionStore,
} from '@imani/nap-server';
import {
  PostgresAclStore,
  PostgresChallengeStore,
  PostgresSessionStore,
} from '@imani/nap-store-postgres';
import { Pool, types as pgTypes } from 'pg';

/**
 * `pg` returns BIGINT as a *string*, because a Postgres bigint does not fit in a
 * JS number. NAP's `expires_at` / `issued_at` columns are bigints, and
 * `PostgresSessionStore` casts them straight to `number` — so without this the
 * `/auth/session` body ships `"expires_at":"1787407576"` on Postgres and
 * `"expires_at":1787407576` in memory, and any client that does arithmetic on
 * it gets string concatenation. See tutorial 04.
 *
 * Scoped to this pool rather than set globally with `pgTypes.setTypeParser`, so
 * an application bigint that genuinely exceeds 2^53 keeps its precision.
 */
const PARSE_BIGINT_AS_NUMBER = {
  getTypeParser: (oid: number, format?: unknown) =>
    oid === pgTypes.builtins.INT8 ? Number : pgTypes.getTypeParser(oid, format as never),
} as { getTypeParser: typeof pgTypes.getTypeParser };

export interface Stores {
  challengeStore: ChallengeStore;
  sessionStore: SessionStore;
  aclStore: AclStore;
  /** Call on shutdown. `undefined` for the in-memory set. */
  close?: () => Promise<void>;
}

/**
 * In-memory when `DATABASE_URL` is unset, Postgres when it is set.
 *
 * The stores are interfaces and the swap is a constructor call — nothing else
 * in the app knows which one it got. That is the whole extent of the change
 * tutorial 04 makes.
 */
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

/**
 * Flip expired challenges to `'expired'` on a timer. Nothing calls this for
 * you.
 *
 * Note what it does *not* do: it never deletes a row, and expired sessions are
 * not swept at all. Both tables grow forever without a DELETE job you write
 * yourself. See tutorial 04.
 */
export function startChallengeSweeper(
  challengeStore: ChallengeStore,
  intervalMs = 60_000
): () => void {
  const timer = setInterval(() => {
    void challengeStore.markExpired(Math.floor(Date.now() / 1000));
  }, intervalMs);

  timer.unref();

  return () => clearInterval(timer);
}
