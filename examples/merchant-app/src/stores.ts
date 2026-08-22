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
  /**
   * Delete rows nothing will ever read again. `undefined` for the in-memory
   * set, which drops everything on restart anyway.
   */
  deleteExpiredRows?: () => Promise<{ challenges: number; sessions: number }>;
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
    async deleteExpiredRows() {
      // The job tutorial 04 said you would have to write. `markExpired()` flips
      // `state`; it never deletes, and nothing sweeps sessions at all.
      //
      // The horizon is a decision, not a default — that is why NAP does not
      // make it for you. An hour for challenges, because a challenge row is
      // what makes a completion idempotent and deleting one on the stroke of
      // expiry turns a retried request into a confusing failure. Seven days for
      // sessions, because "was this person logged in on Tuesday" is a question
      // someone eventually asks. Pick your own numbers on purpose.
      const now = Math.floor(Date.now() / 1000);
      // `state <> 'issued'` so a row the sweeper has not marked yet survives.
      const challenges = await pool.query(
        "DELETE FROM nap_challenges WHERE state <> 'issued' AND expires_at < $1",
        [now - 3600]
      );
      const sessions = await pool.query(
        'DELETE FROM nap_sessions WHERE expires_at < $1',
        [now - 7 * 24 * 3600]
      );
      return { challenges: challenges.rowCount ?? 0, sessions: sessions.rowCount ?? 0 };
    },
  };
}

/**
 * Flip expired challenges to `'expired'` on a timer, and delete rows old
 * enough that nothing will read them again. Nothing calls either for you.
 *
 * Two jobs rather than one because they are different operations with
 * different risks: marking is cheap and idempotent, deleting is neither. See
 * tutorial 04 for the marking and tutorial 09 for the deleting.
 */
export function startChallengeSweeper(
  stores: Pick<Stores, 'challengeStore' | 'deleteExpiredRows'>,
  intervalMs = 60_000
): () => void {
  const timer = setInterval(() => {
    void stores.challengeStore.markExpired(Math.floor(Date.now() / 1000));
    // Hourly, not every minute: a DELETE over two tables is not something to
    // run sixty times as often as it can possibly find work.
    if (Date.now() % 3_600_000 < intervalMs) {
      void stores.deleteExpiredRows?.();
    }
  }, intervalMs);

  timer.unref();

  return () => clearInterval(timer);
}
