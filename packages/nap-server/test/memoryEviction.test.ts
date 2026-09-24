import { describe, expect, it } from 'vitest';
import type { ChallengeRecord, SessionRecord } from '@imani/nap-core';
import { InMemoryChallengeStore, InMemorySessionStore } from '../src/index.js';

const NOW = 1_710_000_000;

/** Mutable clock, so a test can step time past a retention bound deliberately. */
function stubClock(start: number): { nowUnix(): number; set(value: number): void } {
  let current = start;

  return {
    nowUnix: () => current,
    set(value: number) {
      current = value;
    },
  };
}

function challenge(id: string, overrides: Partial<ChallengeRecord> = {}): ChallengeRecord {
  return {
    challenge_id: id,
    challenge: `challenge-${id}`,
    npub: 'npub1example',
    pubkey: 'ff'.repeat(32),
    auth_url: 'https://api.example.com/auth/complete',
    auth_method: 'POST',
    issued_at: NOW,
    expires_at: NOW + 120,
    state: 'issued',
    ...overrides,
  };
}

function session(id: string, overrides: Partial<SessionRecord> = {}): SessionRecord {
  return {
    session_id: id,
    challenge_id: `challenge-${id}`,
    access_token: `access-${id}`,
    principal_npub: 'npub1example',
    principal_pubkey: 'ff'.repeat(32),
    roles: [],
    permissions: [],
    issued_at: NOW,
    expires_at: NOW + 900,
    ...overrides,
  };
}

describe('InMemoryChallengeStore eviction', () => {
  it('drops expired challenges while keeping the live one readable', async () => {
    const clock = stubClock(NOW);
    const store = new InMemoryChallengeStore({ clock });

    for (let index = 0; index < 50; index += 1) {
      await store.create(challenge(`expired-${index}`, { expires_at: NOW + 60 }));
    }

    await store.create(challenge('live', { expires_at: NOW + 10_000 }));

    // Past every short expiry, and the sweep needs a fresh tick to run at all.
    clock.set(NOW + 61);
    await store.create(challenge('trigger', { expires_at: NOW + 10_000 }));

    expect(await store.get('expired-0')).toBeNull();
    expect(await store.get('expired-49')).toBeNull();
    expect((await store.get('live'))?.challenge_id).toBe('live');
  });

  it('keeps a redeemed challenge inside its result-cache window', async () => {
    const clock = stubClock(NOW);
    const store = new InMemoryChallengeStore({ clock });

    await store.create(challenge('redeemed', { expires_at: NOW + 60 }));

    const outcome = await store.redeem('redeemed', {
      eventId: 'event-1',
      sessionId: 'session-1',
      now: NOW,
      resultCacheUntil: NOW + 600,
    });

    expect(outcome.status).toBe('redeemed');

    // The challenge itself has expired, but RFC §13.3 retry safety says the
    // cached result must still answer a client repeating its completion.
    clock.set(NOW + 120);
    await store.create(challenge('trigger', { expires_at: NOW + 10_000 }));

    const retained = await store.get('redeemed');
    expect(retained?.state).toBe('redeemed');
    expect(retained?.redeemed_session_id).toBe('session-1');

    // Once the cache window itself lapses, the record is finally collectable.
    clock.set(NOW + 601);
    await store.create(challenge('trigger-2', { expires_at: NOW + 10_000 }));
    expect(await store.get('redeemed')).toBeNull();
  });
});

describe('InMemorySessionStore eviction', () => {
  it('evicts expired sessions from every index and leaves live ones alone', async () => {
    const clock = stubClock(NOW);
    const store = new InMemorySessionStore({ clock });

    await store.createForChallenge(session('stale', { expires_at: NOW + 100 }));
    await store.createForChallenge(session('live', { expires_at: NOW + 10_000 }));

    clock.set(NOW + 101);
    expect(await store.getByAccessToken('access-stale')).toBeNull();
    expect(await store.getBySessionId('stale')).toBeNull();

    expect((await store.getByAccessToken('access-live'))?.session_id).toBe('live');
  });

  it('keeps a refresh token recognisable as a replay until its own expiry', async () => {
    const clock = stubClock(NOW);
    const store = new InMemorySessionStore({ clock });

    await store.createForChallenge(
      session('refreshable', {
        expires_at: NOW + 100,
        refresh_token: 'refresh-1',
        refresh_expires_at: NOW + 3600,
      })
    );

    await store.rotateRefreshToken('refreshable', {
      expectedRefreshToken: 'refresh-1',
      refreshToken: 'refresh-2',
      accessToken: 'access-2',
      now: NOW,
      expiresAt: NOW + 100,
      refreshExpiresAt: NOW + 3600,
      roles: [],
      permissions: [],
    });

    // The access token has lapsed, but reuse detection only works while the
    // superseded token still resolves to its lineage.
    clock.set(NOW + 200);
    await store.getByAccessToken('unrelated');

    expect((await store.getByRefreshToken('refresh-1'))?.session_id).toBe('refreshable');

    clock.set(NOW + 3601);
    await store.getByAccessToken('unrelated');
    expect(await store.getByRefreshToken('refresh-1')).toBeNull();
  });

  /**
   * The growth path is `createForChallenge`, not `getByAccessToken`.
   *
   * Sweeping only from the read path left the actual attack uncovered: a server
   * taking logins but serving no guarded requests never calls
   * `getByAccessToken`, so nothing swept and every expired session stayed
   * resident. Measured at 500 logins retaining all 500 before the write path
   * swept too.
   *
   * Asserting a constant rather than a threshold is what makes this meaningful.
   * Residue is the sliding retention window (one tick plus `expires_at`), so it
   * depends on the session TTL and not on how much traffic has been served. Ten
   * times the logins must leave the same amount behind.
   */
  it('bounds growth on the write path, independent of login volume', async () => {
    const residentAfter = async (logins: number): Promise<number> => {
      const clock = stubClock(NOW);
      const store = new InMemorySessionStore({ clock });

      for (let index = 0; index < logins; index += 1) {
        await store.createForChallenge(session(`s${index}`, {
          issued_at: clock.nowUnix(),
          expires_at: clock.nowUnix() + 60,
        }));
        clock.set(clock.nowUnix() + 1);
      }

      let alive = 0;
      for (let index = 0; index < logins; index += 1) {
        if (await store.getBySessionId(`s${index}`)) {
          alive += 1;
        }
      }
      return alive;
    };

    const tenfold = await residentAfter(5_000);

    expect(tenfold).toBe(await residentAfter(500));
    expect(tenfold).toBeLessThan(100);
  });
});
