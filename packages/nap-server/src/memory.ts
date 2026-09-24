import type { ChallengeRecord, SessionRecord } from '@imani/nap-core';
import type {
  AclRecord,
  AclStore,
  ChallengeStore,
  Clock,
  OutstandingChallengeFilter,
  RecordChallengeFailureResult,
  RotateRefreshTokenParams,
  SessionStore,
} from './types.js';

const systemClock: Clock = { nowUnix: () => Math.floor(Date.now() / 1000) };

export interface InMemoryStoreOptions {
  /**
   * Clock the eviction sweep reads. Defaults to the wall clock. Pass the same
   * clock you gave `NapServerOptions` when you inject one: a store sweeping on
   * a different clock from the server either keeps records the server has
   * already written off or drops ones it still considers live.
   */
  clock?: Clock;
}

export class InMemoryChallengeStore implements ChallengeStore {
  private readonly records = new Map<string, ChallengeRecord>();
  private readonly clock: Clock;
  private lastSweptAt: number | null = null;

  constructor(options: InMemoryStoreOptions = {}) {
    this.clock = options.clock ?? systemClock;
  }

  /**
   * Drop challenges nothing can still ask about, so an unauthenticated flood of
   * `/auth/init` grows this map by a bounded amount rather than for ever.
   *
   * The retention bound is `result_cache_until` when the challenge was redeemed
   * and `expires_at` otherwise. A redeemed challenge inside its result-cache
   * window must survive: RFC §13.3 retry safety is exactly the promise that a
   * client repeating a completion it already made gets the same answer back
   * instead of a "not found", and evicting the row breaks that for honest
   * clients on a flaky connection.
   *
   * At most once per clock tick, for the reason documented on `prune()` in
   * `rateLimit.ts`: a scan on every call is O(entries) per request, which turns
   * the component that should absorb a flood into the thing that amplifies it.
   * Records surviving a tick longer cost nothing, since every read path already
   * checks the timestamps itself.
   */
  private sweep(now: number): void {
    if (this.lastSweptAt !== null && now <= this.lastSweptAt) {
      return;
    }

    this.lastSweptAt = now;

    for (const [challengeId, record] of this.records) {
      const retainUntil = record.result_cache_until ?? record.expires_at;

      if (retainUntil < now) {
        this.records.delete(challengeId);
      }
    }
  }

  async create(record: ChallengeRecord): Promise<void> {
    // Swept from here because `create()` is the method an attacker drives: the
    // work of cleaning up is then paid by the same traffic that made the mess.
    this.sweep(this.clock.nowUnix());
    this.records.set(record.challenge_id, { ...record });
  }

  async get(challengeId: string): Promise<ChallengeRecord | null> {
    return this.records.get(challengeId) ?? null;
  }

  async redeem(
    challengeId: string,
    params: { eventId: string; sessionId: string; now: number; resultCacheUntil: number }
  ): Promise<
    | { status: 'redeemed' }
    | { status: 'already_redeemed' }
    | { status: 'not_found' }
    | { status: 'expired' }
  > {
    const record = this.records.get(challengeId);

    if (!record) {
      return { status: 'not_found' };
    }

    if (record.expires_at < params.now || record.state === 'expired') {
      record.state = 'expired';
      return { status: 'expired' };
    }

    if (record.state === 'issued') {
      record.state = 'redeemed';
      record.redeemed_event_id = params.eventId;
      record.redeemed_session_id = params.sessionId;
      record.result_cache_until = params.resultCacheUntil;
      return { status: 'redeemed' };
    }

    return { status: 'already_redeemed' };
  }

  async markExpired(now: number): Promise<number> {
    let count = 0;

    for (const record of this.records.values()) {
      if (record.state === 'issued' && record.expires_at < now) {
        record.state = 'expired';
        count += 1;
      }
    }

    return count;
  }

  async countOutstanding(filter: OutstandingChallengeFilter): Promise<number> {
    let count = 0;

    for (const record of this.records.values()) {
      if (record.state !== 'issued' || record.expires_at < filter.now) {
        continue;
      }

      if (filter.npub !== undefined && record.npub !== filter.npub) {
        continue;
      }

      if (filter.clientIp !== undefined && record.client_ip !== filter.clientIp) {
        continue;
      }

      count += 1;
    }

    return count;
  }

  async recordFailure(
    challengeId: string,
    params: { now: number; maxFailures: number }
  ): Promise<RecordChallengeFailureResult | null> {
    const record = this.records.get(challengeId);

    if (!record || record.state !== 'issued') {
      return null;
    }

    record.failure_count = (record.failure_count ?? 0) + 1;

    if (record.failure_count >= params.maxFailures) {
      record.state = 'failed_terminal';
    }

    return { failure_count: record.failure_count, state: record.state };
  }
}

export class InMemorySessionStore implements SessionStore {
  private readonly sessionsByChallengeId = new Map<string, SessionRecord>();
  private readonly sessionsById = new Map<string, SessionRecord>();
  private readonly sessionsByAccessToken = new Map<string, SessionRecord>();
  /** Holds the current *and* previous token per session, so a replay is recognisable. */
  private readonly sessionsByRefreshToken = new Map<string, SessionRecord>();
  private readonly clock: Clock;
  private lastSweptAt: number | null = null;

  constructor(options: InMemoryStoreOptions = {}) {
    this.clock = options.clock ?? systemClock;
  }

  /**
   * Drop sessions nothing can still act on. Revoking or expiring a session only
   * flags the record, so without this every login ever served stays resident.
   *
   * The bound is `expires_at`, extended to `refresh_expires_at` where refresh is
   * enabled. The later bound is the point of the reuse detection in
   * `rotateRefreshToken()`: a stolen refresh token replayed just after the
   * access token lapsed has to still be *recognised* as belonging to this
   * lineage, and a row deleted at `expires_at` would make it merely unknown,
   * which is the quiet failure mode rather than the loud one.
   *
   * All four index maps are swept together. They are views on the same record,
   * and dropping one while another still points at it is a leak that also lets
   * a token resolve through the surviving index.
   *
   * Once per clock tick, for the reason documented on `prune()` in
   * `rateLimit.ts`.
   */
  private sweep(now: number): void {
    if (this.lastSweptAt !== null && now <= this.lastSweptAt) {
      return;
    }

    this.lastSweptAt = now;

    for (const [sessionId, session] of this.sessionsById) {
      const retainUntil = Math.max(session.expires_at, session.refresh_expires_at ?? 0);

      if (retainUntil >= now) {
        continue;
      }

      this.sessionsById.delete(sessionId);
      this.sessionsByChallengeId.delete(session.challenge_id);
      this.sessionsByAccessToken.delete(session.access_token);

      if (session.refresh_token) {
        this.sessionsByRefreshToken.delete(session.refresh_token);
      }

      if (session.previous_refresh_token) {
        this.sessionsByRefreshToken.delete(session.previous_refresh_token);
      }
    }
  }

  async createForChallenge(record: SessionRecord): Promise<SessionRecord> {
    const existing = this.sessionsByChallengeId.get(record.challenge_id);

    if (existing) {
      return existing;
    }

    const stored = { ...record };
    this.sessionsByChallengeId.set(record.challenge_id, stored);
    this.sessionsById.set(record.session_id, stored);
    this.sessionsByAccessToken.set(record.access_token, stored);

    if (stored.refresh_token) {
      this.sessionsByRefreshToken.set(stored.refresh_token, stored);
    }

    return stored;
  }

  async getBySessionId(sessionId: string): Promise<SessionRecord | null> {
    return this.sessionsById.get(sessionId) ?? null;
  }

  async getByAccessToken(token: string): Promise<SessionRecord | null> {
    // Swept from here because every guarded request passes through it, so the
    // sweep runs on live traffic without needing a timer holding the process
    // open. The once-per-tick bound keeps the cost off the hot path.
    this.sweep(this.clock.nowUnix());
    return this.sessionsByAccessToken.get(token) ?? null;
  }

  async revokeBySessionId(sessionId: string, now: number): Promise<void> {
    const session = this.sessionsById.get(sessionId);

    if (!session) {
      return;
    }

    session.revoked_at = now;
  }

  async revokeByPrincipal(pubkey: string, now: number): Promise<number> {
    let count = 0;

    for (const session of this.sessionsById.values()) {
      if (session.principal_pubkey === pubkey && !session.revoked_at) {
        session.revoked_at = now;
        count += 1;
      }
    }

    return count;
  }

  async getByRefreshToken(token: string): Promise<SessionRecord | null> {
    return this.sessionsByRefreshToken.get(token) ?? null;
  }

  async rotateRefreshToken(
    sessionId: string,
    params: RotateRefreshTokenParams
  ): Promise<SessionRecord | null> {
    const session = this.sessionsById.get(sessionId);

    if (!session || session.refresh_token !== params.expectedRefreshToken) {
      return null;
    }

    // The token two rotations back stops being recognisable here. That is the
    // intended bound: whoever rotated past it already answered for it.
    if (session.previous_refresh_token) {
      this.sessionsByRefreshToken.delete(session.previous_refresh_token);
    }

    this.sessionsByAccessToken.delete(session.access_token);

    session.previous_refresh_token = session.refresh_token;
    session.refresh_token = params.refreshToken;
    session.access_token = params.accessToken;
    session.expires_at = params.expiresAt;
    session.refresh_expires_at = params.refreshExpiresAt;
    session.roles = params.roles;
    session.permissions = params.permissions;

    this.sessionsByAccessToken.set(params.accessToken, session);
    this.sessionsByRefreshToken.set(params.refreshToken, session);

    return session;
  }
}

export class InMemoryAclStore implements AclStore {
  private readonly records = new Map<string, AclRecord>();

  async get(pubkey: string, appId: string): Promise<AclRecord | null> {
    return this.records.get(`${appId}:${pubkey}`) ?? null;
  }

  async upsert(record: AclRecord): Promise<void> {
    this.records.set(`${record.app_id}:${record.principal_pubkey}`, {
      ...record,
      permission_overrides: [...record.permission_overrides],
    });
  }

  async suspend(pubkey: string, appId: string, reason?: string): Promise<void> {
    const key = `${appId}:${pubkey}`;
    const existing = this.records.get(key);

    if (!existing) {
      return;
    }

    this.records.set(key, {
      ...existing,
      suspended: true,
      suspended_reason: reason,
      suspended_at: new Date().toISOString(),
    });
  }

  async unsuspend(pubkey: string, appId: string): Promise<void> {
    const key = `${appId}:${pubkey}`;
    const existing = this.records.get(key);

    if (!existing) {
      return;
    }

    this.records.set(key, {
      ...existing,
      suspended: false,
      suspended_reason: undefined,
      suspended_at: undefined,
    });
  }
}
