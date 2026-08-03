import type { ChallengeRecord, SessionRecord } from '@imani/nap-core';
import type {
  AclRecord,
  AclStore,
  ChallengeStore,
  OutstandingChallengeFilter,
  RecordChallengeFailureResult,
  SessionStore,
} from './types.js';

export class InMemoryChallengeStore implements ChallengeStore {
  private readonly records = new Map<string, ChallengeRecord>();

  async create(record: ChallengeRecord): Promise<void> {
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

  async createForChallenge(record: SessionRecord): Promise<SessionRecord> {
    const existing = this.sessionsByChallengeId.get(record.challenge_id);

    if (existing) {
      return existing;
    }

    const stored = { ...record };
    this.sessionsByChallengeId.set(record.challenge_id, stored);
    this.sessionsById.set(record.session_id, stored);
    this.sessionsByAccessToken.set(record.access_token, stored);

    return stored;
  }

  async getBySessionId(sessionId: string): Promise<SessionRecord | null> {
    return this.sessionsById.get(sessionId) ?? null;
  }

  async getByAccessToken(token: string): Promise<SessionRecord | null> {
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
