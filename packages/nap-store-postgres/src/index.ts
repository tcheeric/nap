import type { ChallengeRecord, SessionRecord } from '@imani/nap-core';
import type {
  AclRecord,
  AclStore,
  ChallengeStore,
  OutstandingChallengeFilter,
  PermissionOverride,
  RecordChallengeFailureResult,
  SessionStore,
} from '@imani/nap-server';
import type { QueryResultRow } from 'pg';
import type { Pool, PoolClient } from 'pg';

type Queryable = Pool | PoolClient;

interface RedeemParams {
  eventId: string;
  sessionId: string;
  now: number;
  resultCacheUntil: number;
}

interface RedeemResult {
  status: 'redeemed' | 'already_redeemed' | 'not_found' | 'expired';
}

function normalizeArray(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }

  return value.filter((entry): entry is string => typeof entry === 'string');
}

function normalizeOverrides(value: unknown): PermissionOverride[] {
  if (!Array.isArray(value)) {
    return [];
  }

  return value.flatMap((entry) => {
    if (
      typeof entry !== 'object' ||
      entry === null ||
      (entry as { action?: unknown }).action === undefined ||
      (entry as { permission?: unknown }).permission === undefined
    ) {
      return [];
    }

    const candidate = entry as {
      action: unknown;
      permission: unknown;
    };

    if (
      (candidate.action !== 'grant' && candidate.action !== 'deny') ||
      typeof candidate.permission !== 'string'
    ) {
      return [];
    }

    return [{
      action: candidate.action,
      permission: candidate.permission,
    }];
  });
}

function asNullableNumber(value: unknown): number | undefined {
  return typeof value === 'number' ? value : undefined;
}

function mapChallengeRecord(row: QueryResultRow): ChallengeRecord {
  return {
    challenge_id: row.challenge_id as string,
    challenge: row.challenge as string,
    npub: row.npub as string,
    pubkey: row.pubkey as string,
    auth_url: row.auth_url as string,
    auth_method: row.auth_method as 'POST',
    state: row.state as ChallengeRecord['state'],
    issued_at: row.issued_at as number,
    expires_at: row.expires_at as number,
    redeemed_event_id: row.redeemed_event_id as string | undefined,
    redeemed_session_id: row.redeemed_session_id as string | undefined,
    result_cache_until: asNullableNumber(row.result_cache_until),
    client_ip: (row.client_ip as string | null) ?? undefined,
    failure_count: asNullableNumber(row.failure_count),
  };
}

function mapSessionRecord(row: QueryResultRow): SessionRecord {
  return {
    session_id: row.session_id as string,
    challenge_id: row.challenge_id as string,
    access_token: row.access_token as string,
    principal_npub: row.principal_npub as string,
    principal_pubkey: row.principal_pubkey as string,
    roles: normalizeArray(row.roles),
    permissions: normalizeArray(row.permissions),
    issued_at: row.issued_at as number,
    expires_at: row.expires_at as number,
    revoked_at: asNullableNumber(row.revoked_at),
    step_up_token: row.step_up_token as string | undefined,
    step_up_expires_at: asNullableNumber(row.step_up_expires_at),
  };
}

function mapAclRecord(row: QueryResultRow): AclRecord {
  return {
    principal_pubkey: row.pubkey as string,
    app_id: row.app_id as string,
    role: row.role as string,
    permission_overrides: normalizeOverrides(row.permission_overrides),
    suspended: row.suspended as boolean,
    suspended_at: row.suspended_at as string | undefined,
    suspended_reason: row.suspended_reason as string | undefined,
    created_at: row.created_at as string | undefined,
    updated_at: row.updated_at as string | undefined,
  };
}

export class PostgresChallengeStore implements ChallengeStore {
  constructor(private readonly pool: Queryable) {}

  async create(record: ChallengeRecord): Promise<void> {
    await this.pool.query(
      `INSERT INTO nap_challenges (
        challenge_id, challenge, npub, pubkey, auth_url, auth_method, state, issued_at, expires_at,
        client_ip
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
      [
        record.challenge_id,
        record.challenge,
        record.npub,
        record.pubkey,
        record.auth_url,
        record.auth_method,
        record.state,
        record.issued_at,
        record.expires_at,
        record.client_ip ?? null,
      ]
    );
  }

  async get(challengeId: string): Promise<ChallengeRecord | null> {
    const result = await this.pool.query(
      'SELECT * FROM nap_challenges WHERE challenge_id = $1',
      [challengeId]
    );

    return result.rowCount === 0 ? null : mapChallengeRecord(result.rows[0]);
  }

  async redeem(challengeId: string, params: RedeemParams): Promise<RedeemResult> {
    const updated = await this.pool.query(
      `UPDATE nap_challenges
       SET state = 'redeemed',
           redeemed_event_id = $1,
           redeemed_session_id = $2,
           result_cache_until = $3
       WHERE challenge_id = $4 AND state = 'issued' AND expires_at > $5`,
      [
        params.eventId,
        params.sessionId,
        params.resultCacheUntil,
        challengeId,
        params.now,
      ]
    );

    if (updated.rowCount === 1) {
      return { status: 'redeemed' };
    }

    const record = await this.get(challengeId);

    if (!record) {
      return { status: 'not_found' };
    }

    if (record.state === 'expired' || record.expires_at < params.now) {
      return { status: 'expired' };
    }

    return { status: 'already_redeemed' };
  }

  async markExpired(now: number): Promise<number> {
    const result = await this.pool.query(
      `UPDATE nap_challenges
       SET state = 'expired'
       WHERE state = 'issued' AND expires_at < $1`,
      [now]
    );

    return result.rowCount ?? 0;
  }

  async countOutstanding(filter: OutstandingChallengeFilter): Promise<number> {
    const result = await this.pool.query(
      `SELECT COUNT(*)::int AS count
       FROM nap_challenges
       WHERE state = 'issued'
         AND expires_at >= $1
         AND ($2::text IS NULL OR npub = $2)
         AND ($3::text IS NULL OR client_ip = $3)`,
      [filter.now, filter.npub ?? null, filter.clientIp ?? null]
    );

    return (result.rows[0]?.count as number | undefined) ?? 0;
  }

  /**
   * Increments and flips to `failed_terminal` in one statement so concurrent
   * attempts on the same challenge cannot lose increments to a read-modify-write
   * race and slip past the cap.
   */
  async recordFailure(
    challengeId: string,
    params: { now: number; maxFailures: number }
  ): Promise<RecordChallengeFailureResult | null> {
    const result = await this.pool.query(
      `UPDATE nap_challenges
       SET failure_count = COALESCE(failure_count, 0) + 1,
           state = CASE
             WHEN COALESCE(failure_count, 0) + 1 >= $2 THEN 'failed_terminal'
             ELSE state
           END
       WHERE challenge_id = $1 AND state = 'issued'
       RETURNING failure_count, state`,
      [challengeId, params.maxFailures]
    );

    if (result.rowCount === 0) {
      return null;
    }

    return {
      failure_count: result.rows[0].failure_count as number,
      state: result.rows[0].state as ChallengeRecord['state'],
    };
  }
}

export class PostgresSessionStore implements SessionStore {
  constructor(private readonly pool: Queryable) {}

  async createForChallenge(record: SessionRecord): Promise<SessionRecord> {
    const result = await this.pool.query(
      `INSERT INTO nap_sessions (
        session_id, challenge_id, access_token, principal_npub, principal_pubkey,
        roles, permissions, issued_at, expires_at, step_up_token, step_up_expires_at
      ) VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::jsonb, $8, $9, $10, $11)
      ON CONFLICT (challenge_id) DO NOTHING`,
      [
        record.session_id,
        record.challenge_id,
        record.access_token,
        record.principal_npub,
        record.principal_pubkey,
        JSON.stringify(record.roles),
        JSON.stringify(record.permissions),
        record.issued_at,
        record.expires_at,
        record.step_up_token ?? null,
        record.step_up_expires_at ?? null,
      ]
    );

    if (result.rowCount === 1) {
      return record;
    }

    const existing = await this.findBy('challenge_id', record.challenge_id);

    if (!existing) {
      throw new Error(
        `PostgresSessionStore could not reload session for challenge '${record.challenge_id}'`
      );
    }

    return existing;
  }

  async getBySessionId(sessionId: string): Promise<SessionRecord | null> {
    return this.findBy('session_id', sessionId);
  }

  async getByAccessToken(token: string): Promise<SessionRecord | null> {
    return this.findBy('access_token', token);
  }

  async revokeBySessionId(sessionId: string, now: number): Promise<void> {
    await this.pool.query(
      `UPDATE nap_sessions
       SET revoked_at = $1
       WHERE session_id = $2 AND revoked_at IS NULL`,
      [now, sessionId]
    );
  }

  async revokeByPrincipal(pubkey: string, now: number): Promise<number> {
    const result = await this.pool.query(
      `UPDATE nap_sessions
       SET revoked_at = $1
       WHERE principal_pubkey = $2 AND revoked_at IS NULL`,
      [now, pubkey]
    );

    return result.rowCount ?? 0;
  }

  private async findBy(
    column: 'session_id' | 'access_token' | 'challenge_id',
    value: string
  ): Promise<SessionRecord | null> {
    const result = await this.pool.query(
      `SELECT *
       FROM nap_sessions
       WHERE ${column} = $1 AND revoked_at IS NULL`,
      [value]
    );

    return result.rowCount === 0 ? null : mapSessionRecord(result.rows[0]);
  }
}

export class PostgresAclStore implements AclStore {
  constructor(private readonly pool: Queryable) {}

  async get(pubkey: string, appId: string): Promise<AclRecord | null> {
    const result = await this.pool.query(
      'SELECT * FROM nap_acl WHERE pubkey = $1 AND app_id = $2',
      [pubkey, appId]
    );

    return result.rowCount === 0 ? null : mapAclRecord(result.rows[0]);
  }

  async upsert(record: AclRecord): Promise<void> {
    await this.pool.query(
      `INSERT INTO nap_acl (
        app_id, pubkey, role, permission_overrides, suspended, suspended_at, suspended_reason
      ) VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7)
      ON CONFLICT (app_id, pubkey) DO UPDATE
        SET role = EXCLUDED.role,
            permission_overrides = EXCLUDED.permission_overrides,
            suspended = EXCLUDED.suspended,
            suspended_at = EXCLUDED.suspended_at,
            suspended_reason = EXCLUDED.suspended_reason,
            updated_at = NOW()`,
      [
        record.app_id,
        record.principal_pubkey,
        record.role,
        JSON.stringify(record.permission_overrides),
        record.suspended,
        record.suspended_at ?? null,
        record.suspended_reason ?? null,
      ]
    );
  }

  async suspend(pubkey: string, appId: string, reason?: string): Promise<void> {
    await this.pool.query(
      `UPDATE nap_acl
       SET suspended = TRUE,
           suspended_at = NOW(),
           suspended_reason = $3,
           updated_at = NOW()
       WHERE pubkey = $1 AND app_id = $2`,
      [pubkey, appId, reason ?? null]
    );
  }

  async unsuspend(pubkey: string, appId: string): Promise<void> {
    await this.pool.query(
      `UPDATE nap_acl
       SET suspended = FALSE,
           suspended_at = NULL,
           suspended_reason = NULL,
           updated_at = NOW()
       WHERE pubkey = $1 AND app_id = $2`,
      [pubkey, appId]
    );
  }
}
