import { randomBytes as nodeRandomBytes } from 'node:crypto';
import {
  encodeBase64UrlBytes,
  failure,
  isRetryableNapError,
  type AuthCompleteRequest,
  type AuthFailureResponse,
  type AuthSuccessResponse,
  type ChallengeRecord,
  type SessionRecord,
  validateChallengeBoundCreatedAt,
  verifyNip98Completion,
} from '@imani/nap-core';
import { nip19 } from 'nostr-tools';
import type {
  AuditLogger,
  Clock,
  IssueChallengeInput,
  IssueChallengeResult,
  MalformedRequestFailure,
  NapServerOptions,
  ParsedAuthCompleteRequest,
  NapServer,
  RandomSource,
  VerifyCompletionInput,
  VerifyCompletionOutcome,
} from './types.js';

const DEFAULT_CHALLENGE_TTL_SECONDS = 60;
const DEFAULT_RESULT_CACHE_TTL_SECONDS = 30;
const DEFAULT_SESSION_TTL_SECONDS = 900;
const DEFAULT_MAX_CLOCK_SKEW_SECONDS = 60;
const DEFAULT_LOWER_BOUND_GRACE_SECONDS = 30;
const DEFAULT_UPPER_BOUND_GRACE_SECONDS = 5;

const defaultClock: Clock = {
  nowUnix() {
    return Math.floor(Date.now() / 1000);
  },
};

const defaultRandomSource: RandomSource = {
  randomBytes(length: number) {
    return nodeRandomBytes(length);
  },
};

const noopAuditLogger: AuditLogger = {
  log() {
    return undefined;
  },
};

function base64Url(bytes: Uint8Array): string {
  return encodeBase64UrlBytes(bytes);
}

function decodeNpub(npub: string): string | null {
  try {
    const decoded = nip19.decode(npub);

    if (decoded.type !== 'npub') {
      return null;
    }

    return typeof decoded.data === 'string' ? decoded.data : null;
  } catch {
    return null;
  }
}

function malformedRequestFailure(): MalformedRequestFailure {
  return {
    ok: false,
    malformed: true,
    publicResponse: {
      status: 400,
      body: {
        status: 'error',
        message: 'bad request',
      },
    },
  };
}

async function logFailure(
  auditLogger: AuditLogger,
  code: string,
  details?: Record<string, unknown>
): Promise<void> {
  await auditLogger.log({
    code,
    outcome: 'failure',
    details,
  });
}

async function logSuccess(
  auditLogger: AuditLogger,
  details?: Record<string, unknown>
): Promise<void> {
  await auditLogger.log({
    code: 'NAP_COMPLETE_SUCCESS',
    outcome: 'success',
    details,
  });
}

function createSessionRecord(
  challenge: ChallengeRecord,
  now: number,
  sessionTtlSeconds: number,
  randomSource: RandomSource,
  roles: string[],
  permissions: string[]
): SessionRecord {
  return {
    session_id: base64Url(randomSource.randomBytes(24)),
    challenge_id: challenge.challenge_id,
    access_token: base64Url(randomSource.randomBytes(32)),
    principal_npub: challenge.npub,
    principal_pubkey: challenge.pubkey,
    roles,
    permissions,
    issued_at: now,
    expires_at: now + sessionTtlSeconds,
  };
}

export function createSystemClock(): Clock {
  return defaultClock;
}

export function createNodeRandomSource(): RandomSource {
  return defaultRandomSource;
}

export function createNoopAuditLogger(): AuditLogger {
  return noopAuditLogger;
}

export function parseAuthCompleteRequest(rawBody: Uint8Array): ParsedAuthCompleteRequest {
  try {
    const parsed = JSON.parse(new TextDecoder().decode(rawBody)) as Record<string, unknown>;

    if (typeof parsed.challenge_id !== 'string' || parsed.challenge_id.length === 0) {
      return null;
    }

    return {
      challenge_id: parsed.challenge_id,
    };
  } catch {
    return null;
  }
}

export async function issueChallenge(
  input: IssueChallengeInput,
  options: NapServerOptions
): Promise<IssueChallengeResult> {
  const clock = options.clock ?? defaultClock;
  const randomSource = options.randomSource ?? defaultRandomSource;
  const auditLogger = options.auditLogger ?? noopAuditLogger;
  const ttl = options.challengeTtlSeconds ?? DEFAULT_CHALLENGE_TTL_SECONDS;
  const pubkey = decodeNpub(input.npub);

  if (!pubkey) {
    await logFailure(auditLogger, 'NAP_INIT_INVALID_NPUB', { npub: input.npub });
    return {
      ok: false,
      code: 'NAP_INIT_INVALID_NPUB',
      retryable: isRetryableNapError('NAP_INIT_INVALID_NPUB'),
    };
  }

  const now = clock.nowUnix();
  const record: ChallengeRecord = {
    challenge_id: base64Url(randomSource.randomBytes(12)),
    challenge: base64Url(randomSource.randomBytes(32)),
    npub: input.npub,
    pubkey,
    auth_url: input.authUrl,
    auth_method: input.authMethod ?? 'POST',
    issued_at: now,
    expires_at: now + ttl,
    state: 'issued',
  };

  try {
    await options.challengeStore.create(record);
    return {
      ok: true,
      value: {
        challenge_id: record.challenge_id,
        challenge: record.challenge,
        auth_url: record.auth_url,
        auth_method: record.auth_method,
        issued_at: record.issued_at,
        expires_at: record.expires_at,
      },
    };
  } catch {
    await logFailure(auditLogger, 'NAP_INIT_INTERNAL', { npub: input.npub });
    return {
      ok: false,
      code: 'NAP_INIT_INTERNAL',
      retryable: isRetryableNapError('NAP_INIT_INTERNAL'),
    };
  }
}

export async function verifyCompletion(
  input: VerifyCompletionInput,
  options: NapServerOptions
): Promise<VerifyCompletionOutcome> {
  const clock = options.clock ?? defaultClock;
  const randomSource = options.randomSource ?? defaultRandomSource;
  const auditLogger = options.auditLogger ?? noopAuditLogger;
  const maxClockSkewSeconds = options.maxClockSkewSeconds ?? DEFAULT_MAX_CLOCK_SKEW_SECONDS;
  const lowerBoundGraceSeconds = options.lowerBoundGraceSeconds ?? DEFAULT_LOWER_BOUND_GRACE_SECONDS;
  const upperBoundGraceSeconds = options.upperBoundGraceSeconds ?? DEFAULT_UPPER_BOUND_GRACE_SECONDS;
  const sessionTtlSeconds = options.sessionTtlSeconds ?? DEFAULT_SESSION_TTL_SECONDS;
  const resultCacheTtlSeconds = options.resultCacheTtlSeconds ?? DEFAULT_RESULT_CACHE_TTL_SECONDS;
  const body = parseAuthCompleteRequest(input.rawBody);

  if (!body) {
    return malformedRequestFailure();
  }

  const now = clock.nowUnix();
  const proof = verifyNip98Completion({
    authorization: input.authorization,
    method: input.method,
    url: input.url,
    body,
    rawBody: input.rawBody,
    now,
    maxClockSkewSeconds,
  });

  if (!proof.ok) {
    await logFailure(auditLogger, proof.code, { url: input.url });
    return proof;
  }

  const challenge = await options.challengeStore.get(proof.value.challengeId);

  if (!challenge) {
    await logFailure(auditLogger, 'NAP_COMPLETE_UNKNOWN_CHALLENGE', { challenge_id: proof.value.challengeId });
    return failure('NAP_COMPLETE_UNKNOWN_CHALLENGE');
  }

  if (challenge.expires_at < now || challenge.state === 'expired') {
    await logFailure(auditLogger, 'NAP_COMPLETE_EXPIRED_CHALLENGE', { challenge_id: challenge.challenge_id });
    return failure('NAP_COMPLETE_EXPIRED_CHALLENGE');
  }

  if (challenge.challenge !== proof.value.challenge) {
    await logFailure(auditLogger, 'NAP_COMPLETE_CHALLENGE_MISMATCH', { challenge_id: challenge.challenge_id });
    return failure('NAP_COMPLETE_CHALLENGE_MISMATCH');
  }

  if (challenge.pubkey !== proof.value.event.pubkey) {
    await logFailure(auditLogger, 'NAP_COMPLETE_PRINCIPAL_MISMATCH', { challenge_id: challenge.challenge_id });
    return failure('NAP_COMPLETE_PRINCIPAL_MISMATCH');
  }

  const createdAtWindow = validateChallengeBoundCreatedAt(
    proof.value.event.created_at,
    challenge.issued_at,
    challenge.expires_at,
    lowerBoundGraceSeconds,
    upperBoundGraceSeconds
  );

  if (createdAtWindow !== true) {
    await logFailure(auditLogger, createdAtWindow.code, { challenge_id: challenge.challenge_id });
    return createdAtWindow;
  }

  const aclDecision = await options.aclResolver.resolve(challenge.npub, challenge.pubkey);

  if (!aclDecision.allowed) {
    await logFailure(auditLogger, 'NAP_COMPLETE_ACL_DENIED', { challenge_id: challenge.challenge_id });
    return failure('NAP_COMPLETE_ACL_DENIED');
  }

  const session = await options.sessionStore.createForChallenge(
    createSessionRecord(
      challenge,
      now,
      sessionTtlSeconds,
      randomSource,
      aclDecision.roles,
      aclDecision.permissions
    )
  );

  const redeemResult = await options.challengeStore.redeem(challenge.challenge_id, {
    eventId: proof.value.event.id,
    sessionId: session.session_id,
    now,
    resultCacheUntil: now + resultCacheTtlSeconds,
  });

  if (redeemResult.status === 'redeemed') {
    await logSuccess(auditLogger, { challenge_id: challenge.challenge_id, session_id: session.session_id });
    return {
      ok: true,
      session,
    };
  }

  if (redeemResult.status === 'expired') {
    await logFailure(auditLogger, 'NAP_COMPLETE_EXPIRED_CHALLENGE', { challenge_id: challenge.challenge_id });
    return failure('NAP_COMPLETE_EXPIRED_CHALLENGE');
  }

  if (redeemResult.status === 'not_found') {
    await logFailure(auditLogger, 'NAP_COMPLETE_UNKNOWN_CHALLENGE', { challenge_id: challenge.challenge_id });
    return failure('NAP_COMPLETE_UNKNOWN_CHALLENGE');
  }

  const redeemedChallenge = await options.challengeStore.get(challenge.challenge_id);

  if (
    redeemedChallenge?.redeemed_event_id === proof.value.event.id &&
    redeemedChallenge.redeemed_session_id &&
    (!redeemedChallenge.result_cache_until || redeemedChallenge.result_cache_until >= now)
  ) {
    const existingSession = await options.sessionStore.getBySessionId(redeemedChallenge.redeemed_session_id);

    if (existingSession) {
      await logSuccess(auditLogger, {
        challenge_id: challenge.challenge_id,
        session_id: existingSession.session_id,
        retry: true,
      });
      return {
        ok: true,
        session: existingSession,
      };
    }

    await logFailure(auditLogger, 'NAP_COMPLETE_INTERNAL', {
      challenge_id: challenge.challenge_id,
      reason: 'redeemed_session_missing',
    });
    return failure('NAP_COMPLETE_INTERNAL');
  }

  await logFailure(auditLogger, 'NAP_COMPLETE_REDEEMED_CHALLENGE', {
    challenge_id: challenge.challenge_id,
  });
  return failure('NAP_COMPLETE_REDEEMED_CHALLENGE');
}

export function toPublicAuthSuccess(session: SessionRecord): AuthSuccessResponse {
  return {
    status: 'ok',
    access_token: session.access_token,
    token_type: 'Bearer',
    expires_at: session.expires_at,
    step_up_token: session.step_up_token,
    step_up_expires_at: session.step_up_expires_at,
    principal: {
      npub: session.principal_npub,
      pubkey: session.principal_pubkey,
    },
    roles: session.roles,
    permissions: session.permissions,
  };
}

export function toPublicAuthFailure(): { status: 401; body: AuthFailureResponse } {
  return {
    status: 401,
    body: {
      status: 'error',
      message: 'authentication failed',
    },
  };
}

export function createNapServer(options: NapServerOptions): NapServer {
  return {
    issueChallenge(input: IssueChallengeInput): Promise<IssueChallengeResult> {
      return issueChallenge(input, options);
    },
    verifyCompletion(input: VerifyCompletionInput): Promise<VerifyCompletionOutcome> {
      return verifyCompletion(input, options);
    },
    toPublicAuthSuccess,
    toPublicAuthFailure,
  };
}
