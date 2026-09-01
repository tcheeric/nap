import { randomBytes as nodeRandomBytes } from 'node:crypto';
import {
  encodeBase64UrlBytes,
  failure,
  isRetryableNapError,
  type AuthCompleteRequest,
  type VoucherCredential,
  type AuthFailureResponse,
  type AuthSuccessResponse,
  type ChallengeRecord,
  type NapErrorCode,
  type SessionRecord,
  type VerifyCompleteFailure,
  validateChallengeBoundCreatedAt,
  verifyNip98Completion,
} from '@imani/nap-core';
import { nip19 } from 'nostr-tools';
import { countTotal, withMetrics } from './metrics.js';
import { createInMemoryRateLimiter } from './rateLimit.js';
import type {
  AclResolver,
  AuditLogger,
  Clock,
  IssueChallengeInput,
  IssueChallengeResult,
  MalformedRequestFailure,
  NapServerOptions,
  ParsedAuthCompleteRequest,
  NapServer,
  RandomSource,
  RateLimiter,
  RateLimitKey,
  SessionStore,
  VerifyCompletionInput,
  VerifyCompletionOutcome,
} from './types.js';

const DEFAULT_CHALLENGE_TTL_SECONDS = 60;
const DEFAULT_RESULT_CACHE_TTL_SECONDS = 30;
const DEFAULT_SESSION_TTL_SECONDS = 900;
const DEFAULT_MAX_CLOCK_SKEW_SECONDS = 60;
const DEFAULT_LOWER_BOUND_GRACE_SECONDS = 30;
const DEFAULT_UPPER_BOUND_GRACE_SECONDS = 5;
const DEFAULT_STEP_UP_TTL_SECONDS = 600;
const DEFAULT_MAX_OUTSTANDING_PER_NPUB = 10;
const DEFAULT_MAX_OUTSTANDING_PER_IP = 30;
const DEFAULT_MAX_FAILURES_PER_CHALLENGE = 5;
const DEFAULT_MIN_AUTH_RESPONSE_MILLIS = 100;
const DEFAULT_RESPONSE_JITTER_MILLIS = 25;

/** RFC §10.1: `expires_at` MUST be no more than 60 seconds after `issued_at`. */
export const MAX_CHALLENGE_TTL_SECONDS = 60;

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
  permissions: string[],
  stepUp?: { ttlSeconds: number },
  refreshTtlSeconds?: number
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
    ...(stepUp
      ? {
          step_up_token: base64Url(randomSource.randomBytes(32)),
          step_up_expires_at: now + stepUp.ttlSeconds,
        }
      : {}),
    ...(refreshTtlSeconds
      ? {
          refresh_token: base64Url(randomSource.randomBytes(32)),
          refresh_expires_at: now + refreshTtlSeconds,
        }
      : {}),
  };
}

/**
 * RFC §10.1 caps a challenge at 60 seconds past issuance. A longer TTL widens
 * the window in which a captured completion proof is still replayable, so an
 * over-long value is a configuration error rather than something to clamp
 * silently.
 */
function resolveChallengeTtl(options: NapServerOptions): number {
  const ttl = options.challengeTtlSeconds ?? DEFAULT_CHALLENGE_TTL_SECONDS;

  if (!Number.isFinite(ttl) || ttl <= 0 || ttl > MAX_CHALLENGE_TTL_SECONDS) {
    throw new Error(
      `challengeTtlSeconds must be between 1 and ${MAX_CHALLENGE_TTL_SECONDS} (RFC §10.1), got ${ttl}`
    );
  }

  return ttl;
}

function sleep(millis: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, millis);
  });
}

/**
 * Hold the response until a fixed floor has elapsed (RFC §15).
 *
 * The generic 401 hides which check failed; response latency does not, and an
 * unknown principal answers measurably sooner than one that reached signature
 * verification. Padding every answer to the same floor removes the difference
 * an attacker can measure. The jitter on top costs nothing and blunts
 * averaging attacks against the floor itself.
 */
async function padAuthResponse(
  startedAtMillis: number,
  options: NapServerOptions,
  randomSource: RandomSource
): Promise<void> {
  const floor = options.minAuthResponseMillis ?? DEFAULT_MIN_AUTH_RESPONSE_MILLIS;
  const jitterRange = options.responseJitterMillis ?? DEFAULT_RESPONSE_JITTER_MILLIS;

  if (floor <= 0 && jitterRange <= 0) {
    return;
  }

  const jitter =
    jitterRange > 0 ? (randomSource.randomBytes(1)[0] ?? 0) % (jitterRange + 1) : 0;
  const remaining = floor + jitter - (Date.now() - startedAtMillis);

  if (remaining > 0) {
    await sleep(remaining);
  }
}

/**
 * Default limiters, one per options object so repeated calls share a window.
 *
 * Keyed on `options` rather than held in a module-level singleton because two
 * servers in one process — a test suite, a multi-tenant host — must not share a
 * budget. `WeakMap` so an options object going out of scope takes its counters
 * with it.
 */
const defaultRateLimiters = new WeakMap<NapServerOptions, RateLimiter>();

function resolveRateLimiter(options: NapServerOptions): RateLimiter | null {
  // `null` is an explicit opt-out; `undefined` just means "not configured".
  if (options.rateLimiter === null) {
    return null;
  }

  if (options.rateLimiter) {
    return options.rateLimiter;
  }

  let limiter = defaultRateLimiters.get(options);

  if (!limiter) {
    limiter = createInMemoryRateLimiter();
    defaultRateLimiters.set(options, limiter);
  }

  return limiter;
}

async function checkRateLimit(
  options: NapServerOptions,
  key: RateLimitKey
): Promise<{ allowed: true } | { allowed: false; retryAfterSeconds?: number }> {
  const rateLimiter = resolveRateLimiter(options);

  if (!rateLimiter) {
    return { allowed: true };
  }

  const decision = await rateLimiter.check(key);

  return decision.allowed
    ? { allowed: true }
    : { allowed: false, retryAfterSeconds: decision.retryAfterSeconds };
}

/** A bech32 npub is 63 characters. */
const MAX_NPUB_KEY_LENGTH = 128;

/**
 * The npub reaches the limiter before `decodeNpub` has looked at it, so it is
 * still arbitrary caller input at that point. Oversized values are dropped
 * rather than truncated: truncation would let two distinct npubs share one
 * budget, which is a lockout primitive of its own.
 */
function boundedNpub(npub: string): string | undefined {
  return npub.length <= MAX_NPUB_KEY_LENGTH ? npub : undefined;
}

/**
 * RFC §17.4: bound outstanding challenges per principal and per caller address.
 *
 * Returns the exceeded dimension, or null. Skipped entirely when the store does
 * not implement `countOutstanding` — a store that cannot count cannot cap, and
 * failing closed here would break every existing custom store.
 */
async function findExceededOutstandingCap(
  options: NapServerOptions,
  npub: string,
  clientIp: string | undefined,
  now: number
): Promise<'npub' | 'ip' | null> {
  const countOutstanding = options.challengeStore.countOutstanding?.bind(
    options.challengeStore
  );

  if (!countOutstanding) {
    return null;
  }

  const perNpub = options.maxOutstandingChallengesPerNpub ?? DEFAULT_MAX_OUTSTANDING_PER_NPUB;
  const perIp = options.maxOutstandingChallengesPerIp ?? DEFAULT_MAX_OUTSTANDING_PER_IP;
  const countsIp = Boolean(clientIp) && perIp > 0;

  // Both counts in flight together: they are independent, and the npub check
  // rejecting is the rare case, so serialising them just paid a round trip on
  // every /auth/init to save a query on almost none of them.
  // The npub count is scoped to the caller's address. An npub is public and
  // /auth/init is unauthenticated, so counting one npub across every address
  // lets anyone fill a stranger's slots and lock them out of logging in. The
  // per-address cap already bounds total storage, which is what the cap is for.
  const [npubCount, ipCount] = await Promise.all([
    perNpub > 0
      ? countOutstanding(clientIp ? { npub, clientIp, now } : { npub, now })
      : Promise.resolve(0),
    countsIp ? countOutstanding({ clientIp, now }) : Promise.resolve(0),
  ]);

  if (perNpub > 0 && npubCount >= perNpub) {
    return 'npub';
  }

  if (countsIp && ipCount >= perIp) {
    return 'ip';
  }

  return null;
}

/**
 * RFC §13.4: cap failures per challenge.
 *
 * Called only after the challenge has been loaded and matched, so a wrong
 * `challenge_id` cannot burn down another principal's live challenge. Returns
 * whether this attempt exhausted the budget, purely so the audit trail can say
 * so — the caller's public response is the same 401 either way.
 */
async function recordChallengeFailure(
  options: NapServerOptions,
  auditLogger: AuditLogger,
  challengeId: string,
  now: number
): Promise<void> {
  const recordFailure = options.challengeStore.recordFailure?.bind(options.challengeStore);

  if (!recordFailure) {
    return;
  }

  const maxFailures = options.maxFailuresPerChallenge ?? DEFAULT_MAX_FAILURES_PER_CHALLENGE;

  if (maxFailures <= 0) {
    return;
  }

  const result = await recordFailure(challengeId, { now, maxFailures });

  if (result?.state === 'failed_terminal') {
    await logFailure(auditLogger, 'NAP_COMPLETE_FAILED_TERMINAL', {
      challenge_id: challengeId,
      failure_count: result.failure_count,
    });
  }
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

    if (parsed.step_up !== undefined && typeof parsed.step_up !== 'boolean') {
      return null;
    }

    const voucher = parseVoucherCredential(parsed.voucher);

    // Present but malformed is a rejection, not a silent drop. Dropping it would
    // turn a client bug into a fall-through to the stored ACL, which for a
    // burner key means a generic denial that looks nothing like the real cause.
    if (parsed.voucher !== undefined && voucher === null) {
      return null;
    }

    return {
      challenge_id: parsed.challenge_id,
      ...(parsed.step_up === true ? { step_up: true as const } : {}),
      ...(voucher ? { voucher } : {}),
    };
  } catch {
    return null;
  }
}

/**
 * Shape-check a presented voucher credential, or `null` when it is unusable.
 *
 * Structure only. Nothing here decides whether the voucher is *valid* — the
 * mint allowlist, the DLEQ, the binding to the completion pubkey, and the
 * liveness check all happen later, after NIP-98 verification has already
 * proven key control. This exists so a malformed body is rejected before any of
 * that, and in particular before anything reaches out to a mint.
 *
 * Deliberately does not validate the *contents* of `mint_url`: whether it is an
 * allowed origin is the allowlist's decision, and duplicating it here would put
 * a second, weaker copy of the highest-severity check in the codebase.
 */
function parseVoucherCredential(value: unknown): VoucherCredential | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return null;
  }

  const candidate = value as Record<string, unknown>;
  const dleq = candidate.dleq;

  const hasStrings = (['mint_url', 'keyset_id', 'secret', 'signature'] as const).every(
    (key) => typeof candidate[key] === 'string' && (candidate[key] as string).length > 0
  );

  if (!hasStrings) {
    return null;
  }

  // A non-integer or negative amount cannot select a key from a keyset, and
  // NaN would compare false against every amount without looking wrong.
  if (typeof candidate.amount !== 'number' || !Number.isInteger(candidate.amount)
      || candidate.amount <= 0) {
    return null;
  }

  if (typeof dleq !== 'object' || dleq === null || Array.isArray(dleq)) {
    return null;
  }

  const proof = dleq as Record<string, unknown>;
  const hasDleq = (['e', 's', 'r'] as const).every(
    (key) => typeof proof[key] === 'string' && (proof[key] as string).length > 0
  );

  if (!hasDleq) {
    return null;
  }

  if (candidate.witness !== undefined && typeof candidate.witness !== 'string') {
    return null;
  }

  // Rebuilt rather than passed through, so an unexpected field in the body
  // cannot ride along into the resolver.
  return {
    mint_url: candidate.mint_url as string,
    keyset_id: candidate.keyset_id as string,
    secret: candidate.secret as string,
    signature: candidate.signature as string,
    amount: candidate.amount,
    dleq: { e: proof.e as string, s: proof.s as string, r: proof.r as string },
    ...(typeof candidate.witness === 'string' ? { witness: candidate.witness } : {}),
  };
}

export async function issueChallenge(
  input: IssueChallengeInput,
  options: NapServerOptions
): Promise<IssueChallengeResult> {
  const startedAtMillis = Date.now();
  const randomSource = options.randomSource ?? defaultRandomSource;
  let result: IssueChallengeResult | undefined;

  // `finally`, so a store outage answers on the same schedule as a refusal. An
  // unpadded 500 next to padded 401s is itself a distinguishable response.
  try {
    result = await issueChallengeUnpadded(input, options);
    return result;
  } finally {
    if (!isRateLimited(result, 'NAP_INIT_RATE_LIMITED')) {
      await padAuthResponse(startedAtMillis, options, randomSource);
    }
  }
}

/**
 * A 429 is not padded. Its status code already sets it apart from the 401s the
 * floor exists to make indistinguishable, so holding the response would only
 * give a caller who is already over the limit a free hold on the server for the
 * floor's duration — the amplification the limiter is there to prevent.
 */
function isRateLimited(
  result: IssueChallengeResult | VerifyCompletionOutcome | RefreshSessionOutcome | undefined,
  code: NapErrorCode
): boolean {
  return result !== undefined && !result.ok && 'code' in result && result.code === code;
}

async function issueChallengeUnpadded(
  input: IssueChallengeInput,
  options: NapServerOptions
): Promise<IssueChallengeResult> {
  const clock = options.clock ?? defaultClock;
  const randomSource = options.randomSource ?? defaultRandomSource;
  const auditLogger = withMetrics(options.auditLogger ?? noopAuditLogger, options.metrics);
  const ttl = resolveChallengeTtl(options);

  countTotal(options.metrics, 'auth_init_total');

  const rateLimit = await checkRateLimit(options, {
    scope: 'init',
    npub: boundedNpub(input.npub),
    clientIp: input.clientIp,
  });

  if (!rateLimit.allowed) {
    await auditLogger.log({
      code: 'NAP_INIT_RATE_LIMITED',
      outcome: 'rate_limited',
      details: { npub: input.npub },
    });
    return {
      ok: false,
      code: 'NAP_INIT_RATE_LIMITED',
      retryable: isRetryableNapError('NAP_INIT_RATE_LIMITED'),
      retryAfterSeconds: rateLimit.retryAfterSeconds,
    };
  }

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
  const exceeded = await findExceededOutstandingCap(options, input.npub, input.clientIp, now);

  if (exceeded) {
    // Reported as rate limiting rather than a distinct code: the cap exists to
    // bound storage, and telling the caller which dimension they hit tells them
    // how to spread the load to evade it.
    await auditLogger.log({
      code: 'NAP_INIT_RATE_LIMITED',
      outcome: 'rate_limited',
      details: { npub: input.npub, cap: exceeded },
    });
    return {
      ok: false,
      code: 'NAP_INIT_RATE_LIMITED',
      retryable: isRetryableNapError('NAP_INIT_RATE_LIMITED'),
      // A slot frees when an outstanding challenge expires, so the TTL is the
      // honest answer. Without it the adapter sends a 429 with no `Retry-After`
      // and a caller who legitimately hit the cap can only guess.
      retryAfterSeconds: ttl,
    };
  }

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
    ...(input.clientIp ? { client_ip: input.clientIp } : {}),
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
  const startedAtMillis = Date.now();
  const randomSource = options.randomSource ?? defaultRandomSource;
  let outcome: VerifyCompletionOutcome | undefined;

  try {
    outcome = await verifyCompletionUnpadded(input, options);
    return outcome;
  } finally {
    if (!isRateLimited(outcome, 'NAP_COMPLETE_RATE_LIMITED')) {
      await padAuthResponse(startedAtMillis, options, randomSource);
    }
  }
}

async function verifyCompletionUnpadded(
  input: VerifyCompletionInput,
  options: NapServerOptions
): Promise<VerifyCompletionOutcome> {
  const clock = options.clock ?? defaultClock;
  const randomSource = options.randomSource ?? defaultRandomSource;
  const auditLogger = withMetrics(options.auditLogger ?? noopAuditLogger, options.metrics);
  const maxClockSkewSeconds = options.maxClockSkewSeconds ?? DEFAULT_MAX_CLOCK_SKEW_SECONDS;
  const lowerBoundGraceSeconds = options.lowerBoundGraceSeconds ?? DEFAULT_LOWER_BOUND_GRACE_SECONDS;
  const upperBoundGraceSeconds = options.upperBoundGraceSeconds ?? DEFAULT_UPPER_BOUND_GRACE_SECONDS;
  const sessionTtlSeconds = options.sessionTtlSeconds ?? DEFAULT_SESSION_TTL_SECONDS;
  const resultCacheTtlSeconds = options.resultCacheTtlSeconds ?? DEFAULT_RESULT_CACHE_TTL_SECONDS;
  const stepUpTtlSeconds = options.stepUpTtlSeconds ?? DEFAULT_STEP_UP_TTL_SECONDS;

  // Counted before the body is parsed, so a malformed request — which returns
  // below without reaching any audit point — still shows up as attempted load.
  countTotal(options.metrics, 'auth_complete_total');

  const body = parseAuthCompleteRequest(input.rawBody);

  // RFC §13.4(1): reject malformed requests before touching challenge state.
  if (!body) {
    return malformedRequestFailure();
  }

  const rateLimit = await checkRateLimit(options, {
    scope: 'complete',
    clientIp: input.clientIp,
  });

  if (!rateLimit.allowed) {
    await auditLogger.log({
      code: 'NAP_COMPLETE_RATE_LIMITED',
      outcome: 'rate_limited',
      details: { challenge_id: body.challenge_id },
    });
    return {
      ...failure('NAP_COMPLETE_RATE_LIMITED'),
      retryAfterSeconds: rateLimit.retryAfterSeconds,
    };
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

  // Second check, now that the request has proved who it is.
  //
  // The pre-proof check above has only `clientIp`, and an adapter behind an
  // untrusted proxy is told to report none — which left the one endpoint that
  // runs a Schnorr verify per call with no bound at all. Counting the proved
  // pubkey costs an attacker one signature per request they get through.
  //
  // No `clientIp` here: the pre-proof check already spent this address's budget
  // for the request. Counting it twice would halve the configured per-address
  // rate, and unevenly — a request rejected before the proof would cost one, a
  // request that got through would cost two.
  const provenRateLimit = await checkRateLimit(options, {
    scope: 'complete',
    pubkey: proof.value.event.pubkey,
  });

  if (!provenRateLimit.allowed) {
    await auditLogger.log({
      code: 'NAP_COMPLETE_RATE_LIMITED',
      pubkey: proof.value.event.pubkey,
      outcome: 'rate_limited',
      details: { challenge_id: body.challenge_id },
    });
    return {
      ...failure('NAP_COMPLETE_RATE_LIMITED'),
      retryAfterSeconds: provenRateLimit.retryAfterSeconds,
    };
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

  // RFC §13.4(3): a challenge that burned through its failure budget is dead
  // even though it has not expired yet.
  if (challenge.state === 'failed_terminal') {
    await logFailure(auditLogger, 'NAP_COMPLETE_FAILED_TERMINAL', { challenge_id: challenge.challenge_id });
    return failure('NAP_COMPLETE_FAILED_TERMINAL');
  }

  // The principal check comes first, and deliberately spends no budget. A
  // `challenge_id` is not a secret — it travels in the clear and the client
  // hands it back — so anyone who has seen one could otherwise burn a victim's
  // challenge to `failed_terminal` with proofs signed by their own key, and the
  // budget meant to stop guessing becomes a way to deny someone their login.
  if (challenge.pubkey !== proof.value.event.pubkey) {
    await logFailure(auditLogger, 'NAP_COMPLETE_PRINCIPAL_MISMATCH', { challenge_id: challenge.challenge_id });
    return failure('NAP_COMPLETE_PRINCIPAL_MISMATCH');
  }

  // Past this point the request holds the key the challenge was issued to, so
  // failures count against that challenge's budget (RFC §13.4(2)).
  if (challenge.challenge !== proof.value.challenge) {
    await recordChallengeFailure(options, auditLogger, challenge.challenge_id, now);
    await logFailure(auditLogger, 'NAP_COMPLETE_CHALLENGE_MISMATCH', { challenge_id: challenge.challenge_id });
    return failure('NAP_COMPLETE_CHALLENGE_MISMATCH');
  }

  const createdAtWindow = validateChallengeBoundCreatedAt(
    proof.value.event.created_at,
    challenge.issued_at,
    challenge.expires_at,
    lowerBoundGraceSeconds,
    upperBoundGraceSeconds
  );

  if (createdAtWindow !== true) {
    await recordChallengeFailure(options, auditLogger, challenge.challenge_id, now);
    await logFailure(auditLogger, createdAtWindow.code, { challenge_id: challenge.challenge_id });
    return createdAtWindow;
  }

  // The credential rides in the context rather than the signature, so a resolver
  // that does not want it simply does not declare the parameter.
  const aclDecision = await options.aclResolver.resolve(challenge.npub, challenge.pubkey, {
    ...(body.voucher ? { voucher: body.voucher } : {}),
    now,
  });

  if (!aclDecision.allowed) {
    await logFailure(auditLogger, 'NAP_COMPLETE_ACL_DENIED', { challenge_id: challenge.challenge_id });
    return failure('NAP_COMPLETE_ACL_DENIED');
  }

  // A step-up is a full re-authentication: the caller proved key control again,
  // just now, so the resulting session carries a short-lived token that
  // `requireStepUp()` accepts. The flag is signed (it lives in the hashed body),
  // so it cannot be added in transit to mint a token the user never asked for.
  const session = await options.sessionStore.createForChallenge(
    createSessionRecord(
      challenge,
      now,
      sessionTtlSeconds,
      randomSource,
      aclDecision.roles,
      aclDecision.permissions,
      body.step_up ? { ttlSeconds: stepUpTtlSeconds } : undefined,
      options.refreshTtlSeconds
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

export interface RefreshSessionInput {
  /** The bearer credential from `Authorization`, or undefined when absent. */
  refreshToken?: string;
  clientIp?: string;
}

export type RefreshSessionOutcome =
  | { ok: true; session: SessionRecord }
  | (VerifyCompleteFailure & { retryAfterSeconds?: number });

/**
 * Exchange a refresh token for a fresh access token (RFC §14.1).
 *
 * Rotating: every call retires the presented token and issues a new one, so a
 * stolen token is usable at most once before the theft becomes visible. What
 * makes it visible is that the retired token stays recognisable — presenting it
 * again means two parties hold the lineage, and since the server cannot tell
 * which one is the thief, the session is revoked and both must sign in again.
 *
 * The ACL is re-read on every refresh. A refresh mints a new access token good
 * for the full session TTL, so trusting the login-time snapshot would let a
 * principal suspended an hour ago keep extending their access indefinitely —
 * which is the one thing short access-token lifetimes exist to prevent.
 */
export async function refreshSession(
  input: RefreshSessionInput,
  options: NapServerOptions
): Promise<RefreshSessionOutcome> {
  const startedAtMillis = Date.now();
  const randomSource = options.randomSource ?? defaultRandomSource;
  let outcome: RefreshSessionOutcome | undefined;

  try {
    outcome = await refreshSessionUnpadded(input, options);
    return outcome;
  } finally {
    if (!isRateLimited(outcome, 'NAP_REFRESH_RATE_LIMITED')) {
      await padAuthResponse(startedAtMillis, options, randomSource);
    }
  }
}

async function refreshSessionUnpadded(
  input: RefreshSessionInput,
  options: NapServerOptions
): Promise<RefreshSessionOutcome> {
  const clock = options.clock ?? defaultClock;
  const randomSource = options.randomSource ?? defaultRandomSource;
  const auditLogger = withMetrics(options.auditLogger ?? noopAuditLogger, options.metrics);
  const sessionTtlSeconds = options.sessionTtlSeconds ?? DEFAULT_SESSION_TTL_SECONDS;
  const refreshTtlSeconds = options.refreshTtlSeconds;
  const store = options.sessionStore;

  // Answered exactly like an unknown token. Whether a deployment offers refresh
  // at all is not something an anonymous caller needs confirmed, and the
  // adapters already refuse to start on the misconfiguration that would make
  // this the interesting branch.
  if (!refreshTtlSeconds || !store.getByRefreshToken || !store.rotateRefreshToken) {
    await logFailure(auditLogger, 'NAP_REFRESH_UNKNOWN_TOKEN', { reason: 'not_configured' });
    return failure('NAP_REFRESH_UNKNOWN_TOKEN');
  }

  const rateLimit = await checkRateLimit(options, {
    scope: 'refresh',
    clientIp: input.clientIp,
  });

  if (!rateLimit.allowed) {
    await auditLogger.log({
      code: 'NAP_REFRESH_RATE_LIMITED',
      outcome: 'rate_limited',
    });
    return {
      ...failure('NAP_REFRESH_RATE_LIMITED'),
      retryAfterSeconds: rateLimit.retryAfterSeconds,
    };
  }

  if (!input.refreshToken) {
    await logFailure(auditLogger, 'NAP_REFRESH_UNKNOWN_TOKEN');
    return failure('NAP_REFRESH_UNKNOWN_TOKEN');
  }

  const presented = input.refreshToken;
  const session = await store.getByRefreshToken(presented);

  if (!session) {
    await logFailure(auditLogger, 'NAP_REFRESH_UNKNOWN_TOKEN');
    return failure('NAP_REFRESH_UNKNOWN_TOKEN');
  }

  const now = clock.nowUnix();

  // Checked before expiry and revocation: a replay is worth acting on whatever
  // else is wrong with the session, and reporting it as merely expired would
  // hide the only signal that a token leaked.
  if (
    session.previous_refresh_token &&
    constantTimeEquals(session.previous_refresh_token, input.refreshToken)
  ) {
    await store.revokeBySessionId(session.session_id, now);
    // Logged directly rather than through `logFailure`, which has nowhere to put a
    // pubkey: this is the one event that says a credential leaked, and a sink that
    // alerts on `event.pubkey` must be able to name the principal whose session
    // just ended. Buried in `details` it would only be greppable after the fact.
    await auditLogger.log({
      code: 'NAP_REFRESH_REUSED',
      pubkey: session.principal_pubkey,
      outcome: 'failure',
      details: { session_id: session.session_id },
    });
    return failure('NAP_REFRESH_REUSED');
  }

  // A store that answered with a session holding neither the presented token nor
  // its predecessor has a broken index; treat it as no match rather than rotate
  // a session the caller has not proved anything about.
  if (!session.refresh_token || !constantTimeEquals(session.refresh_token, input.refreshToken)) {
    await logFailure(auditLogger, 'NAP_REFRESH_UNKNOWN_TOKEN', {
      session_id: session.session_id,
    });
    return failure('NAP_REFRESH_UNKNOWN_TOKEN');
  }

  if (session.revoked_at) {
    await logFailure(auditLogger, 'NAP_REFRESH_REVOKED', { session_id: session.session_id });
    return failure('NAP_REFRESH_REVOKED');
  }

  if (!session.refresh_expires_at || session.refresh_expires_at < now) {
    await logFailure(auditLogger, 'NAP_REFRESH_EXPIRED', { session_id: session.session_id });
    return failure('NAP_REFRESH_EXPIRED');
  }

  // No voucher: a refresh sees a session, not the completion body that carried
  // the credential. A voucher resolver must therefore answer from cached state
  // here, and the cache TTL is what bounds how stale that answer can be.
  const aclDecision = await options.aclResolver.resolve(
    session.principal_npub,
    session.principal_pubkey,
    { now }
  );

  if (!aclDecision.allowed) {
    // Same rule as a guarded request: only a denial the resolver is certain
    // about ends every session. A resolver that could not *read* the ACL denies
    // this refresh and nothing more — the access token still expires on its own
    // schedule, so nothing is granted by waiting.
    if (aclDecision.revoke_sessions) {
      await store.revokeByPrincipal(session.principal_pubkey, now);
    }

    await logFailure(auditLogger, 'NAP_REFRESH_ACL_DENIED', {
      session_id: session.session_id,
      reason: aclDecision.reason,
    });
    return failure('NAP_REFRESH_ACL_DENIED');
  }

  const rotated = await store.rotateRefreshToken(session.session_id, {
    expectedRefreshToken: presented,
    accessToken: base64Url(randomSource.randomBytes(32)),
    refreshToken: base64Url(randomSource.randomBytes(32)),
    now,
    expiresAt: now + sessionTtlSeconds,
    refreshExpiresAt: now + refreshTtlSeconds,
    roles: aclDecision.roles,
    permissions: aclDecision.permissions,
  });

  if (!rotated) {
    await logFailure(auditLogger, 'NAP_REFRESH_INTERNAL', { session_id: session.session_id });
    return failure('NAP_REFRESH_INTERNAL');
  }

  await auditLogger.log({
    code: 'NAP_REFRESH_SUCCESS',
    pubkey: rotated.principal_pubkey,
    outcome: 'success',
    details: { session_id: rotated.session_id },
  });

  return { ok: true, session: rotated };
}

export function toPublicAuthSuccess(session: SessionRecord): AuthSuccessResponse {
  return {
    status: 'ok',
    access_token: session.access_token,
    token_type: 'Bearer',
    expires_at: session.expires_at,
    step_up_token: session.step_up_token,
    step_up_expires_at: session.step_up_expires_at,
    refresh_token: session.refresh_token,
    refresh_expires_at: session.refresh_expires_at,
    principal: {
      npub: session.principal_npub,
      pubkey: session.principal_pubkey,
    },
    roles: session.roles,
    permissions: session.permissions,
  };
}

/**
 * Session view for `GET /auth/session`.
 *
 * Deliberately omits `access_token`, `token_type`, and the step-up fields. In
 * cookie mode the access token lives in an HttpOnly cookie; echoing it into a
 * JSON body would make it readable by script and undo that protection. The
 * browser client only reads `principal`, `roles`, `permissions`, and
 * `expires_at` when resuming.
 */
export type PublicSessionView = Omit<
  AuthSuccessResponse,
  'access_token' | 'token_type' | 'step_up_token' | 'step_up_expires_at'
>;

export function toPublicSessionView(session: SessionRecord): PublicSessionView {
  return {
    status: 'ok',
    expires_at: session.expires_at,
    principal: {
      npub: session.principal_npub,
      pubkey: session.principal_pubkey,
    },
    roles: session.roles,
    permissions: session.permissions,
  };
}

export interface EffectiveAcl {
  roles: string[];
  permissions: string[];
}

export interface ResolveEffectiveAclOptions {
  /**
   * When supplied, the ACL is re-read on every request instead of trusting the
   * login-time snapshot. Omit to keep the snapshot behaviour.
   */
  aclResolver?: AclResolver;
  /** When supplied alongside `aclResolver`, a denied principal's sessions are revoked. */
  sessionStore?: SessionStore;
  clock?: Clock;
}

/**
 * Resolve the roles and permissions a request should actually be judged
 * against (RFC §15 rule 1).
 *
 * `session.roles` and `session.permissions` are a snapshot taken at login. RFC
 * §15 requires permissions to be evaluated on every authorized request, not
 * just at login — otherwise revoking access takes effect only when the session
 * expires, which for the default 900-second TTL means a suspended principal
 * keeps working for up to fifteen minutes.
 *
 * Returns `null` when the principal is no longer allowed at all, in which case
 * their sessions are revoked so the next request fails at session lookup
 * without another ACL round trip.
 *
 * Costs one ACL read per guarded request. Guards left without an `aclResolver`
 * keep reading the snapshot, so this is opt-in per guard.
 */
export async function resolveEffectiveAcl(
  session: SessionRecord,
  options: ResolveEffectiveAclOptions
): Promise<EffectiveAcl | null> {
  if (!options.aclResolver) {
    return { roles: session.roles, permissions: session.permissions };
  }

  // Same as refresh: a guarded request has a session, never the credential. See
  // `AclResolutionContext.voucher`.
  const clock = options.clock ?? defaultClock;
  const decision = await options.aclResolver.resolve(
    session.principal_npub,
    session.principal_pubkey,
    { now: clock.nowUnix() }
  );

  if (!decision.allowed) {
    // Only an affirmative denial ends every session the principal holds. A
    // resolver that answers "denied" because it could not read the ACL — a
    // lagging replica, a row mid-rewrite — denies this request and no more;
    // mass-revoking on an unreadable ACL costs everyone a fresh NIP-98 login.
    if (decision.revoke_sessions) {
      await options.sessionStore?.revokeByPrincipal(session.principal_pubkey, clock.nowUnix());
    }

    return null;
  }

  return { roles: decision.roles, permissions: decision.permissions };
}

/**
 * Compare a secret without leaking its content through comparison time.
 *
 * `===` on strings short-circuits at the first differing byte. Guards run
 * outside the auth endpoints' response floor, so nothing else is smoothing that
 * out. Hand-rolled rather than `node:crypto.timingSafeEqual` to keep the
 * package runtime-portable, and because that one throws on unequal lengths —
 * which is itself the leak.
 */
export function constantTimeEquals(a: string, b: string): boolean {
  const encoder = new TextEncoder();
  const left = encoder.encode(a);
  const right = encoder.encode(b);
  let difference = left.length ^ right.length;

  for (let index = 0; index < left.length; index += 1) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }

  return difference === 0;
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
  // Fail at wiring time rather than on the first /auth/init.
  resolveChallengeTtl(options);

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
