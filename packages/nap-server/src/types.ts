import type {
  AclDecision,
  AuthCompleteRequest,
  AuthFailureResponse,
  AuthInitRequest,
  AuthInitResponse,
  AuthSuccessResponse,
  ChallengeRecord,
  NapErrorCode,
  SessionRecord,
  VerifyCompleteFailure,
  VerifyCompleteResult,
} from '@imani/nap-core';

export interface PermissionDefinition {
  key: string;
  description: string;
  stepUp: boolean;
}

export interface RoleDefinition {
  key: string;
  description: string;
  permissions: string[];
}

export interface PermissionRegistry {
  appId: string;
  permissions: PermissionDefinition[];
  roles: RoleDefinition[];
  defaultRole: string;
}

export interface PermissionOverride {
  action: 'grant' | 'deny';
  permission: string;
}

export interface AclRecord {
  principal_pubkey: string;
  app_id: string;
  role: string;
  permission_overrides: PermissionOverride[];
  suspended: boolean;
  suspended_at?: string;
  suspended_reason?: string;
  created_at?: string;
  updated_at?: string;
}

export interface OutstandingChallengeFilter {
  npub?: string;
  clientIp?: string;
  now: number;
}

export interface RecordChallengeFailureResult {
  failure_count: number;
  state: ChallengeRecord['state'];
}

export interface ChallengeStore {
  create(record: ChallengeRecord): Promise<void>;
  get(challengeId: string): Promise<ChallengeRecord | null>;
  redeem(
    challengeId: string,
    params: { eventId: string; sessionId: string; now: number; resultCacheUntil: number }
  ): Promise<
    | { status: 'redeemed' }
    | { status: 'already_redeemed' }
    | { status: 'not_found' }
    | { status: 'expired' }
  >;
  markExpired(now: number): Promise<number>;

  /**
   * Count unexpired challenges still in `issued` state for a principal or a
   * caller address (RFC §17.4).
   *
   * Optional so existing custom stores keep compiling. When a store does not
   * implement it, `maxOutstandingChallengesPerNpub` and
   * `maxOutstandingChallengesPerIp` cannot be enforced and are skipped.
   */
  countOutstanding?(filter: OutstandingChallengeFilter): Promise<number>;

  /**
   * Increment the challenge's failure counter, moving it to `failed_terminal`
   * once `maxFailure` is reached (RFC §13.4).
   *
   * Optional for the same reason as `countOutstanding`. Must be atomic:
   * concurrent attacks on one challenge otherwise lose increments to a
   * read-modify-write race and never reach the cap.
   */
  recordFailure?(
    challengeId: string,
    params: { now: number; maxFailures: number }
  ): Promise<RecordChallengeFailureResult | null>;
}

export interface SessionStore {
  createForChallenge(record: SessionRecord): Promise<SessionRecord>;
  getBySessionId(sessionId: string): Promise<SessionRecord | null>;
  getByAccessToken(token: string): Promise<SessionRecord | null>;
  revokeBySessionId(sessionId: string, now: number): Promise<void>;
  revokeByPrincipal(pubkey: string, now: number): Promise<number>;
}

export interface RateLimitDecision {
  allowed: boolean;
  /** Seconds until the caller may retry, surfaced as `Retry-After` on the 429. */
  retryAfterSeconds?: number;
}

export interface RateLimitKey {
  /** Which endpoint is being called. */
  scope: 'init' | 'complete';
  /** Principal the request claims, when the request names one. */
  npub?: string;
  /**
   * Principal the request has *proved*, hex-encoded.
   *
   * `/auth/complete` names nobody until its NIP-98 proof verifies, so the
   * pre-proof check has only `clientIp` to work with — nothing at all when the
   * adapter opts out of address reporting. This dimension is counted again once
   * the signature is good, which bounds an attacker to one Schnorr verify per
   * request instead of unbounded.
   */
  pubkey?: string;
  /** Caller address, as resolved by the adapter's trust policy. */
  clientIp?: string;
}

/**
 * Pluggable rate limiter (RFC §17.1).
 *
 * `/auth/init` is unauthenticated and writes a row per call, so a limiter in
 * front of it is the difference between a public endpoint and a public write
 * amplifier. `createInMemoryRateLimiter()` covers a single process; anything
 * multi-instance needs a shared backend.
 */
export interface RateLimiter {
  check(key: RateLimitKey): Promise<RateLimitDecision> | RateLimitDecision;
}

export interface AclResolver {
  resolve(npub: string, pubkey: string): Promise<AclDecision>;
}

export interface AclStore {
  get(pubkey: string, appId: string): Promise<AclRecord | null>;
  upsert(record: AclRecord): Promise<void>;
  suspend(pubkey: string, appId: string, reason?: string): Promise<void>;
  unsuspend(pubkey: string, appId: string): Promise<void>;
}

export interface Clock {
  nowUnix(): number;
}

export interface RandomSource {
  randomBytes(length: number): Uint8Array;
}

export interface AuditLogger {
  log(event: {
    code: string;
    challenge_id?: string;
    npub?: string;
    pubkey?: string;
    outcome: 'success' | 'failure' | 'rate_limited';
    details?: Record<string, unknown>;
  }): Promise<void> | void;
}

export interface NapServerOptions {
  challengeStore: ChallengeStore;
  sessionStore: SessionStore;
  aclResolver: AclResolver;
  clock?: Clock;
  randomSource?: RandomSource;
  auditLogger?: AuditLogger;
  /**
   * Defaults to a per-options `createInMemoryRateLimiter()`.
   *
   * On by default because `minAuthResponseMillis` holds every unauthenticated
   * request open for 100 ms: without a limiter that floor is a concurrency
   * amplifier rather than a timing defence. Pass a shared-backend limiter for
   * multi-instance deployments, where the in-memory one allows N× the
   * configured rate. Pass `null` to disable — a deliberate choice, not a
   * default.
   */
  rateLimiter?: RateLimiter | null;
  /** Defaults to 60, which is also the RFC §10.1 ceiling. Anything higher throws. */
  challengeTtlSeconds?: number;
  sessionTtlSeconds?: number;
  resultCacheTtlSeconds?: number;
  maxClockSkewSeconds?: number;
  lowerBoundGraceSeconds?: number;
  upperBoundGraceSeconds?: number;
  /** Lifetime of a minted step-up token, in seconds. Defaults to 600. */
  stepUpTtlSeconds?: number;
  /**
   * Cap on unexpired `issued` challenges per principal (RFC §17.4). Defaults to
   * 10. Requires `ChallengeStore.countOutstanding`; skipped without it.
   */
  maxOutstandingChallengesPerNpub?: number;
  /**
   * Cap on unexpired `issued` challenges per caller address (RFC §17.4).
   * Defaults to 30. Requires `ChallengeStore.countOutstanding` and an adapter
   * that resolves `clientIp`; skipped without either.
   */
  maxOutstandingChallengesPerIp?: number;
  /**
   * Completion attempts a single challenge tolerates before moving to
   * `failed_terminal` (RFC §13.4). Defaults to 5. Requires
   * `ChallengeStore.recordFailure`; skipped without it.
   */
  maxFailuresPerChallenge?: number;
  /**
   * Floor on how long `/auth/init` and `/auth/complete` take to answer, in
   * milliseconds (RFC §15). Defaults to 100. Set to 0 to disable.
   *
   * The uniform 401 hides *which* check failed; without a floor, how long the
   * answer took still distinguishes "no such principal" from "signature did not
   * verify". Padding to a fixed floor collapses that channel. See
   * `responseJitterMillis` for the sub-floor variance.
   */
  minAuthResponseMillis?: number;
  /**
   * Uniform random padding added on top of `minAuthResponseMillis`, in
   * milliseconds. Defaults to 25. Set to 0 for a fixed floor with no variance.
   */
  responseJitterMillis?: number;
}

export interface NapServer {
  issueChallenge(input: IssueChallengeInput): Promise<IssueChallengeResult>;
  verifyCompletion(input: VerifyCompletionInput): Promise<VerifyCompletionOutcome>;
  toPublicAuthSuccess(session: SessionRecord): AuthSuccessResponse;
  toPublicAuthFailure(): { status: 401; body: AuthFailureResponse };
}

export interface IssueChallengeInput extends AuthInitRequest {
  authUrl: string;
  authMethod?: 'POST';
  /**
   * Caller address, for the rate limiter and the per-IP outstanding cap.
   *
   * The adapter decides what this is: it is only as trustworthy as the proxy
   * configuration behind it, so a spoofable `X-Forwarded-For` makes both limits
   * spoofable. Leave it unset rather than pass an untrusted value — the per-IP
   * cap is then skipped instead of being trivially evaded.
   */
  clientIp?: string;
}

export interface IssueChallengeSuccess {
  ok: true;
  value: AuthInitResponse;
}

export interface IssueChallengeFailure {
  ok: false;
  code: Extract<
    NapErrorCode,
    'NAP_INIT_INVALID_NPUB' | 'NAP_INIT_INTERNAL' | 'NAP_INIT_RATE_LIMITED'
  >;
  retryable: boolean;
  /** Set on `NAP_INIT_RATE_LIMITED`, for the adapter's `Retry-After` header. */
  retryAfterSeconds?: number;
}

export type IssueChallengeResult =
  | IssueChallengeSuccess
  | IssueChallengeFailure;

export interface VerifyCompletionInput {
  authorization?: string;
  method: string;
  url: string;
  rawBody: Uint8Array;
  /** Caller address, for the rate limiter. See `IssueChallengeInput.clientIp`. */
  clientIp?: string;
}

export interface MalformedRequestFailure {
  ok: false;
  malformed: true;
  publicResponse: {
    status: 400;
    body: {
      status: 'error';
      message: 'bad request';
    };
  };
}

export type VerifyCompletionOutcome =
  | VerifyCompleteResult
  | MalformedRequestFailure;

export interface PublicSuccessResponse {
  status: 200;
  body: AuthSuccessResponse;
}

export interface PublicFailureResponse {
  status: 401 | 429;
  body: AuthFailureResponse;
}

export function isMalformedRequestFailure(value: VerifyCompletionOutcome): value is MalformedRequestFailure {
  return !value.ok && 'malformed' in value;
}

export function isVerifyFailure(value: VerifyCompletionOutcome): value is VerifyCompleteFailure {
  return !value.ok && !('malformed' in value);
}

export function isVerifySuccess(value: VerifyCompletionOutcome): value is Exclude<VerifyCompletionOutcome, VerifyCompleteFailure | MalformedRequestFailure> {
  return value.ok;
}

export type ParsedAuthCompleteRequest = AuthCompleteRequest | null;
