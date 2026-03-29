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
}

export interface SessionStore {
  createForChallenge(record: SessionRecord): Promise<SessionRecord>;
  getBySessionId(sessionId: string): Promise<SessionRecord | null>;
  getByAccessToken(token: string): Promise<SessionRecord | null>;
  revokeBySessionId(sessionId: string, now: number): Promise<void>;
  revokeByPrincipal(pubkey: string, now: number): Promise<number>;
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
  challengeTtlSeconds?: number;
  sessionTtlSeconds?: number;
  resultCacheTtlSeconds?: number;
  maxClockSkewSeconds?: number;
  lowerBoundGraceSeconds?: number;
  upperBoundGraceSeconds?: number;
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
}

export interface IssueChallengeSuccess {
  ok: true;
  value: AuthInitResponse;
}

export interface IssueChallengeFailure {
  ok: false;
  code: Extract<NapErrorCode, 'NAP_INIT_INVALID_NPUB' | 'NAP_INIT_INTERNAL'>;
  retryable: boolean;
}

export type IssueChallengeResult =
  | IssueChallengeSuccess
  | IssueChallengeFailure;

export interface VerifyCompletionInput {
  authorization?: string;
  method: string;
  url: string;
  rawBody: Uint8Array;
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
