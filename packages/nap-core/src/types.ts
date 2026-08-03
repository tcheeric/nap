export interface AuthInitRequest {
  npub: string;
}

export interface AuthInitResponse {
  challenge_id: string;
  challenge: string;
  auth_url: string;
  auth_method: 'POST';
  issued_at: number;
  expires_at: number;
}

export interface AuthCompleteRequest {
  challenge_id: string;
}

export interface AuthSuccessResponse {
  status: 'ok';
  access_token: string;
  token_type: 'Bearer';
  expires_at: number;
  step_up_token?: string;
  step_up_expires_at?: number;
  refresh_token?: string;
  refresh_expires_at?: number;
  principal: {
    npub: string;
    pubkey: string;
  };
  permissions?: string[];
  roles?: string[];
}

export interface AuthFailureResponse {
  status: 'error';
  message: 'authentication failed';
}

export type ChallengeState =
  | 'issued'
  | 'redeemed'
  | 'expired'
  | 'failed_terminal';

export interface ChallengeRecord {
  challenge_id: string;
  challenge: string;
  npub: string;
  pubkey: string;
  auth_url: string;
  auth_method: 'POST';
  issued_at: number;
  expires_at: number;
  state: ChallengeState;
  redeemed_event_id?: string;
  redeemed_session_id?: string;
  result_cache_until?: number;
}

export interface SessionRecord {
  session_id: string;
  challenge_id: string;
  access_token: string;
  principal_npub: string;
  principal_pubkey: string;
  roles: string[];
  permissions: string[];
  issued_at: number;
  expires_at: number;
  step_up_token?: string;
  step_up_expires_at?: number;
  refresh_token?: string;
  refresh_expires_at?: number;
  revoked_at?: number;
}

export interface AclDecision {
  allowed: boolean;
  roles: string[];
  permissions: string[];
  reason?: string;
}

export type NapErrorCode =
  | 'NAP_INIT_INVALID_JSON'
  | 'NAP_INIT_INVALID_NPUB'
  | 'NAP_INIT_RATE_LIMITED'
  | 'NAP_INIT_INTERNAL'
  | 'NAP_COMPLETE_MISSING_AUTH_HEADER'
  | 'NAP_COMPLETE_INVALID_AUTH_SCHEME'
  | 'NAP_COMPLETE_INVALID_EVENT_JSON'
  | 'NAP_COMPLETE_INVALID_KIND'
  | 'NAP_COMPLETE_INVALID_SIGNATURE'
  | 'NAP_COMPLETE_CREATED_AT_OUT_OF_RANGE'
  | 'NAP_COMPLETE_URL_MISMATCH'
  | 'NAP_COMPLETE_METHOD_MISMATCH'
  | 'NAP_COMPLETE_MISSING_PAYLOAD'
  | 'NAP_COMPLETE_PAYLOAD_MISMATCH'
  | 'NAP_COMPLETE_MISSING_CHALLENGE_ID'
  | 'NAP_COMPLETE_UNKNOWN_CHALLENGE'
  | 'NAP_COMPLETE_EXPIRED_CHALLENGE'
  | 'NAP_COMPLETE_REDEEMED_CHALLENGE'
  | 'NAP_COMPLETE_CHALLENGE_MISMATCH'
  | 'NAP_COMPLETE_PRINCIPAL_MISMATCH'
  | 'NAP_COMPLETE_ACL_DENIED'
  | 'NAP_COMPLETE_RATE_LIMITED'
  | 'NAP_COMPLETE_INTERNAL';

export interface VerifyCompleteSuccess {
  ok: true;
  session: SessionRecord;
}

export interface VerifyCompleteFailure {
  ok: false;
  code: NapErrorCode;
  retryable: boolean;
}

export type VerifyCompleteResult =
  | VerifyCompleteSuccess
  | VerifyCompleteFailure;

export interface Nip98Event {
  id: string;
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
  sig: string;
}

export interface VerifiedNip98Completion {
  event: Nip98Event;
  challenge: string;
  challengeId: string;
  payload: string;
}

export interface VerifyNip98CompletionInput {
  authorization?: string;
  method: string;
  url: string;
  body: AuthCompleteRequest;
  rawBody: Uint8Array;
  now: number;
  maxClockSkewSeconds?: number;
}
