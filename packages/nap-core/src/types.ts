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
  /**
   * Optional extensions this server understands, e.g. `['voucher-acl/1']`.
   *
   * Exists because a 401 does not tell a client holding a credential *which*
   * mistake it made, and the two possibilities call for opposite actions: a
   * server without the extension should be retried without the credential,
   * while a dead or forged credential should not be retried at all. Neither is
   * recoverable from a response that is deliberately identical in both cases.
   *
   * Safe to publish, unlike the failure codes it substitutes for: this is a
   * property of the *server*, known to anyone who reads its docs, and says
   * nothing about any principal, credential, or mint. It is sent before the
   * client has signed anything, and it is not attacker-useful — a server that
   * omits it still rejects everything it would have rejected anyway.
   *
   * Absent means "makes no claim", which is what every existing server sends.
   * A client MUST treat absence as unknown rather than as a denial: an older
   * server that supports an extension but predates this field would otherwise
   * be locked out of it.
   */
  supported_extensions?: string[];
}

export interface AuthCompleteRequest {
  challenge_id: string;
  /**
   * Request a step-up token alongside the session.
   *
   * Carried in the body rather than a query parameter so it falls under the
   * NIP-98 `payload` hash and cannot be added or stripped in transit. The
   * signed `u` tag stays query-free and keeps matching the audience the server
   * computes.
   */
  step_up?: boolean;
  /**
   * A voucher presented as the source of this session's authorization
   * (extension 0001).
   *
   * In the body rather than the NIP-98 event, and that placement is
   * load-bearing: the `payload` tag is `sha256(rawBody)`, so the signature
   * covers the credential. A credential swapped in transit changes the hash and
   * the completion fails with `NAP_COMPLETE_PAYLOAD_MISMATCH` — the same
   * mechanism that already protects `step_up`.
   *
   * Additive and optional. A server without the extension ignores it, the
   * payload hash still matches because it hashes whatever bytes arrived, and
   * the ACL falls through to the store.
   */
  voucher?: VoucherCredential;
}

/**
 * A Cashu voucher presented as an authorization credential (extension 0001).
 *
 * Carries what a server needs to verify the voucher without trusting the
 * client: which mint signed it, the proof itself, and the DLEQ that proves the
 * mint signed it.
 *
 * The secret is a `P2PK_VOUCHER` NUT-10 secret — voucher metadata in the tags,
 * and in `data` the public key `K` that this completion's NIP-98 event must be
 * signed by. That equality is the whole design: holding the credential without
 * `K` proves nothing, because the completion cannot be signed.
 */
export interface VoucherCredential {
  /**
   * Absolute HTTPS URL of the mint that signed the proof. REQUIRED.
   *
   * A Cashu proof carries a keyset id, not a mint URL, so without this the
   * server cannot fetch `/v1/keys` and cannot verify anything at all.
   *
   * **Client-supplied, and therefore matched against an allowlist rather than
   * trusted to select one.** A request field choosing the mint a credential is
   * verified against is the same vulnerability class as a request header
   * choosing the NIP-98 audience.
   */
  mint_url: string;
  /** Keyset id from the proof, used to resolve the mint's public key. */
  keyset_id: string;
  /** The NUT-10 `P2PK_VOUCHER` secret, in its canonical serialization. */
  secret: string;
  /** The unblinded signature `C`, hex. */
  signature: string;
  /** The proof's amount, which selects the key within the keyset. */
  amount: number;
  /**
   * NUT-12 DLEQ proof. REQUIRED.
   *
   * Proves the mint signed this proof. It says nothing about whether the proof
   * is still unspent — a burned voucher carries a perfectly valid DLEQ — so it
   * is necessary rather than sufficient, and a NUT-07 state check still runs.
   * Required so that a server in mint-degraded mode still has cryptographic
   * footing.
   */
  dleq: { e: string; s: string; r: string };
  /** NUT-11 P2PK witness, when the mint requires one for the state check. */
  witness?: string;
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
  /** Caller address at issuance, used for the per-IP outstanding-challenge cap (RFC §17.4). */
  client_ip?: string;
  /** Completion attempts that failed after this challenge was loaded and matched (RFC §13.4). */
  failure_count?: number;
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
  /**
   * Current refresh token (RFC §14.1). Present only when the server is
   * configured with `refreshTtlSeconds`.
   */
  refresh_token?: string;
  refresh_expires_at?: number;
  /**
   * The refresh token this row held before its last rotation.
   *
   * Kept so a replay is *recognised* rather than merely rejected: a token that
   * is unknown could be anything, but one that is this row's immediate
   * predecessor means two parties hold the lineage, and the session is revoked.
   * One step of history is enough — whoever rotated past an older token already
   * tripped this check at the time.
   */
  previous_refresh_token?: string;
  revoked_at?: number;
}

export interface AclDecision {
  allowed: boolean;
  roles: string[];
  permissions: string[];
  reason?: string;
  /**
   * Set on a denial the resolver is *certain* about — the principal was
   * suspended, not merely unreadable. Only then does `resolveEffectiveAcl()`
   * revoke every session they hold.
   *
   * Omitting it denies the one request and leaves sessions intact, which is the
   * safe default: a resolver that answers `allowed: false` because a replica
   * lagged or a row was mid-rewrite would otherwise log the principal out
   * everywhere, and only a fresh NIP-98 login gets them back.
   */
  revoke_sessions?: boolean;
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
  | 'NAP_COMPLETE_FAILED_TERMINAL'
  | 'NAP_COMPLETE_INTERNAL'
  | 'NAP_REFRESH_UNKNOWN_TOKEN'
  | 'NAP_REFRESH_REUSED'
  | 'NAP_REFRESH_EXPIRED'
  | 'NAP_REFRESH_REVOKED'
  | 'NAP_REFRESH_ACL_DENIED'
  | 'NAP_REFRESH_RATE_LIMITED'
  | 'NAP_REFRESH_INTERNAL';

export interface VerifyCompleteSuccess {
  ok: true;
  session: SessionRecord;
}

export interface VerifyCompleteFailure {
  ok: false;
  code: NapErrorCode;
  retryable: boolean;
  /** Set on `NAP_COMPLETE_RATE_LIMITED`, for the adapter's `Retry-After` header. */
  retryAfterSeconds?: number;
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
