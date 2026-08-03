# NAP v2 RFC

**Title:** Nostr Authentication Protocol v2  
**Status:** Draft  
**Date:** 2026-03-21  
**Scope:** HTTP over TLS  
**Relationship to NIP-98:** Extension profile built on standard NIP-98 `kind:27235` request authorization

## 1. Summary

NAP v2 defines a challenge-response login flow for services that authenticate users by Nostr key rather than password.

It is intentionally **not** a replacement for NIP-98. Instead, it is a higher-level login profile that:

1. uses a server-issued challenge,
2. completes authentication with a standard NIP-98 authorization proof,
3. issues a short-lived session for subsequent application requests.

This RFC narrows the scope to **HTTP over TLS only**. WebSocket and relay-native variants are not specified here because they require different audience binding and replay semantics.

---

## 2. Why The Previous Draft Was Unsafe To Package

The earlier draft had four major problems:

1. It claimed to be an extension of NIP-98 but replaced the core NIP-98 request binding (`u`, `method`, optional `payload`) with ad hoc tags like `origin` and `method=AUTH`.
2. It consumed challenges too early, which made normal client retries brittle and enabled avoidable denial-of-service behavior.
3. It treated the protocol as transport-agnostic even though its security model relied on HTTPS origin semantics.
4. It recommended hard binding bearer sessions to `User-Agent + IP prefix`, which is operationally fragile and not a strong sender-constraining mechanism.

This revision fixes those issues and is structured to support a standalone library.

---

## 3. Goals

1. Reuse NIP-98 rather than invent a parallel signing shape.
2. Be explicit enough that independent client and server libraries interoperate.
3. Fail closed on replay, wrong audience, wrong method, wrong payload, expired challenge, and ACL mismatch.
4. Support clustered deployments with a pluggable challenge/session store.
5. Make network retries and duplicated client submissions deterministic instead of brittle.

## 4. Non-Goals

- Replacing NIP-98 for normal authenticated API requests
- Defining a WebSocket auth profile
- Defining a relay-DM auth profile
- Defining sender-constrained session tokens in the core spec
- Defining account recovery, key rotation, or delegation

---

## 5. Relationship To NIP-98

NAP v2 authentication completion uses a standard NIP-98 `kind:27235` event.

The event MUST still contain the NIP-98-required tags:

- `u`
- `method`

It MAY contain NAP-specific extension tags:

- `challenge`
- `challenge_id`

Because the completion request defined by this profile always has a non-empty HTTP body, the event MUST include a standard NIP-98 `payload` tag containing the SHA-256 hash of the exact request body bytes.

NAP v2 therefore extends NIP-98 by adding:

1. a challenge issuance step,
2. challenge-bound validation rules,
3. post-auth session issuance.

---

## 6. Terminology

| Term | Meaning |
|------|---------|
| `npub` | Bech32-encoded Nostr public key identifier |
| `pubkey` | 32-byte hex public key used inside Nostr events |
| challenge | High-entropy server-issued nonce |
| `challenge_id` | Opaque server identifier for challenge lookup |
| audience | The exact absolute HTTP URL the NIP-98 proof authorizes |
| completion request | The HTTP request that redeems the challenge and finalizes auth |
| ACL | Server-side allowlist / role / permission resolver |

---

## 7. Security Objectives

| Threat | Mitigation |
|--------|------------|
| Replay of completion request | Single-use challenge + redemption state + short TTL |
| Cross-endpoint proof replay | NIP-98 exact `u` and `method` binding |
| Body tampering | NIP-98 `payload` hash on completion request body |
| MITM / forwarding | TLS + exact audience binding |
| Key confusion | Standard NIP-98 event shape, exact pubkey/npub matching |
| User enumeration | Indistinguishable challenge issuance for known/unknown users |
| Cluster race / retry ambiguity | Atomic challenge redemption + short result cache |
| Session theft | Short-lived access token + optional refresh rotation + risk checks |
| DoS | Rate limiting, bounded challenge TTL, bounded outstanding challenges |

---

## 8. Scope And Transport

This RFC specifies the **HTTP profile** only.

Why:

1. NIP-98 is defined for HTTP authorization.
2. Exact URL and method binding are well-defined in HTTP.
3. WebSocket and relay transports need different audience and payload rules.

Future profiles may be defined later:

- `NAP-WS`
- `NAP-RELAY`

They MUST NOT claim interoperability with this RFC unless they define equivalent audience, replay, and retry semantics.

---

## 9. Protocol Overview

```text
Client                                              Server
  │                                                   │
  │ 1. POST /auth/init { npub }                      │
  │──────────────────────────────────────────────────►│
  │                                                   │
  │ 2. 200 { challenge_id, challenge, auth_url, ... }│
  │◄──────────────────────────────────────────────────│
  │                                                   │
  │ 3. POST /auth/complete                           │
  │    Authorization: Nostr <base64(kind27235)>      │
  │    Body: { challenge_id }                        │
  │──────────────────────────────────────────────────►│
  │                                                   │
  │ 4. 200 { access_token, expires_at, ... }         │
  │◄──────────────────────────────────────────────────│
```

---

## 10. HTTP Endpoints

### 10.1 `POST /auth/init`

Purpose:

- start an authentication attempt
- request a challenge for a claimed `npub`

Request body:

```json
{
  "npub": "npub1..."
}
```

Validation:

1. `npub` MUST be valid bech32 and decode to a 32-byte pubkey.
2. The server MAY normalize it immediately to hex and store both forms.

Anti-enumeration requirement:

- the server MUST return an indistinguishable challenge response for both known and unknown `npub` values
- ACL membership SHOULD be checked at completion time, not at init time

Example success response:

```json
{
  "challenge_id": "chlg_01HT...",
  "challenge": "P7l6W8J1N1c7Y5nGf7o7QK3W4dU2Nf8Q2D9q2nQ5c6Y",
  "auth_url": "https://api.example.com/auth/complete",
  "auth_method": "POST",
  "issued_at": 1710000000,
  "expires_at": 1710000060
}
```

Field rules:

| Field | Rule |
|------|------|
| `challenge_id` | Opaque server-generated identifier |
| `challenge` | At least 32 bytes of CSPRNG entropy, base64url encoded |
| `auth_url` | Absolute external URL that the completion proof must authorize |
| `auth_method` | HTTP method for the completion request, usually `POST` |
| `issued_at` | Unix seconds from server clock |
| `expires_at` | Unix seconds, MUST be no more than 60 seconds after `issued_at` |

### 10.2 `POST /auth/complete`

Purpose:

- redeem a challenge
- prove control of the Nostr private key
- obtain an application session

HTTP headers:

```text
Authorization: Nostr <base64-encoded kind-27235 event JSON>
Content-Type: application/json
```

Request body:

```json
{
  "challenge_id": "chlg_01HT..."
}
```

The request body SHOULD be minimal. Avoid putting the raw challenge in the body because the body is not the authoritative proof; the NIP-98 event is.

---

## 11. NIP-98 Completion Proof

The `Authorization` header carries a standard NIP-98 event.

Required fields:

```json
{
  "kind": 27235,
  "created_at": 1710000005,
  "pubkey": "63fe6318dc58583cfe16810f86dd09e18bfd76aabc24a0081ce2856f330504ed",
  "tags": [
    ["u", "https://api.example.com/auth/complete"],
    ["method", "POST"],
    ["payload", "f1b2..."],
    ["challenge", "P7l6W8J1N1c7Y5nGf7o7QK3W4dU2Nf8Q2D9q2nQ5c6Y"],
    ["challenge_id", "chlg_01HT..."]
  ],
  "content": "",
  "id": "<derived event id>",
  "sig": "<schnorr signature>"
}
```

Rules:

1. `kind` MUST be `27235`.
2. `content` MUST be empty.
3. There MUST be exactly one `u` tag.
4. There MUST be exactly one `method` tag.
5. There MUST be exactly one `challenge` tag.
6. There MUST be exactly one `challenge_id` tag.
7. There MUST be exactly one `payload` tag containing the SHA-256 of the exact request body bytes as lowercase hex.
8. Duplicate required tags MUST cause rejection.
9. Unknown extension tags MAY be ignored unless the implementation chooses a stricter mode.

Why `u` and `method` matter:

- they preserve NIP-98 interoperability
- they bind the proof to the exact completion endpoint
- they prevent a valid auth proof from being replayed against another endpoint

---

## 12. Validation Rules

The server MUST validate the completion request in this order:

1. Parse the `Authorization` header as a NIP-98 event.
2. Verify event structure, `kind`, and signature.
3. Verify `created_at` is within the allowed time window relative to server time.
4. Verify `u` exactly matches the externally visible absolute completion URL.
5. Verify `method` exactly matches the HTTP method used.
6. Verify exactly one `payload` tag is present and that it matches the SHA-256 of the exact request body bytes.
7. Verify `challenge_id` in the body and event are present and identical.
8. Load the challenge record by `challenge_id`.
9. Verify the challenge is not expired.
10. Verify the challenge record is still redeemable.
11. Verify the `challenge` tag equals the stored challenge value.
12. Verify the event `pubkey` matches the `npub` from init after decoding.
13. Verify ACL authorization for that `npub` or `pubkey`.
14. Create or load the per-challenge session result and atomically record challenge redemption.

Important:

- exact URL comparison MUST use the external URL seen by the client, not an internal service URL behind a proxy
- fragments are never included in HTTP request URLs and therefore MUST NOT be part of comparison
- query parameters are part of the exact URL and MUST match if present

### 12.1 Time Window

Recommendations:

- challenge TTL: 60 seconds max
- NIP-98 `created_at` skew: 60 seconds max from server clock
- lower-bound grace: implementations SHOULD allow a small negative skew relative to `issued_at` to avoid false rejection from slightly skewed client clocks

Suggested rule:

```text
issued_at - 30s <= created_at <= expires_at + 5s
```

The server clock remains authoritative.

### 12.2 Raw Body Requirement

Payload verification depends on the exact request body bytes, not on a parsed-and-reserialized JSON object.

Requirements:

1. the HTTP adapter MUST capture the raw request body bytes before JSON parsing mutates or normalizes them
2. the verifier MUST hash those exact bytes
3. middleware that consumes and reserializes the body before verification MUST NOT be used unless the original raw bytes remain available

This requirement is mandatory for interoperable server adapters.

---

## 13. Challenge State Machine

The challenge store MUST support atomic state transitions.

States:

- `issued`
- `redeemed`
- `expired`
- `failed_terminal`

### 13.1 Required Atomicity

A standalone library MUST NOT assume a single-process in-memory store.

The store interface MUST support an atomic operation equivalent to:

```text
redeem(challenge_id, event_id, session_id, expected_state = issued) -> success | already_redeemed | not_found | expired
```

This is required for:

- multi-instance server deployments
- retry safety
- race-free single-use enforcement

### 13.2 Retry And Duplicate Submission Handling

The previous draft consumed the challenge on first lookup, which is too brittle.

NAP v2 requires:

1. a successful redemption MUST transition the challenge to `redeemed`
2. the server SHOULD retain a short result cache for redeemed challenges
3. if the same valid completion request is retried during the result-cache window, the server SHOULD return the same successful auth result
4. a conflicting second request using the same `challenge_id` MUST be rejected generically

Recommended result-cache TTL:

- 30 to 60 seconds

This makes client retries deterministic if the first response was lost.

### 13.3 Result Recovery And Partial Failure Handling

The retry-success requirement means the server MUST retain enough information to reproduce the same success response during the result-cache window.

Acceptable approaches:

1. store a serialized success envelope keyed by `challenge_id`
2. store `redeemed_event_id` plus `redeemed_session_id` and load the same session record on retry

Recommended server algorithm:

1. create or load a session record idempotently for `challenge_id`
2. atomically redeem the challenge while recording `redeemed_event_id` and `redeemed_session_id`
3. if the same completion request is retried and the stored `redeemed_event_id` matches, return the same session-backed success result
4. if a challenge is marked redeemed but the referenced session record is missing, fail closed with an internal error and emit an audit event

This avoids minting multiple sessions for one challenge while keeping lost-response retries recoverable.

### 13.4 Invalid Attempt Handling

Invalid attempts SHOULD NOT blindly delete the challenge before the server knows whether the request corresponds to the issued challenge.

Recommended behavior:

1. reject malformed requests before touching challenge state
2. only attempt redemption after the challenge record is loaded and matched
3. optionally cap failures per challenge to limit abuse

---

## 14. Session Model

### 14.1 Default Recommendation

Prefer:

- opaque access tokens
- short TTL
- server-side session lookup

Recommended defaults:

| Property | Recommendation |
|----------|----------------|
| access token type | opaque 256-bit random token |
| access token TTL | 5 to 15 minutes |
| refresh token | optional, rotating, server-tracked |
| refresh TTL | 8 to 24 hours |
| revocation | immediate via server-side store |

### 14.2 JWTs

JWTs MAY be supported, but they are **not** the default recommendation.

Why:

1. immediate revocation is harder
2. ACL changes become awkward unless tokens are introspected or extremely short-lived
3. many implementations overstate JWT revocability

If JWTs are used, the implementation MUST define:

- issuer
- audience
- signing key rotation
- `sub`
- `exp`
- `iat`
- `jti`
- revocation / denylist semantics

### 14.3 Hard Fingerprinting

Do **not** hard-bind bearer tokens to `User-Agent + IP prefix` by default.

Why:

1. mobile networks and proxies cause frequent IP drift
2. `User-Agent` is unstable and low-assurance
3. the reliability cost is high while the theft resistance is weak

Safer alternatives:

- short-lived access tokens
- rotating refresh tokens
- optional risk scoring on drift
- future sender-constrained session extension if needed

---

## 15. ACL And Authorization

ACL checks MUST happen after proof verification and before session issuance.

Rules:

1. permissions are evaluated on every authorized application request, not just at login
2. removing a principal from the ACL SHOULD revoke active sessions
3. role changes SHOULD take effect without forcing a new login

Anti-enumeration guidance:

- unknown principals and unauthorized principals SHOULD fail with the same generic auth failure shape
- timing differences SHOULD be bounded; implementations MAY add response jitter or minimum processing time

---

## 16. Error Handling

Client-facing auth failures MUST be generic.

Example:

```json
{
  "status": "error",
  "message": "authentication failed"
}
```

Internally, implementations SHOULD classify errors more precisely:

- malformed_request
- invalid_signature
- wrong_audience
- wrong_method
- missing_payload
- payload_mismatch
- unknown_challenge
- expired_challenge
- challenge_redeemed
- principal_mismatch
- acl_denied
- rate_limited

That classification is for logs and metrics, not for public error bodies.

---

## 17. Reliability Requirements

### 17.1 Storage

The library MUST expose pluggable interfaces for:

- challenge store
- session store
- ACL resolver
- raw body extractor
- clock
- random source
- rate limiter
- audit sink

### 17.2 Cluster Safety

For multi-node deployments:

1. challenge redemption state MUST be shared or externally coordinated
2. session revocation state MUST be shared
3. clock skew between nodes SHOULD be bounded

### 17.3 Proxy Awareness

The library MUST support an external audience resolver because NIP-98 compares the exact absolute URL.

This matters behind:

- reverse proxies
- API gateways
- service meshes
- staging/prod domain shims

Implementations MUST NOT blindly trust forwarded headers from arbitrary clients.

Recommended rule:

1. only honor `Forwarded` or `X-Forwarded-*` headers when the immediate upstream is a configured trusted proxy
2. otherwise derive the audience from the direct request URL and host information available to the application
3. document the precedence order used to resolve scheme, host, port, and path

### 17.4 Bounded Resource Usage

Implementations SHOULD define limits for:

- outstanding issued challenges per IP
- outstanding issued challenges per `npub`
- request body size on `/auth/complete`
- challenge store TTL sweep frequency

---

## 18. HTTP Response Guidance

Recommended responses:

| Condition | Response |
|-----------|----------|
| challenge issued | `200` |
| auth success | `200` |
| auth failure | `401` with generic body |
| rate limited | `429` |
| malformed request | `400` if parsing failed before auth path; otherwise generic `401` |

This keeps protocol failures observable operationally while minimizing user enumeration.

---

## 19. Logging And Metrics

### 19.1 Do Log

- timestamp
- truncated `npub` or `pubkey`
- request id / correlation id
- challenge_id
- outcome class
- rate-limit decisions

### 19.2 Do Not Log

- raw challenge values
- raw signatures
- raw Authorization header values
- session tokens

### 19.3 Recommended Metrics

- auth_init_total
- auth_complete_total
- auth_success_total
- auth_failure_total
- auth_rate_limited_total
- challenge_redeemed_total
- challenge_retry_hit_total
- challenge_expired_total
- audience_mismatch_total
- payload_mismatch_total

---

## 20. Standalone Library Packaging Guidance

If this becomes a standalone library, split it into strict layers.

### 20.1 Package Layout

```text
nap-core/
  types/
  errors/
  validators/
  nip98/
  hashing/
  test-vectors/

nap-client-http/
  auth-init client
  auth-complete request builder
  fetch adapter

nap-server/
  challenge issuer
  challenge verifier
  session issuer
  middleware helpers
  store interfaces

nap-adapter-express/    # optional
nap-adapter-fastify/    # optional
```

### 20.2 Core Interfaces

Recommended interfaces:

- `ChallengeStore`
- `SessionStore`
- `AclResolver`
- `RateLimiter`
- `Clock`
- `RandomSource`
- `AuditLogger`
- `AudienceResolver`
- `RawBodyExtractor`

### 20.3 Test Vectors

The package should ship official test vectors for:

- exact URL matching
- payload hash generation
- duplicate tag rejection
- expired challenge rejection
- retrying the same valid completion request
- pubkey/npub mismatch

### 20.4 Keep Transport Profiles Separate

Do not ship WebSocket or relay adapters in the first package unless their audience and replay rules are fully specified.

---

## 21. Reference HTTP Flow

### 21.1 Init

```http
POST /auth/init HTTP/1.1
Host: api.example.com
Content-Type: application/json

{"npub":"npub1..."}
```

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "challenge_id":"chlg_01HT...",
  "challenge":"P7l6W8J1N1c7Y5nGf7o7QK3W4dU2Nf8Q2D9q2nQ5c6Y",
  "auth_url":"https://api.example.com/auth/complete",
  "auth_method":"POST",
  "issued_at":1710000000,
  "expires_at":1710000060
}
```

### 21.2 Complete

Body bytes:

```json
{"challenge_id":"chlg_01HT..."}
```

Payload hash:

```text
sha256(utf8(body_bytes)) => <lowercase hex>
```

Authorization event tags:

```json
[
  ["u", "https://api.example.com/auth/complete"],
  ["method", "POST"],
  ["payload", "<sha256-hex-of-body>"],
  ["challenge", "<challenge-from-init>"],
  ["challenge_id", "chlg_01HT..."]
]
```

---

## 22. Open Extensions

The following are intentionally left out of the core RFC:

1. sender-constrained session tokens
2. WebSocket auth profile
3. relay-native auth profile
4. stateless server-signed challenge envelopes
5. delegated or multi-key auth

Each of those should be specified as an extension, not implied by the core profile.

---

## 23. Final Recommendations

1. Package NAP v2 as a **NIP-98-based HTTP auth library**, not a transport-agnostic auth framework.
2. Default to **opaque server-side sessions**, not JWTs.
3. Make the challenge store **atomic and cluster-safe** from day one.
4. Treat **retry determinism** as a first-class requirement, not an implementation detail.
5. Keep audience binding based on the exact NIP-98 `u` tag, not a looser `origin` field.

---

## 24. Canonical Wire Schemas

This section defines the canonical request and response shapes the standalone library should expose.

### 24.1 Serialization Rules

1. All HTTP request and response bodies use UTF-8 JSON.
2. Payload hashes are computed over the **exact raw body bytes** sent on the wire.
3. A client library MUST build the JSON body bytes once, hash those bytes, and send the same bytes.
4. Reference client libraries SHOULD serialize JSON in compact form without trailing newline.
5. Field names are snake_case on the wire.

### 24.2 `AuthInitRequest`

```ts
export interface AuthInitRequest {
  npub: string;
}
```

Constraints:

- `npub` MUST be valid bech32
- decoded key length MUST be 32 bytes

### 24.3 `AuthInitResponse`

```ts
export interface AuthInitResponse {
  challenge_id: string;
  challenge: string;
  auth_url: string;
  auth_method: 'POST';
  issued_at: number;
  expires_at: number;
}
```

Constraints:

- `challenge_id`: 16 to 128 chars, URL-safe opaque token
- `challenge`: base64url string representing at least 32 bytes of entropy
- `auth_url`: absolute HTTPS URL
- `expires_at > issued_at`
- `expires_at - issued_at <= 60`

### 24.4 `AuthCompleteRequest`

```ts
export interface AuthCompleteRequest {
  challenge_id: string;
}
```

### 24.5 `AuthSuccessResponse`

```ts
export interface AuthSuccessResponse {
  status: 'ok';
  access_token: string;
  token_type: 'Bearer';
  expires_at: number;
  refresh_token?: string;
  refresh_expires_at?: number;
  principal: {
    npub: string;
    pubkey: string;
  };
  permissions?: string[];
  roles?: string[];
}
```

### 24.6 `AuthFailureResponse`

```ts
export interface AuthFailureResponse {
  status: 'error';
  message: 'authentication failed';
}
```

### 24.7 `AuthCompleteHttpRequest`

Reference HTTP request:

```ts
export interface AuthCompleteHttpRequest {
  method: 'POST';
  url: string;
  authorization: string; // "Nostr <base64-event-json>"
  body: AuthCompleteRequest;
}
```

---

## 25. Core Library Interfaces

These interfaces should live in `nap-core` so the server and adapters share the same contracts.

### 25.1 Challenge Types

```ts
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
```

### 25.2 Session Types

```ts
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
  refresh_token?: string;
  refresh_expires_at?: number;
  revoked_at?: number;
}
```

### 25.3 Store And Resolver Interfaces

```ts
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

export interface AclDecision {
  allowed: boolean;
  roles: string[];
  permissions: string[];
}

export interface AclResolver {
  resolve(npub: string, pubkey: string): Promise<AclDecision>;
}

export interface RateLimiter {
  consume(key: string): Promise<{ allowed: boolean; retry_after_seconds?: number }>;
}

export interface AudienceResolver<RequestLike = unknown> {
  getExternalUrl(request: RequestLike): string;
}

export interface RawBodyExtractor<RequestLike = unknown> {
  getRawBody(request: RequestLike): Promise<Uint8Array> | Uint8Array;
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
```

### 25.4 Verifier Result

`SessionStore.createForChallenge()` MUST be idempotent by `challenge_id`. If a session already exists for that challenge, it MUST return the existing session record rather than minting a second one.

`AudienceResolver` implementations SHOULD be paired with explicit trusted-proxy configuration.

```ts
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
```

---

## 26. Deterministic Error Code Registry

These codes are for logs, metrics, tests, and adapter behavior. They are **not** the public error body.

### 26.1 Init Errors

| Code | Meaning | Retryable |
|------|---------|-----------|
| `NAP_INIT_INVALID_JSON` | Request body could not be parsed | no |
| `NAP_INIT_INVALID_NPUB` | `npub` missing or malformed | no |
| `NAP_INIT_RATE_LIMITED` | Init endpoint rate-limited | yes |
| `NAP_INIT_INTERNAL` | Unexpected server failure during challenge issuance | yes |

### 26.2 Complete Errors

| Code | Meaning | Retryable |
|------|---------|-----------|
| `NAP_COMPLETE_MISSING_AUTH_HEADER` | No `Authorization` header present | no |
| `NAP_COMPLETE_INVALID_AUTH_SCHEME` | `Authorization` header is not `Nostr <...>` | no |
| `NAP_COMPLETE_INVALID_EVENT_JSON` | Header could not be decoded into event JSON | no |
| `NAP_COMPLETE_INVALID_KIND` | Event `kind` is not `27235` | no |
| `NAP_COMPLETE_INVALID_SIGNATURE` | Event signature invalid | no |
| `NAP_COMPLETE_CREATED_AT_OUT_OF_RANGE` | Event timestamp outside allowed window | maybe |
| `NAP_COMPLETE_URL_MISMATCH` | `u` tag does not match completion URL | no |
| `NAP_COMPLETE_METHOD_MISMATCH` | `method` tag does not match request method | no |
| `NAP_COMPLETE_MISSING_PAYLOAD` | `payload` tag missing on completion proof | no |
| `NAP_COMPLETE_PAYLOAD_MISMATCH` | `payload` hash does not match body bytes | no |
| `NAP_COMPLETE_MISSING_CHALLENGE_ID` | `challenge_id` missing from body or event | no |
| `NAP_COMPLETE_UNKNOWN_CHALLENGE` | No such challenge exists | maybe |
| `NAP_COMPLETE_EXPIRED_CHALLENGE` | Challenge expired | no |
| `NAP_COMPLETE_REDEEMED_CHALLENGE` | Challenge already redeemed and result cache unavailable | no |
| `NAP_COMPLETE_CHALLENGE_MISMATCH` | Event `challenge` tag does not match stored challenge | no |
| `NAP_COMPLETE_PRINCIPAL_MISMATCH` | Event pubkey does not match init `npub` | no |
| `NAP_COMPLETE_ACL_DENIED` | Principal not authorized by ACL | no |
| `NAP_COMPLETE_RATE_LIMITED` | Completion path rate-limited | yes |
| `NAP_COMPLETE_INTERNAL` | Unexpected server failure during verification | yes |

### 26.3 Type Definition

```ts
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
```

---

## 27. Conformance And Test Vectors

Every packaged implementation should ship a conformance suite.

### 27.1 Required Conformance Cases

| ID | Case | Expected Result |
|----|------|-----------------|
| `NAP-CONF-001` | valid init request | challenge issued |
| `NAP-CONF-002` | invalid `npub` | `NAP_INIT_INVALID_NPUB` |
| `NAP-CONF-003` | valid complete request | auth success |
| `NAP-CONF-004` | duplicate `challenge` tag | reject |
| `NAP-CONF-005` | exact same valid complete request retried during result-cache window | same auth success result |
| `NAP-CONF-006` | conflicting second request after redemption | generic failure |
| `NAP-CONF-007` | `u` tag differs only by trailing slash | reject unless exact external URL includes slash |
| `NAP-CONF-008` | missing `payload` tag on completion proof | reject |
| `NAP-CONF-009` | `payload` hash mismatch | reject |
| `NAP-CONF-010` | `pubkey` does not match init `npub` | reject |
| `NAP-CONF-011` | expired challenge | reject |

### 27.2 Canonical Payload Hash Vector

Reference body bytes:

```json
{"challenge_id":"chlg_01HT..."}
```

Properties:

- UTF-8 byte length: `31`
- SHA-256 lowercase hex:

```text
df5a3e3495e2fa3163de8b0df9a7b54a7b873ffbee4e24c74ebac529d577e3cd
```

Any client library that serializes that exact body MUST produce that exact payload hash.

### 27.3 URL Matching Vectors

| Completion URL | Event `u` | Expected |
|----------------|-----------|----------|
| `https://api.example.com/auth/complete` | `https://api.example.com/auth/complete` | pass |
| `https://api.example.com/auth/complete` | `https://api.example.com/auth/complete/` | fail |
| `https://api.example.com/auth/complete?x=1` | `https://api.example.com/auth/complete` | fail |
| `https://api.example.com/auth/complete` | `http://api.example.com/auth/complete` | fail |

### 27.4 Minimum Adapter Test Coverage

Each server adapter should test:

1. proxy-aware external URL resolution
2. correct extraction of raw body bytes before parsing
3. generic public failure response body
4. deterministic mapping from internal error code to HTTP status

---

## Appendix A. NAP vs NIP-46

This appendix is explanatory, not normative.

NAP and NIP-46 solve different problems.

| Protocol | Primary purpose | Transport | Output | Who uses it directly |
|----------|-----------------|-----------|--------|----------------------|
| NAP v2 | authenticate a user to an HTTP application and obtain an app session | HTTPS | session token / session state | application client and application server |
| NIP-46 | ask a remote signer to perform signing or crypto operations without exposing the private key to the client | Nostr relays using encrypted `kind:24133` request/response events | signed event or crypto result | client and remote signer / bunker |

### A.1 Core Difference

NAP is an **application authentication profile**.

- It tells an HTTP server how to verify that a user controls a Nostr key right now.
- It produces an application session after successful completion.
- It is server-facing.

NIP-46 is a **remote signing control plane**.

- It tells a client how to ask another system to sign on its behalf.
- It does not define an HTTP login or app-session model.
- It is signer-facing.

### A.2 When To Use NAP

Use NAP when:

- a web app or API needs login-with-Nostr
- the server must issue a first-party application session
- the authentication proof must be bound to an exact HTTP endpoint and body
- the server wants replay protection, ACL checks, and retry-safe session issuance

Typical result:

- `POST /auth/init`
- `POST /auth/complete` with NIP-98 proof
- short-lived session token or cookie

### A.3 When To Use NIP-46

Use NIP-46 when:

- the client should not hold the user's private key
- signing happens in a bunker, hardware signer, mobile wallet, or other remote signer
- the client needs remote `sign_event`, encryption, or decryption capabilities
- transport over Nostr relays is acceptable

Typical result:

- client sends `sign_event` or other command to remote signer
- remote signer returns the signed event or crypto result

### A.4 How They Fit Together

NIP-46 can sit **under** NAP.

Example:

1. web app asks its API for a NAP challenge
2. web app asks a NIP-46 bunker to sign the NIP-98 completion event
3. web app sends that signed event to `/auth/complete`
4. API verifies NAP and issues the app session

In that model:

- NIP-46 is only the signing transport
- NAP is still the HTTP login protocol

### A.5 Selection Guidance

If the question is "how does my server log a Nostr user into my web app?", use NAP.

If the question is "how does my client get something signed without handling the private key locally?", use NIP-46.

If both are true, combine them:

- NIP-46 for key custody and remote signing
- NAP for web login and session issuance

---

## Appendix B. Web App Integration Diagrams

This appendix is explanatory, not normative.

### B.1 Browser App With Injected Signer

```text
┌──────────────┐        ┌─────────────────────┐        ┌────────────────────┐
│ User Browser │        │ Injected Nostr      │        │ App API            │
│ SPA / Web UI │        │ Signer / Extension  │        │ /auth + app routes │
└──────┬───────┘        └──────────┬──────────┘        └─────────┬──────────┘
       │                           │                             │
       │ 1. POST /auth/init        │                             │
       │────────────────────────────────────────────────────────►│
       │                           │                             │
       │ 2. {challenge_id, ...}    │                             │
       │◄────────────────────────────────────────────────────────│
       │                           │                             │
       │ 3. build NIP-98 event     │                             │
       │ 4. request signature      │────────────────────────────►│
       │                           │ 5. signed kind:27235 event │
       │                           │◄────────────────────────────│
       │                           │                             │
       │ 6. POST /auth/complete    │                             │
       │    Authorization: Nostr   │                             │
       │────────────────────────────────────────────────────────►│
       │                           │                             │
       │ 7. session token / cookie │                             │
       │◄────────────────────────────────────────────────────────│
       │                           │                             │
       │ 8. normal authenticated API requests                    │
       │────────────────────────────────────────────────────────►│
```

Use this model when the browser can access a local signer directly.

### B.2 Browser App With BFF Session Cookie

```text
┌──────────────┐        ┌──────────────────────┐        ┌──────────────────┐
│ User Browser │        │ Web App BFF          │        │ Internal API /   │
│ HTML / SPA   │        │ same-origin backend  │        │ service layer    │
└──────┬───────┘        └──────────┬───────────┘        └────────┬─────────┘
       │                           │                              │
       │ 1. start login            │                              │
       │──────────────────────────►│                              │
       │                           │ 2. issue NAP challenge       │
       │                           │ and verify NAP completion    │
       │                           │ locally or via auth module   │
       │                           │                              │
       │ 3. Set-Cookie session     │                              │
       │◄──────────────────────────│                              │
       │                           │                              │
       │ 4. browser sends cookie   │                              │
       │ on later requests         │─────────────────────────────►│
       │                           │                              │
```

Use this model when:

- the web app wants cookie-based auth
- browser JavaScript should not manage bearer tokens directly
- the auth server and web app share an origin or trusted backend boundary

### B.3 Browser App Using NIP-46 Under NAP

```text
┌──────────────┐     ┌─────────────────────┐     ┌────────────────────┐     ┌──────────────────┐
│ User Browser │     │ NIP-46 Remote       │     │ App API            │     │ Session / ACL    │
│ SPA / Web UI │     │ Signer / Bunker     │     │ /auth endpoints    │     │ Stores           │
└──────┬───────┘     └──────────┬──────────┘     └─────────┬──────────┘     └────────┬─────────┘
       │                        │                          │                         │
       │ 1. POST /auth/init     │                          │                         │
       │──────────────────────────────────────────────────►│                         │
       │                        │                          │ 2. store challenge      │
       │                        │                          │────────────────────────►│
       │ 3. challenge response  │                          │                         │
       │◄──────────────────────────────────────────────────│                         │
       │                        │                          │                         │
       │ 4. ask bunker to sign  │─────────────────────────►│                         │
       │    NIP-98 completion   │                          │                         │
       │ 5. signed event        │◄─────────────────────────│                         │
       │                        │                          │                         │
       │ 6. POST /auth/complete │                          │                         │
       │──────────────────────────────────────────────────►│                         │
       │                        │                          │ 7. verify challenge,    │
       │                        │                          │ ACL, session issuance   │
       │                        │                          │────────────────────────►│
       │ 8. session token       │                          │                         │
       │◄──────────────────────────────────────────────────│                         │
```

This is the clean composition model for a web app that wants:

- remote key custody via NIP-46
- HTTP login semantics via NAP
- normal application sessions after login

### B.4 Recommended Web App Boundary

```text
Browser/UI
  ├─ obtains challenge from app API
  ├─ obtains NIP-98 signature from signer
  └─ sends completion proof once

Auth API
  ├─ validates NIP-98 + NAP rules
  ├─ checks ACL
  ├─ issues session
  └─ exposes generic failures only

Signer
  └─ only signs the exact completion event; it does not issue app sessions
```

The important separation is:

- signer proves key control
- app API decides authorization and session issuance

---

## Appendix C. Example Express And Fastify Adapter APIs

This appendix is explanatory, not normative.

The goal of the framework adapters is to keep all protocol logic in `nap-server` while making framework integration safe and low-friction.

### C.1 Adapter Design Principles

An adapter should:

1. extract raw request bytes without mutating them
2. resolve the externally visible absolute URL safely
3. call the shared verifier from `nap-server`
4. map verifier results to framework responses
5. optionally translate auth success into a cookie or bearer-token response

An adapter should not:

- reimplement NAP validation rules
- silently fall back when raw body bytes are unavailable
- trust forwarded headers unless configured to trust the upstream proxy

### C.2 Shared Shape

Both adapters should expose the same conceptual hooks:

```ts
export interface NapAdapterOptions<RequestLike, ResponseLike> {
  issueChallenge: (input: AuthInitRequest, ctx: { req: RequestLike }) => Promise<AuthInitResponse>;
  verifyCompletion: (ctx: {
    req: RequestLike;
    rawBody: Uint8Array;
  }) => Promise<VerifyCompleteResult>;
  writeSuccess?: (ctx: {
    req: RequestLike;
    res: ResponseLike;
    result: VerifyCompleteSuccess;
  }) => Promise<void> | void;
  writeFailure?: (ctx: {
    req: RequestLike;
    res: ResponseLike;
    result: VerifyCompleteFailure;
  }) => Promise<void> | void;
}
```

Recommended default behavior:

- `writeSuccess` returns `200` with `AuthSuccessResponse`
- `writeFailure` returns generic public failures per the core RFC
- apps can override `writeSuccess` to set a cookie instead of returning a bearer token body

### C.3 Express Adapter

Recommended exports:

```ts
export interface NapExpressOptions
  extends NapAdapterOptions<Express.Request, Express.Response> {}

export function createNapExpressJsonParser(): Express.RequestHandler;

export function createNapExpressInitHandler(
  options: NapExpressOptions
): Express.RequestHandler;

export function createNapExpressCompleteHandler(
  options: NapExpressOptions
): Express.RequestHandler;

export function createNapExpressRouter(
  options: NapExpressOptions
): Express.Router;
```

Recommended usage:

```ts
import express from 'express';
import {
  createNapExpressJsonParser,
  createNapExpressRouter,
} from 'nap-adapter-express';

const app = express();

app.use(createNapExpressJsonParser());

app.use(
  '/auth',
  createNapExpressRouter({
    issueChallenge,
    verifyCompletion,
    writeSuccess: ({ res, result }) => {
      res.cookie('session', result.session.access_token, {
        httpOnly: true,
        secure: true,
        sameSite: 'lax',
      });
      res.status(200).json({ status: 'ok' });
    },
  })
);
```

Express-specific requirement:

- `createNapExpressJsonParser()` should internally use `express.json({ verify(...) { ... } })` so the raw request bytes are captured before body parsing

The adapter should attach the raw body to the request object in a private symbol or typed extension rather than a generic untyped field.

### C.4 Fastify Adapter

Recommended exports:

```ts
export interface NapFastifyOptions
  extends NapAdapterOptions<FastifyRequest, FastifyReply> {
  prefix?: string;
}

export const napFastifyPlugin: FastifyPluginAsync<NapFastifyOptions>;
```

Recommended usage:

```ts
import Fastify from 'fastify';
import { napFastifyPlugin } from 'nap-adapter-fastify';

const app = Fastify();

await app.register(napFastifyPlugin, {
  prefix: '/auth',
  issueChallenge,
  verifyCompletion,
  writeSuccess: async ({ res, result }) => {
    res
      .setCookie('session', result.session.access_token, {
        httpOnly: true,
        secure: true,
        sameSite: 'lax',
        path: '/',
      })
      .status(200)
      .send({ status: 'ok' });
  },
});
```

Fastify-specific requirement:

- the plugin should require raw body support through a framework-supported mechanism such as a raw-body plugin or custom parser hook, and it should fail registration if exact raw bytes will not be available for `/auth/complete`

### C.5 Route Surface

Both adapters should expose the same route behavior:

| Route | Method | Behavior |
|-------|--------|----------|
| `/auth/init` | `POST` | parse `AuthInitRequest`, issue challenge, return `AuthInitResponse` |
| `/auth/complete` | `POST` | require raw body + `Authorization`, verify NAP completion, return session result |

They should not automatically install unrelated auth middleware.

### C.6 Cookie vs Bearer Response Modes

The adapters should support two success modes:

1. bearer response mode
2. cookie response mode

Bearer response mode:

- return the RFC `AuthSuccessResponse`
- useful for SPAs and mobile clients

Cookie response mode:

- set an HTTP-only secure cookie
- return a minimal success body
- useful for BFF and same-origin web apps

The session issuance decision still belongs to `nap-server`; the adapter only chooses how that session is returned to the client.

### C.7 Startup Failure Conditions

An adapter should fail fast during startup or registration if:

- raw body extraction is not available
- the audience resolver is missing
- trusted-proxy behavior is ambiguous
- required cookie-signing or response dependencies are misconfigured

These failures should be startup-time errors, not runtime best-effort behavior.

### C.8 What The App Still Owns

Even with adapters, the application still owns:

- `ChallengeStore`
- `SessionStore`
- `AclResolver`
- `AudienceResolver`
- trusted-proxy policy
- cookie policy and CSRF strategy if cookie mode is used

The adapter only removes framework boilerplate. It does not remove application security decisions.

---

## Appendix D. NAP vs OAuth 2.0

This appendix is explanatory, not normative.

NAP and OAuth 2.0 share structural similarities — both are token-based protocols that separate authentication from subsequent API access — but they differ in trust model, complexity, and scope.

### D.1 Structural Comparison

| Aspect | NAP v2 | OAuth 2.0 |
|--------|--------|-----------|
| **Flow shape** | Two-step: `/auth/init` → `/auth/complete` | Multi-step: authorize → token exchange (+ optional refresh) |
| **Identity verification** | Cryptographic — client signs a NIP-98 proof with a Nostr key | Delegated — an authorization server vouches for the user |
| **Third-party authorization server** | None — the application server verifies identity directly | Required — identity is asserted by a separate provider |
| **Browser redirects** | None — two direct API calls | Typically required for the authorization code flow |
| **Token type** | Opaque server-side access token | Access token (opaque or JWT), refresh token, ID token (OIDC), authorization code |
| **Token transport** | `Authorization: Bearer` header or HTTP-only cookie | `Authorization: Bearer` header |
| **Scopes / permissions** | Roles and permissions resolved server-side via ACL at authentication time | Scopes requested at authorization time and encoded in the token grant |
| **Refresh tokens** | Supported (optional) | Supported (standard) |
| **Token revocation** | Server-side (`revoked_at` on session record) | Token revocation endpoint (RFC 7009) |
| **Delegation** | Not supported — single-party authentication only | Core use case — "app A accesses resource B on behalf of user C" |

### D.2 Trust Model

OAuth 2.0 is built around **delegated trust**. The client never sees the user's credentials; instead, it receives a token from a trusted authorization server that asserts the user's identity and granted scopes. This makes OAuth well-suited for third-party integrations where an application needs access to another service's resources on behalf of a user.

NAP uses **direct cryptographic proof**. The user proves control of a Nostr private key by signing a NIP-98 event bound to the server's challenge. There is no intermediary — the application server validates the signature itself. This eliminates the need for a centralized identity provider but limits the protocol to first-party authentication.

### D.3 Complexity

OAuth 2.0 defines multiple grant types (authorization code, client credentials, device code, etc.), token introspection, dynamic client registration, and the OpenID Connect layer for identity. This flexibility comes with significant implementation complexity and a large attack surface that must be carefully managed.

NAP has a single flow with two endpoints. There is one way to authenticate, one token shape, and one session model. The simplicity is intentional — NAP is scoped to HTTP login, not general-purpose authorization.

### D.4 When To Prefer Each

Use **NAP** when:

- the application authenticates users directly by Nostr key
- no third-party identity delegation is needed
- simplicity and a minimal protocol surface are priorities
- cryptographic proof of key ownership is the desired authentication factor

Use **OAuth 2.0** when:

- the application needs delegated access to third-party resources
- users authenticate through an external identity provider (Google, GitHub, etc.)
- fine-grained, per-resource scoping across multiple services is required
- the ecosystem already uses OAuth/OIDC infrastructure

### D.5 Summary

NAP borrows the token-based session pattern from OAuth but replaces the delegated authorization model with direct cryptographic identity verification. OAuth answers "can this app act on behalf of this user at that service?" NAP answers "does this user control this Nostr key right now?"

---

## Appendix E. Implementation Plan

This appendix is explanatory, not normative.

The recommended delivery strategy is to build the protocol from the inside out:

1. `nap-core`
2. `nap-server`
3. `nap-client-http`
4. framework adapters
5. conformance suite
6. packaging and release

That order keeps security-critical logic centralized before any framework-specific integration is added.

### E.1 Phase 0: Freeze Scope

Decisions to freeze before coding:

- HTTP profile only
- NIP-98-based completion proof
- opaque server-side sessions as default
- no WebSocket auth profile in v1
- no JWT-specific behavior in core APIs

Deliverable:

- locked RFC revision and package boundaries

Exit criteria:

- no unresolved transport questions
- no unresolved question about whether the library is signer-side or server-side

### E.2 Phase 1: Build `nap-core`

`nap-core` should contain pure protocol logic with no web-framework dependency.

Work items:

- TypeScript types for wire schemas and result shapes
- tag extraction and duplicate-tag validation
- NIP-98 event parsing and validation helpers
- payload hashing helpers
- exact URL comparison helpers
- timestamp window validation
- deterministic error-code definitions
- official conformance vectors as fixtures

Deliverable:

- framework-agnostic module that can validate completion inputs and produce typed results

Exit criteria:

- all pure protocol tests pass
- all conformance fixtures pass in-process
- no Express/Fastify types leak into `nap-core`

### E.3 Phase 2: Build `nap-server`

`nap-server` should implement the stateful auth flow on top of `nap-core`.

Work items:

- challenge issuance service
- challenge lookup and expiry handling
- idempotent per-challenge session issuance
- atomic challenge redemption flow
- ACL integration hooks
- rate-limiter integration hooks
- audit logging hooks
- generic public error-response helpers

Deliverable:

- server auth engine exposing `issueChallenge()` and `verifyCompletion()`

Exit criteria:

- duplicate valid completion requests return the same success result during result-cache window
- conflicting redemptions fail closed
- missing session after redemption is surfaced as internal failure
- store contracts are usable in single-node and clustered deployments

### E.4 Phase 3: Build `nap-client-http`

`nap-client-http` should help clients produce correct HTTP requests without embedding backend policy.

Work items:

- `auth/init` client
- completion-body serializer
- payload hash generation from exact body bytes
- NIP-98 completion-event builder
- signer abstraction for local signer or injected signer
- `auth/complete` request builder

Deliverable:

- client package that can construct a correct completion request from a challenge response and signing capability

Exit criteria:

- same serialized body bytes are used for hash and request body
- generated NIP-98 completion proof passes server conformance tests
- no session-policy assumptions are embedded in the client package

### E.5 Phase 4: Build Framework Adapters

Adapters should stay thin and only solve framework integration problems.

Work items:

- `nap-adapter-express`
- `nap-adapter-fastify`
- raw-body capture hooks
- proxy-aware audience resolution wiring
- cookie-mode and bearer-mode response helpers

Deliverable:

- small adapter packages that delegate all protocol decisions to `nap-server`

Exit criteria:

- adapters fail fast if raw-body support is unavailable
- adapters can run the same black-box tests against shared fixtures
- adapter code contains no duplicated protocol validation logic

### E.6 Phase 5: Conformance And Interop

The project should ship a reusable test harness, not just unit tests.

Work items:

- shared conformance runner
- golden test vectors
- retry/replay race tests
- proxy/audience mismatch tests
- malformed-header and malformed-body tests
- cookie-mode and bearer-mode adapter tests

Deliverable:

- package-level conformance suite that can be reused by future implementations

Exit criteria:

- all packages pass the same conformance matrix
- client-generated proofs are accepted by the reference server
- regression tests cover retry safety and raw-body correctness

### E.7 Phase 6: Security Hardening

Before publishing, do one explicit hardening pass.

Work items:

- verify no secrets are logged
- verify generic public error behavior
- verify trusted-proxy configuration rules
- verify challenge TTL and result-cache behavior
- verify idempotent session creation under concurrency
- verify denial-of-service limits around challenge issuance

Deliverable:

- security review checklist and hardening notes

Exit criteria:

- no known replay or duplicate-redemption bug
- no known raw-body verification gap
- no adapter path that trusts spoofed forwarded headers by default

### E.8 Phase 7: Packaging And Release

Suggested package order:

1. `nap-core`
2. `nap-server`
3. `nap-client-http`
4. `nap-adapter-express`
5. `nap-adapter-fastify`

Work items:

- package manifests and exports
- semver and versioning policy
- README and quickstart docs
- changelog policy
- minimal example apps

Deliverable:

- publishable packages with docs and example integrations

Exit criteria:

- each package has a clear public API
- examples cover bearer mode and cookie mode
- release artifacts include conformance vectors

### E.9 Recommended v1 Cut

The safest v1 cut is:

- `nap-core`
- `nap-server`
- `nap-client-http`
- one adapter, preferably `nap-adapter-express`
- conformance fixtures

Fastify can follow immediately after if the core APIs remain clean.

### E.10 Post-v1 Work

Post-v1 candidates:

- second server language implementation
- additional Node adapters
- sender-constrained session extension
- stateless signed challenge envelope profile
- formal `NAP-WS` profile as a separate RFC
