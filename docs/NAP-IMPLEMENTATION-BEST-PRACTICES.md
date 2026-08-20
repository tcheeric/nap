# NAP Implementation Best Practices

**Date:** 2026-03-24
**Based on:** NAP v2 RFC, production implementation for Possa Merchant Platform
**Audience:** Developers integrating NAP into Nostr-authenticated web applications

---

## 1. Overview

This document captures implementation lessons from deploying NAP (Nostr Authentication Protocol) in a real merchant SPA with a Spring Boot backend. It covers both client-side (browser) and server-side concerns, with emphasis on the practical problems that arise beyond what the RFC specifies.

The implementation replaced per-request NIP-98 signing with NAP session-based auth, including session resume on page reload, step-up re-authentication, auto-lock timers, and multi-tab coordination.

---

## 2. Client-Side Best Practices

### 2.1 Send Hex Pubkey, Not npub

The RFC specifies `npub` (bech32-encoded) in the init request. In practice, sending the hex pubkey is simpler and avoids a bech32 decode step on the server that adds a library dependency for no security benefit.

The server already works with hex pubkeys internally (NIP-98 events carry hex), so requiring bech32 at the NAP boundary only adds a conversion step that can fail.

**Recommendation:** Accept both formats server-side, but prefer hex from SPA clients.

```typescript
// Preferred: send hex directly
const initResp = await napInit(pubkey); // hex

// Avoid: unnecessary encode/decode round-trip
const initResp = await napInit(hexToNpub(pubkey)); // bech32
```

### 2.2 Use Raw Fetch for Auth Endpoints

NAP auth endpoints (`/auth/init`, `/auth/complete`, `/auth/logout`, `/auth/session`) must NOT go through your authenticated API client. The API client attaches NIP-98 headers or expects session cookies in a specific way. Auth endpoints need `credentials: 'include'` but no Authorization header.

```typescript
// Dedicated fetch wrapper for NAP — bypasses api.* helpers
async function napFetch<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include', // required for Set-Cookie
    body: JSON.stringify(body),
  });
  if (!res.ok) throw Object.assign(new Error(await res.text()), { status: res.status });
  if (res.status === 204) return {} as T;
  return res.json();
}
```

### 2.3 Dual-Mode API Client

During migration, your API client must support both NIP-98 per-request signing and session cookie auth. Use a module-level mode flag:

```typescript
let authMode: 'nip98' | 'session' = 'nip98';

async function request(path, options) {
  const fetchOpts = { /* ... */ };

  if (authMode === 'session') {
    fetchOpts.credentials = 'include'; // browser sends cookie
  } else if (nip98Signer) {
    // compute body hash, sign NIP-98 event, set Authorization header
  }

  const res = await fetch(url, fetchOpts);

  if (res.status === 428) throw new StepUpRequiredError();
  if (res.status === 401 && authMode === 'session') sessionExpiredHandler?.();
  // ...
}
```

### 2.4 NAP Login with NIP-98 Fallback

Not all backends will support NAP immediately. Detect this by catching a 404 on `/auth/init` and falling back to NIP-98:

```typescript
async function loginWithFallback(nsecHex: string, passphrase: string) {
  try {
    await napLogin(nsecHex, passphrase);
  } catch (err) {
    if (err.status === 404) {
      // Backend doesn't support NAP yet
      await legacyLoginWithNsec(nsecHex, passphrase);
    } else {
      throw err;
    }
  }
}
```

### 2.5 Session Resume on Page Reload

**This is the single most important UX concern.** Without session resume, every page refresh forces a password prompt even though the HttpOnly session cookie is still valid.

The pattern:

1. On AuthProvider mount, call `GET /auth/session` with `credentials: 'include'`
2. If valid, set `isAuthenticated: true` immediately — no password needed
3. If expired/missing, fall back to the unlock prompt

```typescript
// AuthProvider mount effect
useEffect(() => {
  hasStoredKey().then(async (has) => {
    if (has) {
      const session = await napResumeSession();
      if (session?.pubkey) {
        setAuthMode('session');
        setState({
          pubkey: session.pubkey,
          isAuthenticated: true,
          isRestoringSession: false,
          // key stays locked — only unlocked for step-up
        });
        return;
      }
    }
    setState(prev => ({ ...prev, isRestoringSession: false }));
  });
}, []);
```

### 2.6 Avoid Redirect Flicker with isRestoringSession

Protected routes must wait for the session resume check to complete. Without this, the user briefly sees the login page before being redirected back.

```typescript
function ProtectedRoute({ children }) {
  const { isAuthenticated, isRestoringSession } = useAuth();
  if (isRestoringSession) return null; // blank while checking
  if (!isAuthenticated) return <Navigate to="/login" />;
  return children;
}
```

The `isRestoringSession` flag starts `true` and becomes `false` after the session resume check resolves — regardless of whether the session was valid. This prevents any route decisions before the check is complete.

### 2.7 Lock the Private Key After Sync

The private key is needed for NIP-04/NIP-44 decryption during the initial data sync from Nostr relays. After sync completes, clear it from memory:

```typescript
// After sync data is stored to localStorage
if (sessionMode === 'session') {
  lockKey(); // clears privkeyRef
  startActivityTimer(() => lockKey());
}
```

The session cookie handles all subsequent API auth. The key is only needed again for:
- Step-up re-auth (Stripe disconnect, nsec export)
- NIP-04/44 decrypt during a fresh sync

### 2.8 Step-Up Re-Auth is Transient

When a sensitive operation requires step-up, decrypt the key, use it for one NAP exchange, and discard immediately. Do NOT keep it in memory or restart the auto-lock timer:

```typescript
async function napStepUp(passphrase: string): Promise<string> {
  const nsecHex = await loadEncryptedKey(passphrase);
  const pubkey = derivePubkey(nsecHex);

  const initResp = await napInit(pubkey);
  const proof = createNip98Event(nsecHex, initResp.auth_url, 'POST');
  const result = await napComplete(initResp.challenge_id, proof);

  // Key is NOT kept in memory — transient use only
  return result.step_up_token || result.session_id;
}
```

### 2.9 Multi-Tab Coordination

Use `BroadcastChannel` to propagate auth state changes across tabs:

```typescript
const channel = new BroadcastChannel('app-session');

// Sending tab
function logout() {
  revokeSession();
  channel.postMessage({ type: 'logout' });
}

// Receiving tabs
channel.onmessage = (event) => {
  if (event.data.type === 'logout') clearLocalAuthState();
  if (event.data.type === 'lock') clearPrivkeyFromMemory();
};
```

Message types to propagate: `logout`, `lock`, `session_refresh`.

### 2.10 Auto-Lock Timer

Reset on `mousemove`, `keydown`, `pointerdown`. When it fires, clear the private key but leave the session cookie intact:

```typescript
function startActivityTimer(onLock: () => void) {
  const TIMEOUT = 15 * 60 * 1000; // 15 minutes
  let timer = setTimeout(onLock, TIMEOUT);

  const reset = () => { clearTimeout(timer); timer = setTimeout(onLock, TIMEOUT); };

  for (const event of ['mousemove', 'keydown', 'pointerdown']) {
    document.addEventListener(event, reset, { passive: true });
  }
}
```

After auto-lock, the user can still browse (session cookie works) but sensitive operations require passphrase entry.

---

## 3. Server-Side Best Practices

### 3.1 Session Filter Before NIP-98 Filter

The session filter must run before the NIP-98 filter in the security chain. If a valid session cookie exists, set the SecurityContext and skip NIP-98 validation entirely. If no valid cookie, fall through to NIP-98:

```
Filter chain: MerchantSessionFilter → Nip98AuthFilter → ApiKeyAuthFilter → ...
```

Both filters set the same SecurityContext type (`NostrAuthentication` with the merchant pubkey), so downstream controllers don't need to know which auth method was used.

### 3.2 Exclude Auth Endpoints from All Auth Filters

NAP auth endpoints are public — they must be excluded from every auth filter in the chain, not just Spring Security's `permitAll()`:

```java
// ApiKeyAuthFilter — add to EXCLUDED_PATHS
"/api/v1/auth"

// Nip98AuthFilter — already excluded (not in protectedPaths)

// Spring Security — add to permitAll()
.requestMatchers("/api/v1/auth/**").permitAll()
```

Missing any one of these causes the auth endpoints to be blocked by a filter that expects credentials the client doesn't have yet.

### 3.3 Session Cookie Configuration

```java
Cookie cookie = new Cookie("merchant_session", sessionId);
cookie.setHttpOnly(true);   // prevents XSS access
cookie.setSecure(true);     // HTTPS only
cookie.setPath("/");        // available to all paths
cookie.setMaxAge(3600);     // 1 hour
cookie.setAttribute("SameSite", "Lax"); // CSRF protection for POST/PUT/DELETE
```

- **HttpOnly** is non-negotiable — the SPA must never read the session ID directly.
- **SameSite=Lax** is correct for SPAs that submit forms/XHR from the same origin. Use `Strict` only if you never navigate from external links.
- **Secure** must be `true` in production. For local development, you may need to set it conditionally.

### 3.4 Session Resume Endpoint

Add `GET /auth/session` that validates the cookie and returns the merchant pubkey. This enables the client to resume sessions on page reload:

```java
@GetMapping("/session")
public ResponseEntity<?> checkSession(HttpServletRequest request) {
    String sessionId = extractSessionCookie(request);
    if (sessionId == null) return ResponseEntity.status(401).body(noSessionError());

    return sessionPort.validateSession(sessionId)
        .map(info -> ResponseEntity.ok(Map.of("pubkey", info.pubkey())))
        .orElse(ResponseEntity.status(401).body(expiredError()));
}
```

This endpoint is lightweight — it only does a database lookup, no Schnorr verification.

### 3.5 Touch Session on Activity

Every time the session filter validates a request, refresh the `expires_at` and `last_activity` timestamps. This implements sliding expiration:

```sql
UPDATE merchant_sessions
SET last_activity = NOW(), expires_at = ?
WHERE session_id = ? AND status = 'ACTIVE'
```

Without this, sessions expire at a fixed time regardless of activity.

### 3.6 Step-Up Token Lifecycle

Step-up tokens are single-use and short-lived (10 minutes):

1. Client completes a fresh NAP exchange with `?step_up=true`
2. Server generates a random token, stores it on the session row with an expiry
3. Client sends the token as `X-Step-Up-Token` header
4. Server validates and consumes (NULLs) the token atomically

```sql
-- Consume step-up token (returns affected rows > 0 if valid)
UPDATE merchant_sessions
SET step_up_token = NULL, step_up_expires = NULL
WHERE step_up_token = ? AND step_up_expires > NOW() AND status = 'ACTIVE'
```

### 3.7 Database Schema

Recommended table structure with indexed columns for the common query patterns:

```sql
CREATE TABLE merchant_sessions (
    session_id       VARCHAR(64)  PRIMARY KEY,
    merchant_pubkey  VARCHAR(64)  NOT NULL,
    challenge_id     VARCHAR(64)  NOT NULL UNIQUE,
    challenge        VARCHAR(256) NOT NULL,
    status           VARCHAR(16)  NOT NULL DEFAULT 'PENDING'
                     CHECK (status IN ('PENDING', 'ACTIVE', 'EXPIRED', 'REVOKED')),
    step_up_token    VARCHAR(64),
    step_up_expires  TIMESTAMPTZ,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    expires_at       TIMESTAMPTZ  NOT NULL,
    last_activity    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- Query patterns that need indexes:
CREATE INDEX idx_sessions_pubkey   ON merchant_sessions (merchant_pubkey);
CREATE INDEX idx_sessions_status   ON merchant_sessions (status) WHERE status = 'ACTIVE';
CREATE INDEX idx_sessions_expires  ON merchant_sessions (expires_at)
    WHERE status IN ('PENDING', 'ACTIVE');
```

### 3.8 Periodic Session Cleanup

Expired sessions should be swept periodically, not left to accumulate:

```java
@Scheduled(fixedRate = 900_000) // every 15 minutes
public void cleanupExpiredSessions() {
    int expired = repository.expireOldSessions();
    if (expired > 0) log.info("session_cleanup expired={}", expired);
}
```

```sql
UPDATE merchant_sessions
SET status = 'EXPIRED'
WHERE status IN ('PENDING', 'ACTIVE') AND expires_at < NOW()
```

### 3.9 Reuse the Same SecurityContext Type

The session filter should set the same `NostrAuthentication` record that the NIP-98 filter sets. This means all downstream code — controllers, services, authorization checks — works identically regardless of auth method:

```java
// In MerchantSessionFilter
NostrAuthentication auth = new NostrAuthentication(
    session.pubkey(),
    "session:" + session.sessionId(), // distinguishable event ID
    request.getMethod(),
    request.getRequestURL().toString(),
    Instant.now()
);
SecurityContext.setNostrAuthentication(auth);
```

Controllers call `SecurityContext.getCurrentNostrPubkey()` and don't care whether it came from a cookie or a NIP-98 header.

### 3.10 CORS Configuration for Session Cookies

For cross-origin cookie flow to work, CORS must be configured correctly:

```java
configuration.setAllowCredentials(true);          // required for cookies
configuration.setAllowedOrigins(List.of(          // explicit origins, no wildcards
    "https://merchant.example.com"
));
configuration.setAllowedHeaders(List.of(
    "Authorization", "Content-Type", "X-Step-Up-Token" // step-up header
));
```

**`allowCredentials(true)` and wildcard origins (`*`) are mutually exclusive.** You must list explicit origins.

---

## 4. Migration Strategy

### 4.1 Dual-Auth During Transition

Both NIP-98 and session cookie auth must work simultaneously. The filter chain checks cookies first, falls through to NIP-98 if no valid cookie:

```
Request arrives
  → Session filter: cookie present and valid? → set SecurityContext, skip NIP-98
  → Session filter: no cookie or invalid?     → fall through
  → NIP-98 filter: Authorization header?      → validate, set SecurityContext
  → NIP-98 filter: no header?                 → 401
```

### 4.2 Feature Detection

The client detects NAP support by attempting `/auth/init`. If 404, fall back to NIP-98. This avoids configuration flags or version negotiation.

### 4.3 Phased Rollout

| Phase | Auth Method | Key Lifetime | Step-Up |
|-------|-------------|-------------|---------|
| 1 (Beta) | NIP-98 per-request | Entire session | None |
| 2 (NAP) | Session cookie | Locked after sync | NAP challenge |
| 3 (Hardening) | Session cookie | Auto-lock 15 min | NAP + multi-tab |

---

## 5. Security Considerations

### 5.1 Key Exposure Reduction

| Operation | NIP-98 | NAP |
|-----------|--------|-----|
| Login | Key in memory entire session | Key used for 2 signatures (init proof + sync decrypt), then cleared |
| API calls | Key signs every request | Cookie sent automatically, key not needed |
| Sensitive ops | No mechanism | Step-up: key decrypted transiently, used once, discarded |

### 5.2 Cookie vs Key Theft

- **Stolen cookie:** time-limited (1 hour), revocable server-side, scoped to one domain
- **Stolen signing key:** permanent access, cannot be revoked without key rotation

NAP significantly reduces the window where the key is vulnerable to memory-scraping attacks.

### 5.3 CSRF Protection

`SameSite=Lax` prevents CSRF for state-changing methods (POST, PUT, DELETE). GET requests can be triggered cross-site but are read-only. This is sufficient for APIs that follow REST conventions.

### 5.4 Challenge Replay

Challenges are single-use (status transitions from PENDING to ACTIVE atomically) with a 5-minute TTL. The NIP-98 proof is bound to the exact completion URL and method, preventing replay against other endpoints.

### 5.5 Session Fixation

Sessions are created server-side after NAP completion. The client never provides a session ID — it's always server-generated and set via `Set-Cookie`.

### 5.6 Step-Up Is Blast Radius, Not Consent

The transient key use in §2.8 is worth doing, but be precise about what the resulting token proves. It proves *key control at this moment*. It does not prove a human approved anything: NIP-98 carries no user-presence bit, so a remembered NIP-07 grant or a bunker with pre-granted permissions completes the entire step-up exchange with nobody watching.

So `stepUp: true` on a permission stops a thief who holds only a stolen cookie, and does nothing about a hostile script in your own page, which can simply run the step-up itself. Use it to cap what a stolen session can reach. Do not build a UI that tells the user they authorised an operation because a step-up succeeded. See `docs/NAP-v2-RFC.md` §10.3.

### 5.7 Code Injection — The Mitigations Worth Having

`docs/NAP-v2-RFC.md` §28.5 is blunt that a hostile script on your origin defeats every key-custody measure, because your own code must be able to decrypt the key. That is a ceiling, not a reason to skip the layers underneath it. The standard Relying Party guidance from W3C WebAuthn §13.5.8 transfers directly:

- **Ship a Content Security Policy** on any origin that can reach the signer. Its job is to make injected script fail to execute at all, which is the only point at which any of this is still preventable.
- **Minimise third-party script** on those origins. Every analytics or widget tag is same-origin code with the same access to an unlocked key that your own bundle has.
- **Never serve user-submitted content from a host inside the credential's scope.** A `usercontent.example.org` that can be reached from `example.org`'s script context is a foothold in the same trust boundary; keep it on a separate registrable domain.

### 5.8 Clickjacking Applies Asymmetrically

Overlay attacks land differently depending on which signer the user has:

- A NIP-07 extension prompt or a NIP-46 bunker prompt is browser or OS chrome. Your page cannot draw over it, and neither can an attacker framing your page.
- The passphrase prompt for an in-page key — the `lockRecovery() === 'passphrase'` path — is your own DOM. It can be framed, overlaid, and mimicked like any other form.

If you support the in-page key path, send `X-Frame-Options: DENY` or a CSP `frame-ancestors 'none'` on the pages that host the passphrase prompt. The extension and bunker paths do not need it for this reason (they may still need it for others).

---

## 6. Testing Recommendations

### 6.1 Session Resume Tests

```typescript
it('returns pubkey when session cookie is valid', async () => {
  mockFetch.mockResolvedValue({ ok: true, json: () => ({ pubkey: 'abc' }) });
  expect(await napResumeSession()).toEqual({ pubkey: 'abc' });
});

it('returns null when session expired', async () => {
  mockFetch.mockResolvedValue({ ok: false, status: 401 });
  expect(await napResumeSession()).toBeNull();
});

it('returns null on network error', async () => {
  mockFetch.mockRejectedValue(new TypeError('Failed to fetch'));
  expect(await napResumeSession()).toBeNull();
});
```

### 6.2 Activity Timer Tests

Use fake timers to verify the lock fires after 15 minutes and resets on activity:

```typescript
vi.useFakeTimers();
startActivityTimer(onLock);
vi.advanceTimersByTime(14 * 60 * 1000); // 14 min — no lock
document.dispatchEvent(new Event('mousemove')); // reset
vi.advanceTimersByTime(15 * 60 * 1000); // 15 min from reset — lock fires
expect(onLock).toHaveBeenCalledTimes(1);
```

### 6.3 Broadcast Channel Tests

Verify messages propagate between channels:

```typescript
const receiver = new BroadcastChannel('app-session');
const received = new Promise(resolve => { receiver.onmessage = resolve; });
initBroadcast(handlers);
broadcastLogout();
expect((await received).data).toEqual({ type: 'logout' });
```

### 6.4 Integration Test: Full NAP Flow

```bash
# 1. Init challenge
curl -X POST /api/v1/auth/init -d '{"pubkey":"..."}'

# 2. Sign proof (use nostr-tools or test helper)
# 3. Complete challenge
curl -X POST /api/v1/auth/complete \
  -H 'Authorization: Nostr <base64>' \
  -d '{"challenge_id":"..."}' -c cookies.txt

# 4. Verify session works
curl -b cookies.txt /api/v1/auth/session
# → {"pubkey":"..."}

# 5. Verify protected endpoint works
curl -b cookies.txt /api/v1/merchant/bootstrap
# → merchant data (no Authorization header needed)
```

---

## 7. Common Pitfalls

| Pitfall | Consequence | Fix |
|---------|-------------|-----|
| Auth endpoints not excluded from all filters | `/auth/init` returns 401 "API key required" | Add to excluded paths in every auth filter, not just Spring Security |
| No `isRestoringSession` loading state | Page flickers to login and back on refresh | Block ProtectedRoute rendering until session check completes |
| Session resume navigates to `/portal` | User loses their place (e.g., was on `/settings`) | Stay on current URL — ProtectedRoute just unblocks, doesn't redirect |
| Step-up key stays in memory | Auto-lock timer restarts, key exposed longer than needed | Use key transiently, don't set `privkeyRef` |
| `credentials: 'include'` missing from API client in session mode | Cookie not sent, all requests fail with 401 | Set `credentials: 'include'` on every fetch when in session mode |
| CORS missing `allowCredentials(true)` | Browser blocks `Set-Cookie` from cross-origin response | Enable credentials + explicit origins (no wildcards) |
| No session cleanup job | Table grows unbounded with expired rows | Sweep expired sessions every 15 minutes |
| `SameSite=Strict` on cookie | External links to your app lose the session | Use `Lax` — it allows top-level GET navigation while blocking CSRF |
| bech32 npub decoding on server | Extra library dependency, fragile if client sends hex | Accept hex pubkey directly |
