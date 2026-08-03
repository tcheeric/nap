import { finalizeEvent, getPublicKey, nip19 } from 'nostr-tools';
import { describe, expect, it } from 'vitest';
import { encodeBase64String, hexToBytes, sha256Hex, utf8Bytes } from '@imani/nap-core';
import type { AclDecision, SessionRecord } from '@imani/nap-core';
import {
  createInMemoryRateLimiter,
  InMemoryChallengeStore,
  InMemorySessionStore,
  issueChallenge,
  refreshSession,
  toPublicAuthSuccess,
  toPublicSessionView,
  verifyCompletion,
  type NapServerOptions,
} from '../src/index.js';

const AUTH_URL = 'https://api.example.com/auth/complete';
const NOW = 1_710_000_000;
const REFRESH_TTL = 3600;

const PRIVATE_KEY_BYTES = hexToBytes(
  '2222222222222222222222222222222222222222222222222222222222222222'
);
const PUBKEY = getPublicKey(PRIVATE_KEY_BYTES);
const NPUB = nip19.npubEncode(PUBKEY);

let counter = 0;

interface Harness {
  options: NapServerOptions;
  sessionStore: InMemorySessionStore;
  /** Moves the server clock; every TTL check reads through this. */
  setNow(value: number): void;
  acl: AclDecision;
}

function buildHarness(overrides: Partial<NapServerOptions> = {}): Harness {
  let now = NOW;
  const sessionStore = new InMemorySessionStore();
  const harness: Harness = {
    sessionStore,
    setNow(value) {
      now = value;
    },
    acl: { allowed: true, roles: ['user'], permissions: ['read'] },
    options: {
      challengeStore: new InMemoryChallengeStore(),
      sessionStore,
      aclResolver: {
        async resolve() {
          return harness.acl;
        },
      },
      refreshTtlSeconds: REFRESH_TTL,
      minAuthResponseMillis: 0,
      responseJitterMillis: 0,
      clock: { nowUnix: () => now },
      randomSource: {
        randomBytes(length: number) {
          const seed = counter++;
          return new Uint8Array(Array.from({ length }, (_, index) => (index + seed * 7 + 1) % 255));
        },
      },
      ...overrides,
    },
  };

  return harness;
}

/** Runs a full login and hands back the session the refresh flow will act on. */
async function login(options: NapServerOptions): Promise<SessionRecord> {
  const issued = await issueChallenge({ npub: NPUB, authUrl: AUTH_URL }, options);

  if (!issued.ok) {
    throw new Error(`expected a challenge, got ${issued.code}`);
  }

  const rawBody = utf8Bytes(JSON.stringify({ challenge_id: issued.value.challenge_id }));
  const event = finalizeEvent(
    {
      kind: 27235,
      created_at: NOW,
      tags: [
        ['u', AUTH_URL],
        ['method', 'POST'],
        ['payload', sha256Hex(rawBody)],
        ['challenge', issued.value.challenge],
        ['challenge_id', issued.value.challenge_id],
      ],
      content: '',
    },
    PRIVATE_KEY_BYTES
  );

  const completed = await verifyCompletion(
    {
      authorization: `Nostr ${encodeBase64String(JSON.stringify(event))}`,
      method: 'POST',
      url: AUTH_URL,
      rawBody,
    },
    options
  );

  if (!completed.ok) {
    throw new Error(`expected a session, got ${JSON.stringify(completed)}`);
  }

  return completed.session;
}

describe('refresh tokens (RFC §14.1)', () => {
  it('issues a refresh token alongside the access token when a TTL is configured', async () => {
    const harness = buildHarness();
    const session = await login(harness.options);

    expect(session.refresh_token).toBeTypeOf('string');
    expect(session.refresh_expires_at).toBe(NOW + REFRESH_TTL);
    expect(toPublicAuthSuccess(session).refresh_token).toBe(session.refresh_token);
  });

  it('issues no refresh token when no TTL is configured', async () => {
    const harness = buildHarness({ refreshTtlSeconds: undefined });
    const session = await login(harness.options);

    expect(session.refresh_token).toBeUndefined();
    expect(session.refresh_expires_at).toBeUndefined();
  });

  it('rotates both tokens and extends the session', async () => {
    const harness = buildHarness();
    const session = await login(harness.options);
    // Snapshotted: the in-memory store rotates the same object it handed back.
    const { session_id: sessionId, access_token: oldAccess, refresh_token: oldRefresh } = session;

    harness.setNow(NOW + 100);
    const outcome = await refreshSession({ refreshToken: oldRefresh }, harness.options);

    if (!outcome.ok) {
      throw new Error(`expected a rotation, got ${outcome.code}`);
    }

    expect(outcome.session.session_id).toBe(sessionId);
    expect(outcome.session.access_token).not.toBe(oldAccess);
    expect(outcome.session.refresh_token).not.toBe(oldRefresh);
    expect(outcome.session.previous_refresh_token).toBe(oldRefresh);
    expect(outcome.session.refresh_expires_at).toBe(NOW + 100 + REFRESH_TTL);

    // The retired access token stops working the moment the new one is minted.
    expect(await harness.sessionStore.getByAccessToken(oldAccess)).toBeNull();
    expect(await harness.sessionStore.getByAccessToken(outcome.session.access_token)).not.toBeNull();
  });

  it('revokes the whole session when a retired refresh token is replayed', async () => {
    const harness = buildHarness();
    const session = await login(harness.options);
    const stolen = session.refresh_token;

    const rotated = await refreshSession({ refreshToken: stolen }, harness.options);

    if (!rotated.ok) {
      throw new Error(`expected a rotation, got ${rotated.code}`);
    }

    const replay = await refreshSession({ refreshToken: stolen }, harness.options);

    expect(replay.ok).toBe(false);
    expect(replay.ok === false && replay.code).toBe('NAP_REFRESH_REUSED');

    // The family is dead, so the token the legitimate holder just received is
    // dead with it — that is the point of revoking rather than rejecting.
    const afterTheft = await refreshSession(
      { refreshToken: rotated.session.refresh_token },
      harness.options
    );

    expect(afterTheft.ok).toBe(false);
    expect(afterTheft.ok === false && afterTheft.code).toBe('NAP_REFRESH_REVOKED');
  });

  it('names the principal on the reuse event, so an alert can say whose session died', async () => {
    const events: { code: string; pubkey?: string }[] = [];
    const harness = buildHarness({
      auditLogger: {
        log(event) {
          events.push({ code: event.code, pubkey: event.pubkey });
        },
      },
    });
    const session = await login(harness.options);
    const stolen = session.refresh_token;

    await refreshSession({ refreshToken: stolen }, harness.options);
    await refreshSession({ refreshToken: stolen }, harness.options);

    expect(events).toContainEqual({ code: 'NAP_REFRESH_REUSED', pubkey: PUBKEY });
  });

  it('rejects an unknown token', async () => {
    const harness = buildHarness();
    await login(harness.options);

    const outcome = await refreshSession({ refreshToken: 'nope' }, harness.options);

    expect(outcome.ok).toBe(false);
    expect(outcome.ok === false && outcome.code).toBe('NAP_REFRESH_UNKNOWN_TOKEN');
  });

  it('rejects a missing token', async () => {
    const harness = buildHarness();

    const outcome = await refreshSession({}, harness.options);

    expect(outcome.ok).toBe(false);
    expect(outcome.ok === false && outcome.code).toBe('NAP_REFRESH_UNKNOWN_TOKEN');
  });

  it('rejects an expired refresh token', async () => {
    const harness = buildHarness();
    const session = await login(harness.options);

    harness.setNow(NOW + REFRESH_TTL + 1);
    const outcome = await refreshSession({ refreshToken: session.refresh_token }, harness.options);

    expect(outcome.ok).toBe(false);
    expect(outcome.ok === false && outcome.code).toBe('NAP_REFRESH_EXPIRED');
  });

  it('rejects a revoked session', async () => {
    const harness = buildHarness();
    const session = await login(harness.options);

    await harness.sessionStore.revokeBySessionId(session.session_id, NOW);
    const outcome = await refreshSession({ refreshToken: session.refresh_token }, harness.options);

    expect(outcome.ok).toBe(false);
    expect(outcome.ok === false && outcome.code).toBe('NAP_REFRESH_REVOKED');
  });

  it('re-resolves the ACL, so a suspended principal cannot extend access', async () => {
    const harness = buildHarness();
    const session = await login(harness.options);

    harness.acl = { allowed: false, reason: 'suspended', roles: [], permissions: [] };
    const outcome = await refreshSession({ refreshToken: session.refresh_token }, harness.options);

    expect(outcome.ok).toBe(false);
    expect(outcome.ok === false && outcome.code).toBe('NAP_REFRESH_ACL_DENIED');
  });

  it('carries an ACL change onto the rotated session', async () => {
    const harness = buildHarness();
    const session = await login(harness.options);

    harness.acl = { allowed: true, roles: ['user', 'admin'], permissions: ['read', 'write'] };
    const outcome = await refreshSession({ refreshToken: session.refresh_token }, harness.options);

    if (!outcome.ok) {
      throw new Error(`expected a rotation, got ${outcome.code}`);
    }

    expect(outcome.session.roles).toEqual(['user', 'admin']);
    expect(outcome.session.permissions).toEqual(['read', 'write']);
  });

  it('revokes every session when the ACL denial says to', async () => {
    const harness = buildHarness();
    const session = await login(harness.options);

    harness.acl = {
      allowed: false,
      reason: 'suspended',
      revoke_sessions: true,
      roles: [],
      permissions: [],
    };
    await refreshSession({ refreshToken: session.refresh_token }, harness.options);

    const stored = await harness.sessionStore.getBySessionId(session.session_id);
    expect(stored?.revoked_at).toBe(NOW);
  });

  it('answers a refresh as unknown when the server has no refresh TTL', async () => {
    const harness = buildHarness();
    const session = await login(harness.options);
    const withoutRefresh = { ...harness.options, refreshTtlSeconds: undefined };

    const outcome = await refreshSession({ refreshToken: session.refresh_token }, withoutRefresh);

    expect(outcome.ok).toBe(false);
    expect(outcome.ok === false && outcome.code).toBe('NAP_REFRESH_UNKNOWN_TOKEN');
  });

  it('rate limits refreshes and reports a retry hint', async () => {
    const harness = buildHarness({
      rateLimiter: createInMemoryRateLimiter({ maxPerWindow: 1, windowSeconds: 60 }),
    });
    const session = await login(harness.options);

    const first = await refreshSession(
      { refreshToken: session.refresh_token, clientIp: '203.0.113.7' },
      harness.options
    );
    const second = await refreshSession(
      { refreshToken: first.ok ? first.session.refresh_token : undefined, clientIp: '203.0.113.7' },
      harness.options
    );

    expect(first.ok).toBe(true);
    expect(second.ok).toBe(false);
    expect(second.ok === false && second.code).toBe('NAP_REFRESH_RATE_LIMITED');
    expect(second.ok === false && second.retryAfterSeconds).toBeGreaterThan(0);
  });

  it('never exposes the refresh token on the session view', async () => {
    const harness = buildHarness();
    const session = await login(harness.options);

    expect(JSON.stringify(toPublicSessionView(session))).not.toContain(session.refresh_token!);
  });
});
