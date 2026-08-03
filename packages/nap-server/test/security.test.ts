import { finalizeEvent, getPublicKey, nip19 } from 'nostr-tools';
import { describe, expect, it } from 'vitest';
import {
  encodeBase64String,
  hexToBytes,
  sha256Hex,
  utf8Bytes,
  type SessionRecord,
} from '@imani/nap-core';
import {
  constantTimeEquals,
  createInMemoryRateLimiter,
  isVerifyFailure,
  createNapServer,
  createRevokingAclStore,
  InMemoryAclStore,
  InMemoryChallengeStore,
  InMemorySessionStore,
  issueChallenge,
  resolveEffectiveAcl,
  verifyCompletion,
  type AclRecord,
  type NapServerOptions,
} from '../src/index.js';

const AUTH_URL = 'https://api.example.com/auth/complete';
const NOW = 1_710_000_000;

const PRIVATE_KEY_BYTES = hexToBytes(
  '1111111111111111111111111111111111111111111111111111111111111111'
);
const OTHER_KEY_BYTES = hexToBytes(
  '2222222222222222222222222222222222222222222222222222222222222222'
);
const PUBKEY = getPublicKey(PRIVATE_KEY_BYTES);
const NPUB = nip19.npubEncode(PUBKEY);

function buildOptions(overrides: Partial<NapServerOptions> = {}): NapServerOptions {
  return {
    challengeStore: new InMemoryChallengeStore(),
    sessionStore: new InMemorySessionStore(),
    aclResolver: {
      async resolve() {
        return { allowed: true, roles: ['merchant'], permissions: ['voucher:issue'] };
      },
    },
    minAuthResponseMillis: 0,
    responseJitterMillis: 0,
    clock: { nowUnix: () => NOW },
    randomSource: {
      // Distinct per call so challenge ids do not collide across iterations.
      randomBytes(length: number) {
        const seed = counter++;
        return new Uint8Array(
          Array.from({ length }, (_, index) => (index + seed * 7 + 1) % 255)
        );
      },
    },
    ...overrides,
  };
}

let counter = 0;

function completionFor(
  challengeId: string,
  challenge: string,
  opts: { key?: Uint8Array; stepUp?: boolean; createdAt?: number } = {}
): { authorization: string; rawBody: Uint8Array } {
  const rawBody = utf8Bytes(
    JSON.stringify({ challenge_id: challengeId, ...(opts.stepUp ? { step_up: true } : {}) })
  );
  const event = finalizeEvent(
    {
      kind: 27235,
      created_at: opts.createdAt ?? NOW,
      tags: [
        ['u', AUTH_URL],
        ['method', 'POST'],
        ['payload', sha256Hex(rawBody)],
        ['challenge', challenge],
        ['challenge_id', challengeId],
      ],
      content: '',
    },
    opts.key ?? PRIVATE_KEY_BYTES
  );

  return {
    authorization: `Nostr ${encodeBase64String(JSON.stringify(event))}`,
    rawBody,
  };
}

async function issue(options: NapServerOptions, clientIp?: string) {
  const result = await issueChallenge({ npub: NPUB, authUrl: AUTH_URL, clientIp }, options);

  if (!result.ok) {
    throw new Error(`expected a challenge, got ${result.code}`);
  }

  return result.value;
}

describe('challenge TTL ceiling (RFC §10.1)', () => {
  it('rejects a TTL above 60 seconds at wiring time', () => {
    expect(() => createNapServer(buildOptions({ challengeTtlSeconds: 120 }))).toThrow(
      /challengeTtlSeconds/
    );
  });

  it('rejects a non-positive TTL', () => {
    expect(() => createNapServer(buildOptions({ challengeTtlSeconds: 0 }))).toThrow(
      /challengeTtlSeconds/
    );
  });

  it('accepts the ceiling itself', async () => {
    const options = buildOptions({ challengeTtlSeconds: 60 });
    const challenge = await issue(options);

    expect(challenge.expires_at - challenge.issued_at).toBe(60);
  });
});

describe('rate limiting (RFC §17.1)', () => {
  it('rejects /auth/init past the window budget', async () => {
    const options = buildOptions({
      rateLimiter: createInMemoryRateLimiter({
        maxPerWindow: 2,
        clock: { nowUnix: () => NOW },
      }),
    });

    await issue(options);
    await issue(options);

    const third = await issueChallenge({ npub: NPUB, authUrl: AUTH_URL }, options);

    expect(third).toMatchObject({
      ok: false,
      code: 'NAP_INIT_RATE_LIMITED',
      retryable: true,
    });
  });

  it('caps a caller address independently of the principal', async () => {
    const limiter = createInMemoryRateLimiter({
      maxPerWindow: 1,
      clock: { nowUnix: () => NOW },
    });
    const options = buildOptions({ rateLimiter: limiter });
    const otherNpub = nip19.npubEncode(getPublicKey(OTHER_KEY_BYTES));

    await issue(options, '203.0.113.7');
    const second = await issueChallenge(
      { npub: otherNpub, authUrl: AUTH_URL, clientIp: '203.0.113.7' },
      options
    );

    expect(second).toMatchObject({ ok: false, code: 'NAP_INIT_RATE_LIMITED' });
  });

  it('scopes the npub dimension to the address it arrived from', async () => {
    // An npub is public and /auth/init is unauthenticated, so a globally counted
    // npub budget lets anyone spend a stranger's and keep them from logging in.
    const options = buildOptions({
      rateLimiter: createInMemoryRateLimiter({
        maxPerWindow: 1,
        clock: { nowUnix: () => NOW },
      }),
    });

    await issue(options, '198.51.100.1');

    expect(
      await issueChallenge({ npub: NPUB, authUrl: AUTH_URL, clientIp: '198.51.100.1' }, options)
    ).toMatchObject({ ok: false, code: 'NAP_INIT_RATE_LIMITED' });

    // Same npub, different address: unaffected.
    expect(
      await issueChallenge({ npub: NPUB, authUrl: AUTH_URL, clientIp: '203.0.113.9' }, options)
    ).toMatchObject({ ok: true });
  });

  it('spends the caller address budget once per completion', async () => {
    // /auth/complete checks the limiter twice — once on the address before the
    // proof, once on the proved pubkey after it. Carrying the address into the
    // second key would charge it twice and halve the configured rate.
    const options = buildOptions({
      rateLimiter: createInMemoryRateLimiter({
        maxPerWindow: 2,
        clock: { nowUnix: () => NOW },
      }),
    });
    const first = await issue(options, '203.0.113.7');
    const second = await issue(options, '203.0.113.7');

    for (const challenge of [first, second]) {
      const completion = completionFor(challenge.challenge_id, challenge.challenge);

      expect(
        await verifyCompletion(
          { ...completion, method: 'POST', url: AUTH_URL, clientIp: '203.0.113.7' },
          options
        )
      ).toMatchObject({ ok: true });
    }
  });

  it('does not pad a rate-limited response', async () => {
    // A 429 is already distinguishable by its status code, so padding hides
    // nothing and only hands a caller who is over the limit a free hold on the
    // server for the floor's duration.
    const options = buildOptions({
      minAuthResponseMillis: 300,
      rateLimiter: { check: () => ({ allowed: false, retryAfterSeconds: 7 }) },
    });

    const startedAt = Date.now();
    const denied = await issueChallenge({ npub: NPUB, authUrl: AUTH_URL }, options);

    expect(denied).toMatchObject({ ok: false, code: 'NAP_INIT_RATE_LIMITED' });
    expect(Date.now() - startedAt).toBeLessThan(150);

    // Control: an ordinary refusal is still held to the floor, which is what
    // makes the 401 paths indistinguishable from each other.
    const padded = buildOptions({ minAuthResponseMillis: 300 });
    const refusedAt = Date.now();

    expect(await issueChallenge({ npub: 'not-an-npub', authUrl: AUTH_URL }, padded)).toMatchObject({
      code: 'NAP_INIT_INVALID_NPUB',
    });
    expect(Date.now() - refusedAt).toBeGreaterThanOrEqual(300);
  });

  it('drops an oversized npub from the limiter key rather than truncating it', async () => {
    // The npub reaches the limiter before decodeNpub has looked at it, so it is
    // still arbitrary caller input. Truncating would let distinct npubs share a
    // budget, which is a lockout primitive of its own.
    const seen: (string | undefined)[] = [];
    const options = buildOptions({
      rateLimiter: {
        check: (key) => {
          seen.push(key.npub);
          return { allowed: true };
        },
      },
    });

    await issueChallenge({ npub: 'npub1'.padEnd(4096, 'x'), authUrl: AUTH_URL }, options);

    expect(seen).toEqual([undefined]);
  });

  it('reports a retry-after the caller can honour', async () => {
    const limiter = createInMemoryRateLimiter({
      windowSeconds: 60,
      maxPerWindow: 1,
      clock: { nowUnix: () => NOW },
    });

    limiter.check({ scope: 'init', npub: NPUB });
    const decision = await limiter.check({ scope: 'init', npub: NPUB });

    expect(decision).toEqual({ allowed: false, retryAfterSeconds: 60 });
  });
});

describe('outstanding challenge caps (RFC §17.4)', () => {
  it('bounds outstanding challenges per npub', async () => {
    const options = buildOptions({ maxOutstandingChallengesPerNpub: 2 });

    await issue(options);
    await issue(options);

    expect(await issueChallenge({ npub: NPUB, authUrl: AUTH_URL }, options)).toMatchObject({
      ok: false,
      code: 'NAP_INIT_RATE_LIMITED',
    });
  });

  it('bounds outstanding challenges per caller address', async () => {
    const options = buildOptions({
      maxOutstandingChallengesPerNpub: 0,
      maxOutstandingChallengesPerIp: 1,
    });

    await issue(options, '203.0.113.9');

    expect(
      await issueChallenge({ npub: NPUB, authUrl: AUTH_URL, clientIp: '203.0.113.9' }, options)
    ).toMatchObject({ ok: false, code: 'NAP_INIT_RATE_LIMITED' });
  });

  it('leaves a caller that opts out of address reporting uncapped on that dimension', async () => {
    const options = buildOptions({
      maxOutstandingChallengesPerNpub: 0,
      maxOutstandingChallengesPerIp: 1,
    });

    await issue(options);

    expect(await issueChallenge({ npub: NPUB, authUrl: AUTH_URL }, options)).toMatchObject({
      ok: true,
    });
  });
});

describe('challenge failure budget (RFC §13.4)', () => {
  it('moves the challenge to failed_terminal and rejects further attempts', async () => {
    const options = buildOptions({ maxFailuresPerChallenge: 2 });
    const challenge = await issue(options);
    // Guessed by the key the challenge was issued to: the case the budget is
    // for, someone brute-forcing the challenge value they were meant to echo.
    const guess = completionFor(challenge.challenge_id, 'not-the-challenge-value');

    const first = await verifyCompletion({ ...guess, method: 'POST', url: AUTH_URL }, options);
    expect(first).toMatchObject({ code: 'NAP_COMPLETE_CHALLENGE_MISMATCH' });

    const second = await verifyCompletion({ ...guess, method: 'POST', url: AUTH_URL }, options);
    expect(second).toMatchObject({ code: 'NAP_COMPLETE_CHALLENGE_MISMATCH' });

    // The budget is spent, so even the rightful holder's valid proof is refused.
    const valid = completionFor(challenge.challenge_id, challenge.challenge);
    const third = await verifyCompletion({ ...valid, method: 'POST', url: AUTH_URL }, options);

    expect(third).toMatchObject({ ok: false, code: 'NAP_COMPLETE_FAILED_TERMINAL' });
  });

  it('cannot be spent by anyone but the principal the challenge was issued to', async () => {
    // A challenge_id is not a secret — it travels in the clear and the client
    // hands it back. If a proof signed by some other key could spend the budget,
    // anyone who saw one could burn a stranger's challenge and deny them a login.
    const options = buildOptions({ maxFailuresPerChallenge: 2 });
    const challenge = await issue(options);
    const stranger = completionFor(challenge.challenge_id, challenge.challenge, {
      key: OTHER_KEY_BYTES,
    });

    for (let attempt = 0; attempt < 5; attempt += 1) {
      expect(
        await verifyCompletion({ ...stranger, method: 'POST', url: AUTH_URL }, options)
      ).toMatchObject({ code: 'NAP_COMPLETE_PRINCIPAL_MISMATCH' });
    }

    const valid = completionFor(challenge.challenge_id, challenge.challenge);

    expect(await verifyCompletion({ ...valid, method: 'POST', url: AUTH_URL }, options))
      .toMatchObject({ ok: true });
  });

  it('does not spend the budget on an ACL denial', async () => {
    const options = buildOptions({
      maxFailuresPerChallenge: 1,
      aclResolver: {
        async resolve() {
          return { allowed: false, roles: [], permissions: [] };
        },
      },
    });
    const challenge = await issue(options);
    const valid = completionFor(challenge.challenge_id, challenge.challenge);

    await verifyCompletion({ ...valid, method: 'POST', url: AUTH_URL }, options);
    const again = await verifyCompletion({ ...valid, method: 'POST', url: AUTH_URL }, options);

    expect(again).toMatchObject({ code: 'NAP_COMPLETE_ACL_DENIED' });
  });
});

describe('step-up authentication', () => {
  it('mints a step-up token when the signed body asks for one', async () => {
    const options = buildOptions({ stepUpTtlSeconds: 300 });
    const challenge = await issue(options);
    const completion = completionFor(challenge.challenge_id, challenge.challenge, {
      stepUp: true,
    });

    const result = await verifyCompletion(
      { ...completion, method: 'POST', url: AUTH_URL },
      options
    );

    expect(result.ok).toBe(true);

    if (result.ok) {
      expect(result.session.step_up_token).toBeTruthy();
      expect(result.session.step_up_expires_at).toBe(NOW + 300);
    }
  });

  it('leaves an ordinary login without a step-up token', async () => {
    const options = buildOptions();
    const challenge = await issue(options);
    const completion = completionFor(challenge.challenge_id, challenge.challenge);

    const result = await verifyCompletion(
      { ...completion, method: 'POST', url: AUTH_URL },
      options
    );

    expect(result.ok).toBe(true);

    if (result.ok) {
      expect(result.session.step_up_token).toBeUndefined();
    }
  });

  it('rejects a body whose step_up is not a boolean', async () => {
    const options = buildOptions();
    const challenge = await issue(options);
    const rawBody = utf8Bytes(
      JSON.stringify({ challenge_id: challenge.challenge_id, step_up: 'yes' })
    );
    const event = finalizeEvent(
      {
        kind: 27235,
        created_at: NOW,
        tags: [
          ['u', AUTH_URL],
          ['method', 'POST'],
          ['payload', sha256Hex(rawBody)],
          ['challenge', challenge.challenge],
          ['challenge_id', challenge.challenge_id],
        ],
        content: '',
      },
      PRIVATE_KEY_BYTES
    );

    const result = await verifyCompletion(
      {
        authorization: `Nostr ${encodeBase64String(JSON.stringify(event))}`,
        method: 'POST',
        url: AUTH_URL,
        rawBody,
      },
      options
    );

    expect(result).toMatchObject({ ok: false, malformed: true });
  });
});

describe('per-request permission evaluation (RFC §15)', () => {
  const session: SessionRecord = {
    session_id: 'session-1',
    challenge_id: 'challenge-1',
    access_token: 'token-1',
    principal_npub: NPUB,
    principal_pubkey: PUBKEY,
    roles: ['merchant'],
    permissions: ['voucher:issue'],
    issued_at: NOW,
    expires_at: NOW + 900,
  };

  it('falls back to the login snapshot without a resolver', async () => {
    expect(await resolveEffectiveAcl(session, {})).toEqual({
      roles: ['merchant'],
      permissions: ['voucher:issue'],
    });
  });

  it('prefers the live ACL over the snapshot', async () => {
    const acl = await resolveEffectiveAcl(session, {
      aclResolver: {
        async resolve() {
          return { allowed: true, roles: ['viewer'], permissions: ['voucher:read'] };
        },
      },
    });

    expect(acl).toEqual({ roles: ['viewer'], permissions: ['voucher:read'] });
  });

  it('denies and revokes the principal once access is affirmatively removed', async () => {
    const sessionStore = new InMemorySessionStore();
    await sessionStore.createForChallenge(session);

    const acl = await resolveEffectiveAcl(session, {
      aclResolver: {
        async resolve() {
          return { allowed: false, roles: [], permissions: [], revoke_sessions: true };
        },
      },
      sessionStore,
      clock: { nowUnix: () => NOW },
    });

    expect(acl).toBeNull();
    expect(await sessionStore.getByAccessToken('token-1')).not.toBeNull();
    expect((await sessionStore.getBySessionId('session-1'))?.revoked_at).toBe(NOW);
  });

  it('denies without revoking when the resolver is not certain', async () => {
    const sessionStore = new InMemorySessionStore();
    await sessionStore.createForChallenge(session);

    // A resolver that cannot read the ACL answers "denied". Revoking on that
    // would turn a lagging replica into a forced re-login for everyone.
    const acl = await resolveEffectiveAcl(session, {
      aclResolver: {
        async resolve() {
          return { allowed: false, roles: [], permissions: [], reason: 'no_acl_record' };
        },
      },
      sessionStore,
      clock: { nowUnix: () => NOW },
    });

    expect(acl).toBeNull();
    expect((await sessionStore.getBySessionId('session-1'))?.revoked_at).toBeUndefined();
  });
});

describe('createRevokingAclStore', () => {
  function aclRecord(overrides: Partial<AclRecord> = {}): AclRecord {
    return {
      principal_pubkey: PUBKEY,
      app_id: 'app',
      role: 'merchant',
      permission_overrides: [],
      suspended: false,
      ...overrides,
    };
  }

  async function seed(): Promise<{ store: ReturnType<typeof createRevokingAclStore>; sessionStore: InMemorySessionStore }> {
    const sessionStore = new InMemorySessionStore();
    await sessionStore.createForChallenge({
      session_id: 'session-1',
      challenge_id: 'challenge-1',
      access_token: 'token-1',
      principal_npub: NPUB,
      principal_pubkey: PUBKEY,
      roles: ['merchant'],
      permissions: ['voucher:issue'],
      issued_at: NOW,
      expires_at: NOW + 900,
    });

    const inner = new InMemoryAclStore();
    await inner.upsert(aclRecord());

    return {
      store: createRevokingAclStore(inner, sessionStore, { nowUnix: () => NOW }),
      sessionStore,
    };
  }

  it('revokes sessions on suspend', async () => {
    const { store, sessionStore } = await seed();

    await store.suspend(PUBKEY, 'app', 'fraud');

    expect((await sessionStore.getBySessionId('session-1'))?.revoked_at).toBe(NOW);
  });

  it('revokes sessions on a role change', async () => {
    const { store, sessionStore } = await seed();

    await store.upsert(aclRecord({ role: 'viewer' }));

    expect((await sessionStore.getBySessionId('session-1'))?.revoked_at).toBe(NOW);
  });

  it('leaves sessions alone when only permission overrides change', async () => {
    const { store, sessionStore } = await seed();

    await store.upsert(
      aclRecord({ permission_overrides: [{ action: 'grant', permission: 'voucher:read' }] })
    );

    expect((await sessionStore.getBySessionId('session-1'))?.revoked_at).toBeUndefined();
  });
});

describe('response timing floor (RFC §15)', () => {
  it('holds every answer to the configured floor', async () => {
    const options = buildOptions({ minAuthResponseMillis: 60, responseJitterMillis: 0 });

    const startedAt = Date.now();
    await issueChallenge({ npub: 'not-an-npub', authUrl: AUTH_URL }, options);
    const elapsed = Date.now() - startedAt;

    // setTimeout may fire a millisecond early; the point is that a rejection
    // that would otherwise return in microseconds does not.
    expect(elapsed).toBeGreaterThanOrEqual(55);
  });
});

describe('rate limiting defaults', () => {
  it('limits /auth/init with no rateLimiter configured', async () => {
    // On by default: the 100 ms response floor holds an unauthenticated request
    // open, so an unlimited endpoint is a concurrency amplifier.
    const options = buildOptions();

    for (let attempt = 0; attempt < 30; attempt += 1) {
      await issueChallenge({ npub: NPUB, authUrl: AUTH_URL }, options);
    }

    const result = await issueChallenge({ npub: NPUB, authUrl: AUTH_URL }, options);

    expect(result.ok).toBe(false);
    expect(result.ok === false && result.code).toBe('NAP_INIT_RATE_LIMITED');
  });

  it('treats rateLimiter: null as a deliberate opt-out', async () => {
    const options = buildOptions({ rateLimiter: null, maxOutstandingChallengesPerNpub: 0 });

    for (let attempt = 0; attempt < 40; attempt += 1) {
      const result = await issueChallenge({ npub: NPUB, authUrl: AUTH_URL }, options);
      expect(result.ok).toBe(true);
    }
  });

  it('keeps separate budgets for two servers in one process', async () => {
    const first = buildOptions();
    const second = buildOptions();

    for (let attempt = 0; attempt < 30; attempt += 1) {
      await issueChallenge({ npub: NPUB, authUrl: AUTH_URL }, first);
    }

    expect((await issueChallenge({ npub: NPUB, authUrl: AUTH_URL }, second)).ok).toBe(true);
  });

  it('counts the proved pubkey on /auth/complete when no address is reported', async () => {
    // The pre-proof check has nothing to key on here, which used to leave the
    // one endpoint that runs a Schnorr verify per call entirely unbounded.
    const options = buildOptions({ maxOutstandingChallengesPerNpub: 0 });
    const challenge = await issue(options);
    const completion = completionFor(challenge.challenge_id, challenge.challenge);

    const attempt = () =>
      verifyCompletion(
        { authorization: completion.authorization, method: 'POST', url: AUTH_URL, rawBody: completion.rawBody },
        options
      );

    for (let index = 0; index < 30; index += 1) {
      await attempt();
    }

    const outcome = await attempt();

    expect(isVerifyFailure(outcome) && outcome.code).toBe('NAP_COMPLETE_RATE_LIMITED');
  });
});

describe('constantTimeEquals', () => {
  it('matches equal strings and rejects everything else', () => {
    expect(constantTimeEquals('token', 'token')).toBe(true);
    expect(constantTimeEquals('token', 'tokeN')).toBe(false);
    expect(constantTimeEquals('token', 'token-longer')).toBe(false);
    expect(constantTimeEquals('', '')).toBe(true);
  });
});

describe('response timing on the throw path', () => {
  it('pads a store failure to the same floor as a refusal', async () => {
    const challengeStore = new InMemoryChallengeStore();
    challengeStore.countOutstanding = async () => {
      throw new Error('store unreachable');
    };

    const options = buildOptions({ challengeStore, minAuthResponseMillis: 60 });
    const startedAt = Date.now();

    await expect(issueChallenge({ npub: NPUB, authUrl: AUTH_URL }, options)).rejects.toThrow(
      'store unreachable'
    );

    expect(Date.now() - startedAt).toBeGreaterThanOrEqual(55);
  });
});
