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
  createInMemoryRateLimiter,
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
    const wrongSigner = completionFor(challenge.challenge_id, challenge.challenge, {
      key: OTHER_KEY_BYTES,
    });

    const first = await verifyCompletion(
      { ...wrongSigner, method: 'POST', url: AUTH_URL },
      options
    );
    expect(first).toMatchObject({ code: 'NAP_COMPLETE_PRINCIPAL_MISMATCH' });

    const second = await verifyCompletion(
      { ...wrongSigner, method: 'POST', url: AUTH_URL },
      options
    );
    expect(second).toMatchObject({ code: 'NAP_COMPLETE_PRINCIPAL_MISMATCH' });

    // The budget is spent, so even the rightful holder's valid proof is refused.
    const valid = completionFor(challenge.challenge_id, challenge.challenge);
    const third = await verifyCompletion({ ...valid, method: 'POST', url: AUTH_URL }, options);

    expect(third).toMatchObject({ ok: false, code: 'NAP_COMPLETE_FAILED_TERMINAL' });
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

  it('denies and revokes the principal once access is removed', async () => {
    const sessionStore = new InMemorySessionStore();
    await sessionStore.createForChallenge(session);

    const acl = await resolveEffectiveAcl(session, {
      aclResolver: {
        async resolve() {
          return { allowed: false, roles: [], permissions: [] };
        },
      },
      sessionStore,
      clock: { nowUnix: () => NOW },
    });

    expect(acl).toBeNull();
    expect(await sessionStore.getByAccessToken('token-1')).not.toBeNull();
    expect((await sessionStore.getBySessionId('session-1'))?.revoked_at).toBe(NOW);
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
