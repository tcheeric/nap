import Fastify from 'fastify';
import { getPublicKey, nip19 } from 'nostr-tools';
import { beforeEach, describe, expect, it } from 'vitest';
import { hexToBytes } from '@imani/nap-core';
import { buildAuthCompleteRequest, createPrivateKeySigner } from '@imani/nap-client-http';
import {
  InMemoryAclStore,
  InMemoryChallengeStore,
  InMemorySessionStore,
  createInMemoryRateLimiter,
  createRegistryAclResolver,
  type NapServerOptions,
  type SessionStore,
  type PermissionRegistry,
} from '@imani/nap-server';
import {
  createRequestDerivedBaseUrlResolver,
  napFastifyPlugin,
  permissionsFastifyPlugin,
  requirePermission,
  requireRole,
  requireStepUp,
  resetPermissionValidationState,
  validatePermissions,
  writeNapCookieSuccess,
} from '../src/index.js';

const PRIVATE_KEY_HEX = '1111111111111111111111111111111111111111111111111111111111111111';
const PRIVATE_KEY_BYTES = hexToBytes(PRIVATE_KEY_HEX);
const NPUB = nip19.npubEncode(getPublicKey(PRIVATE_KEY_BYTES));
const REGISTRY: PermissionRegistry = {
  appId: 'possa-merchant',
  permissions: [
    { key: 'voucher:issue', description: 'Issue vouchers', stepUp: false },
    { key: 'stripe:manage', description: 'Manage Stripe', stepUp: true },
  ],
  roles: [
    {
      key: 'merchant',
      description: 'Merchant access',
      permissions: ['voucher:issue', 'stripe:manage'],
    },
  ],
  defaultRole: 'merchant',
};

function buildServerOptions(now = 1_710_000_000): NapServerOptions {
  const sessionStore = new InMemorySessionStore();
  return {
    challengeStore: new InMemoryChallengeStore(),
    sessionStore,
    aclResolver: createRegistryAclResolver(REGISTRY, new InMemoryAclStore()),
    minAuthResponseMillis: 0,
    clock: {
      nowUnix() {
        return now;
      },
    },
    randomSource: {
      randomBytes(length: number) {
        return new Uint8Array(Array.from({ length }, (_, index) => (index + 1) % 255));
      },
    },
  };
}

async function seedSession(
  sessionStore: InMemorySessionStore,
  overrides: Partial<Awaited<ReturnType<InMemorySessionStore['createForChallenge']>>> = {}
) {
  const now = Math.floor(Date.now() / 1000);
  return sessionStore.createForChallenge({
    session_id: 'session-1',
    challenge_id: 'challenge-1',
    access_token: 'token-1',
    principal_npub: NPUB,
    principal_pubkey: getPublicKey(PRIVATE_KEY_BYTES),
    roles: ['merchant'],
    permissions: ['voucher:issue', 'stripe:manage'],
    issued_at: now,
    expires_at: now + 900,
    ...overrides,
  });
}

async function createApp(options: NapServerOptions) {
  const app = Fastify({ trustProxy: true });

  await app.register(napFastifyPlugin, {
    routePrefix: '/auth',
    server: options,
    getExternalBaseUrl: createRequestDerivedBaseUrlResolver(),
  });

  return app;
}

describe('nap-adapter-fastify', () => {
  beforeEach(() => {
    resetPermissionValidationState();
  });

  it('handles the init and complete flow in bearer mode', async () => {
    const app = await createApp(buildServerOptions());

    const init = await app.inject({
      method: 'POST',
      url: '/auth/init',
      headers: {
        host: 'api.example.com',
        'x-forwarded-proto': 'https',
        'content-type': 'application/json',
      },
      payload: JSON.stringify({ npub: NPUB }),
    });

    expect(init.statusCode).toBe(200);
    const challenge = init.json();
    expect(challenge.auth_url).toBe('https://api.example.com/auth/complete');

    const completion = await buildAuthCompleteRequest({
      challenge,
      signer: createPrivateKeySigner(PRIVATE_KEY_HEX),
      createdAt: 1_710_000_000,
    });

    const complete = await app.inject({
      method: 'POST',
      url: '/auth/complete',
      headers: {
        host: 'api.example.com',
        'x-forwarded-proto': 'https',
        authorization: completion.authorization,
        'content-type': 'application/json',
      },
      payload: new TextDecoder().decode(completion.rawBody),
    });

    expect(complete.statusCode).toBe(200);
    const body = complete.json();
    expect(body.status).toBe('ok');
    expect(body.token_type).toBe('Bearer');
    expect(body.principal.npub).toBe(NPUB);

    await app.close();
  });

  it('supports cookie mode', async () => {
    const app = Fastify({ trustProxy: true });

    await app.register(napFastifyPlugin, {
      routePrefix: '/auth',
      server: buildServerOptions(),
      getExternalBaseUrl: createRequestDerivedBaseUrlResolver(),
      writeSuccess: writeNapCookieSuccess('session', {
        httpOnly: true,
        secure: true,
        sameSite: 'lax',
      }),
    });

    const init = await app.inject({
      method: 'POST',
      url: '/auth/init',
      headers: {
        host: 'api.example.com',
        'x-forwarded-proto': 'https',
        'content-type': 'application/json',
      },
      payload: JSON.stringify({ npub: NPUB }),
    });

    const completion = await buildAuthCompleteRequest({
      challenge: init.json(),
      signer: createPrivateKeySigner(PRIVATE_KEY_HEX),
      createdAt: 1_710_000_000,
    });

    const complete = await app.inject({
      method: 'POST',
      url: '/auth/complete',
      headers: {
        host: 'api.example.com',
        'x-forwarded-proto': 'https',
        authorization: completion.authorization,
        'content-type': 'application/json',
      },
      payload: new TextDecoder().decode(completion.rawBody),
    });

    expect(complete.statusCode).toBe(200);
    expect(complete.json()).toEqual({ status: 'ok' });
    expect(complete.headers['set-cookie']).toContain('session=');

    await app.close();
  });

  it('returns bad request for malformed completion bodies', async () => {
    const app = await createApp(buildServerOptions());

    const response = await app.inject({
      method: 'POST',
      url: '/auth/complete',
      headers: {
        host: 'api.example.com',
        'x-forwarded-proto': 'https',
        'content-type': 'application/json',
      },
      payload: '{"invalid":true}',
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toEqual({
      status: 'error',
      message: 'bad request',
    });

    await app.close();
  });

  it('returns 429 with retry-after when the limiter rejects /auth/init', async () => {
    const options = buildServerOptions();
    options.rateLimiter = createInMemoryRateLimiter({
      maxPerWindow: 1,
      clock: { nowUnix: () => 1_710_000_000 },
    });
    const app = await createApp(options);
    const payload = { npub: NPUB };
    const headers = { host: 'api.example.com', 'content-type': 'application/json' };

    await app.inject({ method: 'POST', url: '/auth/init', headers, payload });
    const second = await app.inject({ method: 'POST', url: '/auth/init', headers, payload });

    expect(second.statusCode).toBe(429);
    expect(second.headers['retry-after']).toBe('60');

    await app.close();
  });

  it('rejects an oversized body before parsing it', async () => {
    const app = await createApp(buildServerOptions());

    const response = await app.inject({
      method: 'POST',
      url: '/auth/init',
      headers: { host: 'api.example.com', 'content-type': 'application/json' },
      payload: JSON.stringify({ npub: NPUB, padding: 'x'.repeat(2048) }),
    });

    expect(response.statusCode).toBe(413);

    await app.close();
  });

  it('denies a guarded request once the live ACL revokes access', async () => {
    const sessionStore = new InMemorySessionStore();
    await seedSession(sessionStore);
    let allowed = true;
    const app = Fastify();

    app.get(
      '/protected',
      {
        preHandler: requirePermission('voucher:issue', {
          sessionStore,
          cookieName: 'session',
          aclResolver: {
            async resolve() {
              return allowed
                ? { allowed: true, roles: ['merchant'], permissions: ['voucher:issue'] }
                : { allowed: false, roles: [], permissions: [] };
            },
          },
        }),
      },
      async () => ({ status: 'ok' })
    );

    const headers = { cookie: 'session=token-1' };
    expect((await app.inject({ method: 'GET', url: '/protected', headers })).statusCode).toBe(200);

    allowed = false;

    // Mid-session, without waiting out the session TTL.
    expect((await app.inject({ method: 'GET', url: '/protected', headers })).statusCode).toBe(401);

    await app.close();
  });

  it('enforces registry step-up on requirePermission', async () => {
    const sessionStore = new InMemorySessionStore();
    await seedSession(sessionStore);
    const app = Fastify();

    app.get(
      '/stripe',
      {
        preHandler: requirePermission('stripe:manage', {
          sessionStore,
          cookieName: 'session',
          registry: REGISTRY,
        }),
      },
      async () => ({ status: 'ok' })
    );

    const response = await app.inject({
      method: 'GET',
      url: '/stripe',
      headers: { cookie: 'session=token-1' },
    });

    // The session holds stripe:manage but no step-up token, and the registry
    // marks that permission stepUp: true.
    expect(response.statusCode).toBe(403);
    expect(response.json().message).toBe('step-up required');

    await app.close();
  });

  it('guards routes with requirePermission and validates permission keys', async () => {
    const sessionStore = new InMemorySessionStore();
    await seedSession(sessionStore);
    const app = Fastify();

    app.get(
      '/protected',
      {
        preHandler: requirePermission('voucher:issue', {
          sessionStore,
          cookieName: 'session',
        }),
      },
      async () => ({ status: 'ok' })
    );
    await app.register(permissionsFastifyPlugin(REGISTRY), { prefix: '/auth' });

    validatePermissions(REGISTRY);

    const response = await app.inject({
      method: 'GET',
      url: '/protected',
      headers: {
        cookie: 'session=token-1',
      },
    });

    expect(response.statusCode).toBe(200);
    expect((await app.inject({ method: 'GET', url: '/auth/permissions' })).json().appId).toBe('possa-merchant');

    await app.close();
  });

  it('rejects missing step-up tokens', async () => {
    const sessionStore = new InMemorySessionStore();
    await seedSession(sessionStore, {
      step_up_token: 'step-up-1',
      step_up_expires_at: Math.floor(Date.now() / 1000) + 900,
    });
    const app = Fastify();

    app.get(
      '/step-up',
      {
        preHandler: [
          requirePermission('stripe:manage', {
            sessionStore,
            cookieName: 'session',
          }),
          requireStepUp({
            sessionStore,
            cookieName: 'session',
          }),
        ],
      },
      async () => ({ status: 'ok' })
    );

    const response = await app.inject({
      method: 'GET',
      url: '/step-up',
      headers: {
        cookie: 'session=token-1',
      },
    });

    expect(response.statusCode).toBe(403);
    expect(response.json().message).toBe('step-up required');

    await app.close();
  });

  it('returns the current session from GET /auth/session', async () => {
    const options = buildServerOptions();
    await seedSession(options.sessionStore as InMemorySessionStore);
    const app = await createApp(options);

    const response = await app.inject({
      method: 'GET',
      url: '/auth/session',
      headers: { cookie: 'session=token-1' },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json().principal.npub).toBe(NPUB);
    expect(response.json().roles).toEqual(['merchant']);

    // In cookie mode the token is HttpOnly. Echoing it into a JSON body would
    // hand a working bearer credential to any script on the page.
    expect(response.json().access_token).toBeUndefined();
    expect(response.json().step_up_token).toBeUndefined();

    await app.close();
  });

  it('returns 401 from GET /auth/session without a session', async () => {
    const app = await createApp(buildServerOptions());

    const response = await app.inject({ method: 'GET', url: '/auth/session' });

    expect(response.statusCode).toBe(401);

    await app.close();
  });

  it('revokes the session and clears the cookie on POST /auth/logout', async () => {
    const options = buildServerOptions();
    await seedSession(options.sessionStore as InMemorySessionStore);
    const app = await createApp(options);

    const logout = await app.inject({
      method: 'POST',
      url: '/auth/logout',
      headers: { cookie: 'session=token-1' },
    });

    expect(logout.statusCode).toBe(204);
    expect(logout.headers['set-cookie']).toContain('session=;');

    const after = await app.inject({
      method: 'GET',
      url: '/auth/session',
      headers: { cookie: 'session=token-1' },
    });

    expect(after.statusCode).toBe(401);

    await app.close();
  });

  it('clears the cookie with the attributes writeNapCookieSuccess set it with', async () => {
    const options = buildServerOptions();
    await seedSession(options.sessionStore as InMemorySessionStore);
    const app = Fastify();
    await app.register(napFastifyPlugin, {
      routePrefix: '/auth',
      server: options,
      getExternalBaseUrl: () => 'https://api.example.com',
      // No clearCookieOptions: the handler has to copy these, or the browser —
      // which matches a deletion on name + domain + path — keeps the cookie.
      writeSuccess: writeNapCookieSuccess('session', {
        httpOnly: true,
        secure: true,
        sameSite: 'lax',
        domain: '.example.com',
        maxAge: 900,
      }),
    });

    const logout = await app.inject({
      method: 'POST',
      url: '/auth/logout',
      headers: { cookie: 'session=token-1' },
    });

    expect(logout.statusCode).toBe(204);
    const setCookie = logout.headers['set-cookie'] as string;
    expect(setCookie).toContain('Domain=.example.com');
    expect(setCookie).toContain('SameSite=Lax');
    expect(setCookie).toContain('HttpOnly');
    expect(setCookie).toContain('Secure');
    // The set's lifetime is the one attribute that must not carry over.
    expect(setCookie).toContain('Max-Age=0');
    expect(setCookie).not.toContain('Max-Age=900');

    await app.close();
  });

  it('lets clearCookieOptions override the attributes copied from the set', async () => {
    const options = buildServerOptions();
    const app = Fastify();
    await app.register(napFastifyPlugin, {
      routePrefix: '/auth',
      server: options,
      getExternalBaseUrl: () => 'https://api.example.com',
      writeSuccess: writeNapCookieSuccess('session', { domain: '.example.com', path: '/app' }),
      clearCookieOptions: { path: '/' },
    });

    const logout = await app.inject({ method: 'POST', url: '/auth/logout' });

    expect(logout.headers['set-cookie'] as string).not.toContain('Domain=');

    await app.close();
  });

  it('returns 204 from POST /auth/logout when no session exists', async () => {
    const app = await createApp(buildServerOptions());

    const response = await app.inject({ method: 'POST', url: '/auth/logout' });

    expect(response.statusCode).toBe(204);

    await app.close();
  });

  it('guards routes with requireRole, including any-of', async () => {
    const sessionStore = new InMemorySessionStore();
    await seedSession(sessionStore);
    const app = Fastify();

    app.get(
      '/staff',
      { preHandler: requireRole('merchant', { sessionStore, cookieName: 'session' }) },
      async () => ({ status: 'ok' })
    );
    app.get(
      '/either',
      // Chaining hooks is AND, so any-of has to be expressed in one guard.
      { preHandler: requireRole(['admin', 'merchant'], { sessionStore, cookieName: 'session' }) },
      async () => ({ status: 'ok' })
    );

    const single = await app.inject({
      method: 'GET',
      url: '/staff',
      headers: { cookie: 'session=token-1' },
    });
    const anyOf = await app.inject({
      method: 'GET',
      url: '/either',
      headers: { cookie: 'session=token-1' },
    });

    expect(single.statusCode).toBe(200);
    expect(anyOf.statusCode).toBe(200);

    await app.close();
  });

  it('forbids a session lacking the role and 401s without one', async () => {
    const sessionStore = new InMemorySessionStore();
    await seedSession(sessionStore, { roles: ['viewer'] });
    const app = Fastify();

    app.get(
      '/staff',
      { preHandler: requireRole('merchant', { sessionStore, cookieName: 'session' }) },
      async () => ({ status: 'ok' })
    );

    const forbidden = await app.inject({
      method: 'GET',
      url: '/staff',
      headers: { cookie: 'session=token-1' },
    });
    const anonymous = await app.inject({ method: 'GET', url: '/staff' });

    expect(forbidden.statusCode).toBe(403);
    expect(anonymous.statusCode).toBe(401);

    await app.close();
  });

  it('fails startup validation for unknown role keys', () => {
    const sessionStore = new InMemorySessionStore();
    requireRole('nonexistent-role', { sessionStore, cookieName: 'session' });

    // Without this, a typo'd role silently 403s forever.
    expect(() => validatePermissions(REGISTRY)).toThrow(
      'Roles used in middleware but missing from registry: nonexistent-role'
    );
  });

  it('fails startup validation for unknown permission keys', () => {
    const sessionStore = new InMemorySessionStore();
    requirePermission('unknown:permission', {
      sessionStore,
      cookieName: 'session',
    });

    expect(() => validatePermissions(REGISTRY)).toThrow(
      'Permissions used in middleware but missing from registry: unknown:permission'
    );
  });

  it('takes the audience verbatim from an audienceResolver (RFC §20.2)', async () => {
    const app = Fastify();

    await app.register(napFastifyPlugin, {
      routePrefix: '/auth',
      server: buildServerOptions(),
      // A path the request itself does not carry, which is the case
      // getExternalBaseUrl cannot express.
      audienceResolver: { resolve: () => 'https://gateway.example.com/v2/nap/finish' },
    });

    const init = await app.inject({
      method: 'POST',
      url: '/auth/init',
      payload: { npub: NPUB },
    });

    expect(init.statusCode).toBe(200);
    expect(init.json().auth_url).toBe('https://gateway.example.com/v2/nap/finish');

    const completion = await buildAuthCompleteRequest({
      challenge: init.json(),
      signer: createPrivateKeySigner(PRIVATE_KEY_HEX),
      createdAt: 1_710_000_000,
    });

    // The proof is signed against that same audience, so it verifies.
    const complete = await app.inject({
      method: 'POST',
      url: '/auth/complete',
      headers: {
        authorization: completion.authorization,
        'content-type': 'application/json',
      },
      payload: new TextDecoder().decode(completion.rawBody),
    });

    expect(complete.statusCode).toBe(200);
    expect(complete.json().status).toBe('ok');

    await app.close();
  });

  it('refuses to register the plugin with neither audience source', async () => {
    const app = Fastify();

    await expect(
      app.register(napFastifyPlugin, { routePrefix: '/auth', server: buildServerOptions() })
        .after()
    ).rejects.toThrow(/exactly one of getExternalBaseUrl or audienceResolver/);
  });

  it('refuses to register the plugin with both audience sources', async () => {
    const app = Fastify();

    await expect(
      app
        .register(napFastifyPlugin, {
          routePrefix: '/auth',
          server: buildServerOptions(),
          getExternalBaseUrl: () => 'https://api.example.com',
          audienceResolver: { resolve: () => 'https://other.example.com/auth/complete' },
        })
        .after()
    ).rejects.toThrow(/exactly one of getExternalBaseUrl or audienceResolver/);
  });

  it('reads the signed bytes through a supplied rawBodyExtractor (RFC §20.2)', async () => {
    const seen: number[] = [];
    const app = Fastify();

    await app.register(napFastifyPlugin, {
      routePrefix: '/auth',
      server: buildServerOptions(),
      getExternalBaseUrl: () => 'https://api.example.com',
      rawBodyExtractor: {
        extract(req) {
          const captured = (req as { rawBody?: Uint8Array }).rawBody ?? null;

          if (captured) {
            seen.push(captured.length);
          }

          return captured;
        },
      },
    });

    const init = await app.inject({
      method: 'POST',
      url: '/auth/init',
      payload: { npub: NPUB },
    });
    const completion = await buildAuthCompleteRequest({
      challenge: init.json(),
      signer: createPrivateKeySigner(PRIVATE_KEY_HEX),
      createdAt: 1_710_000_000,
    });

    const complete = await app.inject({
      method: 'POST',
      url: '/auth/complete',
      headers: {
        authorization: completion.authorization,
        'content-type': 'application/json',
      },
      payload: new TextDecoder().decode(completion.rawBody),
    });

    // Nothing populates `req.rawBody`, so the extractor is genuinely the only
    // source consulted — had the default symbol reader still run, this would
    // have completed.
    expect(seen).toEqual([]);
    expect(complete.statusCode).toBe(500);

    await app.close();
  });
  it('rotates a refresh token over POST /auth/refresh', async () => {
    let seed = 0;
    const options: NapServerOptions = {
      ...buildServerOptions(),
      refreshTtlSeconds: 3600,
      // The shared fixture's random source is constant, which would make a
      // rotated token indistinguishable from the one it replaced.
      randomSource: {
        randomBytes(length: number) {
          seed += 1;
          return new Uint8Array(Array.from({ length }, (_, index) => (index + seed * 7) % 255));
        },
      },
    };
    const app = await createApp(options);

    const init = await app.inject({
      method: 'POST',
      url: '/auth/init',
      headers: { host: 'api.example.com', 'x-forwarded-proto': 'https' },
      payload: { npub: NPUB },
    });
    const completion = await buildAuthCompleteRequest({
      challenge: init.json(),
      signer: createPrivateKeySigner(PRIVATE_KEY_HEX),
      createdAt: 1_710_000_000,
    });
    const complete = await app.inject({
      method: 'POST',
      url: '/auth/complete',
      headers: {
        host: 'api.example.com',
        'x-forwarded-proto': 'https',
        authorization: completion.authorization,
        'content-type': 'application/json',
      },
      payload: new TextDecoder().decode(completion.rawBody),
    });

    const session = complete.json();
    expect(session.refresh_token).toBeTypeOf('string');

    const refreshed = await app.inject({
      method: 'POST',
      url: '/auth/refresh',
      headers: { authorization: `Bearer ${session.refresh_token}` },
    });

    expect(refreshed.statusCode).toBe(200);
    expect(refreshed.json().refresh_token).not.toBe(session.refresh_token);

    // The presented token is now retired, so presenting it again kills the family.
    const replay = await app.inject({
      method: 'POST',
      url: '/auth/refresh',
      headers: { authorization: `Bearer ${session.refresh_token}` },
    });

    expect(replay.statusCode).toBe(401);

    await app.close();
  });

  it('does not register /auth/refresh when no refresh TTL is configured', async () => {
    const app = await createApp(buildServerOptions());

    const refreshed = await app.inject({
      method: 'POST',
      url: '/auth/refresh',
      headers: { authorization: 'Bearer x' },
    });

    expect(refreshed.statusCode).toBe(404);

    await app.close();
  });

  it('refuses to start when the store cannot honour the configured refresh TTL', async () => {
    const capable = new InMemorySessionStore();
    // A store predating refresh tokens: it satisfies the required members and
    // nothing else.
    const legacy: SessionStore = {
      createForChallenge: (record) => capable.createForChallenge(record),
      getBySessionId: (id) => capable.getBySessionId(id),
      getByAccessToken: (token) => capable.getByAccessToken(token),
      revokeBySessionId: (id, now) => capable.revokeBySessionId(id, now),
      revokeByPrincipal: (pubkey, now) => capable.revokeByPrincipal(pubkey, now),
    };

    await expect(
      Fastify()
        .register(napFastifyPlugin, {
          routePrefix: '/auth',
          server: { ...buildServerOptions(), sessionStore: legacy, refreshTtlSeconds: 3600 },
          getExternalBaseUrl: () => 'https://api.example.com',
        })
        .after()
    ).rejects.toThrow(/getByRefreshToken and rotateRefreshToken/);
  });

  it('refuses to start when the cookie writer would throw the refresh token away', async () => {
    await expect(
      Fastify()
        .register(napFastifyPlugin, {
          routePrefix: '/auth',
          server: { ...buildServerOptions(), refreshTtlSeconds: 3600 },
          getExternalBaseUrl: () => 'https://api.example.com',
          writeSuccess: writeNapCookieSuccess('session'),
        })
        .after()
    ).rejects.toThrow(/never receives the refresh token/);
  });

  it('accepts the cookie writer once a transformBody carries the refresh token', async () => {
    await expect(
      Fastify()
        .register(napFastifyPlugin, {
          routePrefix: '/auth',
          server: { ...buildServerOptions(), refreshTtlSeconds: 3600 },
          getExternalBaseUrl: () => 'https://api.example.com',
          writeSuccess: writeNapCookieSuccess('session', undefined, (body) => ({
            refresh_token: body.refresh_token,
          })),
        })
        .after()
    ).resolves.toBeUndefined();
  });
});
