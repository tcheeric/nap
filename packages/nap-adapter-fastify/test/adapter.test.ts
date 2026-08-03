import Fastify from 'fastify';
import { getPublicKey, nip19 } from 'nostr-tools';
import { beforeEach, describe, expect, it } from 'vitest';
import { hexToBytes } from '@imani/nap-core';
import { buildAuthCompleteRequest, createPrivateKeySigner } from '@imani/nap-client-http';
import {
  InMemoryAclStore,
  InMemoryChallengeStore,
  InMemorySessionStore,
  createRegistryAclResolver,
  type NapServerOptions,
  type PermissionRegistry,
} from '@imani/nap-server';
import {
  createRequestDerivedBaseUrlResolver,
  napFastifyPlugin,
  permissionsFastifyPlugin,
  requirePermission,
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

  it('returns 204 from POST /auth/logout when no session exists', async () => {
    const app = await createApp(buildServerOptions());

    const response = await app.inject({ method: 'POST', url: '/auth/logout' });

    expect(response.statusCode).toBe(204);

    await app.close();
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
});
