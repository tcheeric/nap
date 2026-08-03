import express from 'express';
import { getPublicKey, nip19 } from 'nostr-tools';
import request from 'supertest';
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
  createPermissionsRouter,
  createNapExpressRouter,
  createRequestDerivedBaseUrlResolver,
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

function createApp(options: NapServerOptions) {
  const app = express();
  app.set('trust proxy', true);
  app.use(
    '/auth',
    createNapExpressRouter({
      server: options,
      getExternalBaseUrl: createRequestDerivedBaseUrlResolver(),
    })
  );
  app.use((error: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    res.status(500).json({ error: error.message });
  });
  return app;
}

describe('nap-adapter-express', () => {
  beforeEach(() => {
    resetPermissionValidationState();
  });

  it('handles the init and complete flow in bearer mode', async () => {
    const app = createApp(buildServerOptions());
    const init = await request(app)
      .post('/auth/init')
      .set('host', 'api.example.com')
      .set('x-forwarded-proto', 'https')
      .send({ npub: NPUB });

    expect(init.status).toBe(200);
    expect(init.body.auth_url).toBe('https://api.example.com/auth/complete');

    const completion = await buildAuthCompleteRequest({
      challenge: init.body,
      signer: createPrivateKeySigner(PRIVATE_KEY_HEX),
      createdAt: 1_710_000_000,
    });

    const complete = await request(app)
      .post('/auth/complete')
      .set('host', 'api.example.com')
      .set('x-forwarded-proto', 'https')
      .set('authorization', completion.authorization)
      .set('content-type', 'application/json')
      .send(new TextDecoder().decode(completion.rawBody));

    expect(complete.status).toBe(200);
    expect(complete.body.status).toBe('ok');
    expect(complete.body.token_type).toBe('Bearer');
    expect(complete.body.principal.npub).toBe(NPUB);
  });

  it('supports cookie mode', async () => {
    const app = express();
    app.set('trust proxy', true);
    app.use(
      '/auth',
      createNapExpressRouter({
        server: buildServerOptions(),
        getExternalBaseUrl: createRequestDerivedBaseUrlResolver(),
        writeSuccess: writeNapCookieSuccess('session', {
          httpOnly: true,
          secure: true,
          sameSite: 'lax',
        }),
      })
    );
    app.use((error: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
      res.status(500).json({ error: error.message });
    });

    const init = await request(app)
      .post('/auth/init')
      .set('host', 'api.example.com')
      .set('x-forwarded-proto', 'https')
      .send({ npub: NPUB });

    const completion = await buildAuthCompleteRequest({
      challenge: init.body,
      signer: createPrivateKeySigner(PRIVATE_KEY_HEX),
      createdAt: 1_710_000_000,
    });

    const complete = await request(app)
      .post('/auth/complete')
      .set('host', 'api.example.com')
      .set('x-forwarded-proto', 'https')
      .set('authorization', completion.authorization)
      .set('content-type', 'application/json')
      .send(new TextDecoder().decode(completion.rawBody));

    expect(complete.status).toBe(200);
    expect(complete.body).toEqual({ status: 'ok' });
    expect(complete.headers['set-cookie']?.[0]).toContain('session=');
  });

  it('returns a bad request response for malformed completion bodies', async () => {
    const app = createApp(buildServerOptions());
    const response = await request(app)
      .post('/auth/complete')
      .set('host', 'api.example.com')
      .set('x-forwarded-proto', 'https')
      .set('content-type', 'application/json')
      .send('{"invalid":true}');

    expect(response.status).toBe(400);
    expect(response.body).toEqual({
      status: 'error',
      message: 'bad request',
    });
  });

  it('guards routes with requirePermission and validates permission keys', async () => {
    const sessionStore = new InMemorySessionStore();
    await seedSession(sessionStore);
    const app = express();
    app.get(
      '/protected',
      requirePermission('voucher:issue', {
        sessionStore,
        cookieName: 'session',
      }),
      (_req, res) => {
        res.status(200).json({ status: 'ok' });
      }
    );
    app.use('/auth', createPermissionsRouter(REGISTRY));

    validatePermissions(REGISTRY);

    const response = await request(app)
      .get('/protected')
      .set('cookie', 'session=token-1');

    expect(response.status).toBe(200);
    expect((await request(app).get('/auth/permissions')).body.appId).toBe('possa-merchant');
  });

  it('rejects missing step-up tokens', async () => {
    const sessionStore = new InMemorySessionStore();
    await seedSession(sessionStore, {
      step_up_token: 'step-up-1',
      step_up_expires_at: Math.floor(Date.now() / 1000) + 900,
    });
    const app = express();
    app.get(
      '/step-up',
      requirePermission('stripe:manage', {
        sessionStore,
        cookieName: 'session',
      }),
      requireStepUp({
        sessionStore,
        cookieName: 'session',
      }),
      (_req, res) => {
        res.status(200).json({ status: 'ok' });
      }
    );

    const response = await request(app)
      .get('/step-up')
      .set('cookie', 'session=token-1');

    expect(response.status).toBe(403);
    expect(response.body.message).toBe('step-up required');
  });

  it('returns the current session from GET /auth/session', async () => {
    const options = buildServerOptions();
    await seedSession(options.sessionStore as InMemorySessionStore);
    const app = createApp(options);

    const response = await request(app)
      .get('/auth/session')
      .set('cookie', 'session=token-1');

    expect(response.status).toBe(200);
    expect(response.body.status).toBe('ok');
    expect(response.body.principal.npub).toBe(NPUB);
    expect(response.body.roles).toEqual(['merchant']);
  });

  it('does not leak the access token from GET /auth/session', async () => {
    const options = buildServerOptions();
    await seedSession(options.sessionStore as InMemorySessionStore);
    const app = createApp(options);

    const response = await request(app)
      .get('/auth/session')
      .set('cookie', 'session=token-1');

    // In cookie mode the token is HttpOnly. Echoing it into a JSON body would
    // hand a working bearer credential to any script on the page.
    expect(response.body.access_token).toBeUndefined();
    expect(response.body.step_up_token).toBeUndefined();
  });

  it('returns 401 from GET /auth/session without a session', async () => {
    const app = createApp(buildServerOptions());

    const response = await request(app).get('/auth/session');

    expect(response.status).toBe(401);
  });

  it('revokes the session and clears the cookie on POST /auth/logout', async () => {
    const options = buildServerOptions();
    await seedSession(options.sessionStore as InMemorySessionStore);
    const app = createApp(options);

    const logout = await request(app)
      .post('/auth/logout')
      .set('cookie', 'session=token-1');

    expect(logout.status).toBe(204);
    expect(logout.headers['set-cookie']?.[0]).toContain('session=;');

    const after = await request(app)
      .get('/auth/session')
      .set('cookie', 'session=token-1');

    expect(after.status).toBe(401);
  });

  it('returns 204 from POST /auth/logout when no session exists', async () => {
    const app = createApp(buildServerOptions());

    const response = await request(app).post('/auth/logout');

    expect(response.status).toBe(204);
  });

  it('allows a request whose session holds the required role', async () => {
    const options = buildServerOptions();
    await seedSession(options.sessionStore as InMemorySessionStore);
    const app = createApp(options);

    app.get(
      '/staff',
      requireRole('merchant', {
        sessionStore: options.sessionStore,
        cookieName: 'session',
      }),
      (_req, res) => {
        res.status(200).json({ status: 'ok' });
      }
    );

    const response = await request(app).get('/staff').set('cookie', 'session=token-1');

    expect(response.status).toBe(200);
  });

  it('accepts any of several roles', async () => {
    const options = buildServerOptions();
    await seedSession(options.sessionStore as InMemorySessionStore);
    const app = createApp(options);

    app.get(
      '/either',
      // Chaining middleware is AND, so any-of has to be expressed in one guard.
      requireRole(['admin', 'merchant'], {
        sessionStore: options.sessionStore,
        cookieName: 'session',
      }),
      (_req, res) => {
        res.status(200).json({ status: 'ok' });
      }
    );

    const response = await request(app).get('/either').set('cookie', 'session=token-1');

    expect(response.status).toBe(200);
  });

  it('forbids a request whose session lacks the role', async () => {
    const options = buildServerOptions();
    await seedSession(options.sessionStore as InMemorySessionStore, { roles: ['viewer'] });
    const app = createApp(options);

    app.get(
      '/staff',
      requireRole('merchant', {
        sessionStore: options.sessionStore,
        cookieName: 'session',
      }),
      (_req, res) => {
        res.status(200).json({ status: 'ok' });
      }
    );

    const response = await request(app).get('/staff').set('cookie', 'session=token-1');

    expect(response.status).toBe(403);
  });

  it('returns 401 from a role guard without a session', async () => {
    const options = buildServerOptions();
    const app = createApp(options);

    app.get(
      '/staff',
      requireRole('merchant', {
        sessionStore: options.sessionStore,
        cookieName: 'session',
      }),
      (_req, res) => {
        res.status(200).json({ status: 'ok' });
      }
    );

    const response = await request(app).get('/staff');

    expect(response.status).toBe(401);
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
});
