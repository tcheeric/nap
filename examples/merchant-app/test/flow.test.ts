import { getPublicKey, nip19 } from 'nostr-tools';
import request from 'supertest';
import { beforeEach, describe, expect, it } from 'vitest';
import { hexToBytes } from '@imani/nap-core';
import { buildAuthCompleteRequest, createPrivateKeySigner } from '@imani/nap-client-http';
import {
  InMemoryAclStore,
  InMemoryChallengeStore,
  InMemorySessionStore,
  type AclStore,
  type Clock,
} from '@imani/nap-server';
import { resetPermissionValidationState } from '@imani/nap-adapter-express';

import { createMerchantApp, type MerchantAppOptions } from '../src/app.js';
import { REGISTRY } from '../src/registry.js';

const PRIVATE_KEY_HEX = '1111111111111111111111111111111111111111111111111111111111111111';
const PUBKEY = getPublicKey(hexToBytes(PRIVATE_KEY_HEX));
const NPUB = nip19.npubEncode(PUBKEY);
const BASE_URL = 'https://api.example.com';
// Anchored to real time rather than a constant: the adapter's guards compare
// `expires_at` against the system clock, not against the injected one, so a
// session issued at an arbitrary fixed instant reads as expired on every
// guarded route.
const NOW = Math.floor(Date.now() / 1000);

const clock: Clock = { nowUnix: () => NOW };

function build(overrides: Partial<MerchantAppOptions> = {}) {
  return createMerchantApp({
    baseUrl: BASE_URL,
    mode: 'bearer',
    clock,
    challengeStore: new InMemoryChallengeStore(),
    sessionStore: new InMemorySessionStore(),
    aclStore: new InMemoryAclStore(),
    auditLogger: { log() {} },
    server: { minAuthResponseMillis: 0 },
    ...overrides,
  });
}

/** The whole login exchange, exactly as tutorial 01 walks it by hand. */
async function login(
  app: ReturnType<typeof build>['app'],
  options: { stepUp?: boolean } = {}
) {
  const init = await request(app).post('/auth/init').send({ npub: NPUB });
  expect(init.status).toBe(200);
  expect(init.body.auth_url).toBe(`${BASE_URL}/auth/complete`);

  const completion = await buildAuthCompleteRequest({
    challenge: init.body,
    signer: createPrivateKeySigner(PRIVATE_KEY_HEX),
    createdAt: NOW,
    ...(options.stepUp ? { stepUp: true } : {}),
  });

  const complete = await request(app)
    .post('/auth/complete')
    .set('authorization', completion.authorization)
    .set('content-type', 'application/json')
    // The raw bytes the payload tag hashed. Anything that reserialises them
    // here fails the completion, which is the point of sending them this way.
    .send(new TextDecoder().decode(completion.rawBody));

  return complete;
}

async function grant(aclStore: AclStore, role: string) {
  await aclStore.upsert({
    principal_pubkey: PUBKEY,
    app_id: REGISTRY.appId,
    role,
    permission_overrides: [],
    suspended: false,
  });
}

describe('merchant-app', () => {
  beforeEach(() => {
    // The permission validator accumulates into module-level state, so each
    // createMerchantApp() in this file would otherwise see the previous one's.
    resetPermissionValidationState();
  });

  it('issues a challenge and accepts a signed completion', async () => {
    const { app } = build();

    const complete = await login(app);

    expect(complete.status).toBe(200);
    expect(complete.body.status).toBe('ok');
    expect(complete.body.token_type).toBe('Bearer');
    expect(complete.body.principal.npub).toBe(NPUB);
    expect(complete.body.principal.pubkey).toBe(PUBKEY);
    expect(complete.body.permissions).toContain('merchant:read');
  });

  it('rejects a completion whose body was reserialised', async () => {
    const { app } = build();
    const init = await request(app).post('/auth/init').send({ npub: NPUB });
    const completion = await buildAuthCompleteRequest({
      challenge: init.body,
      signer: createPrivateKeySigner(PRIVATE_KEY_HEX),
      createdAt: NOW,
    });

    const reserialised = await request(app)
      .post('/auth/complete')
      .set('authorization', completion.authorization)
      .set('content-type', 'application/json')
      // Same JSON, different bytes — a space is enough.
      .send(` ${new TextDecoder().decode(completion.rawBody)}`);

    expect(reserialised.status).toBe(401);
  });

  it('lets a session through a guarded route and records the principal', async () => {
    const { app } = build();
    const token = (await login(app)).body.access_token;

    const me = await request(app).get('/api/me').set('authorization', `Bearer ${token}`);
    expect(me.status).toBe(200);
    expect(me.body.npub).toBe(NPUB);

    const created = await request(app)
      .post('/api/vouchers')
      .set('authorization', `Bearer ${token}`)
      .send({ amount_cents: 2500 });

    expect(created.status).toBe(201);
    expect(created.body.voucher.issuedBy).toBe(NPUB);

    const list = await request(app).get('/api/vouchers').set('authorization', `Bearer ${token}`);
    expect(list.body.vouchers).toHaveLength(1);
  });

  it('refuses a guarded route with no session at all', async () => {
    const { app } = build();
    expect((await request(app).get('/api/vouchers')).status).toBe(401);
  });

  it('denies a permission the principal\'s role does not carry', async () => {
    const { app } = build();
    const token = (await login(app)).body.access_token;

    // defaultRole is 'merchant', which has no stripe:manage.
    const payout = await request(app)
      .post('/api/payouts')
      .set('authorization', `Bearer ${token}`)
      .send({});

    expect(payout.status).toBe(403);
  });

  it('lets viewer read and refuses viewer the write', async () => {
    const { app, aclStore } = build();
    await grant(aclStore, 'viewer');
    const token = (await login(app)).body.access_token;

    const list = await request(app).get('/api/vouchers').set('authorization', `Bearer ${token}`);
    expect(list.status).toBe(200);

    const created = await request(app)
      .post('/api/vouchers')
      .set('authorization', `Bearer ${token}`)
      .send({ amount_cents: 2500 });

    // The refusal is the half worth asserting. A test that only proves the
    // happy path passes just as well against a route with no guard on it.
    expect(created.status).toBe(403);
  });

  it('guards the staff route on the role, which no permission expresses', async () => {
    const { app, aclStore } = build();

    const merchant = (await login(app)).body.access_token;
    expect(
      (await request(app).get('/api/support/lookup').set('authorization', `Bearer ${merchant}`))
        .status
    ).toBe(403);

    await grant(aclStore, 'support');
    const staff = (await login(app)).body.access_token;
    expect(
      (await request(app).get('/api/support/lookup').set('authorization', `Bearer ${staff}`)).status
    ).toBe(200);
  });

  it('applies a revocation to a live session because the guards re-read the ACL', async () => {
    const { app, aclStore } = build();
    await grant(aclStore, 'owner');
    const token = (await login(app)).body.access_token;

    expect(
      (
        await request(app)
          .post('/api/vouchers')
          .set('authorization', `Bearer ${token}`)
          .send({ amount_cents: 100 })
      ).status
    ).toBe(201);

    // Same session, same token, downgraded role. Without `aclResolver` in the
    // guard options this would keep working until the session TTL expired,
    // because `session.permissions` is the login-time snapshot.
    await grant(aclStore, 'viewer');

    expect(
      (
        await request(app)
          .post('/api/vouchers')
          .set('authorization', `Bearer ${token}`)
          .send({ amount_cents: 100 })
      ).status
    ).toBe(403);
  });

  it('demands a step-up token for a stepUp permission, and accepts one', async () => {
    const { app, aclStore } = build();
    await grant(aclStore, 'owner');

    const plain = (await login(app)).body.access_token;
    const withoutToken = await request(app)
      .post('/api/payouts')
      .set('authorization', `Bearer ${plain}`)
      .send({});

    // The role carries the permission. The missing thing is the fresh signature.
    expect(withoutToken.status).toBe(403);
    expect(withoutToken.body.message).toBe('step-up required');

    const stepped = await login(app, { stepUp: true });
    expect(stepped.body.step_up_token).toBeTruthy();

    const withToken = await request(app)
      .post('/api/payouts')
      .set('authorization', `Bearer ${stepped.body.access_token}`)
      .set('x-step-up-token', stepped.body.step_up_token)
      .send({});

    expect(withToken.status).toBe(200);

    // A step-up is a full re-authentication, so it mints a *second* session
    // rather than upgrading the first. The guard compares the step-up token
    // against the session the request's own credential names, so pairing the
    // new token with the old access token proves nothing and is refused. A
    // bearer client has to adopt both halves of the step-up response.
    expect(
      (
        await request(app)
          .post('/api/payouts')
          .set('authorization', `Bearer ${plain}`)
          .set('x-step-up-token', stepped.body.step_up_token)
          .send({})
      ).status
    ).toBe(403);

    // And the plain session is still a session: it was never revoked, it just
    // never carried a step-up token.
    expect(
      (await request(app).get('/api/vouchers').set('authorization', `Bearer ${plain}`)).status
    ).toBe(200);
  });

  it('rotates a refresh token and refuses the spent one', async () => {
    const { app } = build({ server: { minAuthResponseMillis: 0, refreshTtlSeconds: 3600 } });
    const first = await login(app);
    const original = first.body.refresh_token;
    expect(original).toBeTruthy();

    const refreshed = await request(app)
      .post('/auth/refresh')
      .set('authorization', `Bearer ${original}`)
      .send();

    expect(refreshed.status).toBe(200);
    expect(refreshed.body.refresh_token).not.toBe(original);

    const replayed = await request(app)
      .post('/auth/refresh')
      .set('authorization', `Bearer ${original}`)
      .send();

    expect(replayed.status).toBe(401);
  });

  it('rotates the cookie too, and a replay takes the whole session down', async () => {
    const { app } = build({
      mode: 'cookie',
      server: { minAuthResponseMillis: 0, refreshTtlSeconds: 3600 },
    });

    const first = await login(app);
    const firstCookie = first.headers['set-cookie'];

    // The access token is in the cookie; the refresh token cannot be, because
    // /auth/refresh reads Authorization: Bearer. So cookie mode plus refresh
    // means a transformBody, and the adapter refuses to start without one.
    expect(first.body.access_token).toBeUndefined();
    const original = first.body.refresh_token;
    expect(original).toBeTruthy();

    const refreshed = await request(app)
      .post('/auth/refresh')
      .set('authorization', `Bearer ${original}`)
      .send();

    expect(refreshed.status).toBe(200);
    const secondCookie = refreshed.headers['set-cookie'];
    expect(String(secondCookie)).toContain('HttpOnly');

    // Rotation replaces the access token as well, so the cookie the browser
    // was holding a moment ago is now dead. A client that ignores the
    // Set-Cookie on the refresh response has logged itself out.
    expect((await request(app).get('/api/vouchers').set('cookie', firstCookie)).status).toBe(401);
    expect((await request(app).get('/api/vouchers').set('cookie', secondCookie)).status).toBe(200);

    // Presenting the spent token is indistinguishable from a thief presenting
    // a stolen one, so the server assumes the worse case: not just a 401, but
    // the session revoked out from under the legitimate holder.
    expect(
      (await request(app).post('/auth/refresh').set('authorization', `Bearer ${original}`).send())
        .status
    ).toBe(401);
    expect((await request(app).get('/api/vouchers').set('cookie', secondCookie)).status).toBe(401);
  });

  it('carries a session in a cookie and clears it on logout', async () => {
    const { app } = build({ mode: 'cookie' });

    const complete = await login(app);
    expect(complete.status).toBe(200);
    // The token is in the cookie and deliberately not in the body.
    expect(complete.body.access_token).toBeUndefined();

    const cookie = complete.headers['set-cookie'];
    expect(String(cookie)).toContain('HttpOnly');

    const session = await request(app).get('/auth/session').set('cookie', cookie);
    expect(session.status).toBe(200);
    expect(session.body.principal.npub).toBe(NPUB);
    // Never echo a credential the browser holds as HttpOnly into readable JSON.
    expect(session.body.access_token).toBeUndefined();

    const guarded = await request(app).get('/api/vouchers').set('cookie', cookie);
    expect(guarded.status).toBe(200);

    const logout = await request(app).post('/auth/logout').set('cookie', cookie).send();
    expect([200, 204]).toContain(logout.status);
    // Cleared under the same name it was written with. A mismatch here is the
    // failure the adapter's single-source cookie name exists to prevent: the
    // browser keeps a cookie the server thinks it revoked.
    expect(String(logout.headers['set-cookie'])).toMatch(/^session=;/);

    const after = await request(app).get('/api/vouchers').set('cookie', cookie);
    expect(after.status).toBe(401);
  });
});
