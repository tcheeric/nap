import Fastify from 'fastify';
import { getPublicKey, nip19 } from 'nostr-tools';
import { describe, expect, it } from 'vitest';
import { buildAuthCompleteRequest, createPrivateKeySigner } from '@imani/nap-client-http';
import {
  InMemoryChallengeStore,
  InMemorySessionStore,
  type NapServerOptions,
} from '@imani/nap-server';
import {
  createTrustedProxyAwareBaseUrlResolver,
  napFastifyPlugin,
  writeNapCookieSuccess,
} from '../src/index.js';

const PRIVATE_KEY_HEX = '1111111111111111111111111111111111111111111111111111111111111111';
const PRIVATE_KEY_BYTES = Uint8Array.from(Buffer.from(PRIVATE_KEY_HEX, 'hex'));
const NPUB = nip19.npubEncode(getPublicKey(PRIVATE_KEY_BYTES));

function buildServerOptions(now = 1_710_000_000): NapServerOptions {
  return {
    challengeStore: new InMemoryChallengeStore(),
    sessionStore: new InMemorySessionStore(),
    aclResolver: {
      async resolve() {
        return {
          allowed: true,
          roles: ['merchant'],
          permissions: ['voucher:issue'],
        };
      },
    },
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

async function createApp(options: NapServerOptions) {
  const app = Fastify({ trustProxy: true });

  await app.register(napFastifyPlugin, {
    routePrefix: '/auth',
    server: options,
    getExternalBaseUrl: createTrustedProxyAwareBaseUrlResolver(),
  });

  return app;
}

describe('nap-adapter-fastify', () => {
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
      payload: Buffer.from(completion.rawBody).toString('utf8'),
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
      getExternalBaseUrl: createTrustedProxyAwareBaseUrlResolver(),
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
      payload: Buffer.from(completion.rawBody).toString('utf8'),
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
});
