import express from 'express';
import { getPublicKey, nip19 } from 'nostr-tools';
import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { buildAuthCompleteRequest, createPrivateKeySigner } from '@imani/nap-client-http';
import {
  InMemoryChallengeStore,
  InMemorySessionStore,
  type NapServerOptions,
} from '@imani/nap-server';
import {
  createNapExpressRouter,
  createTrustedProxyAwareBaseUrlResolver,
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

function createApp(options: NapServerOptions) {
  const app = express();
  app.set('trust proxy', true);
  app.use(
    '/auth',
    createNapExpressRouter({
      server: options,
      getExternalBaseUrl: createTrustedProxyAwareBaseUrlResolver(),
    })
  );
  app.use((error: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    res.status(500).json({ error: error.message });
  });
  return app;
}

describe('nap-adapter-express', () => {
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
      .send(Buffer.from(completion.rawBody).toString('utf8'));

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
        getExternalBaseUrl: createTrustedProxyAwareBaseUrlResolver(),
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
      .send(Buffer.from(completion.rawBody).toString('utf8'));

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
      .send(Buffer.from('{"invalid":true}'));

    expect(response.status).toBe(400);
    expect(response.body).toEqual({
      status: 'error',
      message: 'bad request',
    });
  });
});
