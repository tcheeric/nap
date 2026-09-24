import Fastify from 'fastify';
import express from 'express';
import request from 'supertest';
import { describe, expect, it } from 'vitest';

import { exactUrlMatch } from '@imani/nap-core';
import {
  createNapExpressLogoutHandler,
  createNapExpressSessionHandler,
  writeNapCookieSuccess as writeExpressCookie,
} from '@imani/nap-adapter-express';
import {
  createNapFastifyLogoutHandler,
  createNapFastifySessionHandler,
  writeNapCookieSuccess as writeFastifyCookie,
} from '@imani/nap-adapter-fastify';
import { InMemoryChallengeStore, InMemorySessionStore } from '@imani/nap-server';
import type { SessionRecord } from '@imani/nap-core';

/**
 * Cross-cutting checks over the whole security result, through public entry points.
 *
 * Every other suite here tests one package. This one exists because the two defects the
 * remediation actually shipped were both invisible from inside a single package: the
 * session store swept on the read path but not the write path, and the Express adapter
 * gained a fix the Fastify adapter did not. Neither is findable by testing either side
 * alone, and both are the same shape, which is two things that should agree and do not.
 *
 * So the rule here is that every case either drives both adapters from one table, or
 * asserts a property rather than an implementation. Imports come from the package names a
 * consumer would use, so a broken `exports` map fails this file before it reaches anyone.
 */

const NOW = 1_710_000_000;
const pinned = (now: number) => ({ nowUnix: () => now });

function session(overrides: Partial<SessionRecord> = {}): SessionRecord {
  return {
    session_id: 's1',
    challenge_id: 'c1',
    access_token: 'TOK',
    principal_npub: 'npub1example',
    principal_pubkey: 'ff'.repeat(32),
    roles: [],
    permissions: [],
    issued_at: NOW - 10,
    expires_at: NOW + 900,
    ...overrides,
  };
}

/** A store that answers for exactly one session, so the adapters can be driven uniformly. */
function storeFor(record: SessionRecord | null) {
  return {
    getByAccessToken: async (token: string) =>
      record && token === record.access_token ? record : null,
    revokeBySessionId: async () => undefined,
  } as never;
}

/**
 * The two adapters, behind one interface.
 *
 * Both entries must answer identically for every case below. Adding a third adapter means
 * adding a row here, and the existing cases then cover it.
 */
const adapters = [
  {
    name: 'express',
    async setCookie(options?: Record<string, unknown>): Promise<string> {
      const app = express();
      const write = writeExpressCookie('session', options as never);
      app.get('/x', (req, res) => {
        void write({ req, res, body: { access_token: 'TOK' } as never });
      });
      const response = await request(app).get('/x');
      return response.headers['set-cookie']?.[0] ?? '';
    },
    async clearCookie(options?: Record<string, unknown>): Promise<string> {
      const app = express();
      app.post(
        '/auth/logout',
        createNapExpressLogoutHandler({
          server: { sessionStore: storeFor(null) },
          cookieName: 'session',
          writeSuccess: writeExpressCookie('session', options as never),
        } as never)
      );
      const response = await request(app).post('/auth/logout');
      return response.headers['set-cookie']?.[0] ?? '';
    },
    async sessionStatus(expiresAt: number, clockNow: number): Promise<number> {
      const app = express();
      app.get(
        '/auth/session',
        createNapExpressSessionHandler({
          server: { sessionStore: storeFor(session({ expires_at: expiresAt })), clock: pinned(clockNow) },
          getExternalBaseUrl: () => 'https://api.example.com',
        } as never)
      );
      const response = await request(app).get('/auth/session').set('Authorization', 'Bearer TOK');
      return response.status;
    },
  },
  {
    name: 'fastify',
    async setCookie(options?: Record<string, unknown>): Promise<string> {
      const app = Fastify();
      const write = writeFastifyCookie('session', options as never);
      app.get('/x', async (req, reply) => {
        await write({ req, reply, body: { access_token: 'TOK' } as never });
      });
      const response = await app.inject({ method: 'GET', url: '/x' });
      await app.close();
      return (response.headers['set-cookie'] as string) ?? '';
    },
    async clearCookie(options?: Record<string, unknown>): Promise<string> {
      const app = Fastify();
      app.post(
        '/auth/logout',
        createNapFastifyLogoutHandler({
          server: { sessionStore: storeFor(null) },
          cookieName: 'session',
          writeSuccess: writeFastifyCookie('session', options as never),
        } as never)
      );
      const response = await app.inject({ method: 'POST', url: '/auth/logout' });
      await app.close();
      return (response.headers['set-cookie'] as string) ?? '';
    },
    async sessionStatus(expiresAt: number, clockNow: number): Promise<number> {
      const app = Fastify();
      app.get(
        '/auth/session',
        createNapFastifySessionHandler({
          server: { sessionStore: storeFor(session({ expires_at: expiresAt })), clock: pinned(clockNow) },
          getExternalBaseUrl: () => 'https://api.example.com',
        } as never)
      );
      const response = await app.inject({
        method: 'GET',
        url: '/auth/session',
        headers: { authorization: 'Bearer TOK' },
      });
      await app.close();
      return response.statusCode;
    },
  },
] as const;

describe.each(adapters)('$name adapter: cookie and clock parity', (adapter) => {
  it('defaults the session cookie to HttpOnly, Secure and SameSite', async () => {
    const cookie = await adapter.setCookie();

    expect(cookie).toMatch(/httponly/i);
    expect(cookie).toMatch(/secure/i);
    expect(cookie).toMatch(/samesite/i);
  });

  // The case a real deployment hits, and the one the original fix got wrong: setting a
  // single attribute must add to the defaults rather than replace them.
  it('merges partial options over the defaults rather than replacing them', async () => {
    const cookie = await adapter.setCookie({ domain: '.example.com' });

    expect(cookie).toMatch(/domain=\.example\.com/i);
    expect(cookie).toMatch(/httponly/i);
    expect(cookie).toMatch(/secure/i);
    expect(cookie).toMatch(/samesite/i);
  });

  // The escape hatch has to survive, or local development over plain HTTP is impossible
  // and someone reaches for a worse workaround.
  it('lets an explicit opt-out win', async () => {
    const cookie = await adapter.setCookie({ httpOnly: false, secure: false });

    expect(cookie).not.toMatch(/httponly/i);
    expect(cookie).not.toMatch(/secure/i);
  });

  /**
   * A browser matches a deletion against name, domain and path. A clear that omits the
   * domain leaves the cookie in the jar, so logout returns 204 and does not log out.
   */
  it('clears with the attributes the set wrote, and without a live Max-Age', async () => {
    const cookie = await adapter.clearCookie({ domain: '.example.com' });

    expect(cookie).toMatch(/domain=\.example\.com/i);
    expect(cookie).not.toMatch(/max-age=(?!0)\d/i);
  });

  it('judges /auth/session expiry on the injected clock', async () => {
    expect(await adapter.sessionStatus(NOW + 900, NOW)).toBe(200);
  });

  // The pair is the point: the case above alone is satisfied by not checking expiry.
  it('still refuses a session the injected clock has moved past', async () => {
    expect(await adapter.sessionStatus(NOW + 900, NOW + 901)).toBe(401);
  });
});

describe('store growth is bounded on the path that actually grows', () => {
  /**
   * Both stores are filled by unauthenticated traffic, and the write path is what an
   * attacker drives. Sweeping only on reads left a server taking logins and serving no
   * guarded requests growing without bound, which is the shape of the attack rather than
   * an edge case.
   *
   * Asserting equality across a tenfold difference is what makes this meaningful: residue
   * is the retention window, so it tracks the TTL and not the traffic. A threshold would
   * pass against an unbounded store at small volumes.
   */
  it.each([
    {
      label: 'challenges',
      resident: async (count: number) => {
        const clock = { now: NOW, nowUnix: () => clock.now };
        const store = new InMemoryChallengeStore({ clock });
        for (let index = 0; index < count; index += 1) {
          await store.create({
            challenge_id: `c${index}`,
            challenge: 'x',
            npub: 'npub1example',
            pubkey: 'ff'.repeat(32),
            auth_url: 'https://api.example.com/auth/complete',
            auth_method: 'POST',
            state: 'issued',
            issued_at: clock.now,
            expires_at: clock.now + 60,
          });
          clock.now += 1;
        }
        let alive = 0;
        for (let index = 0; index < count; index += 1) {
          if (await store.get(`c${index}`)) alive += 1;
        }
        return alive;
      },
    },
    {
      label: 'sessions',
      resident: async (count: number) => {
        const clock = { now: NOW, nowUnix: () => clock.now };
        const store = new InMemorySessionStore({ clock });
        for (let index = 0; index < count; index += 1) {
          await store.createForChallenge(session({
            session_id: `s${index}`,
            challenge_id: `c${index}`,
            access_token: `a${index}`,
            issued_at: clock.now,
            expires_at: clock.now + 60,
          }));
          clock.now += 1;
        }
        let alive = 0;
        for (let index = 0; index < count; index += 1) {
          if (await store.getBySessionId(`s${index}`)) alive += 1;
        }
        return alive;
      },
    },
  ])('$label: residue does not scale with volume', async ({ resident }) => {
    const small = await resident(500);
    const large = await resident(5_000);

    expect(large).toBe(small);
    expect(large).toBeLessThan(100);
  });
});

describe('the audience binding stayed strict while becoming total', () => {
  // Making exactUrlMatch total is only correct if it did not also become permissive:
  // this is what every NIP-98 proof is checked against, so a false positive is an
  // authentication bypass rather than a cosmetic bug.
  it.each([
    ['unparseable', 'not-a-url'],
    ['empty', ''],
    ['scheme only', 'http://'],
    ['trailing slash', 'https://api.example.com/auth/complete/'],
    ['different host', 'https://evil.example.com/auth/complete'],
    ['different scheme', 'http://api.example.com/auth/complete'],
    ['different port', 'https://api.example.com:8443/auth/complete'],
    ['userinfo', 'https://user@api.example.com/auth/complete'],
  ])('rejects %s without throwing', (_label, candidate) => {
    const audience = 'https://api.example.com/auth/complete';

    expect(() => exactUrlMatch(candidate, audience)).not.toThrow();
    expect(exactUrlMatch(candidate, audience)).toBe(false);
  });

  it('still matches the audience it is supposed to match', () => {
    expect(
      exactUrlMatch('HTTPS://API.example.com/auth/complete', 'https://api.example.com/auth/complete')
    ).toBe(true);
  });
});
