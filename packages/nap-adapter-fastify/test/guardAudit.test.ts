import Fastify from 'fastify';
import { getPublicKey, nip19 } from 'nostr-tools';
import { beforeEach, describe, expect, it } from 'vitest';
import { hexToBytes } from '@imani/nap-core';
import {
  GUARD_DENIAL_CODES,
  InMemorySessionStore,
  type AclResolver,
  type AuditLogger,
  type PermissionRegistry,
} from '@imani/nap-server';
import {
  requirePermission,
  requireRole,
  requireSession,
  requireStepUp,
  resetPermissionValidationState,
} from '../src/index.js';

const PRIVATE_KEY_HEX = '1111111111111111111111111111111111111111111111111111111111111111';
const PRIVATE_KEY_BYTES = hexToBytes(PRIVATE_KEY_HEX);
const PUBKEY = getPublicKey(PRIVATE_KEY_BYTES);
const NPUB = nip19.npubEncode(PUBKEY);
const HEADERS = { cookie: 'session=token-1' };

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

type Recorded = Parameters<AuditLogger['log']>[0];

function recordingAuditLogger(): { logger: AuditLogger; events: Recorded[] } {
  const events: Recorded[] = [];

  return {
    events,
    logger: {
      log(event) {
        events.push(event);
      },
    },
  };
}

async function seedSession(
  sessionStore: InMemorySessionStore,
  overrides: Record<string, unknown> = {}
) {
  const now = Math.floor(Date.now() / 1000);

  return sessionStore.createForChallenge({
    session_id: 'session-1',
    challenge_id: 'challenge-1',
    access_token: 'token-1',
    principal_npub: NPUB,
    principal_pubkey: PUBKEY,
    roles: ['merchant'],
    permissions: ['voucher:issue'],
    issued_at: now,
    expires_at: now + 900,
    ...overrides,
  } as Parameters<InMemorySessionStore['createForChallenge']>[0]);
}

const DENYING_RESOLVER: AclResolver = {
  async resolve() {
    return { allowed: false, roles: [], permissions: [], revoke_sessions: false };
  },
};

describe('fastify guard audit logging (CONTEXT.md finding 12)', () => {
  beforeEach(() => {
    resetPermissionValidationState();
  });

  it('records NAP_GUARD_NO_SESSION with no principal', async () => {
    const sessionStore = new InMemorySessionStore();
    const { logger, events } = recordingAuditLogger();
    const app = Fastify();
    app.get('/protected', {
      preHandler: requirePermission('voucher:issue', { sessionStore, auditLogger: logger }),
      handler: async () => ({ status: 'ok' }),
    });

    const response = await app.inject({ method: 'GET', url: '/protected' });

    expect(response.statusCode).toBe(401);
    expect(events).toHaveLength(1);
    expect(events[0]?.code).toBe(GUARD_DENIAL_CODES.NO_SESSION);
    expect(events[0]?.pubkey).toBeUndefined();
  });

  it('records NAP_GUARD_PERMISSION_DENIED naming the principal', async () => {
    const sessionStore = new InMemorySessionStore();
    await seedSession(sessionStore);
    const { logger, events } = recordingAuditLogger();
    const app = Fastify();
    app.get('/protected', {
      preHandler: requirePermission('stripe:manage', { sessionStore, auditLogger: logger }),
      handler: async () => ({ status: 'ok' }),
    });

    const response = await app.inject({ method: 'GET', url: '/protected', headers: HEADERS });

    expect(response.statusCode).toBe(403);
    expect(events[0]?.code).toBe(GUARD_DENIAL_CODES.PERMISSION_DENIED);
    expect(events[0]?.pubkey).toBe(PUBKEY);
    expect(events[0]?.details?.permission).toBe('stripe:manage');
  });

  it('distinguishes an ACL denial from an absent session', async () => {
    const sessionStore = new InMemorySessionStore();
    await seedSession(sessionStore);
    const { logger, events } = recordingAuditLogger();
    const app = Fastify();
    app.get('/protected', {
      preHandler: requirePermission('voucher:issue', {
        sessionStore,
        auditLogger: logger,
        aclResolver: DENYING_RESOLVER,
      }),
      handler: async () => ({ status: 'ok' }),
    });

    const response = await app.inject({ method: 'GET', url: '/protected', headers: HEADERS });

    expect(response.statusCode).toBe(401);
    expect(events[0]?.code).toBe(GUARD_DENIAL_CODES.ACL_DENIED);
    expect(events[0]?.pubkey).toBe(PUBKEY);
  });

  it('records NAP_GUARD_ROLE_DENIED with the accepted roles', async () => {
    const sessionStore = new InMemorySessionStore();
    await seedSession(sessionStore, { roles: ['customer'] });
    const { logger, events } = recordingAuditLogger();
    const app = Fastify();
    app.get('/staff', {
      preHandler: requireRole(['admin', 'owner'], { sessionStore, auditLogger: logger }),
      handler: async () => ({ status: 'ok' }),
    });

    const response = await app.inject({ method: 'GET', url: '/staff', headers: HEADERS });

    expect(response.statusCode).toBe(403);
    expect(events[0]?.code).toBe(GUARD_DENIAL_CODES.ROLE_DENIED);
    expect(events[0]?.details?.roles).toEqual(['admin', 'owner']);
  });

  it('records step-up denials from both requireStepUp and requirePermission', async () => {
    const sessionStore = new InMemorySessionStore();
    await seedSession(sessionStore, { permissions: ['stripe:manage'] });
    const { logger, events } = recordingAuditLogger();
    const app = Fastify();
    app.get('/danger', {
      preHandler: requireStepUp({ sessionStore, auditLogger: logger }),
      handler: async () => ({ status: 'ok' }),
    });
    app.get('/managed', {
      preHandler: requirePermission('stripe:manage', {
        sessionStore,
        auditLogger: logger,
        registry: REGISTRY,
      }),
      handler: async () => ({ status: 'ok' }),
    });

    expect(
      (await app.inject({ method: 'GET', url: '/danger', headers: HEADERS })).statusCode
    ).toBe(403);
    expect(
      (await app.inject({ method: 'GET', url: '/managed', headers: HEADERS })).statusCode
    ).toBe(403);

    expect(events.map((event) => event.code)).toEqual([
      GUARD_DENIAL_CODES.STEP_UP_REQUIRED,
      GUARD_DENIAL_CODES.STEP_UP_REQUIRED,
    ]);
  });

  it('records a denial from requireSession and nothing on success', async () => {
    const sessionStore = new InMemorySessionStore();
    await seedSession(sessionStore);
    const { logger, events } = recordingAuditLogger();
    const app = Fastify();
    app.get('/me', {
      preHandler: requireSession({ sessionStore, auditLogger: logger }),
      handler: async () => ({ status: 'ok' }),
    });

    expect((await app.inject({ method: 'GET', url: '/me', headers: HEADERS })).statusCode).toBe(200);
    expect(events).toEqual([]);

    expect((await app.inject({ method: 'GET', url: '/me' })).statusCode).toBe(401);
    expect(events.map((event) => event.code)).toEqual([GUARD_DENIAL_CODES.NO_SESSION]);
  });

  it('still denies when the audit sink throws', async () => {
    const sessionStore = new InMemorySessionStore();
    await seedSession(sessionStore);
    const app = Fastify();
    app.get('/protected', {
      preHandler: requirePermission('stripe:manage', {
        sessionStore,
        auditLogger: {
          log() {
            throw new Error('audit sink down');
          },
        },
      }),
      handler: async () => ({ status: 'ok' }),
    });

    const response = await app.inject({ method: 'GET', url: '/protected', headers: HEADERS });

    // A 500 on exactly one branch is a side channel; a broken sink costs a log
    // line and nothing else.
    expect(response.statusCode).toBe(403);
  });
});
