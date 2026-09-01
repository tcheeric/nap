import express from 'express';
import { getPublicKey, nip19 } from 'nostr-tools';
import request from 'supertest';
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

/** An ACL resolver that denies everyone, standing in for a mid-session suspension. */
const DENYING_RESOLVER: AclResolver = {
  async resolve() {
    return { allowed: false, roles: [], permissions: [], revoke_sessions: false };
  },
};

describe('guard audit logging (CONTEXT.md finding 12)', () => {
  beforeEach(() => {
    resetPermissionValidationState();
  });

  it('records NAP_GUARD_NO_SESSION with no principal when the caller has no token', async () => {
    const sessionStore = new InMemorySessionStore();
    const { logger, events } = recordingAuditLogger();
    const app = express();
    app.get(
      '/protected',
      requirePermission('voucher:issue', { sessionStore, auditLogger: logger }),
      (_req, res) => res.status(200).json({ status: 'ok' })
    );

    const response = await request(app).get('/protected');

    expect(response.status).toBe(401);
    expect(events).toHaveLength(1);
    expect(events[0]?.code).toBe(GUARD_DENIAL_CODES.NO_SESSION);
    expect(events[0]?.outcome).toBe('failure');
    // No session means no principal to name, and that absence is itself the
    // signal: principal-less denials are unauthenticated traffic.
    expect(events[0]?.pubkey).toBeUndefined();
    expect(events[0]?.npub).toBeUndefined();
    expect(events[0]?.details?.permission).toBe('voucher:issue');
  });

  it('records NAP_GUARD_PERMISSION_DENIED naming the principal and the permission', async () => {
    const sessionStore = new InMemorySessionStore();
    await seedSession(sessionStore);
    const { logger, events } = recordingAuditLogger();
    const app = express();
    app.get(
      '/protected',
      // Held permissions are ['voucher:issue'], so this one is genuinely absent.
      requirePermission('stripe:manage', { sessionStore, auditLogger: logger }),
      (_req, res) => res.status(200).json({ status: 'ok' })
    );

    const response = await request(app).get('/protected').set('cookie', 'session=token-1');

    expect(response.status).toBe(403);
    expect(events).toHaveLength(1);
    expect(events[0]?.code).toBe(GUARD_DENIAL_CODES.PERMISSION_DENIED);
    expect(events[0]?.pubkey).toBe(PUBKEY);
    expect(events[0]?.npub).toBe(NPUB);
    expect(events[0]?.details?.permission).toBe('stripe:manage');
  });

  it('distinguishes an ACL denial from an absent session', async () => {
    const sessionStore = new InMemorySessionStore();
    await seedSession(sessionStore);
    const { logger, events } = recordingAuditLogger();
    const app = express();
    app.get(
      '/protected',
      requirePermission('voucher:issue', {
        sessionStore,
        auditLogger: logger,
        aclResolver: DENYING_RESOLVER,
      }),
      (_req, res) => res.status(200).json({ status: 'ok' })
    );

    const response = await request(app).get('/protected').set('cookie', 'session=token-1');

    expect(response.status).toBe(401);
    // The session was valid, so unlike NO_SESSION the principal is nameable —
    // which is the point of auditing this branch apart. "Was this user
    // suspended mid-session?" is answerable from the log only because of this.
    expect(events).toHaveLength(1);
    expect(events[0]?.code).toBe(GUARD_DENIAL_CODES.ACL_DENIED);
    expect(events[0]?.pubkey).toBe(PUBKEY);
  });

  it('records NAP_GUARD_ROLE_DENIED with the roles that would have been accepted', async () => {
    const sessionStore = new InMemorySessionStore();
    await seedSession(sessionStore, { roles: ['customer'] });
    const { logger, events } = recordingAuditLogger();
    const app = express();
    app.get('/staff', requireRole(['admin', 'owner'], { sessionStore, auditLogger: logger }), (_req, res) =>
      res.status(200).json({ status: 'ok' })
    );

    const response = await request(app).get('/staff').set('cookie', 'session=token-1');

    expect(response.status).toBe(403);
    expect(events[0]?.code).toBe(GUARD_DENIAL_CODES.ROLE_DENIED);
    expect(events[0]?.details?.roles).toEqual(['admin', 'owner']);
  });

  it('records NAP_GUARD_STEP_UP_REQUIRED from requireStepUp', async () => {
    const sessionStore = new InMemorySessionStore();
    await seedSession(sessionStore);
    const { logger, events } = recordingAuditLogger();
    const app = express();
    app.get('/danger', requireStepUp({ sessionStore, auditLogger: logger }), (_req, res) =>
      res.status(200).json({ status: 'ok' })
    );

    const response = await request(app).get('/danger').set('cookie', 'session=token-1');

    expect(response.status).toBe(403);
    expect(response.body.message).toBe('step-up required');
    expect(events[0]?.code).toBe(GUARD_DENIAL_CODES.STEP_UP_REQUIRED);
    expect(events[0]?.pubkey).toBe(PUBKEY);
  });

  it('records step-up denial from the registry-enforced branch of requirePermission', async () => {
    const sessionStore = new InMemorySessionStore();
    await seedSession(sessionStore, { permissions: ['stripe:manage'] });
    const { logger, events } = recordingAuditLogger();
    const app = express();
    app.get(
      '/danger',
      requirePermission('stripe:manage', {
        sessionStore,
        auditLogger: logger,
        registry: REGISTRY,
      }),
      (_req, res) => res.status(200).json({ status: 'ok' })
    );

    const response = await request(app).get('/danger').set('cookie', 'session=token-1');

    expect(response.status).toBe(403);
    expect(events[0]?.code).toBe(GUARD_DENIAL_CODES.STEP_UP_REQUIRED);
    expect(events[0]?.details?.permission).toBe('stripe:manage');
  });

  it('records a denial from requireSession', async () => {
    const sessionStore = new InMemorySessionStore();
    const { logger, events } = recordingAuditLogger();
    const app = express();
    app.get('/me', requireSession({ sessionStore, auditLogger: logger }), (_req, res) =>
      res.status(200).json({ status: 'ok' })
    );

    expect((await request(app).get('/me')).status).toBe(401);
    expect(events[0]?.code).toBe(GUARD_DENIAL_CODES.NO_SESSION);
  });

  it('logs nothing when the guard allows the request', async () => {
    const sessionStore = new InMemorySessionStore();
    await seedSession(sessionStore);
    const { logger, events } = recordingAuditLogger();
    const app = express();
    app.get(
      '/protected',
      requirePermission('voucher:issue', { sessionStore, auditLogger: logger }),
      (_req, res) => res.status(200).json({ status: 'ok' })
    );

    const response = await request(app).get('/protected').set('cookie', 'session=token-1');

    expect(response.status).toBe(200);
    expect(events).toEqual([]);
  });

  it('denies identically whether or not a logger is wired', async () => {
    const build = async (auditLogger?: AuditLogger) => {
      const sessionStore = new InMemorySessionStore();
      await seedSession(sessionStore);
      const app = express();
      app.get(
        '/protected',
        requirePermission('stripe:manage', { sessionStore, auditLogger }),
        (_req, res) => res.status(200).json({ status: 'ok' })
      );
      return request(app).get('/protected').set('cookie', 'session=token-1');
    };

    const withLogger = await build(recordingAuditLogger().logger);
    const withoutLogger = await build();

    // The audit stream is the only thing that changes. Anything observable to
    // the client must not, or the logger becomes a distinguisher.
    expect(withLogger.status).toBe(withoutLogger.status);
    expect(withLogger.body).toEqual(withoutLogger.body);
  });

  it('still denies when the audit sink throws', async () => {
    const sessionStore = new InMemorySessionStore();
    await seedSession(sessionStore);
    const app = express();
    app.get(
      '/protected',
      requirePermission('stripe:manage', {
        sessionStore,
        auditLogger: {
          log() {
            throw new Error('audit sink down');
          },
        },
      }),
      (_req, res) => res.status(200).json({ status: 'ok' })
    );
    app.use((error: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
      res.status(500).json({ error: error.message });
    });

    const response = await request(app).get('/protected').set('cookie', 'session=token-1');

    // A 500 on exactly one branch tells an attacker which branch they hit, so a
    // broken sink costs a log line and nothing else.
    expect(response.status).toBe(403);
  });

  it('produces a record per refusal across the tutorial-06 sequence', async () => {
    // The exact sequence CONTEXT.md finding 12 ran to demonstrate the gap: it
    // yielded two records, both NAP_COMPLETE_SUCCESS, with every guard refusal
    // invisible. Each refusal must now appear.
    const sessionStore = new InMemorySessionStore();
    await seedSession(sessionStore, { permissions: ['voucher:issue', 'stripe:manage'] });
    const { logger, events } = recordingAuditLogger();
    const guard = { sessionStore, auditLogger: logger, registry: REGISTRY };
    const app = express();
    app.get('/issue', requirePermission('voucher:issue', guard), (_req, res) =>
      res.status(200).json({ status: 'ok' })
    );
    app.get('/manage', requirePermission('stripe:manage', guard), (_req, res) =>
      res.status(200).json({ status: 'ok' })
    );

    // 1. plain session succeeds on a non-step-up permission
    expect((await request(app).get('/issue').set('cookie', 'session=token-1')).status).toBe(200);
    // 2. same session refused on the step-up permission
    expect((await request(app).get('/manage').set('cookie', 'session=token-1')).status).toBe(403);
    // 3. no session at all
    expect((await request(app).get('/issue')).status).toBe(401);
    // 4. a token that does not exist
    expect((await request(app).get('/issue').set('cookie', 'session=nope')).status).toBe(401);

    expect(events.map((event) => event.code)).toEqual([
      GUARD_DENIAL_CODES.STEP_UP_REQUIRED,
      GUARD_DENIAL_CODES.NO_SESSION,
      GUARD_DENIAL_CODES.NO_SESSION,
    ]);
  });
});
