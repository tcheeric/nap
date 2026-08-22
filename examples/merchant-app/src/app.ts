import express, { type Express } from 'express';
import {
  InMemoryAclStore,
  InMemoryChallengeStore,
  InMemorySessionStore,
  createRegistryAclResolver,
  type AclStore,
  type AuditLogger,
  type ChallengeStore,
  type Clock,
  type NapServerOptions,
  type SessionStore,
} from '@imani/nap-server';
import {
  createNapExpressRouter,
  createPermissionsRouter,
  requirePermission,
  requireSession,
  validatePermissions,
  writeNapCookieSuccess,
} from '@imani/nap-adapter-express';

import { REGISTRY } from './registry.js';
import { attachPrincipal, principalOf } from './principal.js';
import { createVoucherStore, type VoucherStore } from './vouchers.js';

export interface MerchantAppOptions {
  /**
   * The audience every NIP-98 proof is checked against. A pinned constant,
   * because a single-host deployment has no reason to let a request header pick
   * it. Tutorial 09 covers the multi-domain case.
   */
  baseUrl: string;
  /**
   * `bearer` returns the access token in the `/auth/complete` body, which is
   * what tutorial 01 curls. `cookie` writes an HttpOnly cookie and returns
   * `{ status: 'ok' }`, which is what a browser wants and what `nap-client-web`
   * assumes from tutorial 02 onward.
   */
  mode?: 'bearer' | 'cookie';
  /** Set on HTTPS. Left off so the tutorials work on plain-HTTP localhost. */
  secureCookies?: boolean;
  /** Injectable so the integration test can use a fixed clock and known stores. */
  challengeStore?: ChallengeStore;
  sessionStore?: SessionStore;
  aclStore?: AclStore;
  clock?: Clock;
  auditLogger?: AuditLogger;
  vouchers?: VoucherStore;
  server?: Partial<NapServerOptions>;
}

export interface MerchantApp {
  app: Express;
  sessionStore: SessionStore;
  aclStore: AclStore;
  vouchers: VoucherStore;
}

const COOKIE_NAME = 'session';

export function createMerchantApp(options: MerchantAppOptions): MerchantApp {
  const sessionStore = options.sessionStore ?? new InMemorySessionStore();
  const aclStore = options.aclStore ?? new InMemoryAclStore();
  const vouchers = options.vouchers ?? createVoucherStore();
  const clock = options.clock;

  const napServerOptions: NapServerOptions = {
    challengeStore: options.challengeStore ?? new InMemoryChallengeStore(),
    sessionStore,
    aclResolver: createRegistryAclResolver(REGISTRY, aclStore),
    auditLogger: options.auditLogger ?? consoleAuditLogger,
    ...(clock ? { clock } : {}),
    ...options.server,
  };

  const app = express();

  // Note the absence of a global `express.json()`. The NAP router installs its
  // own parser that keeps the raw bytes, because the NIP-98 payload tag is a
  // hash over them. A global parser mounted before this line re-stringifies the
  // body and fails every completion with NAP_COMPLETE_PAYLOAD_MISMATCH.
  app.use(
    '/auth',
    createNapExpressRouter({
      server: napServerOptions,
      getExternalBaseUrl: () => options.baseUrl,
      cookieName: COOKIE_NAME,
      ...(options.mode === 'cookie'
        ? {
            writeSuccess: writeNapCookieSuccess(COOKIE_NAME, {
              httpOnly: true,
              sameSite: 'lax',
              secure: options.secureCookies ?? false,
              path: '/',
            }),
          }
        : {}),
    })
  );

  // Publishes the registry so a frontend can render the vocabulary rather than
  // hard-coding permission strings it might get wrong.
  // Mounts GET /permissions itself, so it goes on at the root.
  app.use(createPermissionsRouter(REGISTRY));

  const guardOptions = {
    sessionStore,
    cookieName: COOKIE_NAME,
    // Re-read the ACL per request rather than trusting the login-time snapshot,
    // so a revocation lands immediately instead of at the next session expiry.
    aclResolver: napServerOptions.aclResolver,
    registry: REGISTRY,
    // Used when a re-read ACL revokes sessions. Note that the guard's own
    // expiry check reads the system clock regardless, so a test clock has to be
    // anchored near real time rather than pinned to an arbitrary constant.
    ...(clock ? { clock } : {}),
  };

  const principal = attachPrincipal({ sessionStore, cookieName: COOKIE_NAME });

  app.get('/api/me', requireSession(guardOptions), principal, (req, res) => {
    const session = principalOf(req);
    res.json({ npub: session.principal_npub, pubkey: session.principal_pubkey });
  });

  app.get(
    '/api/vouchers',
    requirePermission('merchant:read', guardOptions),
    (_req, res) => {
      res.json({ vouchers: vouchers.list() });
    }
  );

  app.post(
    '/api/vouchers',
    requirePermission('voucher:create', guardOptions),
    principal,
    express.json({ limit: '1kb' }),
    (req, res) => {
      const amountCents = Number((req.body as { amount_cents?: unknown })?.amount_cents);

      if (!Number.isInteger(amountCents) || amountCents <= 0) {
        res.status(400).json({ error: 'amount_cents must be a positive integer' });
        return;
      }

      const voucher = vouchers.create({
        amountCents,
        issuedBy: principalOf(req).principal_npub,
        now: napServerOptions.clock?.nowUnix() ?? Math.floor(Date.now() / 1000),
      });

      res.status(201).json({ voucher });
    }
  );

  // stripe:manage is marked `stepUp: true` in the registry, so passing the
  // registry to the guard makes this route demand an X-Step-Up-Token as well as
  // a session. Tutorial 06.
  app.post(
    '/api/payouts',
    requirePermission('stripe:manage', guardOptions),
    express.json({ limit: '1kb' }),
    (_req, res) => {
      res.json({ status: 'payout settings updated' });
    }
  );

  // Every permission string used in a guard above must be declared in the
  // registry. Called after the routes are mounted, so it can see all of them,
  // and it throws — a typo is a boot failure, not a 403 nobody can explain.
  validatePermissions(REGISTRY);

  return { app, sessionStore, aclStore, vouchers };
}

const consoleAuditLogger: AuditLogger = {
  log(event) {
    // Every auth failure is an identical 401 on the wire, on purpose. This is
    // the only place the reason exists. Wire it on day one; you cannot debug
    // NAP without it.
    console.log(JSON.stringify({ at: new Date().toISOString(), ...event }));
  },
};
