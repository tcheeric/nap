import express, { type Express } from 'express';
import {
  InMemoryAclStore,
  InMemoryChallengeStore,
  InMemorySessionStore,
  createInMemoryRateLimiter,
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
  requireRole,
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
  /**
   * Turn on Express's `trust proxy` when something else terminates TLS.
   *
   * It decides two things NAP depends on: `req.ip`, which is the dimension the
   * per-IP challenge cap counts on, and `req.protocol`, which a
   * request-derived audience resolver would read. Off, both describe the proxy
   * rather than the client. On with nothing in front of you, both are whatever
   * a header says — so this is a deployment fact, not a default.
   */
  trustProxy?: boolean | string | number;
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
    // On by default, and spelled out here anyway, because the defaults are the
    // thing you are supposed to size. 30 challenge requests a minute per
    // address is generous for a human and mean for a script.
    //
    // It counts in one process. Behind N instances the effective rate is N
    // times this, and a restart forgets everything. Anything production-facing
    // wants a shared backend behind the same `RateLimiter` interface — this one
    // is a floor, not a control.
    rateLimiter: createInMemoryRateLimiter({ windowSeconds: 60, maxPerWindow: 30 }),
    // The rate limiter caps how fast challenges arrive; these cap how many can
    // be alive at once. Different failure: a challenge row lives for its whole
    // TTL, so a slow drip under the rate limit still accumulates. Both defaults
    // (10 and 30), both enforced only because the stores here implement
    // `countOutstanding` — a store that cannot count silently does not cap.
    maxOutstandingChallengesPerNpub: 10,
    // Counted per address, and the address has to be real: without
    // `trustProxy` set behind a proxy, every request shares the proxy's IP and
    // this becomes a global cap on all users at once.
    maxOutstandingChallengesPerIp: 30,
    ...(clock ? { clock } : {}),
    ...options.server,
  };

  const app = express();

  if (options.trustProxy !== undefined) {
    app.set('trust proxy', options.trustProxy);
  }

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
      // The adapter's own default, written out because the number that matters
      // is the one you chose. An /auth/init body is two short strings and a
      // completion is one signed event; nothing legitimate approaches 1 kB.
      // `express.json()`'s default is 100 kB, which is what you would inherit
      // if you parsed these routes yourself.
      bodyLimit: '1kb',
      ...(options.mode === 'cookie'
        ? {
            writeSuccess: writeNapCookieSuccess(
              COOKIE_NAME,
              {
                httpOnly: true,
                sameSite: 'lax',
                secure: options.secureCookies ?? false,
                path: '/',
              },
              // Everything the bearer body would have carried, minus the two
              // fields that are now in the cookie. Not a render optimisation:
              // `nap-client-web`'s login() maps this body into its session
              // state and dereferences `principal.pubkey`, so against the
              // default `{status:'ok'}` a browser login throws a TypeError
              // before it ever has a session (CONTEXT.md finding 11).
              //
              // It is also the only way the refresh token reaches the client:
              // /auth/refresh reads `Authorization: Bearer`, which a cookie
              // cannot produce, so the token has to be readable by script.
              // That is the trade tutorial 05 makes explicit.
              ({ access_token, token_type, ...rest }) => rest
            ),
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

  // The one route guarded by role rather than permission. `support` holds no
  // permissions at all, so there is no permission check that expresses it —
  // which is the test for whether a role guard is the right tool. Everywhere
  // else, guard the permission: adding a role that should have access is then a
  // registry edit rather than an edit to every guard site.
  app.get('/api/support/lookup', requireRole('support', guardOptions), (_req, res) => {
    res.json({ vouchers: vouchers.list().length });
  });

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
