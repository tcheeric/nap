/**
 * End-to-end acceptance test for extension 0001.
 *
 * Every other test in `nap-voucher` exercises one module in isolation. This one
 * drives the path the extension is actually *for*: a real NAP login over HTTP,
 * through the real Express adapter, against a real `createNapServer`, where the
 * session's roles and permissions come from a voucher instead of an ACL row —
 * and then a real guarded request judged on those permissions.
 *
 * The mint is a real HTTP server performing real BDHKE and real DLEQ, so the
 * proofs verified here were genuinely signed rather than fixtures. That matters:
 * a stubbed mint would let a broken verifier pass.
 *
 * What this is not: it is not the shipped resolver. #23 owns that, and it is
 * blocked on decision #13 (the secret-modelling question — the Imani mint does
 * not enforce P2PK on a VOUCHER secret, so how the lock and the metadata coexist
 * is unsettled). The resolver here is the smallest thing that composes the
 * shipped modules in the §6 order, which is exactly what makes it evidence that
 * those modules fit together on the real path.
 */

import express from 'express';
import request from 'supertest';
import { getPublicKey, nip19 } from 'nostr-tools';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createServer, type Server } from 'node:http';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { hexToBytes } from '@imani/nap-core';
import { buildAuthCompleteRequest, createPrivateKeySigner } from '@imani/nap-client-http';
import {
  InMemoryChallengeStore,
  InMemorySessionStore,
  type AclDecision,
  type AclResolver,
  type AuditLogger,
  type NapServerOptions,
} from '@imani/nap-server';
import {
  createNapExpressRouter,
  createRequestDerivedBaseUrlResolver,
  requirePermission,
  resetPermissionValidationState,
} from '@imani/nap-adapter-express';
import {
  createIssuerAllowlist,
  createMintAllowlist,
  createMintAvailabilityPolicy,
  createMintClient,
  hashToCurve,
  proofY,
  verifyProofDleq,
  MintUnavailableError,
  type MintClient,
} from '../src/index.js';

const Point = secp256k1.Point;
const CURVE_ORDER = Point.Fn.ORDER;
const toHex = (bytes: Uint8Array) =>
  Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
const pad = (value: bigint) => value.toString(16).padStart(64, '0');
const hashE = (...points: Array<{ toHex(c: boolean): string }>) =>
  sha256(new TextEncoder().encode(points.map((point) => point.toHex(false)).join('')));

/** The burner key a voucher is P2PK-locked to. It also signs the NIP-98 event (§3.1). */
const BURNER_HEX = '2222222222222222222222222222222222222222222222222222222222222222';
const BURNER_PUBKEY = getPublicKey(hexToBytes(BURNER_HEX));
const BURNER_NPUB = nip19.npubEncode(BURNER_PUBKEY);

/** A key with no voucher, standing in for a stranger. */
const STRANGER_HEX = '3333333333333333333333333333333333333333333333333333333333333333';
const STRANGER_NPUB = nip19.npubEncode(getPublicKey(hexToBytes(STRANGER_HEX)));

const ISSUER_PRIVATE = 7n;
const ISSUER_PUBKEY = toHex(Point.BASE.multiply(ISSUER_PRIVATE).toBytes(true)).slice(2);
const MINT_KEY = 12_345n;
const MINT_A = Point.BASE.multiply(MINT_KEY);
const KEYSET_ID = '00882760bfa2eb41';

interface IssuedVoucher {
  mint_url: string;
  keyset_id: string;
  secret: string;
  amount: number;
  C: string;
  dleq: { e: string; s: string; r: string };
}

/**
 * Issue a genuine voucher: real BDHKE blind-sign-unblind, plus a real DLEQ.
 *
 * The secret carries the voucher metadata and the P2PK lock key as NUT-10 tags.
 * Which NUT-10 kind this should be is decision #13; the shape below is only
 * enough to exercise the pipeline.
 */
function issueVoucher(options: {
  mintUrl: string;
  lockedTo: string;
  expiresAt: number;
  roles?: string[];
  blinding?: bigint;
}): IssuedVoucher {
  const payload = {
    issuer_pubkey: ISSUER_PUBKEY,
    p2pk: options.lockedTo,
    expires_at: options.expiresAt,
    roles: options.roles ?? ['voucher-holder'],
  };
  // The issuer signs the metadata, so a mint-signed proof still cannot invent
  // its own authorization claims (§4.3).
  const canonical = JSON.stringify(payload);
  const issuerSig = toHex(
    secp256k1.sign(sha256(new TextEncoder().encode(canonical)), hexToBytes(pad(ISSUER_PRIVATE)))
  );
  const secret = JSON.stringify(['VOUCHER', { nonce: options.lockedTo.slice(0, 16), ...payload, issuer_sig: issuerSig }]);

  const blinding = options.blinding ?? 98_765n;
  const Y = hashToCurve(new TextEncoder().encode(secret));
  const B_ = Y.add(Point.BASE.multiply(blinding));
  const C_ = B_.multiply(MINT_KEY);
  const C = C_.add(MINT_A.multiply(blinding).negate());

  const nonce = 424_242n;
  const e = BigInt(`0x${toHex(hashE(Point.BASE.multiply(nonce), B_.multiply(nonce), MINT_A, C_))}`);
  const s = (nonce + e * MINT_KEY) % CURVE_ORDER;

  return {
    mint_url: options.mintUrl,
    keyset_id: KEYSET_ID,
    secret,
    amount: 1,
    C: C.toHex(true),
    dleq: { e: pad(e), s: pad(s), r: pad(blinding) },
  };
}

function parseSecret(secret: string): Record<string, unknown> | null {
  try {
    const parsed = JSON.parse(secret);
    return Array.isArray(parsed) && parsed[0] === 'VOUCHER' ? parsed[1] : null;
  } catch {
    return null;
  }
}

/**
 * The §6 step-13 procedure, in order, over the shipped modules.
 *
 * Ordering is the security property: (a) before any network call so an unvetted
 * URL is never reached, and (d) before (h) so a mismatched binding is rejected
 * locally before the mint is told anything.
 */
function createVoucherResolver(options: {
  mintClient: MintClient;
  mints: ReturnType<typeof createMintAllowlist>;
  issuers: ReturnType<typeof createIssuerAllowlist>;
  availability: ReturnType<typeof createMintAvailabilityPolicy>;
  auditLogger: AuditLogger;
  now: () => number;
  credentials: Map<string, IssuedVoucher>;
}): AclResolver {
  const deny = async (code: string, pubkey: string): Promise<AclDecision> => {
    await options.auditLogger.log({ code, outcome: 'failure', pubkey });
    return { allowed: false, roles: [], permissions: [], revoke_sessions: false };
  };

  return {
    async resolve(_npub: string, pubkey: string): Promise<AclDecision> {
      const credential = options.credentials.get(pubkey);

      if (!credential) {
        return deny('NAP_VOUCHER_ABSENT', pubkey);
      }

      // (a) allowlist first — never reach an unvetted URL.
      const mint = options.mints.resolve(credential.mint_url);

      if (!mint) {
        return deny('NAP_VOUCHER_MINT_NOT_ALLOWED', pubkey);
      }

      const claims = parseSecret(credential.secret);

      if (!claims) {
        return deny('NAP_VOUCHER_DLEQ_INVALID', pubkey);
      }

      // (d) binding before any mint round trip.
      if (claims.p2pk !== pubkey) {
        return deny('NAP_VOUCHER_BINDING_MISMATCH', pubkey);
      }

      // (f) issuer pair allowlisted.
      if (!options.issuers.allows(mint, String(claims.issuer_pubkey))) {
        return deny('NAP_VOUCHER_ISSUER_UNTRUSTED', pubkey);
      }

      // (g) expiry against the server clock.
      if (Number(claims.expires_at) <= options.now()) {
        return deny('NAP_VOUCHER_EXPIRED', pubkey);
      }

      try {
        // (b) DLEQ against the mint's published keyset.
        const A = await options.mintClient.getKey(mint, credential.keyset_id, credential.amount);

        if (!verifyProofDleq({ A, secret: credential.secret, C: credential.C, dleq: credential.dleq })) {
          return deny('NAP_VOUCHER_DLEQ_INVALID', pubkey);
        }

        // (h) liveness.
        if ((await options.mintClient.checkState(mint, credential.secret)) !== 'UNSPENT') {
          return deny('NAP_VOUCHER_SPENT', pubkey);
        }
      } catch (error) {
        if (!(error instanceof MintUnavailableError)) {
          throw error;
        }

        const decision = options.availability.decide(error.reason);

        if (decision.outcome === 'deny') {
          return deny('NAP_VOUCHER_MINT_UNAVAILABLE', pubkey);
        }

        await options.auditLogger.log({
          code: 'NAP_VOUCHER_DEGRADED',
          outcome: 'success',
          pubkey,
        });

        return { allowed: true, ...decision.grant, revoke_sessions: false };
      }

      // (i) grant.
      return {
        allowed: true,
        roles: claims.roles as string[],
        permissions: ['voucher:view'],
        revoke_sessions: false,
      };
    },
  };
}

describe('extension 0001 end to end: a voucher authorizes a real NAP login', () => {
  let mintServer: Server;
  let mintUrl: string;
  let spent: Set<string>;
  let mintDown: boolean;
  let keyCalls: number;
  let now: number;

  beforeAll(async () => {
    spent = new Set();
    mintDown = false;
    keyCalls = 0;

    // A real mint: publishes a keyset and answers NUT-07 from live state.
    mintServer = createServer((req, res) => {
      let body = '';
      req.on('data', (chunk) => (body += chunk));
      req.on('end', () => {
        if (mintDown) {
          res.statusCode = 503;
          res.end('{}');
          return;
        }

        res.setHeader('content-type', 'application/json');

        if (req.url === '/v1/keys') {
          keyCalls += 1;
          res.end(
            JSON.stringify({
              keysets: [{ id: KEYSET_ID, unit: 'sat', keys: { '1': MINT_A.toHex(true) } }],
            })
          );
          return;
        }

        if (req.url === '/v1/checkstate') {
          const { Ys } = JSON.parse(body) as { Ys: string[] };
          res.end(
            JSON.stringify({
              states: Ys.map((Y) => ({ Y, state: spent.has(Y) ? 'SPENT' : 'UNSPENT' })),
            })
          );
          return;
        }

        res.statusCode = 404;
        res.end('{}');
      });
    });

    await new Promise<void>((resolve) => mintServer.listen(0, resolve));
    mintUrl = `http://127.0.0.1:${(mintServer.address() as { port: number }).port}`;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => mintServer.close(() => resolve()));
  });

  /**
   * Build the whole stack. The mint is plaintext loopback, and the shipped
   * allowlist is https-only by design (§4.3), so the origin is pinned by a
   * purpose-built allowlist rather than by relaxing the shipped one. That
   * substitution is confined to scheme checking; every other property under
   * test is the shipped code.
   */
  function buildStack(options: { degrade?: boolean } = {}) {
    now = 1_710_000_000;
    const credentials = new Map<string, IssuedVoucher>();
    const events: Array<{ code: string; pubkey?: string }> = [];
    const auditLogger: AuditLogger = {
      log(event) {
        events.push({ code: event.code, pubkey: event.pubkey });
      },
    };

    const httpsMints = createMintAllowlist(['https://mint.example.com']);
    const mints = {
      origins: [mintUrl] as readonly string[],
      resolve: (url: string) => (url === mintUrl ? mintUrl : httpsMints.resolve(url)),
    };
    const issuers = createIssuerAllowlist(
      [{ mint: 'https://mint.example.com', issuerPubkey: ISSUER_PUBKEY }],
      httpsMints
    );

    const mintClient = createMintClient({ allowlist: mints, keysetCacheTtlSeconds: 3600 });
    const aclResolver = createVoucherResolver({
      mintClient,
      mints,
      // The pair is registered against the https origin, so allow the loopback
      // origin to satisfy the same pair for this harness.
      issuers: {
        entries: issuers.entries,
        allows: (mint: string, issuer: string) =>
          issuers.allows(mint === mintUrl ? 'https://mint.example.com' : mint, issuer),
      },
      availability: options.degrade
        ? createMintAvailabilityPolicy({
            onMintUnavailable: 'degrade',
            degradedGrant: { roles: ['degraded'], permissions: ['voucher:view'] },
            destructivePermissions: ['voucher:redeem'],
          })
        : createMintAvailabilityPolicy(),
      auditLogger,
      now: () => now,
      credentials,
    });

    const sessionStore = new InMemorySessionStore();
    const serverOptions: NapServerOptions = {
      challengeStore: new InMemoryChallengeStore(),
      sessionStore,
      aclResolver,
      auditLogger,
      minAuthResponseMillis: 0,
      clock: { nowUnix: () => now },
      randomSource: {
        randomBytes: (length: number) =>
          new Uint8Array(Array.from({ length }, (_, index) => (index + 7) % 255)),
      },
    };

    const app = express();
    app.set('trust proxy', true);
    app.use(
      '/auth',
      createNapExpressRouter({
        server: serverOptions,
        getExternalBaseUrl: createRequestDerivedBaseUrlResolver(['api.example.com']),
      })
    );
    app.get(
      '/vouchers',
      requirePermission('voucher:view', {
        sessionStore,
        aclResolver,
        auditLogger,
        clock: { nowUnix: () => now },
      }),
      (_req, res) => {
        res.status(200).json({ status: 'ok' });
      }
    );

    return { app, credentials, events, mintClient, sessionStore };
  }

  /** A complete, honest NIP-98 login. */
  async function login(app: express.Express, privateKeyHex: string, npub: string) {
    const init = await request(app)
      .post('/auth/init')
      .set('host', 'api.example.com')
      .set('x-forwarded-proto', 'https')
      .send({ npub });

    const completion = await buildAuthCompleteRequest({
      challenge: init.body,
      signer: createPrivateKeySigner(privateKeyHex),
      createdAt: now,
    });

    return request(app)
      .post('/auth/complete')
      .set('host', 'api.example.com')
      .set('x-forwarded-proto', 'https')
      .set('authorization', completion.authorization)
      .set('content-type', 'application/json')
      .send(new TextDecoder().decode(completion.rawBody));
  }

  beforeAll(() => {
    resetPermissionValidationState();
  });

  it('grants a session and access from a genuinely mint-signed voucher', async () => {
    const { app, credentials, events } = buildStack();
    credentials.set(
      BURNER_PUBKEY,
      issueVoucher({ mintUrl, lockedTo: BURNER_PUBKEY, expiresAt: now + 86_400 })
    );

    const complete = await login(app, BURNER_HEX, BURNER_NPUB);

    expect(complete.status).toBe(200);
    expect(complete.body.principal.pubkey).toBe(BURNER_PUBKEY);
    // §1.2 non-goal 4: the session body contract is unchanged.
    expect(complete.body.roles).toEqual(['voucher-holder']);

    // The permissions came from the voucher, and they actually open the door.
    const guarded = await request(app)
      .get('/vouchers')
      .set('authorization', `Bearer ${complete.body.access_token}`);

    expect(guarded.status).toBe(200);
    expect(events.map((event) => event.code)).toContain('NAP_COMPLETE_SUCCESS');
  });

  it('denies a stranger with no voucher, and the denial is auditable', async () => {
    const { app, events } = buildStack();

    const complete = await login(app, STRANGER_HEX, STRANGER_NPUB);

    expect(complete.status).toBe(401);
    expect(events.map((event) => event.code)).toContain('NAP_VOUCHER_ABSENT');
  });

  it('denies a voucher locked to someone else — §3.1, the whole design', async () => {
    const { app, credentials, events } = buildStack();
    // Stolen voucher: valid, mint-signed, live, but locked to another key. The
    // thief cannot sign the NIP-98 event with it.
    credentials.set(
      BURNER_PUBKEY,
      issueVoucher({ mintUrl, lockedTo: 'ff'.repeat(32), expiresAt: now + 86_400 })
    );

    const complete = await login(app, BURNER_HEX, BURNER_NPUB);

    expect(complete.status).toBe(401);
    expect(events.map((event) => event.code)).toContain('NAP_VOUCHER_BINDING_MISMATCH');
  });

  it('denies a spent voucher even though its DLEQ is perfectly valid', async () => {
    // The reason §4.2 makes the mint mandatory: DLEQ cannot see this.
    const { app, credentials, events } = buildStack();
    const voucher = issueVoucher({ mintUrl, lockedTo: BURNER_PUBKEY, expiresAt: now + 86_400 });
    credentials.set(BURNER_PUBKEY, voucher);
    spent.add(proofY(voucher.secret));

    const complete = await login(app, BURNER_HEX, BURNER_NPUB);

    expect(complete.status).toBe(401);
    expect(events.map((event) => event.code)).toContain('NAP_VOUCHER_SPENT');
    spent.clear();
  });

  it('denies an expired voucher', async () => {
    const { app, credentials, events } = buildStack();
    credentials.set(
      BURNER_PUBKEY,
      issueVoucher({ mintUrl, lockedTo: BURNER_PUBKEY, expiresAt: now - 1 })
    );

    const complete = await login(app, BURNER_HEX, BURNER_NPUB);

    expect(complete.status).toBe(401);
    expect(events.map((event) => event.code)).toContain('NAP_VOUCHER_EXPIRED');
  });

  it('denies a forged proof the mint never signed', async () => {
    const { app, credentials, events } = buildStack();
    const voucher = issueVoucher({ mintUrl, lockedTo: BURNER_PUBKEY, expiresAt: now + 86_400 });
    // A forger who wants a voucher the mint never signed. Note that C = a*Y is
    // independent of the blinding factor, so reusing another proof's C for the
    // *same* secret is not a forgery at all — it is the same signature. The
    // real attack is inventing C, which is what DLEQ exists to catch.
    const forgedC = Point.BASE.multiply(999_983n).toHex(true);
    credentials.set(BURNER_PUBKEY, { ...voucher, C: forgedC });

    const complete = await login(app, BURNER_HEX, BURNER_NPUB);

    expect(complete.status).toBe(401);
    expect(events.map((event) => event.code)).toContain('NAP_VOUCHER_DLEQ_INVALID');
  });

  it('denies a proof whose authorization claims were edited after signing', async () => {
    // The metadata-tampering attack: keep the mint's signature, rewrite the
    // roles. Changing the secret changes Y, so B' no longer reconstructs and
    // the DLEQ fails.
    const { app, credentials, events } = buildStack();
    const voucher = issueVoucher({ mintUrl, lockedTo: BURNER_PUBKEY, expiresAt: now + 86_400 });
    const claims = parseSecret(voucher.secret)!;
    const escalated = JSON.stringify(['VOUCHER', { ...claims, roles: ['admin'] }]);
    credentials.set(BURNER_PUBKEY, { ...voucher, secret: escalated });

    const complete = await login(app, BURNER_HEX, BURNER_NPUB);

    expect(complete.status).toBe(401);
    expect(events.map((event) => event.code)).toContain('NAP_VOUCHER_DLEQ_INVALID');
  });

  it('denies a voucher from a mint that is not allowlisted, with no outbound request', async () => {
    const { app, credentials, events } = buildStack();
    credentials.set(BURNER_PUBKEY, {
      ...issueVoucher({ mintUrl, lockedTo: BURNER_PUBKEY, expiresAt: now + 86_400 }),
      mint_url: 'https://evil.example.com',
    });
    const before = keyCalls;

    const complete = await login(app, BURNER_HEX, BURNER_NPUB);

    expect(complete.status).toBe(401);
    expect(events.map((event) => event.code)).toContain('NAP_VOUCHER_MINT_NOT_ALLOWED');
    // §6 ordering: step (a) precedes every network call.
    expect(keyCalls).toBe(before);
  });

  it('denies every login when the mint is down and the policy is the default', async () => {
    const { app, credentials, events } = buildStack();
    credentials.set(
      BURNER_PUBKEY,
      issueVoucher({ mintUrl, lockedTo: BURNER_PUBKEY, expiresAt: now + 86_400 })
    );
    mintDown = true;

    try {
      const complete = await login(app, BURNER_HEX, BURNER_NPUB);

      expect(complete.status).toBe(401);
      expect(events.map((event) => event.code)).toContain('NAP_VOUCHER_MINT_UNAVAILABLE');
    } finally {
      mintDown = false;
    }
  });

  it('issues a reduced session when the mint is down and degrade is configured', async () => {
    const { app, credentials, events } = buildStack({ degrade: true });
    credentials.set(
      BURNER_PUBKEY,
      issueVoucher({ mintUrl, lockedTo: BURNER_PUBKEY, expiresAt: now + 86_400 })
    );
    mintDown = true;

    try {
      const complete = await login(app, BURNER_HEX, BURNER_NPUB);

      expect(complete.status).toBe(200);
      expect(complete.body.roles).toEqual(['degraded']);
      // The point of §7.3: a degraded session carries nothing destructive.
      expect(complete.body.permissions).not.toContain('voucher:redeem');
      expect(events.map((event) => event.code)).toContain('NAP_VOUCHER_DEGRADED');
    } finally {
      mintDown = false;
    }
  });

  it('leaves the proof UNSPENT after login, and a repeated login still works', async () => {
    // §6.1: login MUST NOT spend. Asserted behaviourally against the mint's own
    // state rather than structurally.
    const { app, credentials, mintClient } = buildStack();
    const voucher = issueVoucher({ mintUrl, lockedTo: BURNER_PUBKEY, expiresAt: now + 86_400 });
    credentials.set(BURNER_PUBKEY, voucher);

    expect((await login(app, BURNER_HEX, BURNER_NPUB)).status).toBe(200);
    expect(await mintClient.checkState(mintUrl, voucher.secret)).toBe('UNSPENT');

    // A second login on the same voucher succeeds, which it could not do if the
    // first had burned it.
    expect((await login(app, BURNER_HEX, BURNER_NPUB)).status).toBe(200);
    expect(await mintClient.checkState(mintUrl, voucher.secret)).toBe('UNSPENT');
  });

  it('revokes access at the guard when the voucher is spent mid-session (§7.1)', async () => {
    const { app, credentials } = buildStack();
    const voucher = issueVoucher({ mintUrl, lockedTo: BURNER_PUBKEY, expiresAt: now + 86_400 });
    credentials.set(BURNER_PUBKEY, voucher);

    const complete = await login(app, BURNER_HEX, BURNER_NPUB);
    const token = complete.body.access_token;

    expect((await request(app).get('/vouchers').set('authorization', `Bearer ${token}`)).status).toBe(
      200
    );

    // The voucher dies underneath the live session.
    spent.add(proofY(voucher.secret));

    try {
      const after = await request(app).get('/vouchers').set('authorization', `Bearer ${token}`);

      // Per-request re-resolution (RFC §15 rule 1) closes the window that §7.1
      // is about.
      expect(after.status).toBe(401);
    } finally {
      spent.clear();
    }
  });

  it('caches the keyset across logins rather than refetching per request', async () => {
    const { app, credentials } = buildStack();
    credentials.set(
      BURNER_PUBKEY,
      issueVoucher({ mintUrl, lockedTo: BURNER_PUBKEY, expiresAt: now + 86_400 })
    );
    const before = keyCalls;

    await login(app, BURNER_HEX, BURNER_NPUB);
    await login(app, BURNER_HEX, BURNER_NPUB);

    expect(keyCalls).toBe(before + 1);
  });
});
