import express from 'express';
import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { getPublicKey, nip19 } from 'nostr-tools';
import { hexToBytes } from '@imani/nap-core';
import { buildAuthCompleteRequest, createPrivateKeySigner } from '@imani/nap-client-http';
import {
  InMemoryChallengeStore,
  InMemorySessionStore,
  type NapServerOptions,
} from '@imani/nap-server';
import {
  createNapExpressRouter,
  createRequestDerivedBaseUrlResolver,
  requirePermission,
} from '@imani/nap-adapter-express';
import { schnorr, secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes as hb } from '@noble/hashes/utils.js';
import { createIssuerAllowlist, createMintAllowlist } from '../src/allowlist.js';
import { createMintAvailabilityPolicy } from '../src/availability.js';
import { hashE, hashToCurve } from '../src/dleq.js';
import type { MintClient } from '../src/mintClient.js';
import { createVoucherAclResolver } from '../src/resolver.js';
import { parseVoucherSecret, voucherCanonicalBytes, VOUCHER_TAGS } from '../src/secret.js';

/**
 * The outcome the extension exists to deliver, end to end and unmocked.
 *
 * Everything else in this package tests a step. This tests the thing a user
 * actually gets: present a voucher, receive a session whose permissions came
 * from the voucher's tags rather than from any stored ACL row, and have a real
 * guarded route honour them.
 *
 * ## Why the DLEQ is real here
 *
 * `resolver.test.ts` mocks `verifyProofDleq`, which is right for isolating the
 * other steps — a test for the issuer allowlist should not fail because a
 * hand-built DLEQ was malformed. But it means nothing in that file ever proves
 * the real verifier accepts a real proof. This file plays the mint: it produces
 * a genuine blind signature and a genuine NUT-12 proof, and the resolver
 * verifies them with the actual implementation.
 *
 * That distinction is not hypothetical. The first run of this scenario failed
 * with `NAP_VOUCHER_DLEQ_INVALID` on a placeholder proof, which is exactly the
 * failure the mocked tests could not have surfaced.
 */

const PK = '1111111111111111111111111111111111111111111111111111111111111111';
const HOLDER = getPublicKey(hexToBytes(PK));
const NPUB = nip19.npubEncode(HOLDER);
const NOW = 1_710_000_000;
const MINT = 'https://mint.example.com';
const ISSUER_PRIVATE = hb('11'.repeat(32));
const ISSUER_PUBKEY = bytesToHex(schnorr.getPublicKey(ISSUER_PRIVATE));
const Point = secp256k1.Point;
const ORDER = secp256k1.Point.Fn.ORDER;

/** An issuer-signed voucher locked to `lockedTo`, carrying real metadata. */
function issueVoucher(lockedTo: string): string {
  const body = {
    nonce: 'n',
    data: `02${lockedTo}`,
    tags: [
      [VOUCHER_TAGS.ISSUER, 'imani'],
      [VOUCHER_TAGS.UNIT, 'sat'],
      [VOUCHER_TAGS.FACE_VALUE, '1000'],
    ],
  };
  const unsigned = parseVoucherSecret(JSON.stringify(['P2PK_VOUCHER', body]))!;
  const sig = bytesToHex(schnorr.sign(sha256(voucherCanonicalBytes(unsigned)), ISSUER_PRIVATE));

  return JSON.stringify([
    'P2PK_VOUCHER',
    {
      ...body,
      tags: [...body.tags, [VOUCHER_TAGS.ISSUER_PUBKEY, ISSUER_PUBKEY], [VOUCHER_TAGS.ISSUER_SIG, sig]],
    },
  ]);
}

/**
 * Plays the mint: a real BDHKE signature over the secret, and a real NUT-12
 * DLEQ proving the mint produced it.
 */
function mintProof(secret: string) {
  const a = BigInt(`0x${'44'.repeat(32)}`) % ORDER;
  const A = Point.BASE.multiply(a);
  const r = BigInt(`0x${'55'.repeat(32)}`) % ORDER;
  const Y = hashToCurve(new TextEncoder().encode(secret));
  const B_ = Y.add(Point.BASE.multiply(r));
  const C_ = B_.multiply(a);
  const C = C_.add(A.multiply(r).negate());

  const k = BigInt(`0x${'66'.repeat(32)}`) % ORDER;
  const e = BigInt(`0x${bytesToHex(hashE(Point.BASE.multiply(k), B_.multiply(k), A, C_))}`) % ORDER;
  const s = (k + e * a) % ORDER;
  const hex = (value: bigint) => value.toString(16).padStart(64, '0');

  return { A: A.toHex(true), C: C.toHex(true), dleq: { e: hex(e), s: hex(s), r: hex(r) } };
}

describe('a voucher-bound login, end to end', () => {
  it('turns a voucher into a session whose permissions guard a real route', async () => {
    const secret = issueVoucher(HOLDER);
    const minted = mintProof(secret);
    const audit: Array<{ code: string }> = [];
    const sessionStore = new InMemorySessionStore();

    const options: NapServerOptions = {
      challengeStore: new InMemoryChallengeStore(),
      sessionStore,
      auditLogger: { log: (event) => void audit.push({ code: event.code }) },
      aclResolver: createVoucherAclResolver({
        mintAllowlist: createMintAllowlist([MINT]),
        issuerAllowlist: createIssuerAllowlist(
          [{ mint: MINT, issuerPubkey: ISSUER_PUBKEY }],
          createMintAllowlist([MINT])
        ),
        mintClient: {
          getKey: async () => minted.A,
          checkState: async () => 'UNSPENT' as const,
          clearCache: () => {},
        } as MintClient,
        availability: createMintAvailabilityPolicy(),
        auditLogger: { log: (event) => void audit.push({ code: event.code }) },
        // The grant reads the voucher's own tags, so the permission below can
        // only exist if the metadata survived parsing, signing, and
        // verification intact.
        grant: (voucher) => ({
          roles: ['voucher-holder'],
          permissions: [`voucher:view:${voucher.unit}:${voucher.faceValue}`],
        }),
      }),
      minAuthResponseMillis: 0,
      clock: { nowUnix: () => NOW },
    };

    const app = express();
    app.set('trust proxy', true);
    app.use(
      '/auth',
      createNapExpressRouter({
        server: options,
        getExternalBaseUrl: createRequestDerivedBaseUrlResolver(['api.example.com']),
      })
    );
    const guard = { sessionStore, clock: { nowUnix: () => NOW } };
    app.get('/data', requirePermission('voucher:view:sat:1000', guard), (_req, res) =>
      res.json({ ok: true })
    );
    app.get('/redeem', requirePermission('voucher:redeem', guard), (_req, res) =>
      res.json({ ok: true })
    );

    const post = (path: string) =>
      request(app).post(path).set('host', 'api.example.com').set('x-forwarded-proto', 'https');

    const init = await post('/auth/init').send({ npub: NPUB });
    const built = await buildAuthCompleteRequest({
      challenge: init.body,
      signer: createPrivateKeySigner(PK),
      createdAt: NOW,
      voucher: {
        mint_url: MINT,
        keyset_id: '00882760bfa2eb41',
        secret,
        signature: minted.C,
        amount: 8,
        dleq: minted.dleq,
      },
    });

    const login = await post('/auth/complete')
      .set('authorization', built.authorization)
      .set('content-type', 'application/json')
      .send(new TextDecoder().decode(built.rawBody));

    expect(login.status).toBe(200);
    // No ACL store is wired at all, so these can only have come from the
    // voucher. That is the extension's whole claim.
    expect(login.body.roles).toEqual(['voucher-holder']);
    expect(login.body.permissions).toEqual(['voucher:view:sat:1000']);
    expect(audit.map((entry) => entry.code)).toContain('NAP_VOUCHER_ACCEPTED');

    const authed = (path: string) =>
      request(app)
        .get(path)
        .set('host', 'api.example.com')
        .set('x-forwarded-proto', 'https')
        .set('authorization', `Bearer ${login.body.access_token}`);

    expect((await authed('/data')).status).toBe(200);
    // Authenticated and allowed, but the voucher does not carry this one: 403,
    // not 401. The session is real; the permission is absent.
    expect((await authed('/redeem')).status).toBe(403);
  });

  it('refuses a proof the mint did not sign, with the real verifier', async () => {
    // resolver.test.ts mocks verifyProofDleq, so nothing there proves the real
    // verifier rejects a real forgery *through the resolver*. Here the DLEQ is
    // genuine except for one tampered scalar, and no mock stands in for it.
    const secret = issueVoucher(HOLDER);
    const minted = mintProof(secret);
    const forged = { ...minted.dleq, s: minted.dleq.s.replace(/^./, (c) => (c === 'a' ? 'b' : 'a')) };

    const options: NapServerOptions = {
      challengeStore: new InMemoryChallengeStore(),
      sessionStore: new InMemorySessionStore(),
      aclResolver: createVoucherAclResolver({
        mintAllowlist: createMintAllowlist([MINT]),
        issuerAllowlist: createIssuerAllowlist(
          [{ mint: MINT, issuerPubkey: ISSUER_PUBKEY }],
          createMintAllowlist([MINT])
        ),
        mintClient: {
          getKey: async () => minted.A,
          checkState: async () => 'UNSPENT' as const,
          clearCache: () => {},
        } as MintClient,
        availability: createMintAvailabilityPolicy(),
        grant: () => ({ roles: ['voucher-holder'], permissions: ['voucher:view:sat:1000'] }),
      }),
      minAuthResponseMillis: 0,
      clock: { nowUnix: () => NOW },
    };

    const app = express();
    app.set('trust proxy', true);
    app.use(
      '/auth',
      createNapExpressRouter({
        server: options,
        getExternalBaseUrl: createRequestDerivedBaseUrlResolver(['api.example.com']),
      })
    );

    const post = (path: string) =>
      request(app).post(path).set('host', 'api.example.com').set('x-forwarded-proto', 'https');

    const init = await post('/auth/init').send({ npub: NPUB });
    const built = await buildAuthCompleteRequest({
      challenge: init.body,
      signer: createPrivateKeySigner(PK),
      createdAt: NOW,
      voucher: {
        mint_url: MINT,
        keyset_id: '00882760bfa2eb41',
        secret,
        signature: minted.C,
        amount: 8,
        dleq: forged,
      },
    });

    const login = await post('/auth/complete')
      .set('authorization', built.authorization)
      .set('content-type', 'application/json')
      .send(new TextDecoder().decode(built.rawBody));

    expect(login.status).toBe(401);
  });

  it('refuses the same voucher presented by a different key', async () => {
    // The stolen-credential case against the full stack rather than the
    // resolver alone: a genuine, unspent, correctly signed voucher, presented
    // by someone who holds it but is not the key it is locked to.
    const otherKey = '2'.repeat(64);
    const secret = issueVoucher(getPublicKey(hexToBytes(otherKey)));
    const minted = mintProof(secret);

    const options: NapServerOptions = {
      challengeStore: new InMemoryChallengeStore(),
      sessionStore: new InMemorySessionStore(),
      aclResolver: createVoucherAclResolver({
        mintAllowlist: createMintAllowlist([MINT]),
        issuerAllowlist: createIssuerAllowlist(
          [{ mint: MINT, issuerPubkey: ISSUER_PUBKEY }],
          createMintAllowlist([MINT])
        ),
        mintClient: {
          getKey: async () => minted.A,
          checkState: async () => 'UNSPENT' as const,
          clearCache: () => {},
        } as MintClient,
        availability: createMintAvailabilityPolicy(),
        grant: () => ({ roles: ['voucher-holder'], permissions: ['voucher:view:sat:1000'] }),
      }),
      minAuthResponseMillis: 0,
      clock: { nowUnix: () => NOW },
    };

    const app = express();
    app.set('trust proxy', true);
    app.use(
      '/auth',
      createNapExpressRouter({
        server: options,
        getExternalBaseUrl: createRequestDerivedBaseUrlResolver(['api.example.com']),
      })
    );

    const post = (path: string) =>
      request(app).post(path).set('host', 'api.example.com').set('x-forwarded-proto', 'https');

    const init = await post('/auth/init').send({ npub: NPUB });
    const built = await buildAuthCompleteRequest({
      challenge: init.body,
      signer: createPrivateKeySigner(PK),
      createdAt: NOW,
      voucher: {
        mint_url: MINT,
        keyset_id: '00882760bfa2eb41',
        secret,
        signature: minted.C,
        amount: 8,
        dleq: minted.dleq,
      },
    });

    const login = await post('/auth/complete')
      .set('authorization', built.authorization)
      .set('content-type', 'application/json')
      .send(new TextDecoder().decode(built.rawBody));

    expect(login.status).toBe(401);
    expect(login.body.access_token).toBeUndefined();
  });
});

/**
 * The guide's §3.5.11 wiring example, run rather than merely type-checked.
 *
 * `docsTypecheck.test.ts` proves the snippet compiles against the real API,
 * which catches a renamed option but not a wrong one: an example that
 * constructs a resolver nobody could log in through would type-check happily.
 * So this builds the resolver exactly as the guide shows and drives a real
 * login through it.
 *
 * Keep the two in step. If this needs a change the guide does not have, the
 * guide is wrong.
 */
describe('the wiring example in guide §3.5.11', () => {
  it('produces a resolver a real login succeeds through', async () => {
    const secret = issueVoucher(HOLDER);
    const minted = mintProof(secret);
    const registry = {
      permissions: [{ key: 'voucher:view:sat' }],
      roles: [{ key: 'voucher-holder' }],
    };

    // --- exactly as documented, except the mint client, which is stubbed so
    // the test makes no outbound request. Its construction is covered by
    // mintClient.test.ts.
    const mints = createMintAllowlist(['https://mint.example.com']);
    const issuers = createIssuerAllowlist(
      [{ mint: 'https://mint.example.com', issuerPubkey: ISSUER_PUBKEY }],
      mints
    );

    const aclResolver = createVoucherAclResolver({
      mintAllowlist: mints,
      issuerAllowlist: issuers,
      mintClient: {
        getKey: async () => minted.A,
        checkState: async () => 'UNSPENT' as const,
        clearCache: () => {},
      } as MintClient,
      availability: createMintAvailabilityPolicy(),
      permissionRegistry: registry,
      grant: (voucher) => ({
        roles: ['voucher-holder'],
        permissions: [`voucher:view:${voucher.unit}`],
      }),
    });
    // --- end of the documented snippet

    const options: NapServerOptions = {
      challengeStore: new InMemoryChallengeStore(),
      sessionStore: new InMemorySessionStore(),
      aclResolver,
      minAuthResponseMillis: 0,
      clock: { nowUnix: () => NOW },
    };

    const app = express();
    app.set('trust proxy', true);
    app.use(
      '/auth',
      createNapExpressRouter({
        server: options,
        getExternalBaseUrl: createRequestDerivedBaseUrlResolver(['api.example.com']),
      })
    );

    const post = (path: string) =>
      request(app).post(path).set('host', 'api.example.com').set('x-forwarded-proto', 'https');

    const init = await post('/auth/init').send({ npub: NPUB });
    const built = await buildAuthCompleteRequest({
      challenge: init.body,
      signer: createPrivateKeySigner(PK),
      createdAt: NOW,
      voucher: {
        mint_url: MINT,
        keyset_id: '00882760bfa2eb41',
        secret,
        signature: minted.C,
        amount: 8,
        dleq: minted.dleq,
      },
    });

    const login = await post('/auth/complete')
      .set('authorization', built.authorization)
      .set('content-type', 'application/json')
      .send(new TextDecoder().decode(built.rawBody));

    expect(login.status).toBe(200);
    // The permission the documented grant() derives, and which the documented
    // registry declares. Both halves of the example have to be right for this.
    expect(login.body.permissions).toEqual(['voucher:view:sat']);
  });
});
