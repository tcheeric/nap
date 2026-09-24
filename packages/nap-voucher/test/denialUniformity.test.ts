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
} from '@imani/nap-adapter-express';
import { schnorr, secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes as hb } from '@noble/hashes/utils.js';
import { createIssuerAllowlist, createMintAllowlist } from '../src/allowlist.js';
import { createMintAvailabilityPolicy } from '../src/availability.js';
import { hashE, hashToCurve } from '../src/dleq.js';
import { MintUnavailableError, type MintClient } from '../src/mintClient.js';
import { createVoucherAclResolver, VOUCHER_DENIAL_CODES } from '../src/resolver.js';
import { parseVoucherSecret, voucherCanonicalBytes, VOUCHER_TAGS } from '../src/secret.js';

/**
 * §6.2: seven distinct audit codes behind one indistinguishable 401.
 *
 * The two halves are in tension and both matter. The operator needs to know
 * *which* check refused, or a voucher deployment is undebuggable. The client
 * must learn nothing, because the codes together are an oracle: whether a mint
 * is allowlisted, whether an issuer is trusted, and — most sensitive — whether
 * a given proof has been spent.
 *
 * So this asserts both at once, through the real endpoint: the audit log
 * distinguishes all seven, and the HTTP responses do not differ at all.
 *
 * Asserting only the codes would let a response body drift apart unnoticed;
 * asserting only the responses would pass if every check emitted the same code,
 * or none.
 */

const PK = '1'.repeat(64);
const HOLDER = getPublicKey(hexToBytes(PK));
const NPUB = nip19.npubEncode(HOLDER);
const NOW = 1_710_000_000;
const MINT = 'https://mint.example.com';
const ISSUER_PRIVATE = hb('11'.repeat(32));
const ISSUER_PUBKEY = bytesToHex(schnorr.getPublicKey(ISSUER_PRIVATE));
const UNTRUSTED_PRIVATE = hb('33'.repeat(32));
const Point = secp256k1.Point;
const ORDER = secp256k1.Point.Fn.ORDER;

/**
 * Note this is non-deterministic: BIP-340 signing draws auxiliary randomness,
 * so two calls with identical arguments produce different secrets. Anything
 * needing the *same* secret twice must hold on to one string.
 */
function signed(
  lockedTo: string,
  expiresAt: number | null = NOW + 3600,
  issuerPrivate: Uint8Array = ISSUER_PRIVATE
): string {
  const body = {
    nonce: 'n',
    data: `02${lockedTo}`,
    tags: [
      [VOUCHER_TAGS.ISSUER, 'imani'],
      ...(expiresAt === null ? [] : [[VOUCHER_TAGS.EXPIRES_AT, String(expiresAt)]]),
    ],
  };
  const unsigned = parseVoucherSecret(JSON.stringify(['P2PK_VOUCHER', body]))!;
  const sig = bytesToHex(schnorr.sign(sha256(voucherCanonicalBytes(unsigned)), issuerPrivate));

  return JSON.stringify([
    'P2PK_VOUCHER',
    {
      ...body,
      tags: [
        ...body.tags,
        [VOUCHER_TAGS.ISSUER_PUBKEY, bytesToHex(schnorr.getPublicKey(issuerPrivate))],
        [VOUCHER_TAGS.ISSUER_SIG, sig],
      ],
    },
  ]);
}

/** A real BDHKE signature and NUT-12 proof, so the state check is reachable. */
function mintProof(secret: string) {
  const a = BigInt(`0x${'44'.repeat(32)}`) % ORDER;
  const A = Point.BASE.multiply(a);
  const r = BigInt(`0x${'55'.repeat(32)}`) % ORDER;
  const B_ = hashToCurve(new TextEncoder().encode(secret)).add(Point.BASE.multiply(r));
  const C_ = B_.multiply(a);
  const k = BigInt(`0x${'66'.repeat(32)}`) % ORDER;
  const e = BigInt(`0x${bytesToHex(hashE(Point.BASE.multiply(k), B_.multiply(k), A, C_))}`) % ORDER;
  const hex = (value: bigint) => value.toString(16).padStart(64, '0');

  return {
    A: A.toHex(true),
    C: C_.add(A.multiply(r).negate()).toHex(true),
    dleq: { e: hex(e), s: hex((k + e * a) % ORDER), r: hex(r) },
  };
}

const credential = (overrides: Record<string, unknown> = {}) => ({
  mint_url: MINT,
  keyset_id: '00882760bfa2eb41',
  secret: signed(HOLDER),
  signature: '02'.padEnd(66, 'a'),
  amount: 8,
  dleq: { e: 'e'.repeat(64), s: '0'.repeat(64), r: '0'.repeat(64) },
  ...overrides,
});

async function attempt(voucher: Record<string, unknown>, mintClient: Partial<MintClient> = {}) {
  const audit: string[] = [];
  const options: NapServerOptions = {
    challengeStore: new InMemoryChallengeStore(),
    sessionStore: new InMemorySessionStore(),
    minAuthResponseMillis: 0,
    clock: { nowUnix: () => NOW },
    aclResolver: createVoucherAclResolver({
      mintAllowlist: createMintAllowlist([MINT]),
      issuerAllowlist: createIssuerAllowlist(
        [{ mint: MINT, issuerPubkey: ISSUER_PUBKEY }],
        createMintAllowlist([MINT])
      ),
      mintClient: {
        getKey: async () => '02'.padEnd(66, 'b'),
        checkState: async () => 'UNSPENT' as const,
        clearCache: () => {},
        ...mintClient,
      } as MintClient,
      availability: createMintAvailabilityPolicy(),
      grant: () => ({ roles: ['r'], permissions: ['p'] }),
      auditLogger: { log: (event) => void audit.push(event.code) },
    }),
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
    voucher: voucher as never,
  });
  const response = await post('/auth/complete')
    .set('authorization', built.authorization)
    .set('content-type', 'application/json')
    .send(new TextDecoder().decode(built.rawBody));

  return {
    code: audit[0] ?? '(none)',
    status: response.status,
    body: JSON.stringify(response.body),
    // Date and ETag vary per response by nature; Content-Length is implied by
    // the body, which is compared directly.
    headers: JSON.stringify(
      Object.entries(response.headers)
        .filter(([key]) => !['date', 'etag', 'content-length'].includes(key))
        .sort()
    ),
  };
}

describe('§6.2: every voucher failure is the same 401', () => {
  it('emits all seven codes at the right step, behind one identical response', async () => {
    // The same secret string is reused for the SPENT case: `signed()` draws
    // fresh BIP-340 randomness, so proving a *different* secret would fail DLEQ
    // first and mask the state check -- which is exactly what happened on the
    // first run of this scenario.
    const spentSecret = signed(HOLDER);
    const minted = mintProof(spentSecret);

    const outcomes = [
      await attempt(credential({ mint_url: 'https://evil.example.com' })),
      await attempt(credential()),
      await attempt(credential({ secret: signed('cc'.repeat(32)) })),
      await attempt(credential({ secret: signed(HOLDER, NOW + 3600, UNTRUSTED_PRIVATE) })),
      await attempt(credential({ secret: signed(HOLDER, NOW - 1) })),
      await attempt(
        credential({ secret: spentSecret, signature: minted.C, dleq: minted.dleq }),
        { getKey: async () => minted.A, checkState: async () => 'SPENT' as const }
      ),
      await attempt(credential(), {
        getKey: async () => {
          throw new MintUnavailableError('unavailable', 'connection refused');
        },
      }),
    ];

    // The operator can tell the seven apart.
    expect(outcomes.map((outcome) => outcome.code)).toEqual([
      VOUCHER_DENIAL_CODES.MINT_NOT_ALLOWED,
      VOUCHER_DENIAL_CODES.DLEQ_INVALID,
      VOUCHER_DENIAL_CODES.BINDING_MISMATCH,
      VOUCHER_DENIAL_CODES.ISSUER_UNTRUSTED,
      VOUCHER_DENIAL_CODES.EXPIRED,
      VOUCHER_DENIAL_CODES.SPENT,
      VOUCHER_DENIAL_CODES.MINT_UNAVAILABLE,
    ]);

    // The client cannot. Status, body, and headers are compared together: any
    // one of them differing would be an oracle, and the spent-proof case is the
    // one that matters most, since it would leak the state of somebody else's
    // proof.
    const responses = new Set(
      outcomes.map((outcome) => `${outcome.status}|${outcome.body}|${outcome.headers}`)
    );

    expect(responses.size).toBe(1);
    expect(outcomes[0]?.status).toBe(401);
    expect(outcomes[0]?.body).toBe(
      JSON.stringify({ status: 'error', message: 'authentication failed' })
    );
  });
});
