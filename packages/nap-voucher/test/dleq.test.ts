import { describe, expect, it } from 'vitest';
import { hashE, hashToCurve, proofY, verifyDleq, verifyProofDleq } from '../src/index.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';

const Point = secp256k1.Point;
const hex = (bytes: Uint8Array) =>
  Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
const fromHexUtf8 = (value: string) =>
  Uint8Array.from(value.match(/.{2}/g)!.map((byte) => Number.parseInt(byte, 16)));

/** NUT-12 §"DLEQ verification on BlindSignature" — the valid vector. */
const BLIND_SIGNATURE_VECTOR = {
  A: '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
  B_: '02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2',
  C_: '02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2',
  dleq: {
    e: '9818e061ee51d5c8edc3342369a554998ff7b4381c8652d724cdf46429be73d9',
    s: '9818e061ee51d5c8edc3342369a554998ff7b4381c8652d724cdf46429be73da',
  },
};

/** NUT-12 §"DLEQ verification on Proof" — the valid vector. */
const PROOF_VECTOR = {
  A: '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
  secret: 'daf4dd00a2b68a0858a80450f52c8a7d2ccf87d375e43e216e0c571f089f63e9',
  C: '024369d2d22a80ecf78f3937da9d5f30c1b9f74f0c32684d583cca0fa6a61cdcfc',
  dleq: {
    e: 'b31e58ac6527f34975ffab13e70a48b6d2b0d35abc4b03f0151f09ee1a9763d4',
    s: '8fbae004c59e754d71df67e392b6ae4e29293113ddc2ec86592a0431d16306d8',
    r: 'a6d13fcd7a18442e6076f5e1e7c887ad5de40a019824bdfa9fe740d302e8d861',
  },
};

describe('NUT-00 hash_to_curve', () => {
  // Official NUT-00 test vectors. Test 3 deliberately needs several counter
  // iterations before landing on the curve, which is the branch most likely to
  // be wrong in a fresh implementation.
  it.each([
    [
      '0000000000000000000000000000000000000000000000000000000000000000',
      '024cce997d3b518f739663b757deaec95bcd9473c30a14ac2fd04023a739d1a725',
    ],
    [
      '0000000000000000000000000000000000000000000000000000000000000001',
      '022e7158e11c9506f1aa4248bf531298daa7febd6194f003edcd9b93ade6253acf',
    ],
    [
      '0000000000000000000000000000000000000000000000000000000000000002',
      '026cdbe15362df59cd1dd3c9c11de8aedac2106eca69236ecd9fbe117af897be4f',
    ],
  ])('maps %s to the specified point', (message, expected) => {
    expect(hashToCurve(fromHexUtf8(message)).toHex(true)).toBe(expected);
  });

  it('derives Y from a utf-8 secret for the NUT-07 state check', () => {
    // The secret is a UTF-8 string, not hex bytes. Getting this wrong produces
    // a Y the mint has never heard of, and every state check silently misses.
    expect(proofY('test')).toBe(hashToCurve(new TextEncoder().encode('test')).toHex(true));
  });
});

describe('NUT-12 hash_e', () => {
  it('matches the specified vector', () => {
    // Pins two things that are easy to get wrong: the *uncompressed* point
    // encoding, and that it hashes the UTF-8 bytes of the 130-char hex string
    // rather than the 65 raw bytes.
    const one = Point.fromHex('020000000000000000000000000000000000000000000000000000000000000001');
    const C_ = Point.fromHex('02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2');

    expect(hex(hashE(one, one, one, C_))).toBe(
      'a4dc034b74338c28c6bc3ea49731f2a24440fc7c4affc08b31a93fc9fbe6401e'
    );
  });
});

describe('verifyDleq on a BlindSignature', () => {
  it('accepts the official valid vector', () => {
    expect(verifyDleq(BLIND_SIGNATURE_VECTOR)).toBe(true);
  });

  it('accepts the deterministic-nonce vector', () => {
    // The spec requires an implementation reproduce e and s exactly for these
    // fixed inputs, so verification against them must pass.
    expect(
      verifyDleq({
        A: '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5',
        B_: '02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2',
        C_: '0244eccfc7a348274458bb38044c7f3c389b3c2086c7ec18b5812d2877ab937787',
        dleq: {
          e: '2a16ffee280aff3c429045607f9b8e0bf8b35910c44c1b20b9dfaf01b263d7b3',
          s: '9df27731238334718d120d4f74611a7c668233f988e687ac3fb188f0a34a2dab',
        },
      })
    ).toBe(true);
  });

  it('rejects a tampered e', () => {
    expect(
      verifyDleq({
        ...BLIND_SIGNATURE_VECTOR,
        dleq: { ...BLIND_SIGNATURE_VECTOR.dleq, e: `${BLIND_SIGNATURE_VECTOR.dleq.e.slice(0, 63)}0` },
      })
    ).toBe(false);
  });

  it('rejects a tampered s', () => {
    expect(
      verifyDleq({
        ...BLIND_SIGNATURE_VECTOR,
        dleq: { ...BLIND_SIGNATURE_VECTOR.dleq, s: `${BLIND_SIGNATURE_VECTOR.dleq.s.slice(0, 63)}0` },
      })
    ).toBe(false);
  });

  it('rejects a substituted mint key A', () => {
    // The attack this actually stops: a different mint claiming the signature.
    expect(
      verifyDleq({
        ...BLIND_SIGNATURE_VECTOR,
        A: '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5',
      })
    ).toBe(false);
  });

  it('rejects a substituted C_', () => {
    expect(
      verifyDleq({
        ...BLIND_SIGNATURE_VECTOR,
        C_: '0244eccfc7a348274458bb38044c7f3c389b3c2086c7ec18b5812d2877ab937787',
      })
    ).toBe(false);
  });

  it.each([
    ['zero e', { e: '0'.repeat(64) }],
    ['zero s', { s: '0'.repeat(64) }],
    // n itself is out of range; accepting it would admit a second encoding of 0.
    ['e at the curve order', { e: 'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141' }],
    ['s above the curve order', { s: 'f'.repeat(64) }],
    ['short e', { e: 'abcd' }],
    ['non-hex s', { s: 'z'.repeat(64) }],
  ])('rejects %s without throwing', (_label, override) => {
    const call = () =>
      verifyDleq({ ...BLIND_SIGNATURE_VECTOR, dleq: { ...BLIND_SIGNATURE_VECTOR.dleq, ...override } });

    // Malformed input and a failed proof must be indistinguishable to the
    // client: both are the same generic 401, so neither may throw.
    expect(call).not.toThrow();
    expect(call()).toBe(false);
  });

  it.each([
    ['an off-curve point', '02' + 'f'.repeat(64)],
    ['garbage', 'not-a-point'],
    ['empty', ''],
    ['the uncompressed-length prefix with no body', '04'],
  ])('rejects %s as A without throwing', (_label, A) => {
    expect(() => verifyDleq({ ...BLIND_SIGNATURE_VECTOR, A })).not.toThrow();
    expect(verifyDleq({ ...BLIND_SIGNATURE_VECTOR, A })).toBe(false);
  });

  it('rejects a missing dleq object without throwing', () => {
    expect(() =>
      verifyDleq({ ...BLIND_SIGNATURE_VECTOR, dleq: undefined as never })
    ).not.toThrow();
    expect(verifyDleq({ ...BLIND_SIGNATURE_VECTOR, dleq: undefined as never })).toBe(false);
  });

  it('is case-insensitive on hex input', () => {
    expect(
      verifyDleq({
        A: BLIND_SIGNATURE_VECTOR.A.toUpperCase(),
        B_: BLIND_SIGNATURE_VECTOR.B_.toUpperCase(),
        C_: BLIND_SIGNATURE_VECTOR.C_.toUpperCase(),
        dleq: {
          e: BLIND_SIGNATURE_VECTOR.dleq.e.toUpperCase(),
          s: BLIND_SIGNATURE_VECTOR.dleq.s.toUpperCase(),
        },
      })
    ).toBe(true);
  });
});

describe('verifyProofDleq — the form the extension actually uses', () => {
  it('accepts the official valid vector', () => {
    // A VoucherCredential carries a Proof, not a BlindSignature, so B' and C'
    // must be reconstructed from the blinding factor r.
    expect(verifyProofDleq(PROOF_VECTOR)).toBe(true);
  });

  it('rejects a tampered blinding factor', () => {
    expect(
      verifyProofDleq({
        ...PROOF_VECTOR,
        dleq: { ...PROOF_VECTOR.dleq, r: `${PROOF_VECTOR.dleq.r.slice(0, 63)}0` },
      })
    ).toBe(false);
  });

  it('rejects a different secret against the same signature', () => {
    // Swapping the secret changes Y, so B' no longer reconstructs. This is what
    // stops a proof's authorization metadata being lifted onto another secret.
    expect(verifyProofDleq({ ...PROOF_VECTOR, secret: `${PROOF_VECTOR.secret.slice(0, 63)}0` })).toBe(
      false
    );
  });

  it('rejects a substituted C', () => {
    expect(
      verifyProofDleq({
        ...PROOF_VECTOR,
        C: '02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2',
      })
    ).toBe(false);
  });

  it.each([
    ['an empty secret', { secret: '' }],
    ['a missing r', { dleq: { ...PROOF_VECTOR.dleq, r: '' } }],
    ['an out-of-range r', { dleq: { ...PROOF_VECTOR.dleq, r: 'f'.repeat(64) } }],
  ])('rejects %s without throwing', (_label, override) => {
    const call = () => verifyProofDleq({ ...PROOF_VECTOR, ...override } as typeof PROOF_VECTOR);

    expect(call).not.toThrow();
    expect(call()).toBe(false);
  });
});
