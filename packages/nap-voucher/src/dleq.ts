/**
 * NUT-12 DLEQ verification and NUT-00 `hash_to_curve`.
 *
 * DLEQ proves that the mint used the same private key `a` to produce its
 * public key `A = a*G` and to sign the blinded message `B' = a -> C' = a*B'`.
 * What it buys the extension is offline cryptographic footing: the proof came
 * from *this* mint's keyset, verifiable without asking anyone.
 *
 * What it does **not** buy, and the reason extension 0001 §4.2 makes the mint
 * mandatory anyway: DLEQ says nothing about whether the proof is still
 * unspent. A burned voucher carries a perfectly valid DLEQ. Liveness is
 * mint-local state and only NUT-07 answers it. DLEQ is necessary, not
 * sufficient.
 *
 * Dependency-free apart from `@noble/curves`, per §11 step 2.
 */

import { secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';

const Point = secp256k1.Point;
type Point = InstanceType<typeof Point>;

const CURVE_ORDER = Point.Fn.ORDER;
const DOMAIN_SEPARATOR = new TextEncoder().encode('Secp256k1_HashToCurve_Cashu_');
const HEX_32 = /^[0-9a-f]{64}$/;

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);

  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }

  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

/**
 * Parse a scalar, rejecting zero and anything at or above the curve order.
 *
 * Both bounds matter. A zero `s` or `e` makes the verification equation
 * degenerate, and a value ≥ n is a non-canonical encoding of a smaller one, so
 * accepting it would admit a second valid representation of the same proof.
 */
function parseScalar(value: string): bigint | null {
  if (typeof value !== 'string' || !HEX_32.test(value.trim().toLowerCase())) {
    return null;
  }

  const scalar = BigInt(`0x${value.trim().toLowerCase()}`);

  return scalar > 0n && scalar < CURVE_ORDER ? scalar : null;
}

/** Parse a compressed SEC1 point, or `null` if it is not on the curve. */
function parsePoint(value: string): Point | null {
  if (typeof value !== 'string') {
    return null;
  }

  try {
    // `fromHex` rejects points not on the curve, which is the check that
    // matters: an attacker-supplied off-curve point is the classic way to make
    // scalar multiplication leak.
    return Point.fromHex(value.trim().toLowerCase());
  } catch {
    return null;
  }
}

/**
 * NUT-00 `hash_to_curve`: deterministically map a secret to a curve point.
 *
 * `Y = PublicKey('02' || SHA256(msg_hash || counter))` where `msg_hash =
 * SHA256(DOMAIN_SEPARATOR || x)` and `counter` is a little-endian uint32
 * incremented from 0 until the result lies on the curve.
 *
 * This is also how the `Y` that NUT-07 wants for a state check is derived, so
 * it is shared rather than duplicated there.
 */
export function hashToCurve(secret: Uint8Array): Point {
  const messageHash = sha256(concat(DOMAIN_SEPARATOR, secret));

  for (let counter = 0; counter < 0x0100_0000; counter += 1) {
    const counterBytes = new Uint8Array(4);
    new DataView(counterBytes.buffer).setUint32(0, counter, true);
    const candidate = concat(new Uint8Array([0x02]), sha256(concat(messageHash, counterBytes)));

    try {
      return Point.fromHex(bytesToHex(candidate));
    } catch {
      // Not on the curve; the spec's counter loop exists for exactly this.
    }
  }

  // Unreachable in practice: roughly half of all candidates are on the curve,
  // so the chance of exhausting the counter is about 2^-16777216.
  throw new Error('hash_to_curve failed to find a point on the curve');
}

/** The `Y` a NUT-07 state check is keyed on, as a compressed hex point. */
export function proofY(secret: string): string {
  return hashToCurve(new TextEncoder().encode(secret)).toHex(true);
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;

  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }

  return out;
}

/**
 * NUT-12 `hash_e`: SHA256 over the concatenated *uncompressed* hex encodings.
 *
 * The uncompressed form and the hex-of-hex are both load-bearing and both easy
 * to get wrong: the spec hashes the UTF-8 bytes of the 130-character hex
 * string, not the 65 raw bytes. Pinned by the spec's `hash_e` test vector.
 */
export function hashE(...points: Point[]): Uint8Array {
  const joined = points.map((point) => point.toHex(false)).join('');

  return sha256(new TextEncoder().encode(joined));
}

export interface DleqProof {
  e: string;
  s: string;
}

/**
 * Verify a DLEQ proof on a `BlindSignature`: `e == hash(R1, R2, A, C')` where
 * `R1 = s*G - e*A` and `R2 = s*B' - e*C'`.
 *
 * Returns a boolean rather than throwing, and returns `false` for malformed
 * input as well as for a failed proof. Every voucher failure must reach the
 * client as the same generic 401, so the two cases must not be distinguishable
 * by exception shape or by timing.
 */
export function verifyDleq(params: {
  /** Mint public key `A` for the proof's amount, compressed hex. */
  A: string;
  /** Blinded message `B'`, compressed hex. */
  B_: string;
  /** Blind signature `C'`, compressed hex. */
  C_: string;
  dleq: DleqProof;
}): boolean {
  const A = parsePoint(params.A);
  const B_ = parsePoint(params.B_);
  const C_ = parsePoint(params.C_);
  const e = parseScalar(params.dleq?.e ?? '');
  const s = parseScalar(params.dleq?.s ?? '');

  if (!A || !B_ || !C_ || e === null || s === null) {
    return false;
  }

  try {
    // R1 = s*G - e*A
    const R1 = Point.BASE.multiply(s).add(A.multiply(e).negate());
    // R2 = s*B' - e*C'
    const R2 = B_.multiply(s).add(C_.multiply(e).negate());
    const expected = bytesToHex(hashE(R1, R2, A, C_));

    return expected === params.dleq.e.trim().toLowerCase();
  } catch {
    // A point at infinity makes toHex throw. That is a failed proof, not a
    // server error.
    return false;
  }
}

/**
 * Verify a DLEQ proof carried on a `Proof` rather than a `BlindSignature`.
 *
 * The holder does not have `B'` and `C'`, so they are reconstructed from the
 * blinding factor `r` the sender included: `C' = C + r*A` and `B' = Y + r*G`,
 * where `Y = hash_to_curve(secret)`. This is the form the extension actually
 * needs, since a `VoucherCredential` carries a proof.
 */
export function verifyProofDleq(params: {
  /** Mint public key `A` for this proof's amount, compressed hex. */
  A: string;
  /** The proof's secret, as the UTF-8 string it is. */
  secret: string;
  /** Unblinded signature `C`, compressed hex. */
  C: string;
  dleq: DleqProof & { r: string };
}): boolean {
  const A = parsePoint(params.A);
  const C = parsePoint(params.C);
  const r = parseScalar(params.dleq?.r ?? '');

  if (!A || !C || r === null || typeof params.secret !== 'string' || !params.secret) {
    return false;
  }

  try {
    const Y = hashToCurve(new TextEncoder().encode(params.secret));
    const C_ = C.add(A.multiply(r));
    const B_ = Y.add(Point.BASE.multiply(r));

    return verifyDleq({ A: A.toHex(true), B_: B_.toHex(true), C_: C_.toHex(true), dleq: params.dleq });
  } catch {
    return false;
  }
}
