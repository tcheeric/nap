/**
 * NUT-10 `P2PK_VOUCHER` secret parsing, and the canonical bytes an issuer signs.
 *
 * Two jobs that have to live together, because the second is only meaningful if
 * the first preserved enough of the input to reproduce it.
 *
 * ## Why this is a re-render rather than a substring
 *
 * The issuer signature covers a canonical rendering of the secret, not the
 * secret's own wire bytes. So verification has to parse the wire form and write
 * it back out in the canonical form, and any disagreement between this renderer
 * and the Java one in `cashu-voucher` (`VoucherCanonicalBytes`) is a signature
 * that fails to verify — or, far worse, one that verifies over different
 * content than the issuer meant.
 *
 * That is a real risk and not a theoretical one, so the parity is pinned by a
 * golden vector generated from the Java implementation rather than by reading
 * both and judging them equivalent. See `secret.test.ts`.
 *
 * ## What is deliberately not here
 *
 * No signature verification, no expiry check, no allowlist. This module answers
 * "what does this secret say, and what bytes did the issuer sign", and the
 * resolver decides what that is worth. Keeping the rendering free of policy is
 * what lets the golden vector be a pure function of the secret.
 */

/** The NUT-10 kinds that carry issuer-signed voucher metadata. */
export type VoucherKind = 'VOUCHER' | 'P2PK_VOUCHER';

/**
 * Tag keys, mirroring `VoucherTags` in `cashu-lib`.
 *
 * The issuer signs over these keys and the mint reads them back, so a
 * divergence here is a signature that covers a document neither side wrote.
 */
export const VOUCHER_TAGS = {
  VOUCHER_ID: 'voucher_id',
  ISSUER: 'issuer',
  UNIT: 'unit',
  FACE_VALUE: 'face_value',
  EXPIRES_AT: 'expires_at',
  MEMO: 'memo',
  FACE_DECIMALS: 'face_decimals',
  BACKING_STRATEGY: 'backing_strategy',
  ISSUANCE_RATIO: 'issuance_ratio',
  ISSUER_SIG: 'issuer_sig',
  ISSUER_PUBKEY: 'issuer_pubkey',
  MERCHANT_METADATA: 'merchant_metadata',
} as const;

/**
 * Tags written as bare JSON numbers rather than quoted strings.
 *
 * Keyed on the tag name rather than on the runtime type of the value, matching
 * Java. NUT-10 carries every value as a string, so the runtime type says
 * nothing about how it was written when the signature was made; the tag schema
 * is the durable record. Java learned this the hard way when modelling tag
 * values as `String` silently changed `1000` to `"1000"` and would have
 * invalidated every voucher ever issued.
 */
const NUMERIC_TAGS: ReadonlySet<string> = new Set([
  VOUCHER_TAGS.FACE_VALUE,
  VOUCHER_TAGS.EXPIRES_AT,
  VOUCHER_TAGS.FACE_DECIMALS,
  VOUCHER_TAGS.ISSUANCE_RATIO,
]);

/** Tags carrying the signature itself, which cannot be covered by it. */
const ADDED_AFTER_SIGNING: ReadonlySet<string> = new Set([
  VOUCHER_TAGS.ISSUER_SIG,
  VOUCHER_TAGS.ISSUER_PUBKEY,
]);

/** A parsed NUT-10 secret, with the voucher tags read out. */
export interface ParsedVoucherSecret {
  kind: VoucherKind;
  nonce: string | null;
  /**
   * The `data` field, hex.
   *
   * For `P2PK_VOUCHER` this is the P2PK lock key `K` — the key the completion
   * event must be signed by (§3.1). For `VOUCHER` it is the voucher id, which
   * is why the two kinds cannot share a checker.
   */
  data: string;
  /** Tags in wire order. Order is preserved because the signature covers it. */
  tags: ReadonlyArray<readonly string[]>;
  /**
   * The P2PK lock key, or `null` for an unlocked `VOUCHER`.
   *
   * Separate from `data` so a caller cannot read a lock key off a secret that
   * has none. A `VOUCHER` secret's `data` is a voucher id, and comparing that
   * to a Nostr pubkey would be a type confusion that silently never matches.
   */
  lockKey: string | null;
  voucherId: string | null;
  issuer: string | null;
  issuerPubkey: string | null;
  issuerSig: string | null;
  expiresAt: number | null;
  unit: string | null;
  faceValue: number | null;
}

function tagValue(tags: ReadonlyArray<readonly string[]>, key: string): string | null {
  for (const tag of tags) {
    if (tag[0] === key && tag.length > 1) {
      return tag[1] ?? null;
    }
  }
  return null;
}

function numericTagValue(tags: ReadonlyArray<readonly string[]>, key: string): number | null {
  const raw = tagValue(tags, key);
  if (raw === null) {
    return null;
  }
  const parsed = Number(raw);
  return Number.isFinite(parsed) ? parsed : null;
}

/**
 * Parses a NUT-10 secret string.
 *
 * Returns `null` for anything malformed rather than throwing, because every
 * byte of the input is attacker-controlled: this is called on a credential
 * supplied in a login request, and a thrown parse error would turn a hostile
 * string into a 500 that is both an availability problem and an oracle
 * distinguishing malformed from merely-wrong.
 */
export function parseVoucherSecret(secret: string): ParsedVoucherSecret | null {
  if (typeof secret !== 'string' || secret.length === 0) {
    return null;
  }

  let decoded: unknown;
  try {
    decoded = JSON.parse(secret);
  } catch {
    return null;
  }

  if (!Array.isArray(decoded) || decoded.length !== 2) {
    return null;
  }

  const [kind, body] = decoded as [unknown, unknown];

  if (kind !== 'VOUCHER' && kind !== 'P2PK_VOUCHER') {
    return null;
  }

  if (typeof body !== 'object' || body === null || Array.isArray(body)) {
    return null;
  }

  const record = body as Record<string, unknown>;
  const rawNonce = record.nonce;
  const rawData = record.data;
  const rawTags = record.tags;

  if (rawNonce !== null && rawNonce !== undefined && typeof rawNonce !== 'string') {
    return null;
  }

  if (typeof rawData !== 'string') {
    return null;
  }

  const tags: string[][] = [];

  if (rawTags !== undefined && rawTags !== null) {
    if (!Array.isArray(rawTags)) {
      return null;
    }
    for (const tag of rawTags) {
      if (!Array.isArray(tag) || tag.length === 0) {
        return null;
      }
      const values: string[] = [];
      for (const value of tag) {
        // Numbers are accepted and stringified because a sender may write a
        // numeric tag as a bare JSON number; the canonical renderer decides how
        // it is written back, keyed on the tag name.
        if (typeof value === 'string') {
          values.push(value);
        } else if (typeof value === 'number' && Number.isFinite(value)) {
          values.push(String(value));
        } else {
          return null;
        }
      }
      tags.push(values);
    }
  }

  const frozenTags = Object.freeze(tags.map((tag) => Object.freeze(tag)));

  return {
    kind,
    nonce: typeof rawNonce === 'string' ? rawNonce : null,
    data: rawData,
    tags: frozenTags,
    lockKey: kind === 'P2PK_VOUCHER' ? rawData : null,
    voucherId: kind === 'P2PK_VOUCHER' ? tagValue(frozenTags, VOUCHER_TAGS.VOUCHER_ID) : rawData,
    issuer: tagValue(frozenTags, VOUCHER_TAGS.ISSUER),
    issuerPubkey: tagValue(frozenTags, VOUCHER_TAGS.ISSUER_PUBKEY),
    issuerSig: tagValue(frozenTags, VOUCHER_TAGS.ISSUER_SIG),
    expiresAt: numericTagValue(frozenTags, VOUCHER_TAGS.EXPIRES_AT),
    unit: tagValue(frozenTags, VOUCHER_TAGS.UNIT),
    faceValue: numericTagValue(frozenTags, VOUCHER_TAGS.FACE_VALUE),
  };
}

/**
 * JSON string escaping, matching the Java renderer's `escapeJson`.
 *
 * Written out rather than delegated to `JSON.stringify` because the two differ
 * on non-ASCII: `JSON.stringify` emits characters like `é` literally, and Java
 * here does the same, but any future divergence in either would be silent and
 * would only show up as signatures that fail on vouchers containing an accented
 * memo. Keeping the escape table explicit makes the contract inspectable.
 */
function escapeJson(input: string): string {
  let out = '';
  for (const char of input) {
    switch (char) {
      case '"':
        out += '\\"';
        break;
      case '\\':
        out += '\\\\';
        break;
      case '\b':
        out += '\\b';
        break;
      case '\f':
        out += '\\f';
        break;
      case '\n':
        out += '\\n';
        break;
      case '\r':
        out += '\\r';
        break;
      case '\t':
        out += '\\t';
        break;
      default: {
        const code = char.codePointAt(0) ?? 0;
        if (code < 0x20) {
          out += `\\u${code.toString(16).padStart(4, '0')}`;
        } else {
          out += char;
        }
      }
    }
  }
  return out;
}

/**
 * Renders a numeric tag value the way Java's `appendNumber` does.
 *
 * An integral double is written as a long, so `1.0` and `1` produce identical
 * bytes rather than two valid forms of the same voucher. Non-finite values fall
 * back to the integral form rather than emitting `NaN`, which is not JSON.
 */
function renderNumber(raw: string): string {
  const parsed = Number(raw);

  if (!Number.isFinite(parsed)) {
    // Java's longValue() on a non-finite double yields 0 via saturation rules
    // that TypeScript does not share, so this case is pinned rather than
    // inferred. It is unreachable for a well-formed voucher.
    return '0';
  }

  if (!Number.isInteger(parsed)) {
    return String(parsed);
  }

  return String(Math.trunc(parsed));
}

/**
 * The exact bytes the issuer signature commits to.
 *
 * Form: `[kind,"data_hex","nonce",[[tag,value...],...]]`, with `issuer_sig` and
 * `issuer_pubkey` omitted because they are added after signing.
 *
 * The kind is written from the secret rather than fixed, which is what makes a
 * signature over an unlocked `VOUCHER` fail to verify against a `P2PK_VOUCHER`
 * carrying the same metadata. Without that, an issuer's attestation for an
 * unlocked voucher would transfer to a locked one and the lock would not be
 * covered by anything the issuer said.
 */
export function voucherCanonicalBytes(secret: ParsedVoucherSecret): Uint8Array {
  let out = `["${secret.kind}","${secret.data}","${secret.nonce ?? ''}",[`;

  let first = true;
  for (const tag of secret.tags) {
    const key = tag[0] ?? '';
    if (ADDED_AFTER_SIGNING.has(key)) {
      continue;
    }
    if (!first) {
      out += ',';
    }
    first = false;
    out += `["${escapeJson(key)}"`;
    for (const value of tag.slice(1)) {
      out += ',';
      out += NUMERIC_TAGS.has(key) ? renderNumber(value) : `"${escapeJson(value)}"`;
    }
    out += ']';
  }

  out += ']]';

  return new TextEncoder().encode(out);
}
