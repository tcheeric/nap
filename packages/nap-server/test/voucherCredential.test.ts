import { describe, expect, it } from 'vitest';
import { parseAuthCompleteRequest } from '../src/server.js';
import type { VoucherCredential } from '@imani/nap-core';

/**
 * The `voucher` field on the completion body (extension 0001 §3.4).
 *
 * Its placement is the point: the NIP-98 `payload` tag is `sha256(rawBody)`, so
 * a credential in the body is covered by the signature and cannot be swapped in
 * transit. That property is exercised end to end elsewhere; what is pinned here
 * is that the parser accepts a well-formed credential, refuses a malformed one
 * rather than dropping it, and never lets an unexpected field ride along.
 */
describe('parseAuthCompleteRequest with a voucher', () => {
  const VALID: VoucherCredential = {
    mint_url: 'https://mint.example.com',
    keyset_id: '00882760bfa2eb41',
    secret: '["P2PK_VOUCHER",{"nonce":"aa","data":"02ab","tags":[]}]',
    signature: '02'.padEnd(66, 'c'),
    amount: 8,
    dleq: { e: 'a'.repeat(64), s: 'b'.repeat(64), r: 'c'.repeat(64) },
  };

  const body = (extra: Record<string, unknown>) =>
    new TextEncoder().encode(JSON.stringify({ challenge_id: 'chal-1', ...extra }));

  it('accepts a well-formed credential', () => {
    const parsed = parseAuthCompleteRequest(body({ voucher: VALID }));

    expect(parsed?.voucher).toEqual(VALID);
  });

  it('accepts an optional witness', () => {
    const parsed = parseAuthCompleteRequest(body({ voucher: { ...VALID, witness: '{"sig":[]}' } }));

    expect(parsed?.voucher?.witness).toBe('{"sig":[]}');
  });

  it('leaves the field absent when no voucher is presented', () => {
    // The field is additive: today's clients send no voucher and must be
    // unaffected.
    const parsed = parseAuthCompleteRequest(body({}));

    expect(parsed).toEqual({ challenge_id: 'chal-1' });
    expect(parsed).not.toHaveProperty('voucher');
  });

  it('coexists with step_up', () => {
    const parsed = parseAuthCompleteRequest(body({ step_up: true, voucher: VALID }));

    expect(parsed?.step_up).toBe(true);
    expect(parsed?.voucher).toEqual(VALID);
  });

  it('drops an unexpected field rather than passing it to the resolver', () => {
    // The credential is rebuilt from known keys, so a body carrying extra data
    // cannot smuggle it into the resolver.
    const parsed = parseAuthCompleteRequest(
      body({ voucher: { ...VALID, roles: ['admin'], grant: 'everything' } })
    );

    expect(parsed?.voucher).toEqual(VALID);
    expect(parsed?.voucher).not.toHaveProperty('roles');
    expect(parsed?.voucher).not.toHaveProperty('grant');
  });

  describe('a malformed credential is a rejection, not a silent drop', () => {
    // Dropping it would turn a client bug into a fall-through to the stored
    // ACL, which for a burner key is a generic denial that looks nothing like
    // the real cause.
    it.each([
      ['a null voucher', null],
      ['an array', []],
      ['a string', 'not-an-object'],
      ['a number', 42],
    ])('rejects %s', (_label, voucher) => {
      expect(parseAuthCompleteRequest(body({ voucher }))).toBeNull();
    });

    it.each(['mint_url', 'keyset_id', 'secret', 'signature'] as const)(
      'rejects a missing %s',
      (field) => {
        const { [field]: _omitted, ...rest } = VALID;

        expect(parseAuthCompleteRequest(body({ voucher: rest }))).toBeNull();
      }
    );

    it.each(['mint_url', 'keyset_id', 'secret', 'signature'] as const)(
      'rejects an empty %s',
      (field) => {
        expect(parseAuthCompleteRequest(body({ voucher: { ...VALID, [field]: '' } }))).toBeNull();
      }
    );

    it.each([
      ['a missing amount', undefined],
      ['a string amount', '8'],
      ['a fractional amount', 1.5],
      ['a zero amount', 0],
      ['a negative amount', -8],
      ['NaN', Number.NaN],
    ])('rejects %s', (_label, amount) => {
      // A non-integer cannot select a key from a keyset, and NaN would compare
      // false against every amount without looking wrong.
      expect(parseAuthCompleteRequest(body({ voucher: { ...VALID, amount } }))).toBeNull();
    });

    it.each([
      ['a missing dleq', undefined],
      ['a null dleq', null],
      ['an array dleq', []],
      ['a dleq missing e', { s: 'b', r: 'c' }],
      ['a dleq missing s', { e: 'a', r: 'c' }],
      ['a dleq missing r', { e: 'a', s: 'b' }],
      ['a dleq with an empty component', { e: '', s: 'b', r: 'c' }],
    ])('rejects %s', (_label, dleq) => {
      // DLEQ is REQUIRED (§4.2): without it a server in degraded mode would
      // have no cryptographic footing at all.
      expect(parseAuthCompleteRequest(body({ voucher: { ...VALID, dleq } }))).toBeNull();
    });

    it('rejects a non-string witness', () => {
      expect(
        parseAuthCompleteRequest(body({ voucher: { ...VALID, witness: 42 } }))
      ).toBeNull();
    });
  });

  it('does not validate the mint_url beyond its being a non-empty string', () => {
    // Deliberate. Whether an origin is allowed is the allowlist's decision, and
    // a second, weaker copy of the highest-severity check here would be a
    // liability rather than defence in depth.
    const parsed = parseAuthCompleteRequest(
      body({ voucher: { ...VALID, mint_url: 'http://evil.example.com' } })
    );

    expect(parsed?.voucher?.mint_url).toBe('http://evil.example.com');
  });
});

/**
 * The reason the credential lives in the body rather than the NIP-98 event.
 *
 * The `payload` tag is `sha256(rawBody)`, so the signature covers the
 * credential. This is asserted at the hash level rather than through a full
 * login, because it is a property of the signing rule and not of the adapter:
 * change the body, and the hash the server recomputes no longer matches the one
 * that was signed.
 */
describe('the payload hash covers the credential', () => {
  const withVoucher = (mintUrl: string) =>
    new TextEncoder().encode(
      JSON.stringify({
        challenge_id: 'chal-1',
        voucher: {
          mint_url: mintUrl,
          keyset_id: '00882760bfa2eb41',
          secret: 's',
          signature: 'c',
          amount: 8,
          dleq: { e: 'a', s: 'b', r: 'c' },
        },
      })
    );

  it('changes when the credential changes', async () => {
    const { sha256Hex } = await import('@imani/nap-core');

    const signed = sha256Hex(withVoucher('https://mint.example.com'));
    const swapped = sha256Hex(withVoucher('https://evil.example.com'));

    // A credential swapped in transit therefore fails with
    // NAP_COMPLETE_PAYLOAD_MISMATCH, the same mechanism that protects step_up.
    expect(swapped).not.toBe(signed);
  });
});
