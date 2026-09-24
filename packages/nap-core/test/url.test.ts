import { finalizeEvent } from 'nostr-tools';
import { describe, expect, it } from 'vitest';
import {
  encodeBase64String,
  exactUrlMatch,
  hexToBytes,
  sha256Hex,
  utf8Bytes,
  verifyNip98Completion,
  type AuthCompleteRequest,
} from '../src/index.js';

const PRIVATE_KEY_BYTES = hexToBytes(
  '1111111111111111111111111111111111111111111111111111111111111111'
);
const AUDIENCE = 'https://api.example.com/auth/complete';

/**
 * A completion whose `u` tag is whatever the caller passes, signed correctly.
 *
 * The signature has to be valid for the request to reach the URL check at all,
 * which is the point: a throwaway key costs an attacker nothing, so "you need a
 * valid signature first" is not a barrier to reaching this code path.
 */
function signedCompletionWithUrlTag(urlTag: string): {
  authorization: string;
  rawBody: Uint8Array;
  body: AuthCompleteRequest;
} {
  const body: AuthCompleteRequest = { challenge_id: 'challenge-id-1' };
  const rawBody = utf8Bytes(JSON.stringify(body));
  const event = finalizeEvent(
    {
      kind: 27235,
      created_at: 1_710_000_005,
      tags: [
        ['u', urlTag],
        ['method', 'POST'],
        ['payload', sha256Hex(rawBody)],
        ['challenge', 'challenge-123'],
        ['challenge_id', body.challenge_id],
      ],
      content: '',
    },
    PRIVATE_KEY_BYTES
  );

  return { authorization: `Nostr ${encodeBase64String(JSON.stringify(event))}`, rawBody, body };
}

describe('exactUrlMatch', () => {
  it('is total: an unparseable URL is a mismatch, not a thrown error', () => {
    // `new URL()` throws on each of these. Before the fix that throw escaped
    // `verifyNip98Completion()` and became a 500 at the adapter.
    for (const malformed of ['not-a-url', '', '   ', '///', 'http://', '::::']) {
      expect(() => exactUrlMatch(malformed, AUDIENCE)).not.toThrow();
      expect(exactUrlMatch(malformed, AUDIENCE)).toBe(false);
    }
  });

  it('is total when the configured audience is the unparseable side', () => {
    expect(() => exactUrlMatch(AUDIENCE, 'not-a-url')).not.toThrow();
    expect(exactUrlMatch(AUDIENCE, 'not-a-url')).toBe(false);
  });

  it('still matches identical absolute URLs', () => {
    expect(exactUrlMatch(AUDIENCE, AUDIENCE)).toBe(true);
  });

  it('still normalizes scheme and host case', () => {
    expect(exactUrlMatch('HTTPS://API.example.com/auth/complete', AUDIENCE)).toBe(true);
  });

  // The guard against "fixing" the throw by loosening the comparison. A path,
  // scheme, or host difference must still be a mismatch -- this is the audience
  // binding, so a false positive here is an authentication bypass.
  it.each([
    ['trailing slash', 'https://api.example.com/auth/complete/'],
    ['different path', 'https://api.example.com/auth/other'],
    ['different host', 'https://evil.example.com/auth/complete'],
    ['different scheme', 'http://api.example.com/auth/complete'],
    ['different port', 'https://api.example.com:8443/auth/complete'],
    ['userinfo', 'https://user@api.example.com/auth/complete'],
  ])('still rejects a %s', (_label, candidate) => {
    expect(exactUrlMatch(candidate, AUDIENCE)).toBe(false);
  });
});

describe('verifyNip98Completion with a malformed u tag', () => {
  it('returns NAP_COMPLETE_URL_MISMATCH rather than throwing', () => {
    const { authorization, rawBody, body } = signedCompletionWithUrlTag('not-a-url');

    const result = verifyNip98Completion({
      authorization,
      method: 'POST',
      url: AUDIENCE,
      body,
      rawBody,
      now: 1_710_000_005,
    });

    // The whole point: this reaches the caller as an ordinary failure, so the
    // adapter answers the uniform padded 401 and `logFailure()` records a code.
    expect(result).toEqual(
      expect.objectContaining({ ok: false, code: 'NAP_COMPLETE_URL_MISMATCH' })
    );
  });

  it('does not throw for any unparseable u tag', () => {
    for (const malformed of ['not-a-url', '', 'http://', 'javascript:alert(1)']) {
      const { authorization, rawBody, body } = signedCompletionWithUrlTag(malformed);

      expect(() =>
        verifyNip98Completion({
          authorization,
          method: 'POST',
          url: AUDIENCE,
          body,
          rawBody,
          now: 1_710_000_005,
        })
      ).not.toThrow();
    }
  });
});
