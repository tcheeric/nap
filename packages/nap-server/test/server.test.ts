import { finalizeEvent, getPublicKey, nip19 } from 'nostr-tools';
import { describe, expect, it } from 'vitest';
import { encodeBase64String, hexToBytes, sha256Hex, utf8Bytes } from '@imani/nap-core';
import type { AuthInitResponse } from '@imani/nap-core';
import {
  createNapServer,
  InMemoryChallengeStore,
  InMemorySessionStore,
  issueChallenge,
  toPublicAuthSuccess,
  verifyCompletion,
  type NapServerOptions,
} from '../src/index.js';

const PRIVATE_KEY_HEX = '1111111111111111111111111111111111111111111111111111111111111111';
const PRIVATE_KEY_BYTES = hexToBytes(PRIVATE_KEY_HEX);
const PUBKEY = getPublicKey(PRIVATE_KEY_BYTES);
const NPUB = nip19.npubEncode(PUBKEY);
const AUTH_URL = 'https://api.example.com/auth/complete';

function buildOptions(now = 1_710_000_000): NapServerOptions {
  return {
    challengeStore: new InMemoryChallengeStore(),
    sessionStore: new InMemorySessionStore(),
    aclResolver: {
      async resolve() {
        return {
          allowed: true,
          roles: ['merchant'],
          permissions: ['voucher:issue'],
        };
      },
    },
    // The 100 ms response floor is a production timing defence; paying it on
    // every assertion here would cost more wall-clock than the suite.
    minAuthResponseMillis: 0,
    clock: {
      nowUnix() {
        return now;
      },
    },
    randomSource: {
      randomBytes(length: number) {
        return new Uint8Array(Array.from({ length }, (_, index) => (index + 1) % 255));
      },
    },
  };
}

function buildAuthorization(challengeId: string, challenge: string, createdAt = 1_710_000_000): { authorization: string; rawBody: Uint8Array } {
  const rawBody = utf8Bytes(JSON.stringify({ challenge_id: challengeId }));
  const event = finalizeEvent(
    {
      kind: 27235,
      created_at: createdAt,
      tags: [
        ['u', 'https://api.example.com/auth/complete'],
        ['method', 'POST'],
        ['payload', sha256Hex(rawBody)],
        ['challenge', challenge],
        ['challenge_id', challengeId],
      ],
      content: '',
    },
    PRIVATE_KEY_BYTES
  );

  return {
    authorization: `Nostr ${encodeBase64String(JSON.stringify(event))}`,
    rawBody,
  };
}

describe('nap-server', () => {
  it('issues a challenge and completes authentication', async () => {
    const options = buildOptions();
    const challenge = await issueChallenge(
      {
        npub: NPUB,
        authUrl: 'https://api.example.com/auth/complete',
      },
      options
    );

    expect(challenge.ok).toBe(true);

    if (!challenge.ok) {
      return;
    }

    const completion = buildAuthorization(challenge.value.challenge_id, challenge.value.challenge);
    const result = await verifyCompletion(
      {
        authorization: completion.authorization,
        method: 'POST',
        url: 'https://api.example.com/auth/complete',
        rawBody: completion.rawBody,
      },
      options
    );

    expect(result.ok).toBe(true);

    if (result.ok) {
      const publicResult = toPublicAuthSuccess(result.session);
      expect(publicResult.principal.npub).toBe(NPUB);
      expect(publicResult.roles).toEqual(['merchant']);
    }
  });

  it('returns the same session on a valid retry', async () => {
    const options = buildOptions();
    const challenge = await issueChallenge(
      {
        npub: NPUB,
        authUrl: 'https://api.example.com/auth/complete',
      },
      options
    );

    expect(challenge.ok).toBe(true);

    if (!challenge.ok) {
      return;
    }

    const completion = buildAuthorization(challenge.value.challenge_id, challenge.value.challenge);
    const first = await verifyCompletion(
      {
        authorization: completion.authorization,
        method: 'POST',
        url: 'https://api.example.com/auth/complete',
        rawBody: completion.rawBody,
      },
      options
    );

    const second = await verifyCompletion(
      {
        authorization: completion.authorization,
        method: 'POST',
        url: 'https://api.example.com/auth/complete',
        rawBody: completion.rawBody,
      },
      options
    );

    expect(first.ok).toBe(true);
    expect(second.ok).toBe(true);

    if (first.ok && second.ok) {
      expect(first.session.session_id).toBe(second.session.session_id);
      expect(first.session.access_token).toBe(second.session.access_token);
    }
  });

  it('provides a bound server instance API', async () => {
    const options = buildOptions();
    const server = createNapServer(options);
    const challenge = await server.issueChallenge({
      npub: NPUB,
      authUrl: 'https://api.example.com/auth/complete',
    });

    expect(challenge.ok).toBe(true);

    if (!challenge.ok) {
      return;
    }

    const completion = buildAuthorization(challenge.value.challenge_id, challenge.value.challenge);
    const result = await server.verifyCompletion({
      authorization: completion.authorization,
      method: 'POST',
      url: 'https://api.example.com/auth/complete',
      rawBody: completion.rawBody,
    });

    expect(result.ok).toBe(true);
  });

  it('rejects a principal mismatch', async () => {
    const options = buildOptions();
    const challenge = await issueChallenge(
      {
        npub: NPUB,
        authUrl: 'https://api.example.com/auth/complete',
      },
      options
    );

    expect(challenge.ok).toBe(true);

    if (!challenge.ok) {
      return;
    }

    const otherKey = hexToBytes('2222222222222222222222222222222222222222222222222222222222222222');
    const rawBody = utf8Bytes(JSON.stringify({ challenge_id: challenge.value.challenge_id }));
    const event = finalizeEvent(
      {
        kind: 27235,
        created_at: 1_710_000_000,
        tags: [
          ['u', 'https://api.example.com/auth/complete'],
          ['method', 'POST'],
          ['payload', sha256Hex(rawBody)],
          ['challenge', challenge.value.challenge],
          ['challenge_id', challenge.value.challenge_id],
        ],
        content: '',
      },
      otherKey
    );

    const result = await verifyCompletion(
      {
        authorization: `Nostr ${encodeBase64String(JSON.stringify(event))}`,
        method: 'POST',
        url: 'https://api.example.com/auth/complete',
        rawBody,
      },
      options
    );

    expect(result).toEqual({
      ok: false,
      code: 'NAP_COMPLETE_PRINCIPAL_MISMATCH',
      retryable: false,
    });
  });
});

/**
 * Capability advertisement (#16, extension 0001 §8).
 *
 * A client holding a credential that gets a 401 cannot tell "this server has no
 * such feature" from "your credential was refused" — and the two call for
 * opposite actions: retry without the credential, or do not retry at all. The
 * failure codes that would distinguish them are deliberately invisible, so the
 * signal has to arrive before the attempt.
 *
 * Safe to publish precisely because it describes the *server*, not a principal:
 * it names a feature anyone can read about in the docs, is sent before the
 * client signs anything, and reveals nothing about any credential or mint.
 */
describe('supported_extensions on /auth/init', () => {
  it('is absent when unconfigured, which is what every existing server sends', async () => {
    const options = buildOptions();
    const outcome = await issueChallenge({ npub: NPUB, authUrl: AUTH_URL }, options);

    expect(outcome.ok).toBe(true);
    // Absent rather than `[]`: "makes no claim" and "supports nothing" are
    // different, and a client must read absence as unknown. An older server
    // that supports an extension but predates this field would otherwise be
    // locked out of it.
    expect((outcome as { ok: true; value: AuthInitResponse }).value.supported_extensions).toBeUndefined();
  });

  it('advertises what the operator declared', async () => {
    const options = { ...buildOptions(), supportedExtensions: ['voucher-acl/1'] };
    const outcome = await issueChallenge({ npub: NPUB, authUrl: AUTH_URL }, options);

    expect((outcome as { ok: true; value: AuthInitResponse }).value.supported_extensions).toEqual([
      'voucher-acl/1',
    ]);
  });

  it('treats an empty list as no claim rather than as an empty claim', async () => {
    const options = { ...buildOptions(), supportedExtensions: [] };
    const outcome = await issueChallenge({ npub: NPUB, authUrl: AUTH_URL }, options);

    expect((outcome as { ok: true; value: AuthInitResponse }).value.supported_extensions).toBeUndefined();
  });

  it('copies the array, so a later mutation cannot change what was advertised', async () => {
    const declared = ['voucher-acl/1'];
    const options = { ...buildOptions(), supportedExtensions: declared };
    const outcome = await issueChallenge({ npub: NPUB, authUrl: AUTH_URL }, options);
    const advertised = (outcome as { ok: true; value: AuthInitResponse }).value.supported_extensions!;

    advertised.push('mutated');

    expect(declared).toEqual(['voucher-acl/1']);
  });
});
