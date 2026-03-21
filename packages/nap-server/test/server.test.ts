import { finalizeEvent, getPublicKey, nip19 } from 'nostr-tools';
import { describe, expect, it } from 'vitest';
import { encodeBase64String, sha256Hex, utf8Bytes } from '@imani/nap-core';
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
const PRIVATE_KEY_BYTES = Uint8Array.from(Buffer.from(PRIVATE_KEY_HEX, 'hex'));
const PUBKEY = getPublicKey(PRIVATE_KEY_BYTES);
const NPUB = nip19.npubEncode(PUBKEY);

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

    const otherKey = Uint8Array.from(Buffer.from('2222222222222222222222222222222222222222222222222222222222222222', 'hex'));
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
