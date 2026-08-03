import { finalizeEvent, getPublicKey } from 'nostr-tools';
import { describe, expect, it } from 'vitest';
import {
  encodeBase64String,
  hexToBytes,
  sha256Hex,
  utf8Bytes,
  verifyNip98Completion,
  type AuthCompleteRequest,
} from '../src/index.js';

const PRIVATE_KEY_HEX = '1111111111111111111111111111111111111111111111111111111111111111';
const PRIVATE_KEY_BYTES = hexToBytes(PRIVATE_KEY_HEX);

function buildBody(body: AuthCompleteRequest): Uint8Array {
  return utf8Bytes(JSON.stringify(body));
}

function buildAuthorization(body: AuthCompleteRequest, challenge = 'challenge-123', createdAt = 1_710_000_005): string {
  const rawBody = buildBody(body);
  const event = finalizeEvent(
    {
      kind: 27235,
      created_at: createdAt,
      tags: [
        ['u', 'https://api.example.com/auth/complete'],
        ['method', 'POST'],
        ['payload', sha256Hex(rawBody)],
        ['challenge', challenge],
        ['challenge_id', body.challenge_id],
      ],
      content: '',
    },
    PRIVATE_KEY_BYTES
  );

  return `Nostr ${encodeBase64String(JSON.stringify(event))}`;
}

describe('nap-core', () => {
  it('produces the canonical payload hash vector', () => {
    const rawBody = utf8Bytes('{"challenge_id":"chlg_01HT..."}');

    expect(rawBody.byteLength).toBe(31);
    expect(sha256Hex(rawBody)).toBe('df5a3e3495e2fa3163de8b0df9a7b54a7b873ffbee4e24c74ebac529d577e3cd');
  });

  it('verifies a valid completion proof', () => {
    const body = { challenge_id: 'chlg_123' };
    const rawBody = buildBody(body);

    const result = verifyNip98Completion({
      authorization: buildAuthorization(body),
      method: 'POST',
      url: 'https://api.example.com/auth/complete',
      body,
      rawBody,
      now: 1_710_000_010,
    });

    expect(result.ok).toBe(true);

    if (result.ok) {
      expect(result.value.challengeId).toBe(body.challenge_id);
      expect(result.value.event.pubkey).toBe(getPublicKey(PRIVATE_KEY_BYTES));
    }
  });

  it('rejects missing payload tag', () => {
    const body = { challenge_id: 'chlg_123' };
    const rawBody = buildBody(body);
    const event = finalizeEvent(
      {
        kind: 27235,
        created_at: 1_710_000_005,
        tags: [
          ['u', 'https://api.example.com/auth/complete'],
          ['method', 'POST'],
          ['challenge', 'challenge-123'],
          ['challenge_id', body.challenge_id],
        ],
        content: '',
      },
      PRIVATE_KEY_BYTES
    );

    const result = verifyNip98Completion({
      authorization: `Nostr ${encodeBase64String(JSON.stringify(event))}`,
      method: 'POST',
      url: 'https://api.example.com/auth/complete',
      body,
      rawBody,
      now: 1_710_000_010,
    });

    expect(result).toEqual({
      ok: false,
      code: 'NAP_COMPLETE_MISSING_PAYLOAD',
      retryable: false,
    });
  });

  it('rejects exact URL mismatch', () => {
    const body = { challenge_id: 'chlg_123' };
    const rawBody = buildBody(body);

    const result = verifyNip98Completion({
      authorization: buildAuthorization(body),
      method: 'POST',
      url: 'https://api.example.com/auth/complete/',
      body,
      rawBody,
      now: 1_710_000_010,
    });

    expect(result).toEqual({
      ok: false,
      code: 'NAP_COMPLETE_URL_MISMATCH',
      retryable: false,
    });
  });
});
