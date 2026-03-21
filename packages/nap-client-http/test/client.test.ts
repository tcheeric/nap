import { describe, expect, it } from 'vitest';
import { parseNostrAuthorizationHeader } from '@imani/nap-core';
import {
  buildAuthCompleteRequest,
  createPrivateKeySigner,
  serializeAuthCompleteBody,
} from '../src/index.js';

const PRIVATE_KEY_HEX = '1111111111111111111111111111111111111111111111111111111111111111';

describe('nap-client-http', () => {
  it('serializes the canonical completion body', () => {
    const rawBody = serializeAuthCompleteBody({ challenge_id: 'chlg_01HT...' });

    expect(new TextDecoder().decode(rawBody)).toBe('{"challenge_id":"chlg_01HT..."}');
  });

  it('builds a completion request with a NIP-98 authorization header', async () => {
    const request = await buildAuthCompleteRequest({
      challenge: {
        challenge_id: 'chlg_123',
        challenge: 'challenge-123',
        auth_url: 'https://api.example.com/auth/complete',
        auth_method: 'POST',
        issued_at: 1_710_000_000,
        expires_at: 1_710_000_060,
      },
      signer: createPrivateKeySigner(PRIVATE_KEY_HEX),
      createdAt: 1_710_000_005,
    });

    expect(request.method).toBe('POST');
    expect(request.url).toBe('https://api.example.com/auth/complete');
    expect(new TextDecoder().decode(request.rawBody)).toBe('{"challenge_id":"chlg_123"}');
    expect(request.authorization.startsWith('Nostr ')).toBe(true);

    const event = parseNostrAuthorizationHeader(request.authorization);
    expect(event?.tags).toContainEqual(['challenge_id', 'chlg_123']);
    expect(event?.tags).toContainEqual(['challenge', 'challenge-123']);
  });
});
