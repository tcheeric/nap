import { finalizeEvent, getPublicKey, nip19 } from 'nostr-tools';
import { beforeEach, describe, expect, it } from 'vitest';
import { encodeBase64String, hexToBytes, sha256Hex, utf8Bytes } from '@imani/nap-core';
import {
  createInMemoryRateLimiter,
  InMemoryChallengeStore,
  InMemorySessionStore,
  issueChallenge,
  verifyCompletion,
  type MetricsRecorder,
  type NapCounter,
  type NapServerOptions,
} from '../src/index.js';

const AUTH_URL = 'https://api.example.com/auth/complete';
const NOW = 1_710_000_000;

const PRIVATE_KEY_BYTES = hexToBytes(
  '1111111111111111111111111111111111111111111111111111111111111111'
);
const PUBKEY = getPublicKey(PRIVATE_KEY_BYTES);
const NPUB = nip19.npubEncode(PUBKEY);

let counter = 0;

/** Counts by name, so a test asserts on the counter and not on call order. */
function recordingMetrics(): MetricsRecorder & { counts: Partial<Record<NapCounter, number>> } {
  const counts: Partial<Record<NapCounter, number>> = {};

  return {
    counts,
    increment(name) {
      counts[name] = (counts[name] ?? 0) + 1;
    },
  };
}

function buildOptions(overrides: Partial<NapServerOptions> = {}): NapServerOptions {
  return {
    challengeStore: new InMemoryChallengeStore(),
    sessionStore: new InMemorySessionStore(),
    aclResolver: {
      async resolve() {
        return { allowed: true, roles: [], permissions: [] };
      },
    },
    minAuthResponseMillis: 0,
    responseJitterMillis: 0,
    clock: { nowUnix: () => NOW },
    randomSource: {
      randomBytes(length: number) {
        const seed = counter++;
        return new Uint8Array(Array.from({ length }, (_, index) => (index + seed * 7 + 1) % 255));
      },
    },
    ...overrides,
  };
}

function completionFor(
  challengeId: string,
  challenge: string,
  opts: { url?: string; tamperBody?: boolean } = {}
): { authorization: string; rawBody: Uint8Array } {
  const rawBody = utf8Bytes(JSON.stringify({ challenge_id: challengeId }));
  const event = finalizeEvent(
    {
      kind: 27235,
      created_at: NOW,
      tags: [
        ['u', opts.url ?? AUTH_URL],
        ['method', 'POST'],
        ['payload', sha256Hex(opts.tamperBody ? utf8Bytes('{}') : rawBody)],
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

async function issue(options: NapServerOptions) {
  const result = await issueChallenge({ npub: NPUB, authUrl: AUTH_URL }, options);

  if (!result.ok) {
    throw new Error(`expected a challenge, got ${result.code}`);
  }

  return result.value;
}

function complete(
  options: NapServerOptions,
  proof: { authorization: string; rawBody: Uint8Array },
  url = AUTH_URL
) {
  return verifyCompletion(
    { authorization: proof.authorization, method: 'POST', url, rawBody: proof.rawBody },
    options
  );
}

describe('metrics recorder (RFC §19.3)', () => {
  let metrics: ReturnType<typeof recordingMetrics>;
  let options: NapServerOptions;

  beforeEach(() => {
    metrics = recordingMetrics();
    options = buildOptions({ metrics });
  });

  it('counts a full login across the init, complete, success, and redeemed counters', async () => {
    const challenge = await issue(options);
    const outcome = await complete(
      options,
      completionFor(challenge.challenge_id, challenge.challenge)
    );

    expect(outcome.ok).toBe(true);
    expect(metrics.counts).toEqual({
      auth_init_total: 1,
      auth_complete_total: 1,
      auth_success_total: 1,
      challenge_redeemed_total: 1,
    });
  });

  it('separates a replayed completion into the retry counter, not a second redemption', async () => {
    const challenge = await issue(options);
    const proof = completionFor(challenge.challenge_id, challenge.challenge);

    await complete(options, proof);
    const retry = await complete(options, proof);

    expect(retry.ok).toBe(true);
    expect(metrics.counts.challenge_redeemed_total).toBe(1);
    expect(metrics.counts.challenge_retry_hit_total).toBe(1);
    expect(metrics.counts.auth_success_total).toBe(2);
  });

  it('counts an expired challenge as both a failure and an expiry', async () => {
    let now = NOW;
    // A short TTL so the clock can pass `expires_at` while the signed
    // `created_at` is still inside the skew window — otherwise the proof is
    // rejected before the challenge is ever looked up.
    options = buildOptions({
      metrics,
      challengeTtlSeconds: 5,
      clock: { nowUnix: () => now },
    });

    const challenge = await issue(options);
    const proof = completionFor(challenge.challenge_id, challenge.challenge);

    now = challenge.expires_at + 1;
    const outcome = await complete(options, proof);

    expect(outcome.ok).toBe(false);
    expect(metrics.counts.auth_failure_total).toBe(1);
    expect(metrics.counts.challenge_expired_total).toBe(1);
    expect(metrics.counts.challenge_redeemed_total).toBeUndefined();
  });

  it('counts a signed audience that is not the one the server computed', async () => {
    const challenge = await issue(options);
    const proof = completionFor(challenge.challenge_id, challenge.challenge, {
      url: 'https://evil.example.com/auth/complete',
    });

    const outcome = await complete(options, proof);

    expect(outcome.ok).toBe(false);
    expect(metrics.counts.audience_mismatch_total).toBe(1);
  });

  it('counts a body that no longer hashes to the signed payload tag', async () => {
    const challenge = await issue(options);
    const proof = completionFor(challenge.challenge_id, challenge.challenge, {
      tamperBody: true,
    });

    const outcome = await complete(options, proof);

    expect(outcome.ok).toBe(false);
    expect(metrics.counts.payload_mismatch_total).toBe(1);
  });

  it('counts a rate-limited request apart from a failure', async () => {
    options = buildOptions({
      metrics,
      rateLimiter: createInMemoryRateLimiter({ maxPerWindow: 1, windowSeconds: 60 }),
    });

    await issue(options);
    const denied = await issueChallenge({ npub: NPUB, authUrl: AUTH_URL }, options);

    expect(denied.ok).toBe(false);
    expect(metrics.counts.auth_rate_limited_total).toBe(1);
    expect(metrics.counts.auth_failure_total).toBeUndefined();
    expect(metrics.counts.auth_init_total).toBe(2);
  });

  it('counts a request too malformed to reach any audit point', async () => {
    const outcome = await complete(options, {
      authorization: 'Nostr not-base64',
      rawBody: utf8Bytes('not json'),
    });

    expect(outcome.ok).toBe(false);
    expect(metrics.counts.auth_complete_total).toBe(1);
    expect(metrics.counts.auth_failure_total).toBeUndefined();
  });

  it('still calls the audit logger it decorates', async () => {
    const seen: string[] = [];
    options = buildOptions({
      metrics,
      auditLogger: {
        log(event) {
          seen.push(event.code);
        },
      },
    });

    const challenge = await issue(options);
    await complete(options, completionFor(challenge.challenge_id, challenge.challenge));

    expect(seen).toEqual(['NAP_COMPLETE_SUCCESS']);
  });
});
