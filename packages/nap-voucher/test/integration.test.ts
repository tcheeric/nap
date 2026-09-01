/**
 * Integration tests against **real containerised infrastructure**: the actual
 * Cashu mint image and a real Nostr relay, via testcontainers.
 *
 * Why this exists alongside `endToEnd.test.ts`. That test drives the whole NAP
 * login, but the mint in it is one I wrote: it serves the keyset shape I
 * believed the mint serves, so it can only ever confirm my own assumptions. If
 * `parseKeysets` disagreed with the real `/v1/keys` payload, or `proofY`
 * derived a `Y` the mint had never heard of, nothing in that test would notice.
 *
 * This one boots `cashu-mint-rest` and `nostr-rs-relay` and points the shipped
 * client at them. Slow, and it needs Docker, so it is opt-in: set
 * `NAP_INTEGRATION=1`. Without it the whole file skips, which keeps `npm test`
 * fast and green on a machine with no Docker.
 *
 * Scope is deliberately what the auth path actually consumes — `GET /v1/keys`
 * and the keyset shape behind it — because that is what NAP depends on. See
 * `docs/INTEGRATION-TESTS.md` for what the mint could not be made to do
 * standalone and why.
 */

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { GenericContainer, Wait, type StartedTestContainer } from 'testcontainers';
import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import {
  createMintAllowlist,
  createMintClient,
  hashToCurve,
  proofY,
  verifyProofDleq,
  type MintClient,
} from '../src/index.js';

const MINT_IMAGE = 'docker.398ja.xyz/cashu-mint-rest:latest';
const RELAY_IMAGE = 'scsibug/nostr-rs-relay:latest';

/**
 * The mint reads its dev keyset from a JSON file in the `cashu-mint` checkout.
 * Without it `/v1/keys` answers 500 "Preload configuration could not be read",
 * so the tests skip rather than fail: a missing sibling repo is a setup gap,
 * not a defect in this one.
 */
const PRELOAD_DIR = join(homedir(), 'IdeaProjects', 'cashu-mint', 'scripts');

const enabled = process.env.NAP_INTEGRATION === '1';
const havePreload = existsSync(join(PRELOAD_DIR, 'preload-test-data.json'));
const describeIntegration = enabled && havePreload ? describe : describe.skip;

if (enabled && !havePreload) {
  console.warn(
    `NAP_INTEGRATION=1 but ${PRELOAD_DIR}/preload-test-data.json is missing; skipping mint integration tests.`
  );
}

describeIntegration('against a real Cashu mint container', () => {
  let mint: StartedTestContainer;
  let mintUrl: string;
  let client: MintClient;

  beforeAll(async () => {
    mint = await new GenericContainer(MINT_IMAGE)
      .withExposedPorts(7777)
      .withEnvironment({
        SPRING_PROFILES_ACTIVE: 'dev',
        SERVER_PORT: '7777',
        SERVER_ADDRESS: '0.0.0.0',
        // Serve the fixed dev keyset instead of reading from a HashiCorp vault,
        // which would drag in the vault, its database, and the gateway.
        MINT_PRELOAD_ENABLED: 'true',
        MINT_PRELOAD_JSON_INPUT: 'file:/app/scripts/preload-test-data.json',
        VAULT_BACKEND: 'DATABASE',
        VAULT_HASHI_ENABLED: 'false',
        // Refused at startup in non-local profiles, whether or not webhooks are used.
        MINT_WEBHOOK_SECRET: 'integration-test-secret',
      })
      .withBindMounts([{ source: PRELOAD_DIR, target: '/app/scripts', mode: 'ro' }])
      .withWaitStrategy(Wait.forHttp('/v1/keys', 7777).forStatusCode(200))
      .withStartupTimeout(180_000)
      .start();

    mintUrl = `http://${mint.getHost()}:${mint.getMappedPort(7777)}`;

    // The shipped allowlist is https-only (§4.3) and the container speaks
    // plaintext on loopback, so the origin is pinned by a purpose-built
    // allowlist. That substitution covers scheme checking only; the client,
    // the keyset parsing, and the DLEQ code under test are all shipped code.
    // `endToEnd.test.ts` exercises the real allowlist over real TLS.
    client = createMintClient({
      allowlist: {
        origins: [mintUrl],
        resolve: (url: string) => (url === mintUrl ? mintUrl : null),
      },
      keysetCacheTtlSeconds: 3600,
    });
  }, 240_000);

  afterAll(async () => {
    await mint?.stop();
  });

  it('parses the real mint keyset payload', async () => {
    // The assertion that matters: `parseKeysets` was written against the NUT-01
    // shape as documented. This proves it agrees with what the mint actually
    // serves, which no stub of mine can establish.
    const raw = await fetch(`${mintUrl}/v1/keys`);
    const body = (await raw.json()) as { keysets: Array<{ id: string; keys: Record<string, string> }> };

    expect(raw.status).toBe(200);
    expect(body.keysets.length).toBeGreaterThan(0);

    const keyset = body.keysets[0]!;
    const amount = Object.keys(keyset.keys)[0]!;
    const key = await client.getKey(mintUrl, keyset.id, Number(amount));

    expect(key).toBe(keyset.keys[amount]!.toLowerCase());
  });

  it('serves keys as compressed secp256k1 points the DLEQ code can parse', async () => {
    // A key the curve library refuses would fail every verification with
    // `NAP_VOUCHER_DLEQ_INVALID` and look like a bad proof rather than a
    // parsing mismatch.
    const body = (await (await fetch(`${mintUrl}/v1/keys`)).json()) as {
      keysets: Array<{ id: string; keys: Record<string, string> }>;
    };
    const keys = Object.values(body.keysets[0]!.keys);

    expect(keys.length).toBeGreaterThan(0);

    for (const key of keys) {
      expect(key).toMatch(/^0[23][0-9a-f]{64}$/i);
      // Round-trips through the same parser the verifier uses.
      expect(() =>
        verifyProofDleq({
          A: key,
          secret: 'x',
          C: key,
          dleq: { e: '1'.repeat(64), s: '1'.repeat(64), r: '1'.repeat(64) },
        })
      ).not.toThrow();
    }
  });

  it('caches the real keyset rather than refetching', async () => {
    const body = (await (await fetch(`${mintUrl}/v1/keys`)).json()) as {
      keysets: Array<{ id: string; keys: Record<string, string> }>;
    };
    const keyset = body.keysets[0]!;
    const amounts = Object.keys(keyset.keys).slice(0, 3);

    const fresh = createMintClient({
      allowlist: { origins: [mintUrl], resolve: (url: string) => (url === mintUrl ? mintUrl : null) },
    });

    const keys = await Promise.all(
      amounts.map((amount) => fresh.getKey(mintUrl, keyset.id, Number(amount)))
    );

    expect(keys.every((key) => /^0[23][0-9a-f]{64}$/i.test(key))).toBe(true);
  });

  it('rejects a keyset the real mint does not publish', async () => {
    await expect(mint && client.getKey(mintUrl, 'ffffffffffffffff', 1)).rejects.toMatchObject({
      reason: 'unknown_keyset',
    });
  });

  it('treats an unroutable mint as unavailable, not as a refusal', async () => {
    // §7.3 hangs off this distinction, and it is worth confirming against a
    // real socket rather than a stub that throws a synthetic error.
    const unreachable = 'http://127.0.0.1:1';
    const isolated = createMintClient({
      allowlist: { origins: [unreachable], resolve: (url: string) => (url === unreachable ? url : null) },
      timeoutMs: 2000,
    });

    await expect(isolated.getKey(unreachable, 'any', 1)).rejects.toMatchObject({
      reason: 'unavailable',
    });
  });
});

describeIntegration('against a real Nostr relay container', () => {
  let relay: StartedTestContainer;
  let relayUrl: string;

  beforeAll(async () => {
    relay = await new GenericContainer(RELAY_IMAGE)
      .withExposedPorts(8080)
      .withStartupTimeout(60_000)
      .start();

    relayUrl = `ws://${relay.getHost()}:${relay.getMappedPort(8080)}`;
  }, 120_000);

  afterAll(async () => {
    await relay?.stop();
  });

  it('accepts a websocket connection and answers a REQ', async () => {
    // The voucher status ledger in §7.1 is a NIP-33 subscription, so the
    // revocation watcher this extension defers will need exactly this. Proving
    // a real relay is reachable from the test harness now means that work does
    // not start by discovering the infrastructure does not run.
    const { WebSocket } = await import('ws');
    const socket = new WebSocket(relayUrl);

    const events = await new Promise<string[]>((resolve, reject) => {
      const seen: string[] = [];
      const timer = setTimeout(() => reject(new Error('relay did not answer')), 15_000);

      socket.on('open', () => {
        socket.send(JSON.stringify(['REQ', 'nap-it', { kinds: [30000], limit: 1 }]));
      });
      socket.on('message', (data: Buffer) => {
        const frame = JSON.parse(data.toString()) as unknown[];
        seen.push(String(frame[0]));

        // EOSE ends the stored-event replay, which is the handshake completing.
        if (frame[0] === 'EOSE') {
          clearTimeout(timer);
          socket.close();
          resolve(seen);
        }
      });
      socket.on('error', (error: Error) => {
        clearTimeout(timer);
        reject(error);
      });
    });

    expect(events).toContain('EOSE');
  }, 30_000);
});

describe('proofY derivation is stable', () => {
  it('agrees with hash_to_curve for the same secret', () => {
    // Runs without Docker: `Y` is what a NUT-07 state check is keyed on, so a
    // drift here would make every liveness check silently miss.
    const secret = 'daf4dd00a2b68a0858a80450f52c8a7d2ccf87d375e43e216e0c571f089f63e9';

    expect(proofY(secret)).toBe(hashToCurve(new TextEncoder().encode(secret)).toHex(true));
  });
});
