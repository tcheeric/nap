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
import express from 'express';
import request from 'supertest';
import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { getPublicKey, nip19 } from 'nostr-tools';
import { schnorr, secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes as nobleHexToBytes } from '@noble/hashes/utils.js';
import { hexToBytes } from '@imani/nap-core';
import { buildAuthCompleteRequest, createPrivateKeySigner } from '@imani/nap-client-http';
import {
  InMemoryChallengeStore,
  InMemorySessionStore,
  type NapServerOptions,
} from '@imani/nap-server';
import {
  createNapExpressRouter,
  createRequestDerivedBaseUrlResolver,
} from '@imani/nap-adapter-express';
import {
  createIssuerAllowlist,
  createMintAllowlist,
  createMintAvailabilityPolicy,
  createVoucherAclResolver,
  hashE,
  hashToCurve,
  parseVoucherSecret,
  proofY,
  verifyProofDleq,
  voucherCanonicalBytes,
  createMintClient,
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

// --- helpers for the real-mint login block -------------------------------
//
// Kept here rather than in the describe so the crypto is readable in one place:
// this is the part a reader has to trust, and burying it inside a test body
// would make it look incidental.

const Point = secp256k1.Point;
const ORDER = secp256k1.Point.Fn.ORDER;
const NOW = 1_710_000_000;
const HOLDER_PRIVATE = '1'.repeat(64);
const ISSUER_PRIVATE = nobleHexToBytes('11'.repeat(32));
const ISSUER_PUBKEY = bytesToHex(schnorr.getPublicKey(ISSUER_PRIVATE));

/**
 * The preload fixture's private key for one amount.
 *
 * The fixture is `{ keySetId, keys: [{ amount, privateKeyHex }, ...] }`. Read
 * by shape rather than by index, so a reordered or extended fixture still
 * resolves -- and so a *missing* amount fails with a message naming it rather
 * than yielding undefined somewhere further down.
 */
function privateKeyForAmount(
  fixture: unknown,
  amount: number
): { keysetId: string; privateKeyHex: string } | null {
  if (fixture === null || typeof fixture !== 'object') {
    return null;
  }

  const record = fixture as { keySetId?: unknown; keys?: unknown };

  if (typeof record.keySetId !== 'string' || !Array.isArray(record.keys)) {
    return null;
  }

  for (const entry of record.keys) {
    if (entry === null || typeof entry !== 'object') {
      continue;
    }

    const key = entry as { amount?: unknown; privateKeyHex?: unknown };

    if (
      key.amount === amount &&
      typeof key.privateKeyHex === 'string' &&
      /^[0-9a-f]{64}$/i.test(key.privateKeyHex)
    ) {
      return { keysetId: record.keySetId, privateKeyHex: key.privateKeyHex };
    }
  }

  return null;
}

/** An issuer-signed `P2PK_VOUCHER` secret locked to `lockedTo`. */
function issuerSignedSecret(lockedTo: string, expiresAt: number): string {
  const body = {
    nonce: 'nap-integration',
    data: `02${lockedTo}`,
    tags: [
      ['issuer', 'imani'],
      ['unit', 'sat'],
      ['expires_at', String(expiresAt)],
    ],
  };
  const unsigned = parseVoucherSecret(JSON.stringify(['P2PK_VOUCHER', body]))!;
  const signature = bytesToHex(
    schnorr.sign(sha256(voucherCanonicalBytes(unsigned)), ISSUER_PRIVATE)
  );

  return JSON.stringify([
    'P2PK_VOUCHER',
    {
      ...body,
      tags: [...body.tags, ['issuer_pubkey', ISSUER_PUBKEY], ['issuer_sig', signature]],
    },
  ]);
}

/**
 * Plays the mint: a BDHKE blind signature over `secret` using private scalar
 * `a`, plus the NUT-12 DLEQ proving it.
 */
function blindSignWith(a: bigint, secret: string) {
  const A = Point.BASE.multiply(a);
  const r = BigInt(`0x${'55'.repeat(32)}`) % ORDER;
  const B_ = hashToCurve(new TextEncoder().encode(secret)).add(Point.BASE.multiply(r));
  const C_ = B_.multiply(a);
  const k = BigInt(`0x${'66'.repeat(32)}`) % ORDER;
  const e = BigInt(`0x${bytesToHex(hashE(Point.BASE.multiply(k), B_.multiply(k), A, C_))}`) % ORDER;
  const hex = (value: bigint) => value.toString(16).padStart(64, '0');

  return {
    C: C_.add(A.multiply(r).negate()).toHex(true),
    dleq: { e: hex(e), s: hex((k + e * a) % ORDER), r: hex(r) },
  };
}

/** Drives a full NAP login whose resolver fetches keys from the real mint. */
async function login(input: {
  mintUrl: string;
  keysetId: string;
  amount: number;
  secret: string;
  signature: string;
  dleq: { e: string; s: string; r: string };
}) {
  const allowlist = {
    origins: [input.mintUrl],
    resolve: (url: string) => (url === input.mintUrl ? input.mintUrl : null),
  };
  const mintClient = createMintClient({ allowlist });

  const options: NapServerOptions = {
    challengeStore: new InMemoryChallengeStore(),
    sessionStore: new InMemorySessionStore(),
    aclResolver: createVoucherAclResolver({
      mintAllowlist: allowlist,
      issuerAllowlist: createIssuerAllowlist(
        [{ mint: input.mintUrl, issuerPubkey: ISSUER_PUBKEY }],
        allowlist
      ),
      // Keys come from the real mint; only the NUT-07 state check is stubbed,
      // because that endpoint needs a datastore this container does not run.
      // See docs/INTEGRATION-TESTS.md.
      mintClient: {
        getKey: mintClient.getKey,
        checkState: async () => 'UNSPENT' as const,
        clearCache: mintClient.clearCache,
      },
      availability: createMintAvailabilityPolicy(),
      grant: (voucher) => ({
        roles: ['voucher-holder'],
        permissions: [`voucher:view:${voucher.unit}`],
      }),
    }),
    minAuthResponseMillis: 0,
    clock: { nowUnix: () => NOW },
  };

  const app = express();
  app.set('trust proxy', true);
  app.use(
    '/auth',
    createNapExpressRouter({
      server: options,
      getExternalBaseUrl: createRequestDerivedBaseUrlResolver(['api.example.com']),
    })
  );

  const post = (path: string) =>
    request(app).post(path).set('host', 'api.example.com').set('x-forwarded-proto', 'https');

  const npub = nip19.npubEncode(getPublicKey(hexToBytes(HOLDER_PRIVATE)));
  const init = await post('/auth/init').send({ npub });
  const built = await buildAuthCompleteRequest({
    challenge: init.body,
    signer: createPrivateKeySigner(HOLDER_PRIVATE),
    createdAt: NOW,
    voucher: {
      mint_url: input.mintUrl,
      keyset_id: input.keysetId,
      secret: input.secret,
      signature: input.signature,
      amount: input.amount,
      dleq: input.dleq,
    },
  });

  return post('/auth/complete')
    .set('authorization', built.authorization)
    .set('content-type', 'application/json')
    .send(new TextDecoder().decode(built.rawBody));
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

  it('advertises the NUTs this extension is built on', async () => {
    // Extension 0001 rests on NUT-10 (well-known secrets), NUT-11 (P2PK),
    // NUT-12 (DLEQ) and NUT-07 (state). If a mint stopped advertising one, the
    // extension's assumptions would be wrong in a way no NAP-side test could
    // see -- the failures would surface as invalid proofs rather than as a
    // missing capability.
    const info = (await (await fetch(`${mintUrl}/v1/info`)).json()) as {
      version: string;
      nuts: Record<string, unknown>;
    };

    expect(info.version).toMatch(/^cashu-mint\//);

    for (const nut of ['7', '10', '11', '12']) {
      expect(Object.keys(info.nuts), `NUT-${nut} should be advertised`).toContain(nut);
    }
  });

  it('does not advertise P2PK_VOUCHER, which is deliberate', async () => {
    // ADR 0003: the composite kind is an Imani extension with no NUT number and
    // no published vectors, so `/v1/info` deliberately stays silent about it.
    // Asserted so that if it ever *is* advertised, that is a considered change
    // rather than a drift -- and so a reader does not assume its absence is an
    // oversight.
    const body = await (await fetch(`${mintUrl}/v1/info`)).text();

    expect(body).not.toContain('P2PK_VOUCHER');
  });

  it('serves every advertised keyset through the shipped client', async () => {
    // `/v1/keysets` lists what `/v1/keys` should resolve. A mint advertising a
    // keyset it cannot serve keys for would fail a login only for proofs from
    // that keyset, which is the kind of partial failure that hides in
    // production.
    const listed = (await (await fetch(`${mintUrl}/v1/keysets`)).json()) as {
      keysets: Array<{ id: string; unit: string; active?: boolean }>;
    };

    expect(listed.keysets.length).toBeGreaterThan(0);

    const served = (await (await fetch(`${mintUrl}/v1/keys`)).json()) as {
      keysets: Array<{ id: string; keys: Record<string, string> }>;
    };
    const servedIds = new Set(served.keysets.map((keyset) => keyset.id));

    for (const keyset of listed.keysets) {
      // Only active keysets must serve keys; an inactive one is a historical
      // keyset kept for verification of old proofs.
      if (keyset.active === false) {
        continue;
      }

      expect(servedIds, `keyset ${keyset.id} is advertised`).toContain(keyset.id);

      const amount = Number(Object.keys(served.keysets.find((k) => k.id === keyset.id)!.keys)[0]);

      await expect(client.getKey(mintUrl, keyset.id, amount)).resolves.toMatch(
        /^0[23][0-9a-f]{64}$/i
      );
    }
  });

  it('rejects an amount the keyset does not carry', async () => {
    // Amounts are powers of two; 3 is not one. A mint answering *something* for
    // a nonsense amount would let a forged proof pick a key the mint never
    // used, so the refusal matters more than it looks.
    const served = (await (await fetch(`${mintUrl}/v1/keys`)).json()) as {
      keysets: Array<{ id: string; keys: Record<string, string> }>;
    };
    const keyset = served.keysets[0]!;

    expect(Object.keys(keyset.keys)).not.toContain('3');
    await expect(client.getKey(mintUrl, keyset.id, 3)).rejects.toMatchObject({
      reason: 'unknown_keyset',
    });
  });

  it('refuses a mint URL the allowlist does not carry, before any request', async () => {
    // The SSRF guard (§4.3) against a real client rather than a stub: the
    // client must refuse without opening a socket, and the reason must be the
    // definite `mint_not_allowed` rather than the degradable `unavailable`.
    await expect(client.getKey('http://169.254.169.254', 'any', 1)).rejects.toMatchObject({
      reason: 'mint_not_allowed',
    });
  });

  it('reports a definite refusal when the mint answers 4xx', async () => {
    // §7.3 turns on this distinction: only `unavailable` may degrade. A mint
    // that answers -- even with an error -- has refused, and degrading on that
    // would accept a voucher the mint has actually rejected. Verified against a
    // real 404 from the real server rather than a synthesised response.
    const notFound = `${mintUrl}/v1/definitely-not-an-endpoint`;
    const response = await fetch(notFound);

    expect(response.status).toBeGreaterThanOrEqual(400);
    expect(response.status).toBeLessThan(500);
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

/**
 * A complete voucher-bound login where the **mint is real**.
 *
 * `acceptance.test.ts` proves the same outcome, but every byte in it comes from
 * this repository: I mint the proof, I serve the key, I decide what `/v1/keys`
 * would have said. It cannot tell me that the key the real mint publishes is
 * one the DLEQ verifier accepts as `A`, only that the key I invented is.
 *
 * Here the mint's own published key is the `A` the proof is built against and
 * the `A` the resolver fetches. A disagreement between the mint's key encoding
 * and this package's parsing shows up as a failed login rather than as a
 * passing test built on a shared assumption.
 *
 * The mint's private key is known here because the container is preloaded with
 * a fixed dev keyset -- which is what makes signing a proof against it possible
 * at all. That is a property of the test fixture, not of any real mint.
 */
describeIntegration('a voucher-bound login against the real mint', () => {
  let mint: StartedTestContainer;
  let mintUrl: string;

  beforeAll(async () => {
    mint = await new GenericContainer(MINT_IMAGE)
      .withExposedPorts(7777)
      .withEnvironment({
        SPRING_PROFILES_ACTIVE: 'dev',
        SERVER_PORT: '7777',
        SERVER_ADDRESS: '0.0.0.0',
        MINT_PRELOAD_ENABLED: 'true',
        MINT_PRELOAD_JSON_INPUT: 'file:/app/scripts/preload-test-data.json',
        VAULT_BACKEND: 'DATABASE',
        VAULT_HASHI_ENABLED: 'false',
        MINT_WEBHOOK_SECRET: 'integration-test-secret',
      })
      .withBindMounts([{ source: PRELOAD_DIR, target: '/app/scripts', mode: 'ro' }])
      .withWaitStrategy(Wait.forHttp('/v1/keys', 7777).forStatusCode(200))
      .withStartupTimeout(180_000)
      .start();

    mintUrl = `http://${mint.getHost()}:${mint.getMappedPort(7777)}`;
  }, 240_000);

  afterAll(async () => {
    await mint?.stop();
  });

  /** The dev keyset's private scalar for one amount, from the preload fixture. */
  async function mintSecretFor(amount: number): Promise<{ a: bigint; A: string; keysetId: string }> {
    const preload = JSON.parse(
      await readFile(join(PRELOAD_DIR, 'preload-test-data.json'), 'utf8')
    ) as unknown;
    const found = privateKeyForAmount(preload, amount);

    expect(found, `preload fixture should carry a key for amount ${amount}`).not.toBeNull();

    const a = BigInt(`0x${found!.privateKeyHex}`) % ORDER;

    return { a, A: Point.BASE.multiply(a).toHex(true), keysetId: found!.keysetId };
  }

  it('logs in with a proof signed by the real mint key, and refuses a forged one', async () => {
    const AMOUNT = 8;
    const { a, A, keysetId } = await mintSecretFor(AMOUNT);

    // The mint's published key for this amount must match the one derived from
    // the fixture's private key. If it does not, everything below is testing
    // the wrong key and the failure would be misleading.
    const published = (await (await fetch(`${mintUrl}/v1/keys`)).json()) as {
      keysets: Array<{ id: string; keys: Record<string, string> }>;
    };
    const publishedKey = published.keysets
      .find((keyset) => keyset.id === keysetId)!
      .keys[String(AMOUNT)]!.toLowerCase();

    expect(publishedKey).toBe(A);

    const holder = getPublicKey(hexToBytes(HOLDER_PRIVATE));
    const secret = issuerSignedSecret(holder, NOW + 3600);
    const proof = blindSignWith(a, secret);

    const honest = await login({
      mintUrl,
      keysetId,
      amount: AMOUNT,
      secret,
      signature: proof.C,
      dleq: proof.dleq,
    });

    expect(honest.status).toBe(200);
    expect(honest.body.permissions).toEqual(['voucher:view:sat']);

    // The same login with the DLEQ from a *different* mint key. The proof is
    // well-formed and the voucher is genuine; only the claim that this mint
    // signed it is false.
    const otherMint = blindSignWith((a + 1n) % ORDER, secret);
    const forged = await login({
      mintUrl,
      keysetId,
      amount: AMOUNT,
      secret,
      signature: otherMint.C,
      dleq: otherMint.dleq,
    });

    expect(forged.status).toBe(401);
  }, 60_000);

  it('refuses a voucher locked to another key, against the real mint', async () => {
    // The stolen-credential case with nothing stubbed: real mint key, real
    // DLEQ, real issuer signature, and a lock naming somebody else.
    const AMOUNT = 8;
    const { a, keysetId } = await mintSecretFor(AMOUNT);
    const secret = issuerSignedSecret('cc'.repeat(32), NOW + 3600);
    const proof = blindSignWith(a, secret);

    const stolen = await login({
      mintUrl,
      keysetId,
      amount: AMOUNT,
      secret,
      signature: proof.C,
      dleq: proof.dleq,
    });

    expect(stolen.status).toBe(401);
  }, 60_000);

  it('refuses an expired voucher, against the real mint', async () => {
    const AMOUNT = 8;
    const { a, keysetId } = await mintSecretFor(AMOUNT);
    const holder = getPublicKey(hexToBytes(HOLDER_PRIVATE));
    const secret = issuerSignedSecret(holder, NOW - 1);
    const proof = blindSignWith(a, secret);

    const expired = await login({
      mintUrl,
      keysetId,
      amount: AMOUNT,
      secret,
      signature: proof.C,
      dleq: proof.dleq,
    });

    expect(expired.status).toBe(401);
  }, 60_000);
});

describe('proofY derivation is stable', () => {
  it('agrees with hash_to_curve for the same secret', () => {
    // Runs without Docker: `Y` is what a NUT-07 state check is keyed on, so a
    // drift here would make every liveness check silently miss.
    const secret = 'daf4dd00a2b68a0858a80450f52c8a7d2ccf87d375e43e216e0c571f089f63e9';

    expect(proofY(secret)).toBe(hashToCurve(new TextEncoder().encode(secret)).toHex(true));
  });
});
