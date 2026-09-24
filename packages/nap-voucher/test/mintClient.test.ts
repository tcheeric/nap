import { describe, expect, it } from 'vitest';
import {
  createMintAllowlist,
  createMintClient,
  MintUnavailableError,
  proofY,
  type MintClientOptions,
} from '../src/index.js';

const MINT = 'https://mint.example.com';
const KEYSET_ID = '00882760bfa2eb41';
const KEY = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';

const KEYS_RESPONSE = {
  keysets: [{ id: KEYSET_ID, unit: 'sat', keys: { '1': KEY, '8': KEY } }],
};

interface StubCall {
  url: string;
  init?: RequestInit;
}

/** A fetch stub that records every call, so "no network" is assertable. */
function stubFetch(handler: (url: string, init?: RequestInit) => unknown | Promise<unknown>) {
  const calls: StubCall[] = [];

  const fetchImpl = (async (input: unknown, init?: RequestInit) => {
    const url = String(input);
    calls.push({ url, init });
    const result = await handler(url, init);

    if (result instanceof Response) {
      return result;
    }

    return new Response(JSON.stringify(result), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  }) as unknown as typeof fetch;

  return { fetch: fetchImpl, calls };
}

type StubHandler = (url: string, init?: RequestInit) => unknown | Promise<unknown>;

function client(overrides: Partial<MintClientOptions> = {}, handler: StubHandler = () => KEYS_RESPONSE) {
  const stub = stubFetch(handler);

  return {
    stub,
    client: createMintClient({
      allowlist: createMintAllowlist([MINT]),
      fetch: stub.fetch,
      ...overrides,
    }),
  };
}

describe('mint client construction', () => {
  it('refuses to build without an allowlist', () => {
    // The mint_url arrives in the request. A client that could be pointed
    // anywhere is the SSRF the §6 ordering note exists to prevent, so the
    // dependency is mandatory rather than optional.
    expect(() => createMintClient({} as MintClientOptions)).toThrow(/requires a MintAllowlist/);
  });

  it.each([0, -1, Number.NaN])('rejects a %s cache TTL', (keysetCacheTtlSeconds) => {
    expect(() =>
      createMintClient({ allowlist: createMintAllowlist([MINT]), keysetCacheTtlSeconds })
    ).toThrow(/positive number/);
  });
});

describe('SSRF: unvetted URLs are never reached', () => {
  it.each([
    'https://evil.example.com',
    'https://169.254.169.254',
    'http://mint.example.com',
    'https://mint.example.com.evil.com',
    'not-a-url',
  ])('refuses %s without any outbound request', async (mintUrl) => {
    const { client: mint, stub } = client();

    await expect(mint.getKey(mintUrl, KEYSET_ID, 1)).rejects.toMatchObject({
      reason: 'mint_not_allowed',
    });
    await expect(mint.checkState(mintUrl, 'secret')).rejects.toMatchObject({
      reason: 'mint_not_allowed',
    });
    // The assertion that matters: the allowlist check happens *before* the
    // network call, not after it.
    expect(stub.calls).toEqual([]);
  });
});

describe('keyset fetch and cache', () => {
  it('fetches the key for a keyset and amount', async () => {
    const { client: mint, stub } = client();

    expect(await mint.getKey(MINT, KEYSET_ID, 8)).toBe(KEY);
    expect(stub.calls[0]?.url).toBe(`${MINT}/v1/keys`);
  });

  it('serves a second read from cache', async () => {
    const { client: mint, stub } = client();

    await mint.getKey(MINT, KEYSET_ID, 1);
    await mint.getKey(MINT, KEYSET_ID, 8);

    expect(stub.calls).toHaveLength(1);
  });

  it('refetches once the TTL expires', async () => {
    let now = 1_000;
    const { client: mint, stub } = client({
      keysetCacheTtlSeconds: 60,
      clock: { nowUnix: () => now },
    });

    await mint.getKey(MINT, KEYSET_ID, 1);
    now += 59;
    await mint.getKey(MINT, KEYSET_ID, 1);
    expect(stub.calls).toHaveLength(1);

    now += 2;
    await mint.getKey(MINT, KEYSET_ID, 1);
    expect(stub.calls).toHaveLength(2);
  });

  it('clearCache forces a refetch', async () => {
    const { client: mint, stub } = client();

    await mint.getKey(MINT, KEYSET_ID, 1);
    mint.clearCache();
    await mint.getKey(MINT, KEYSET_ID, 1);

    expect(stub.calls).toHaveLength(2);
  });

  it('retries once for an unknown keyset, then fails closed', async () => {
    const { client: mint, stub } = client();

    await mint.getKey(MINT, KEYSET_ID, 1);
    await expect(mint.getKey(MINT, 'deadbeefdeadbeef', 1)).rejects.toMatchObject({
      reason: 'unknown_keyset',
    });

    // Bounded to one refetch: an attacker supplying random keyset ids must not
    // drive one mint request per attempt.
    expect(stub.calls).toHaveLength(2);
  });

  it('bounds miss-triggered refetches per cache entry, not per request', async () => {
    // Found in review: the refetch deleted the cache on every miss, so N
    // unknown keyset ids cost N mint fetches -- the exact flood the retry was
    // supposed to prevent. The bound has to be per cache entry, because keying
    // it on the id cannot help when every attacker id is fresh by construction.
    const { client: mint, stub } = client();

    for (let attempt = 0; attempt < 10; attempt += 1) {
      await expect(mint.getKey(MINT, `unknown-${attempt}`, 1)).rejects.toMatchObject({
        reason: 'unknown_keyset',
      });
    }

    // One initial load plus one refresh, not eleven.
    expect(stub.calls).toHaveLength(2);
  });

  it('still resolves a real keyset after a miss has refreshed the entry', async () => {
    const { client: mint } = client();

    await expect(mint.getKey(MINT, 'unknown', 1)).rejects.toMatchObject({
      reason: 'unknown_keyset',
    });

    // The bound must not make the cache useless: a genuine keyset still works.
    expect(await mint.getKey(MINT, KEYSET_ID, 1)).toBe(KEY);
  });

  it('fails closed for an amount the keyset does not cover', async () => {
    const { client: mint } = client();

    await expect(mint.getKey(MINT, KEYSET_ID, 4)).rejects.toMatchObject({
      reason: 'unknown_keyset',
    });
  });

  it.each([
    ['a non-object body', 'nonsense'],
    ['no keysets array', { foo: 1 }],
    ['an empty keyset list', { keysets: [] }],
    ['keysets with no usable keys', { keysets: [{ id: KEYSET_ID, keys: {} }] }],
  ])('reports %s as malformed rather than unavailable', async (_label, body) => {
    const { client: mint } = client({}, () => body);

    // Distinct from `unavailable` on purpose: a mint returning an error page is
    // not the same condition as a mint that is down, and only the latter may
    // trigger §7.3 degraded mode.
    await expect(mint.getKey(MINT, KEYSET_ID, 1)).rejects.toMatchObject({
      reason: 'malformed_response',
    });
  });
});

describe('mint unavailability is a distinct, catchable condition (§7.3)', () => {
  it('reports a network error as unavailable', async () => {
    const { client: mint } = client({}, () => {
      throw new Error('ECONNREFUSED');
    });

    await expect(mint.getKey(MINT, KEYSET_ID, 1)).rejects.toBeInstanceOf(MintUnavailableError);
    await expect(mint.getKey(MINT, KEYSET_ID, 1)).rejects.toMatchObject({ reason: 'unavailable' });
  });

  it('reports a 5xx as unavailable', async () => {
    const { client: mint } = client({}, () => new Response('nope', { status: 503 }));

    await expect(mint.getKey(MINT, KEYSET_ID, 1)).rejects.toMatchObject({ reason: 'unavailable' });
  });

  it.each([400, 401, 403, 404, 429])('does not treat %i as unavailable', async (status) => {
    // Found in review: mapping every non-2xx to `unavailable` would let
    // `onMintUnavailable: 'degrade'` fire on a mint that answered clearly. A
    // 4xx is a definite refusal, not silence.
    const { client: mint } = client({}, () => new Response('no', { status }));

    await expect(mint.getKey(MINT, KEYSET_ID, 1)).rejects.toMatchObject({
      reason: 'malformed_response',
    });
  });

  it('reports unparseable JSON as unavailable', async () => {
    const { client: mint } = client({}, () => new Response('<html>', { status: 200 }));

    await expect(mint.getKey(MINT, KEYSET_ID, 1)).rejects.toMatchObject({ reason: 'unavailable' });
  });

  it('times out rather than holding the auth path open', async () => {
    // Without a timeout an unresponsive mint pins the login path until the
    // platform default, turning a slow third party into resource exhaustion.
    // The stub honours `signal` exactly as real fetch does, so this asserts the
    // AbortController is actually wired rather than merely constructed.
    let aborted = false;
    const { client: mint } = client(
      { timeoutMs: 20 },
      (_url, init) =>
        new Promise((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () => {
            aborted = true;
            reject(new DOMException('aborted', 'AbortError'));
          });
        })
    );

    await expect(mint.getKey(MINT, KEYSET_ID, 1)).rejects.toMatchObject({ reason: 'unavailable' });
    expect(aborted).toBe(true);
  });
});

describe('NUT-07 state check', () => {
  const SECRET = 'daf4dd00a2b68a0858a80450f52c8a7d2ccf87d375e43e216e0c571f089f63e9';

  function stateClient(states: unknown) {
    return client({}, (url) => (url.endsWith('/v1/checkstate') ? { states } : KEYS_RESPONSE));
  }

  it.each(['UNSPENT', 'SPENT', 'PENDING'] as const)('maps %s distinctly', async (state) => {
    const { client: mint } = stateClient([{ Y: proofY(SECRET), state }]);

    expect(await mint.checkState(MINT, SECRET)).toBe(state);
  });

  it('posts Y = hash_to_curve(secret) to /v1/checkstate', async () => {
    const { client: mint, stub } = stateClient([{ Y: proofY(SECRET), state: 'UNSPENT' }]);
    await mint.checkState(MINT, SECRET);

    const call = stub.calls[0]!;
    expect(call.url).toBe(`${MINT}/v1/checkstate`);
    expect(call.init?.method).toBe('POST');
    expect(JSON.parse(String(call.init?.body))).toEqual({ Ys: [proofY(SECRET)] });
  });

  it('matches on Y rather than trusting response order', async () => {
    // NUT-07 requires request order, but a mint that reorders would otherwise
    // hand us another proof's state — and here that decides an authorization.
    const { client: mint } = stateClient([
      { Y: proofY('some other secret'), state: 'UNSPENT' },
      { Y: proofY(SECRET), state: 'SPENT' },
    ]);

    expect(await mint.checkState(MINT, SECRET)).toBe('SPENT');
  });

  it('fails closed when the response contains no matching Y', async () => {
    const { client: mint } = stateClient([{ Y: proofY('unrelated'), state: 'UNSPENT' }]);

    await expect(mint.checkState(MINT, SECRET)).rejects.toMatchObject({
      reason: 'malformed_response',
    });
  });

  it('refuses to interpret an unknown state', async () => {
    // Never treat an unrecognised state as UNSPENT. Refusing to guess is the
    // entire point of the check.
    const { client: mint } = stateClient([{ Y: proofY(SECRET), state: 'DEFINITELY_FINE' }]);

    await expect(mint.checkState(MINT, SECRET)).rejects.toMatchObject({
      reason: 'malformed_response',
    });
  });

  it('fails closed on a malformed states payload', async () => {
    const { client: mint } = stateClient('not-an-array');

    await expect(mint.checkState(MINT, SECRET)).rejects.toMatchObject({
      reason: 'malformed_response',
    });
  });
});
