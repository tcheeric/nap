import { describe, expect, it } from 'vitest';
import { createMintAllowlist, createMintClient } from '../src/index.js';
import { readFileSync } from 'node:fs';

const MINT = 'https://mint.example.com';

/**
 * Extension 0001 §6.1: login MUST NOT spend.
 *
 * The state check is read-only. Redemption is a business action, and in this
 * repo's own example it is the destructive action behind `requireStepUp`
 * (tutorial 06). Conflating the two would burn a voucher on every login and
 * make the retry-safe completion path (RFC §13.2, where a duplicate submission
 * MUST return the same session) destructive on retry.
 *
 * The strongest guarantee available at this layer is structural: the client the
 * auth path holds has no method that could spend, and its source contains no
 * call to a spending endpoint. That is asserted here rather than left to review.
 */
describe('the auth-path mint client cannot spend (§6.1)', () => {
  const client = createMintClient({ allowlist: createMintAllowlist([MINT]) });

  it('exposes only read-only operations', () => {
    expect(Object.keys(client).sort()).toEqual(['checkState', 'clearCache', 'getKey']);
  });

  it.each(['swap', 'melt', 'mint', 'redeem', 'spend', 'burn'])(
    'has no %s method',
    (method) => {
      expect((client as unknown as Record<string, unknown>)[method]).toBeUndefined();
    }
  );

  it('never references a spending endpoint in its source', () => {
    // A method could be added later without touching the surface assertions
    // above if it were called internally, so pin the endpoints themselves.
    const source = readFileSync(new URL('../src/mintClient.ts', import.meta.url), 'utf8');

    for (const endpoint of ['/v1/swap', '/v1/melt', '/v1/mint']) {
      expect(source).not.toContain(endpoint);
    }

    // The two it is allowed to reach, so the assertion above is not vacuous.
    expect(source).toContain('/v1/keys');
    expect(source).toContain('/v1/checkstate');
  });

  it('only ever issues GET /v1/keys and POST /v1/checkstate', async () => {
    const seen: Array<{ url: string; method: string }> = [];
    const tracked = createMintClient({
      allowlist: createMintAllowlist([MINT]),
      fetch: (async (input: unknown, init?: RequestInit) => {
        seen.push({ url: String(input), method: init?.method ?? 'GET' });

        return new Response(
          JSON.stringify(
            String(input).endsWith('/v1/keys')
              ? { keysets: [{ id: 'abc', keys: { '1': '02'.padEnd(66, '0') } }] }
              : { states: [] }
          ),
          { status: 200, headers: { 'content-type': 'application/json' } }
        );
      }) as unknown as typeof fetch,
    });

    await tracked.getKey(MINT, 'abc', 1);
    await tracked.checkState(MINT, 'secret').catch(() => undefined);

    expect(seen).toEqual([
      { url: `${MINT}/v1/keys`, method: 'GET' },
      { url: `${MINT}/v1/checkstate`, method: 'POST' },
    ]);
  });
});
