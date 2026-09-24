/**
 * Cashu mint client for the auth path: keyset fetch with a TTL cache, and the
 * NUT-07 state check.
 *
 * Extension 0001 §4. Deliberately dependency-free apart from `@noble/*` (§11
 * step 2): built standalone and testable with no NAP dependency, so the
 * verification logic can be exercised without standing up an auth server.
 *
 * Every method takes an origin that came from `MintAllowlist.resolve()`, never
 * a URL from the request. §6's ordering note is a security property, not a
 * performance one: "never make an outbound request to an unvetted URL. SSRF."
 * The types here cannot enforce that on their own, so the constructor demands
 * the allowlist and does the resolution itself.
 */

import type { MintAllowlist } from './allowlist.js';
import { proofY } from './dleq.js';

/** NUT-07 proof states. */
export type ProofState = 'UNSPENT' | 'SPENT' | 'PENDING';

/**
 * Why a mint interaction did not produce an answer.
 *
 * `unavailable` is deliberately distinct from every other failure, because
 * §7.3 hangs off it: it is the only condition `onMintUnavailable: 'degrade'`
 * may act on. Collapsing "the mint is down" into "the check failed" would let
 * degraded mode fire on a mint that answered clearly and said SPENT.
 */
export type MintFailureReason =
  | 'mint_not_allowed'
  | 'unavailable'
  | 'malformed_response'
  | 'unknown_keyset';

export class MintUnavailableError extends Error {
  readonly reason: MintFailureReason;

  constructor(reason: MintFailureReason, message: string) {
    super(message);
    this.name = 'MintUnavailableError';
    this.reason = reason;
  }
}

/** A keyset: amount (as a decimal string) to compressed public key hex. */
export type Keyset = Readonly<Record<string, string>>;

export interface Clock {
  nowUnix(): number;
}

const systemClock: Clock = {
  nowUnix() {
    return Math.floor(Date.now() / 1000);
  },
};

export interface MintClientOptions {
  /** Required. The only source of origins this client will ever contact. */
  allowlist: MintAllowlist;
  /**
   * How long a fetched keyset stays cached. Default 3600.
   *
   * Keysets are long-lived and a mint rotates by publishing a new id, so this
   * is a availability/staleness tradeoff rather than a security parameter —
   * unlike the ACL cache TTL in §7.2, which bounds how stale an authorization
   * decision may be.
   */
  keysetCacheTtlSeconds?: number;
  /** Per-request timeout in milliseconds. Default 5000. */
  timeoutMs?: number;
  /** Injectable for tests. Defaults to `globalThis.fetch`. */
  fetch?: typeof fetch;
  clock?: Clock;
}

interface CacheEntry {
  keysets: Map<string, Keyset>;
  expiresAt: number;
  /**
   * Whether this entry is already the result of a miss-triggered refetch.
   *
   * A keyset miss may mean the mint rotated, so it is worth one refetch. But
   * the bound has to be per *cache entry*, not per request and not per keyset
   * id: an attacker sending N unknown ids would otherwise drive N mint fetches,
   * because each miss clears the cache the next miss would have hit. Keying it
   * on the id does not help, since every fresh random id is unseen by
   * construction.
   *
   * So: the first miss against a given entry refreshes it, and every later miss
   * is answered from that refreshed copy until the TTL expires normally. A
   * genuine rotation is picked up within one request; a flood costs one fetch.
   */
  refreshed: boolean;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

/**
 * Parse `GET /v1/keys`.
 *
 * Shape per NUT-01: `{ keysets: [{ id, unit, keys: { "<amount>": "<hex>" } }] }`.
 * Anything that does not match is `malformed_response` rather than an
 * exception, so a mint that starts returning an error page cannot crash the
 * auth path.
 */
function parseKeysets(payload: unknown): Map<string, Keyset> {
  if (!isRecord(payload) || !Array.isArray(payload.keysets)) {
    throw new MintUnavailableError('malformed_response', 'mint /v1/keys did not return a keysets array');
  }

  const out = new Map<string, Keyset>();

  for (const entry of payload.keysets) {
    if (!isRecord(entry) || typeof entry.id !== 'string' || !isRecord(entry.keys)) {
      continue;
    }

    const keys: Record<string, string> = {};

    for (const [amount, key] of Object.entries(entry.keys)) {
      if (typeof key === 'string') {
        keys[amount] = key.toLowerCase();
      }
    }

    if (Object.keys(keys).length > 0) {
      out.set(entry.id, Object.freeze(keys));
    }
  }

  if (out.size === 0) {
    throw new MintUnavailableError('malformed_response', 'mint /v1/keys contained no usable keyset');
  }

  return out;
}

export interface MintClient {
  /**
   * The public key for `(keysetId, amount)`, fetching and caching the mint's
   * keysets as needed.
   *
   * Throws `MintUnavailableError` rather than returning null, because the
   * caller must distinguish "mint is down" (§7.3 may degrade) from "this
   * keyset does not exist" (a hard reject).
   */
  getKey(mintUrl: string, keysetId: string, amount: number): Promise<string>;
  /** NUT-07 state of a proof, keyed on `Y = hash_to_curve(secret)`. */
  checkState(mintUrl: string, secret: string): Promise<ProofState>;
  /** Drop cached keysets. Exposed for tests and for operational rotation. */
  clearCache(): void;
}

export function createMintClient(options: MintClientOptions): MintClient {
  if (!options?.allowlist) {
    throw new Error(
      'NAP voucher mint client requires a MintAllowlist: the mint_url arrives in the request, and an unvetted URL must never be reached (SSRF)'
    );
  }

  const ttl = options.keysetCacheTtlSeconds ?? 3600;

  if (!Number.isFinite(ttl) || ttl <= 0) {
    throw new Error('NAP voucher keysetCacheTtlSeconds must be a positive number');
  }

  const timeoutMs = options.timeoutMs ?? 5000;
  const clock = options.clock ?? systemClock;
  const cache = new Map<string, CacheEntry>();

  const doFetch: typeof fetch = (...args) =>
    (options.fetch ?? globalThis.fetch)(...(args as Parameters<typeof fetch>));

  /** Resolve through the allowlist, or refuse. Every outbound call starts here. */
  function requireAllowedOrigin(mintUrl: string): string {
    const origin = options.allowlist.resolve(mintUrl);

    if (!origin) {
      throw new MintUnavailableError(
        'mint_not_allowed',
        'mint_url is not in the allowlist'
      );
    }

    return origin;
  }

  /**
   * A timeout is not optional. Without one an unresponsive mint holds the auth
   * path open until the platform's default socket timeout, which turns a slow
   * third party into a resource-exhaustion vector on login.
   */
  async function request(url: string, init?: RequestInit): Promise<unknown> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const response = await doFetch(url, {
        ...init,
        signal: controller.signal,
        headers: { accept: 'application/json', ...(init?.headers ?? {}) },
      });

      if (!response.ok) {
        // 4xx is the mint answering clearly: the request was malformed, the
        // endpoint is gone, we are rate limited or unauthorized. Reporting that
        // as `unavailable` would let `onMintUnavailable: 'degrade'` (§7.3) fire
        // on a definite refusal, which is exactly the confusion the reason codes
        // exist to prevent. Only 5xx and transport failures are "the mint did
        // not answer".
        throw new MintUnavailableError(
          response.status >= 400 && response.status < 500 ? 'malformed_response' : 'unavailable',
          `mint responded ${response.status} for ${url}`
        );
      }

      return await response.json();
    } catch (error) {
      if (error instanceof MintUnavailableError) {
        throw error;
      }

      // A network error, an abort, or unparseable JSON. All are "the mint did
      // not answer", which is the condition §7.3 is allowed to degrade on.
      throw new MintUnavailableError('unavailable', `mint request failed: ${String(error)}`);
    } finally {
      clearTimeout(timer);
    }
  }

  async function loadKeysets(origin: string, refreshed = false): Promise<Map<string, Keyset>> {
    const cached = cache.get(origin);

    if (cached && cached.expiresAt > clock.nowUnix()) {
      return cached.keysets;
    }

    const keysets = parseKeysets(await request(`${origin}/v1/keys`));
    cache.set(origin, { keysets, expiresAt: clock.nowUnix() + ttl, refreshed });

    return keysets;
  }

  return {
    async getKey(mintUrl: string, keysetId: string, amount: number): Promise<string> {
      const origin = requireAllowedOrigin(mintUrl);
      let keysets = await loadKeysets(origin);
      let keyset = keysets.get(keysetId);

      // A miss may mean the mint rotated since the cache was filled, so refetch
      // once per cache entry before concluding the keyset does not exist. See
      // `CacheEntry.refreshed` for why the bound is per entry rather than per
      // request or per id.
      if (!keyset && cache.get(origin)?.refreshed === false) {
        cache.delete(origin);
        keysets = await loadKeysets(origin, true);
        keyset = keysets.get(keysetId);
      }

      if (!keyset) {
        throw new MintUnavailableError(
          'unknown_keyset',
          `mint ${origin} does not publish keyset ${keysetId}`
        );
      }

      const key = keyset[String(amount)];

      if (!key) {
        throw new MintUnavailableError(
          'unknown_keyset',
          `keyset ${keysetId} has no key for amount ${amount}`
        );
      }

      return key;
    },

    async checkState(mintUrl: string, secret: string): Promise<ProofState> {
      const origin = requireAllowedOrigin(mintUrl);
      const Y = proofY(secret);
      const payload = await request(`${origin}/v1/checkstate`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ Ys: [Y] }),
      });

      if (!isRecord(payload) || !Array.isArray(payload.states)) {
        throw new MintUnavailableError('malformed_response', 'checkstate did not return states');
      }

      // NUT-07 requires states in request order, but match on Y rather than
      // trusting position: a mint that reorders would otherwise hand us the
      // state of a different proof, and here that decides an authorization.
      const state = payload.states.find(
        (entry) => isRecord(entry) && typeof entry.Y === 'string' && entry.Y.toLowerCase() === Y
      );

      if (!isRecord(state) || typeof state.state !== 'string') {
        throw new MintUnavailableError('malformed_response', 'checkstate returned no state for Y');
      }

      if (state.state !== 'UNSPENT' && state.state !== 'SPENT' && state.state !== 'PENDING') {
        // An unrecognised state must never be treated as UNSPENT. Refusing to
        // guess is the whole point.
        throw new MintUnavailableError(
          'malformed_response',
          `checkstate returned unknown state '${state.state}'`
        );
      }

      return state.state;
    },

    clearCache(): void {
      cache.clear();
    },
  };
}
