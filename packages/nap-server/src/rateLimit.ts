import type { Clock, RateLimitDecision, RateLimitKey, RateLimiter } from './types.js';

export interface InMemoryRateLimiterOptions {
  /** Window length in seconds. Defaults to 60. */
  windowSeconds?: number;
  /** Requests allowed per identifier per window. Defaults to 30. */
  maxPerWindow?: number;
  clock?: Clock;
}

interface Window {
  startedAt: number;
  count: number;
}

const DEFAULT_WINDOW_SECONDS = 60;
const DEFAULT_MAX_PER_WINDOW = 30;

/**
 * Single-process fixed-window rate limiter (RFC §17.1).
 *
 * Enough to stop a single client hammering `/auth/init`, and the honest limit
 * is that the counters live in one process: behind more than one instance each
 * gets its own budget, so the effective rate is the configured one multiplied
 * by the instance count. Multi-instance deployments want a shared backend
 * behind the same `RateLimiter` interface.
 *
 * The `npub` and `clientIp` dimensions are counted separately and both must
 * pass — one principal cycling addresses is still capped, and one address
 * cycling principals is too.
 */
export function createInMemoryRateLimiter(
  options: InMemoryRateLimiterOptions = {}
): RateLimiter {
  const windowSeconds = options.windowSeconds ?? DEFAULT_WINDOW_SECONDS;
  const maxPerWindow = options.maxPerWindow ?? DEFAULT_MAX_PER_WINDOW;
  const clock = options.clock ?? { nowUnix: () => Math.floor(Date.now() / 1000) };
  const windows = new Map<string, Window>();

  function hit(identifier: string, now: number): RateLimitDecision {
    const existing = windows.get(identifier);

    if (!existing || now - existing.startedAt >= windowSeconds) {
      windows.set(identifier, { startedAt: now, count: 1 });
      return { allowed: true };
    }

    existing.count += 1;

    if (existing.count > maxPerWindow) {
      return {
        allowed: false,
        retryAfterSeconds: Math.max(1, existing.startedAt + windowSeconds - now),
      };
    }

    return { allowed: true };
  }

  function prune(now: number): void {
    for (const [identifier, window] of windows) {
      if (now - window.startedAt >= windowSeconds) {
        windows.delete(identifier);
      }
    }
  }

  return {
    check(key: RateLimitKey): RateLimitDecision {
      const now = clock.nowUnix();

      // Sweep before counting so an attacker cycling identifiers grows the map
      // by at most one window's worth of entries rather than without bound.
      prune(now);

      const identifiers = [
        key.npub ? `${key.scope}:npub:${key.npub}` : null,
        key.clientIp ? `${key.scope}:ip:${key.clientIp}` : null,
      ].filter((value): value is string => value !== null);

      if (identifiers.length === 0) {
        return { allowed: true };
      }

      // Every dimension is counted, not just up to the first rejection: an
      // early return would leave the other counter under-counted and let a
      // caller who is already blocked on one dimension build headroom on the
      // other.
      return identifiers
        .map((identifier) => hit(identifier, now))
        .reduce((worst, decision) => (decision.allowed ? worst : decision), {
          allowed: true,
        } as RateLimitDecision);
    },
  };
}
