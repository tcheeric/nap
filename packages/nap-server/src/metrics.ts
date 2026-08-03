import type { AuditLogger, MetricsRecorder, NapCounter } from './types.js';

const noopMetrics: MetricsRecorder = {
  increment() {
    return undefined;
  },
};

export function createNoopMetricsRecorder(): MetricsRecorder {
  return noopMetrics;
}

export function resolveMetrics(metrics: MetricsRecorder | undefined): MetricsRecorder {
  return metrics ?? noopMetrics;
}

/**
 * The three RFC §19.3 counters that follow from the outcome alone, so every
 * audit point present today — and every one added later — is counted without
 * being touched.
 */
const COUNTER_BY_OUTCOME = {
  success: 'auth_success_total',
  failure: 'auth_failure_total',
  rate_limited: 'auth_rate_limited_total',
} as const satisfies Record<string, NapCounter>;

/**
 * The counters that name a specific failure. `audience_mismatch_total` is keyed
 * on `NAP_COMPLETE_URL_MISMATCH` because the NIP-98 `u` tag *is* the audience.
 * `NAP_COMPLETE_MISSING_PAYLOAD` is deliberately not counted as a payload
 * mismatch: nothing was compared, so calling it a mismatch would blur a client
 * that omits the tag with one whose body was rewritten in transit — the very
 * thing the counter is watched for.
 */
const COUNTER_BY_CODE: Partial<Record<string, NapCounter>> = {
  NAP_COMPLETE_EXPIRED_CHALLENGE: 'challenge_expired_total',
  NAP_COMPLETE_URL_MISMATCH: 'audience_mismatch_total',
  NAP_COMPLETE_PAYLOAD_MISMATCH: 'payload_mismatch_total',
};

/**
 * Wraps an `AuditLogger` so the RFC §19.3 counters it implies are incremented
 * alongside it. Returns the logger untouched when nothing is bound, so the
 * default costs one comparison at construction and nothing per request.
 *
 * Every audit event already carries the outcome and the code, which is what the
 * counters are: metrics derived from audit points rather than a parallel set of
 * call sites to keep in step with them. Only `auth_init_total` and
 * `auth_complete_total` are counted separately — they must include requests too
 * malformed to reach any audit point.
 */
export function withMetrics(
  auditLogger: AuditLogger,
  metrics: MetricsRecorder | undefined
): AuditLogger {
  if (!metrics) {
    return auditLogger;
  }

  return {
    async log(event) {
      metrics.increment(COUNTER_BY_OUTCOME[event.outcome]);

      const specific = COUNTER_BY_CODE[event.code];

      if (specific) {
        metrics.increment(specific);
      }

      if (event.outcome === 'success') {
        // A replayed completion returns the cached session rather than minting
        // one, so it is a retry hit and not a redemption. RFC §13.3 makes that
        // the correct response, which is exactly why the two are counted apart:
        // a retry rate that climbs is a client bug, not an attack.
        metrics.increment(
          event.details?.retry === true ? 'challenge_retry_hit_total' : 'challenge_redeemed_total'
        );
      }

      await auditLogger.log(event);
    },
  };
}
