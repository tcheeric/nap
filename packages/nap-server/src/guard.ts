import type { AuditLogger, MetricsRecorder } from './types.js';
import type { SessionRecord } from '@imani/nap-core';
import { withMetrics } from './metrics.js';

/**
 * Denial codes for the guards, mirroring the `NAP_COMPLETE_*` family the
 * `/auth/*` endpoints already emit.
 *
 * The guards are the actual authorization boundary — `/auth/complete` decides
 * who you are once, the guards decide what you may do on every request after —
 * and until now a refusal there produced no audit record at all (CONTEXT.md
 * finding 12). An operator reading the log saw a clean run of
 * `NAP_COMPLETE_SUCCESS` whether or not half the requests were being refused.
 *
 * These are deliberately distinct from the `/auth/*` codes rather than reusing
 * `NAP_COMPLETE_ACL_DENIED`. A denial at login and a denial at a guard are
 * different events with different remedies: the first means the principal never
 * got in, the second means their access changed underneath a live session.
 * Collapsing them would make "was this user suspended mid-session?" unanswerable
 * from the log.
 */
export const GUARD_DENIAL_CODES = {
  /** No token, or a token that is unknown, expired, or revoked. */
  NO_SESSION: 'NAP_GUARD_NO_SESSION',
  /** The session is valid but the ACL resolver now denies the principal. */
  ACL_DENIED: 'NAP_GUARD_ACL_DENIED',
  /** Authenticated and allowed, but lacking the required permission. */
  PERMISSION_DENIED: 'NAP_GUARD_PERMISSION_DENIED',
  /** Authenticated and allowed, but holding none of the accepted roles. */
  ROLE_DENIED: 'NAP_GUARD_ROLE_DENIED',
  /** The permission is held, but the step-up token is missing, wrong, or expired. */
  STEP_UP_REQUIRED: 'NAP_GUARD_STEP_UP_REQUIRED',
} as const;

export type GuardDenialCode = (typeof GUARD_DENIAL_CODES)[keyof typeof GUARD_DENIAL_CODES];

export interface GuardDenialDetails {
  /** The permission the guard was checking, when it was a permission guard. */
  permission?: string;
  /** The roles the guard would have accepted, when it was a role guard. */
  roles?: string[];
  /** Anything else the caller wants on the record. */
  [key: string]: unknown;
}

export interface LogGuardDenialOptions {
  auditLogger?: AuditLogger;
  metrics?: MetricsRecorder;
  /**
   * Absent for `NO_SESSION`, where by definition there is no principal to name.
   * That absence is itself the signal: a burst of principal-less denials is
   * unauthenticated traffic, a burst naming one principal is a permission
   * problem for that user.
   */
  session?: SessionRecord | null;
  details?: GuardDenialDetails;
}

/**
 * Record a guard refusal.
 *
 * Never throws and never rejects. A guard's job is to deny the request; an
 * audit sink that is down must not turn a clean 403 into a 500, because a 500
 * on exactly one branch is a side channel that tells an attacker which branch
 * they hit. This is the same reasoning `metrics.ts` documents for a throwing
 * recorder, and it matters more here: the guards run outside the auth
 * endpoints' `minAuthResponseMillis` floor, so nothing else is smoothing the
 * difference out.
 *
 * Awaiting the logger is still correct — a caller who wants durability gets it —
 * but a rejection is swallowed rather than propagated.
 */
export async function logGuardDenial(
  code: GuardDenialCode,
  options: LogGuardDenialOptions
): Promise<void> {
  if (!options.auditLogger) {
    return;
  }

  try {
    const logger = withMetrics(options.auditLogger, options.metrics);

    await logger.log({
      code,
      outcome: 'failure',
      npub: options.session?.principal_npub,
      pubkey: options.session?.principal_pubkey,
      details: options.details,
    });
  } catch {
    // Deliberately swallowed. See the note above: a broken audit sink must cost
    // a log line, not the uniformity of the response.
  }
}
