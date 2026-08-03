import type { NapErrorCode, VerifyCompleteFailure } from './types.js';

const RETRYABLE_ERRORS: ReadonlySet<NapErrorCode> = new Set([
  'NAP_INIT_RATE_LIMITED',
  'NAP_INIT_INTERNAL',
  'NAP_COMPLETE_CREATED_AT_OUT_OF_RANGE',
  'NAP_COMPLETE_UNKNOWN_CHALLENGE',
  'NAP_COMPLETE_RATE_LIMITED',
  'NAP_COMPLETE_INTERNAL',
  'NAP_REFRESH_RATE_LIMITED',
  'NAP_REFRESH_INTERNAL',
]);

export function isRetryableNapError(code: NapErrorCode): boolean {
  return RETRYABLE_ERRORS.has(code);
}

export function failure(code: NapErrorCode): VerifyCompleteFailure {
  return {
    ok: false,
    code,
    retryable: isRetryableNapError(code),
  };
}

