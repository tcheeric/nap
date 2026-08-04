import { Nip46Error } from './errors.js';

/**
 * Per-call bounds. A remote signer is a human holding a phone, so the bound on
 * "approve this signature" is far looser than the bound on "are you alive".
 */
export const DEFAULT_CONNECT_TIMEOUT_MS = 15_000;
export const DEFAULT_SIGN_TIMEOUT_MS = 30_000;
export const DEFAULT_PING_TIMEOUT_MS = 5_000;

/**
 * Reject with `TIMEOUT` if `promise` has not settled within `ms`.
 *
 * The timer is always cleared, including on the success path — a pending timer
 * per outstanding request would keep a test runner (and a browser tab) awake.
 *
 * `nap-client-web/src/nip07.ts` has a twin of this that rejects with
 * `Nip07Error`. The duplication buys package independence: this package is
 * opt-in, and nap-client-web must not depend on it.
 */
export function withTimeout<T>(promise: Promise<T>, ms: number, label: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;

  const timeout = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => {
      reject(new Nip46Error('TIMEOUT', `${label} timed out after ${ms}ms`));
    }, ms);
  });

  return Promise.race([promise, timeout]).finally(() => {
    clearTimeout(timer);
  });
}
