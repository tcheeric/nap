/** The slice of `Storage` anything in this package actually uses. */
export type WebStorage = Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>;

/**
 * Resolve the storage to use, or `null` when there is none.
 *
 * The `try` is not defensive padding: **reading `globalThis.localStorage` can
 * itself throw**, not only `setItem`. A document denied storage access — a
 * third-party iframe, or a browser with third-party cookies blocked — raises
 * `SecurityError` on the property access, and there is no `localStorage` at all
 * under SSR. Every caller here treats "no storage" as an ordinary answer, so
 * turning that into a thrown `SecurityError` out of an unrelated call stack is
 * strictly worse than reporting absence.
 */
export function resolveStorage(explicit?: WebStorage): WebStorage | null {
  try {
    return explicit ?? (globalThis as { localStorage?: Storage }).localStorage ?? null;
  } catch {
    return null;
  }
}
