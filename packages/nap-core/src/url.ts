export function normalizeAbsoluteUrl(value: string): string {
  return new URL(value).toString();
}

/**
 * Whether two URLs are the same absolute URL.
 *
 * Total by construction. The left-hand side is the NIP-98 `u` tag, which is
 * attacker-supplied: `new URL()` throws on anything that is not an absolute
 * URL, and an unhandled throw here escapes `verifyNip98Completion()` entirely.
 * That costs three things at once — the adapter answers 500 instead of the
 * uniform 401, the response skips the `padAuthResponse()` floor that makes
 * failures indistinguishable (RFC §15), and no audit record is written because
 * the throw happens before `logFailure()`.
 *
 * A `u` tag that will not parse cannot match the audience, so `false` is the
 * honest answer and it reaches the client through the same padded, audited
 * `NAP_COMPLETE_URL_MISMATCH` as every other mismatch. This is the same reason
 * `parseVoucherSecret()` returns null rather than throwing on hostile input.
 */
export function exactUrlMatch(left: string, right: string): boolean {
  try {
    return normalizeAbsoluteUrl(left) === normalizeAbsoluteUrl(right);
  } catch {
    return false;
  }
}

