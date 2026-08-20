export class SessionLockedError extends Error {
  constructor() {
    super('Session is locked');
    this.name = 'SessionLockedError';
  }
}

/**
 * A NAP request that reached the server and came back refused.
 *
 * `terminal` is the distinction callers act on. Every auth failure is the same
 * uniform 401 by design (RFC §10.1, §15), so the client cannot learn that *this
 * npub* was removed from the ACL — only that the server will not accept this
 * attempt. That is still enough to stop offering the same login forever: a
 * status in the 4xx range means retrying with the same signer gets the same
 * answer, while a 429, a 5xx, or a transport error that never produced a status
 * is a retry away from working and must not be treated as rejection.
 */
export class AuthRequestError extends Error {
  readonly code = 'AUTH_REQUEST_FAILED' as const;
  readonly phase: 'init' | 'complete';
  readonly status: number;
  readonly terminal: boolean;

  constructor(phase: 'init' | 'complete', status: number) {
    super(`NAP ${phase} failed with status ${status}`);
    this.name = 'AuthRequestError';
    this.phase = phase;
    this.status = status;
    // 429 is excluded deliberately: rate limiting is the one 4xx that says
    // "later", not "no".
    this.terminal = status >= 400 && status < 500 && status !== 429;
  }
}

export async function fetchJson<T>(
  fetchImpl: typeof fetch,
  input: string,
  init?: RequestInit
): Promise<{ status: number; body: T | null }> {
  const response = await fetchImpl(input, {
    credentials: 'include',
    ...init,
  });

  if (response.status === 204) {
    return { status: response.status, body: null };
  }

  const text = await response.text();
  return {
    status: response.status,
    body: text.length === 0 ? null : (JSON.parse(text) as T),
  };
}
