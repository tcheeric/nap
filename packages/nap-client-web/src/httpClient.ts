export class SessionLockedError extends Error {
  constructor() {
    super('Session is locked');
    this.name = 'SessionLockedError';
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
