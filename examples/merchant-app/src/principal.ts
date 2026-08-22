import type { RequestHandler, Request } from 'express';
import type { SessionRecord } from '@imani/nap-core';
import type { SessionStore } from '@imani/nap-server';

/**
 * NAP's guards answer "may this request proceed?" and stop there — they do not
 * hand the route the principal behind the session. That is deliberate on their
 * part (they are an authorization boundary, not a session-loading convenience),
 * but a route that writes `issued_by` needs the pubkey, so we read it here.
 *
 * Mount this *after* a guard. On its own it authorises nothing.
 */
export function attachPrincipal(options: {
  sessionStore: SessionStore;
  cookieName: string;
}): RequestHandler {
  return async (req, _res, next) => {
    try {
      const token = readToken(req, options.cookieName);
      (req as Request & { principal?: SessionRecord }).principal = token
        ? ((await options.sessionStore.getByAccessToken(token)) ?? undefined)
        : undefined;
      next();
    } catch (error) {
      next(error);
    }
  };
}

export function principalOf(req: Request): SessionRecord {
  const principal = (req as Request & { principal?: SessionRecord }).principal;

  if (!principal) {
    // Unreachable behind a guard. Thrown rather than defaulted, because a
    // silently anonymous principal is how audit trails become fiction.
    throw new Error('attachPrincipal() must be mounted after a NAP guard');
  }

  return principal;
}

function readToken(req: Request, cookieName: string): string | null {
  const authorization = req.header('authorization');

  if (authorization?.startsWith('Bearer ')) {
    return authorization.slice('Bearer '.length).trim();
  }

  for (const candidate of (req.header('cookie') ?? '').split(';')) {
    const [name, ...rest] = candidate.trim().split('=');

    if (name === cookieName) {
      return rest.join('=');
    }
  }

  return null;
}
