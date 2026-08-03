import express, { type CookieOptions, type Request, type RequestHandler, type Response, type Router } from 'express';
import {
  toPublicAuthFailure,
  toPublicAuthSuccess,
  toPublicSessionView,
  validatePermissionRegistry,
  issueChallenge,
  isMalformedRequestFailure,
  isVerifyFailure,
  verifyCompletion,
  type IssueChallengeResult,
  type NapServerOptions,
  type PermissionRegistry,
  type SessionStore,
} from '@imani/nap-server';
import type { VerifyCompleteFailure } from '@imani/nap-core';

const RAW_BODY_SYMBOL = Symbol.for('nap.rawBody');
const REGISTERED_PERMISSIONS = new Set<string>();

function currentEpochSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

export interface NapExpressOptions {
  server: NapServerOptions;
  getExternalBaseUrl(req: Request): string;
  /** Cookie carrying the access token, read by `/auth/session` and cleared by `/auth/logout`. Defaults to `session`. */
  cookieName?: string;
  /** Attributes used when clearing the cookie on logout. Must match those used to set it, or the browser keeps it. Defaults to `{ path: '/' }`. */
  clearCookieOptions?: CookieOptions;
  writeSuccess?: (ctx: {
    req: Request;
    res: Response;
    body: ReturnType<typeof toPublicAuthSuccess>;
  }) => void | Promise<void>;
  writeFailure?: (ctx: {
    req: Request;
    res: Response;
    result: VerifyCompleteFailure;
  }) => void | Promise<void>;
}

export interface NapExpressRequest extends Request {
  [RAW_BODY_SYMBOL]?: Uint8Array;
}

export interface NapExpressGuardOptions {
  sessionStore: SessionStore;
  cookieName?: string;
}

function getRawBody(req: Request): Uint8Array | null {
  return (req as NapExpressRequest)[RAW_BODY_SYMBOL] ?? null;
}

function setRawBody(req: object, rawBody: Uint8Array): void {
  (req as NapExpressRequest)[RAW_BODY_SYMBOL] = rawBody;
}

function defaultWriteFailure(res: Response): void {
  const failure = toPublicAuthFailure();
  res.status(failure.status).json(failure.body);
}

function normalizeBaseUrl(value: string): string {
  return value.endsWith('/') ? value.slice(0, -1) : value;
}

function unauthorized(res: Response): void {
  const failure = toPublicAuthFailure();
  res.status(failure.status).json(failure.body);
}

function forbidden(res: Response, reason = 'forbidden'): void {
  res.status(403).json({
    status: 'error',
    message: reason,
  });
}

function parseCookieValue(header: string | undefined, cookieName: string): string | null {
  if (!header) {
    return null;
  }

  for (const candidate of header.split(';')) {
    const [name, ...rest] = candidate.trim().split('=');

    if (name === cookieName) {
      return rest.join('=');
    }
  }

  return null;
}

async function loadSession(
  req: Request,
  options: NapExpressGuardOptions
): Promise<Awaited<ReturnType<SessionStore['getByAccessToken']>>> {
  const authorization = req.header('authorization');
  const bearerToken = authorization?.startsWith('Bearer ')
    ? authorization.slice('Bearer '.length).trim()
    : null;
  const cookieToken = parseCookieValue(
    req.header('cookie') ?? undefined,
    options.cookieName ?? 'session'
  );
  const token = bearerToken || cookieToken;

  if (!token) {
    return null;
  }

  const session = await options.sessionStore.getByAccessToken(token);

  if (!session) {
    return null;
  }

  if (session.revoked_at || session.expires_at <= currentEpochSeconds()) {
    return null;
  }

  return session;
}

function authCompleteUrl(req: Request, options: NapExpressOptions): string {
  return `${normalizeBaseUrl(options.getExternalBaseUrl(req))}/auth/complete`;
}

function issueChallengeFailure(res: Response, result: Exclude<IssueChallengeResult, { ok: true }>): void {
  const status = result.code === 'NAP_INIT_INVALID_NPUB' ? 400 : 500;
  res.status(status).json({
    status: 'error',
    message: result.code === 'NAP_INIT_INVALID_NPUB' ? 'bad request' : 'internal error',
  });
}

export function createNapExpressJsonParser(): RequestHandler {
  return express.json({
    verify(req, _res, buf) {
      setRawBody(req, new Uint8Array(buf));
    },
  });
}

export function createNapExpressInitHandler(options: NapExpressOptions): RequestHandler {
  return async (req, res, next) => {
    try {
      const npub = (req.body as Record<string, unknown> | undefined)?.npub;

      if (typeof npub !== 'string') {
        res.status(400).json({
          status: 'error',
          message: 'bad request',
        });
        return;
      }

      const result = await issueChallenge(
        {
          npub,
          authUrl: authCompleteUrl(req, options),
          authMethod: 'POST',
        },
        options.server
      );

      if (!result.ok) {
        issueChallengeFailure(res, result);
        return;
      }

      res.status(200).json(result.value);
    } catch (error) {
      next(error);
    }
  };
}

export function createNapExpressCompleteHandler(options: NapExpressOptions): RequestHandler {
  return async (req, res, next) => {
    try {
      const rawBody = getRawBody(req);

      if (!rawBody) {
        throw new Error(
          'nap-adapter-express requires createNapExpressJsonParser() before /auth/complete handlers'
        );
      }

      const result = await verifyCompletion(
        {
          authorization: req.header('authorization') ?? undefined,
          method: req.method,
          url: authCompleteUrl(req, options),
          rawBody,
        },
        options.server
      );

      if (isMalformedRequestFailure(result)) {
        res.status(result.publicResponse.status).json(result.publicResponse.body);
        return;
      }

      if (isVerifyFailure(result)) {
        if (options.writeFailure) {
          await options.writeFailure({ req, res, result });
          return;
        }

        defaultWriteFailure(res);
        return;
      }

      const body = toPublicAuthSuccess(result.session);

      if (options.writeSuccess) {
        await options.writeSuccess({ req, res, body });
        return;
      }

      res.status(200).json(body);
    } catch (error) {
      next(error);
    }
  };
}

/**
 * `GET /auth/session` — returns the current session, or 401 if there is none.
 *
 * The body omits `access_token` (see `toPublicSessionView`): in cookie mode the
 * token is HttpOnly, and echoing it here would hand it to any script on the
 * page.
 */
export function createNapExpressSessionHandler(options: NapExpressOptions): RequestHandler {
  return async (req, res, next) => {
    try {
      const session = await loadSession(req, {
        sessionStore: options.server.sessionStore,
        cookieName: options.cookieName,
      });

      if (!session) {
        unauthorized(res);
        return;
      }

      res.status(200).json(toPublicSessionView(session));
    } catch (error) {
      next(error);
    }
  };
}

/**
 * `POST /auth/logout` — revokes the current session and clears the cookie.
 *
 * Idempotent: returns 204 whether or not a session was found, so a client
 * clearing local state never has to distinguish "logged out" from "was already
 * logged out".
 */
export function createNapExpressLogoutHandler(options: NapExpressOptions): RequestHandler {
  return async (req, res, next) => {
    try {
      const session = await loadSession(req, {
        sessionStore: options.server.sessionStore,
        cookieName: options.cookieName,
      });

      if (session) {
        await options.server.sessionStore.revokeBySessionId(
          session.session_id,
          currentEpochSeconds()
        );
      }

      res.clearCookie(options.cookieName ?? 'session', options.clearCookieOptions ?? { path: '/' });
      res.status(204).end();
    } catch (error) {
      next(error);
    }
  };
}

export function createNapExpressRouter(options: NapExpressOptions): Router {
  const router = express.Router();

  router.use(createNapExpressJsonParser());
  router.post('/init', createNapExpressInitHandler(options));
  router.post('/complete', createNapExpressCompleteHandler(options));
  router.get('/session', createNapExpressSessionHandler(options));
  router.post('/logout', createNapExpressLogoutHandler(options));

  return router;
}

export function requirePermission(
  permission: string,
  options: NapExpressGuardOptions
): RequestHandler {
  REGISTERED_PERMISSIONS.add(permission);

  return async (req, res, next) => {
    try {
      const session = await loadSession(req, options);

      if (!session) {
        unauthorized(res);
        return;
      }

      if (!session.permissions.includes(permission)) {
        forbidden(res);
        return;
      }

      next();
    } catch (error) {
      next(error);
    }
  };
}

export function requireStepUp(options: NapExpressGuardOptions): RequestHandler {
  return async (req, res, next) => {
    try {
      const session = await loadSession(req, options);

      if (!session) {
        unauthorized(res);
        return;
      }

      const providedToken = req.header('x-step-up-token');

      if (
        !providedToken ||
        !session.step_up_token ||
        session.step_up_token !== providedToken ||
        !session.step_up_expires_at ||
        session.step_up_expires_at <= currentEpochSeconds()
      ) {
        forbidden(res, 'step-up required');
        return;
      }

      next();
    } catch (error) {
      next(error);
    }
  };
}

export function validatePermissions(registry: PermissionRegistry): void {
  validatePermissionRegistry(registry);

  const declared = new Set(registry.permissions.map((permission) => permission.key));
  const unknown = Array.from(REGISTERED_PERMISSIONS).filter(
    (permission) => !declared.has(permission)
  );

  if (unknown.length > 0) {
    throw new Error(
      `Permissions used in middleware but missing from registry: ${unknown.join(', ')}`
    );
  }
}

export function resetPermissionValidationState(): void {
  REGISTERED_PERMISSIONS.clear();
}

export function createPermissionsRouter(registry: PermissionRegistry): Router {
  const router = express.Router();
  router.get('/permissions', (_req, res) => {
    res.status(200).json(registry);
  });
  return router;
}

export function writeNapCookieSuccess(
  cookieName: string,
  cookieOptions?: CookieOptions,
  transformBody?: (body: ReturnType<typeof toPublicAuthSuccess>) => unknown
): NapExpressOptions['writeSuccess'] {
  return ({ res, body }) => {
    if (cookieOptions) {
      res.cookie(cookieName, body.access_token, cookieOptions);
    } else {
      res.cookie(cookieName, body.access_token);
    }
    res.status(200).json(transformBody ? transformBody(body) : { status: 'ok' });
  };
}

/**
 * Derives the audience from the incoming request. Contains no trust policy:
 * `Host` is read raw, and whether `X-Forwarded-Proto` is believed is entirely
 * Express's `trust proxy` setting. Prefer a pinned constant
 * (`() => 'https://api.example.com'`) or a Host allowlist. See §9.4 of
 * docs/NAP-INTEGRATION-GUIDE.md.
 */
export function createRequestDerivedBaseUrlResolver(): NapExpressOptions['getExternalBaseUrl'] {
  return (req) => {
    const host = req.get('host');

    if (!host) {
      throw new Error('Unable to resolve external host for NAP request');
    }

    return `${req.protocol}://${host}`;
  };
}
