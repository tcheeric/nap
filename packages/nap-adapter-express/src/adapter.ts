import express, { type CookieOptions, type Request, type RequestHandler, type Response, type Router } from 'express';
import {
  resolveEffectiveAcl,
  constantTimeEquals,
  toPublicAuthFailure,
  toPublicAuthSuccess,
  toPublicSessionView,
  validatePermissionRegistry,
  issueChallenge,
  isMalformedRequestFailure,
  isVerifyFailure,
  refreshSession,
  verifyCompletion,
  createAudienceHostAllowlist,
  logGuardDenial,
  GUARD_DENIAL_CODES,
  type AclResolver,
  type AudienceResolver,
  type AuditLogger,
  type Clock,
  type EffectiveAcl,
  type GuardDenialDetails,
  type IssueChallengeResult,
  type MetricsRecorder,
  type NapServerOptions,
  type PermissionRegistry,
  type RawBodyExtractor,
  type SessionStore,
} from '@imani/nap-server';
import type { SessionRecord, VerifyCompleteFailure } from '@imani/nap-core';

const RAW_BODY_SYMBOL = Symbol.for('nap.rawBody');
const REGISTERED_PERMISSIONS = new Set<string>();
const REGISTERED_ROLES = new Set<string>();

function currentEpochSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

/**
 * The guard's notion of now.
 *
 * `NapExpressGuardOptions.clock` was previously honoured only by
 * `resolveEffectiveAcl`, while session expiry and step-up expiry read the wall
 * clock directly. A guard configured with an injected clock therefore agreed
 * with the server about the ACL and disagreed about time, which is the kind of
 * split that shows up as a session that logs in successfully and is then
 * rejected by the very next guarded request.
 */
function guardNow(options: { clock?: Clock }): number {
  return options.clock ? options.clock.nowUnix() : currentEpochSeconds();
}

export interface NapExpressOptions {
  server: NapServerOptions;
  /**
   * Shorthand for the common case: return the external origin and the adapter
   * appends `/auth/complete`. Mutually exclusive with `audienceResolver` —
   * supply exactly one.
   */
  getExternalBaseUrl?: (req: Request) => string;
  /**
   * The RFC §20.2 form, for when the completion endpoint is not `<base>/auth/complete`
   * — a rewriting gateway, a mounted prefix the app knows and the request does not.
   * Whatever it returns *is* the audience the NIP-98 `u` tag must equal, so it
   * takes the full URL rather than an origin.
   */
  audienceResolver?: AudienceResolver<Request>;
  /** Cookie carrying the access token, read by `/auth/session` and cleared by `/auth/logout`. Defaults to `session`. */
  cookieName?: string;
  /**
   * Attributes used when clearing the cookie on logout. They must match the ones it was
   * set with — a browser matches a deletion against name + domain + path — or the browser
   * keeps it and the logout is cosmetic.
   *
   * Leave it unset and the handler reuses the attributes `writeNapCookieSuccess` was given,
   * which is the only pairing that cannot drift. Set it only to override that, e.g. when
   * `writeSuccess` is your own function and the adapter has nothing to copy. Falls back to
   * `{ path: '/' }` when there is neither.
   *
   * The copy is read off `options.writeSuccess`, so it only happens when the logout handler
   * is given the same options object as the cookie writer. Mounting handlers individually
   * with a trimmed options object means there is nothing to copy from, and this field is
   * the only thing standing between you and a `{ path: '/' }` guess.
   */
  clearCookieOptions?: CookieOptions;
  /**
   * Maximum accepted body size on the NAP routes. Defaults to `'1kb'`.
   *
   * A valid `/auth/complete` body is around 40 bytes and `/auth/init` under
   * 100; `express.json()`'s own default is 100 kB, which on an unauthenticated
   * endpoint is 100 kB of parsing an anonymous caller can buy per request.
   * Oversized bodies are rejected by `express.json()` with a 413.
   */
  bodyLimit?: string | number;
  /**
   * Caller address for rate limiting and the per-IP outstanding-challenge cap.
   *
   * Defaults to `req.ip`, which honours `X-Forwarded-For` only when the app has
   * set Express's `trust proxy` — so it is correct behind a configured proxy and
   * correct on a direct connection, and wrong exactly when `trust proxy` is
   * wrong. Return `undefined` to opt out: the per-IP cap is then skipped rather
   * than enforced against a value anyone can forge.
   */
  getClientIp?: (req: Request) => string | undefined;
  /**
   * Where `/auth/complete` reads the exact bytes the NIP-98 `payload` tag hashed.
   *
   * Defaults to the buffer `createNapExpressJsonParser()` stashes on the request.
   * Supply your own only if the raw body is captured somewhere else — never one
   * that re-stringifies `req.body`, which changes key order and whitespace and
   * fails every completion with `NAP_COMPLETE_PAYLOAD_MISMATCH`.
   */
  rawBodyExtractor?: RawBodyExtractor<Request>;
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
  /**
   * Re-read the ACL on every guarded request instead of trusting the login-time
   * snapshot in `session.permissions` (RFC §15 rule 1).
   *
   * Without it, a suspension or role change takes effect only when the session
   * expires — up to the full session TTL, 15 minutes by default. With it, a
   * principal who has lost access is denied on their next request and their
   * sessions are revoked.
   *
   * Costs one ACL read per guarded request. Pass the same resolver you gave
   * `NapServerOptions.aclResolver`.
   */
  aclResolver?: AclResolver;
  /**
   * Registry used to decide whether a permission requires a step-up token.
   *
   * When supplied, `requirePermission('stripe:manage')` additionally demands a
   * valid `X-Step-Up-Token` if the registry marks that permission
   * `stepUp: true` — so the flag on the definition is enforced rather than
   * documentation.
   */
  registry?: PermissionRegistry;
  /**
   * Records a `NAP_GUARD_*` code per refusal.
   *
   * The guards are the authorization boundary — `/auth/complete` decides who
   * you are once, these decide what you may do on every request after — and
   * without this a refusal is invisible: no code, no principal, no record. An
   * operator watching the log sees an unbroken run of `NAP_COMPLETE_SUCCESS`
   * whether or not half the traffic is being denied.
   *
   * Pass the same logger you gave `NapServerOptions.auditLogger`, so login and
   * per-request authorization land in one stream.
   */
  auditLogger?: AuditLogger;
  /** Pass the same recorder as `NapServerOptions.metrics` to count guard denials. */
  metrics?: MetricsRecorder;
  /**
   * The guard's notion of "now", for session expiry, step-up expiry, and ACL
   * re-resolution.
   *
   * Defaults to the wall clock. **Pass the same clock you gave
   * `NapServerOptions`** if you inject one: a guard on a different clock from
   * the server disagrees about when a session ends, and the symptom is a login
   * that succeeds and is then refused by the very next guarded request.
   */
  clock?: Clock;
}

/**
 * Why a guard refused, so the denial can be audited with a code.
 *
 * `loadGuardContext` previously collapsed "no session" and "the ACL now denies
 * this principal" into a single `null`, which is exactly the distinction an
 * operator needs: the first is unauthenticated traffic, the second is a live
 * session whose access was revoked underneath it.
 */
type GuardContext =
  | { ok: true; session: SessionRecord; acl: EffectiveAcl }
  | { ok: false; code: typeof GUARD_DENIAL_CODES[keyof typeof GUARD_DENIAL_CODES]; session?: SessionRecord };

async function denyGuard(
  res: Response,
  options: NapExpressGuardOptions,
  code: typeof GUARD_DENIAL_CODES[keyof typeof GUARD_DENIAL_CODES],
  session: SessionRecord | undefined,
  write: () => void,
  details?: GuardDenialDetails
): Promise<void> {
  await logGuardDenial(code, {
    auditLogger: options.auditLogger,
    metrics: options.metrics,
    session,
    details,
  });

  write();
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

function rateLimited(res: Response, retryAfterSeconds?: number): void {
  if (retryAfterSeconds !== undefined) {
    res.setHeader('Retry-After', String(retryAfterSeconds));
  }

  // Not the generic auth-failure body: the whole reason this is a 429 and not a
  // 401 is to stop the client retrying harder, and telling it the credentials
  // were rejected undoes that. The status code has already leaked everything
  // this message could.
  res.status(429).json({
    status: 'error',
    message: 'rate limited',
  });
}

function hasValidStepUpToken(
  req: Request,
  session: SessionRecord,
  options: NapExpressGuardOptions
): boolean {
  const providedToken = req.header('x-step-up-token');

  return Boolean(
    providedToken &&
      session.step_up_token &&
      constantTimeEquals(session.step_up_token, providedToken) &&
      session.step_up_expires_at &&
      session.step_up_expires_at > guardNow(options)
  );
}

function requiresStepUp(permission: string, registry: PermissionRegistry | undefined): boolean {
  return registry?.permissions.some(
    (definition) => definition.key === permission && definition.stepUp
  ) === true;
}

/**
 * Load the session and the roles/permissions the request should be judged
 * against, or null when either step denies.
 */
async function loadGuardContext(
  req: Request,
  options: NapExpressGuardOptions
): Promise<GuardContext> {
  const session = await loadSession(req, options);

  if (!session) {
    return { ok: false, code: GUARD_DENIAL_CODES.NO_SESSION };
  }

  const acl = await resolveEffectiveAcl(session, {
    aclResolver: options.aclResolver,
    sessionStore: options.sessionStore,
    clock: options.clock,
  });

  // The session was valid, so the principal is nameable even though the ACL
  // just refused them — which is the whole value of auditing this branch apart.
  return acl
    ? { ok: true, session, acl }
    : { ok: false, code: GUARD_DENIAL_CODES.ACL_DENIED, session };
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

  if (session.revoked_at || session.expires_at <= guardNow(options)) {
    return null;
  }

  return session;
}

function authCompleteUrl(req: Request, options: NapExpressOptions): string {
  return options.audienceResolver
    ? options.audienceResolver.resolve(req)
    : `${normalizeBaseUrl(options.getExternalBaseUrl!(req))}/auth/complete`;
}

/**
 * Both options set means two answers to "what is the audience", and the wrong
 * one silently becomes the value every NIP-98 proof is checked against. Neither
 * means the adapter would have to guess from the request, which is exactly the
 * trust decision `createRequestDerivedBaseUrlResolver()` documents as the
 * caller's to make. Either way it is a wiring mistake, so it fails at startup
 * rather than as a uniform 401 per request.
 */
function assertOneAudienceSource(options: {
  getExternalBaseUrl?: unknown;
  audienceResolver?: unknown;
}): void {
  const supplied = [options.getExternalBaseUrl, options.audienceResolver].filter(Boolean).length;

  if (supplied !== 1) {
    throw new Error(
      'NAP adapter requires exactly one of getExternalBaseUrl or audienceResolver'
    );
  }
}

/**
 * Marks a `writeSuccess` that replies without the tokens. `Symbol.for` rather than a
 * module-local symbol so it survives an adapter loaded twice through different paths —
 * a duplicated copy failing this check open would be exactly the silent case it exists
 * to catch.
 */
const DISCARDS_TOKENS = Symbol.for('nap.writeSuccess.discardsTokens');

function discardsTokens(writeSuccess: NapExpressOptions['writeSuccess']): boolean {
  return Boolean(writeSuccess && (writeSuccess as unknown as Record<symbol, unknown>)[DISCARDS_TOKENS]);
}

/**
 * Carries the attributes `writeNapCookieSuccess` set the cookie with, so `/auth/logout`
 * can clear it with the same ones. A browser matches a deletion against name + domain +
 * path and drops a `Set-Cookie` whose `SameSite` it disagrees with, so a clear guessing
 * `{ path: '/' }` at a cookie set with a domain leaves it in the jar — a logout that
 * returns 204 and does not log out. `Symbol.for` for the same reason as above.
 */
const COOKIE_ATTRS = Symbol.for('nap.writeSuccess.cookieAttrs');

/**
 * `maxAge` and `expires` are dropped deliberately: they are the one pair that must *not*
 * carry over. `res.clearCookie` sets `expires` to the epoch, but then hands the options to
 * `res.cookie`, which recomputes `expires` from any surviving `maxAge` — so a copied
 * `maxAge` would reissue the cookie the clear exists to remove.
 */
function setCookieAttrsOf(writeSuccess: NapExpressOptions['writeSuccess']): CookieOptions | undefined {
  const attrs = writeSuccess && (writeSuccess as unknown as Record<symbol, unknown>)[COOKIE_ATTRS];

  if (!attrs) {
    return undefined;
  }

  const { maxAge: _maxAge, expires: _expires, ...rest } = attrs as CookieOptions;

  return rest;
}

/** The name `writeNapCookieSuccess` writes under, so wiring can check it against `cookieName`. */
const COOKIE_NAME = Symbol.for('nap.writeSuccess.cookieName');

/**
 * `writeNapCookieSuccess` takes the cookie name as its own argument, but every read of that
 * cookie — `/auth/session`, the guards, the logout clear — goes through `options.cookieName`.
 * Nothing forces the two to be the same string, and when they are not, the failure is mute:
 * login returns 200 and sets the cookie, then `/auth/session` looks for a different name,
 * finds nothing, and 401s. Every page load logs the user back out, and logout clears a
 * cookie that was never set.
 *
 * So refuse to wire it. Inert rather than insecure, but silently inert is the case worth
 * failing loudly on — the same reason `assertRefreshIsWirable` exists.
 */
function assertCookieNamesAgree(options: NapExpressOptions): void {
  const written = options.writeSuccess && (options.writeSuccess as unknown as Record<symbol, unknown>)[COOKIE_NAME];

  if (typeof written !== 'string') {
    return;
  }

  const read = options.cookieName ?? 'session';

  if (written !== read) {
    throw new Error(
      `NAP cookie name mismatch: writeNapCookieSuccess writes '${written}' but the adapter ` +
        `reads '${read}'. /auth/session and /auth/logout would look for a cookie that is never ` +
        `set. Pass cookieName: '${written}' alongside writeSuccess, or write under '${read}'.`
    );
  }
}

function rawBodyOf(req: Request, options: NapExpressOptions): Uint8Array | null {
  return options.rawBodyExtractor ? options.rawBodyExtractor.extract(req) : getRawBody(req);
}

function bearerTokenOf(req: Request): string | undefined {
  const header = req.header('authorization');

  return header?.toLowerCase().startsWith('bearer ') ? header.slice(7).trim() : undefined;
}

/**
 * A `refreshTtlSeconds` the store cannot honour would mint refresh tokens that
 * every `/auth/refresh` then rejects — indistinguishable, from the client, from
 * a stolen token. It is a wiring error, so it surfaces at startup.
 */
function assertRefreshIsWirable(options: NapExpressOptions): void {
  const store = options.server.sessionStore;

  if (!options.server.refreshTtlSeconds) {
    throw new Error('NAP /auth/refresh requires server.refreshTtlSeconds to be set');
  }

  if (!store.getByRefreshToken || !store.rotateRefreshToken) {
    throw new Error(
      'NAP refreshTtlSeconds requires a SessionStore implementing getByRefreshToken and rotateRefreshToken'
    );
  }

  // The refresh token would be minted, stored, and then dropped on the floor by a
  // `writeSuccess` that replies `{ status: 'ok' }` — leaving a client that can never
  // present the credential this endpoint exists to accept. Inert rather than insecure,
  // but silently inert, which is why it fails here.
  if (discardsTokens(options.writeSuccess)) {
    throw new Error(
      'NAP refreshTtlSeconds cannot be combined with the default writeNapCookieSuccess body: ' +
        'it replies {status:"ok"}, so the client never receives the refresh token that ' +
        '/auth/refresh requires. Pass a transformBody that returns refresh_token, or leave ' +
        'refreshTtlSeconds unset.'
    );
  }
}

function issueChallengeFailure(res: Response, result: Exclude<IssueChallengeResult, { ok: true }>): void {
  if (result.code === 'NAP_INIT_RATE_LIMITED') {
    rateLimited(res, result.retryAfterSeconds);
    return;
  }

  const status = result.code === 'NAP_INIT_INVALID_NPUB' ? 400 : 500;
  res.status(status).json({
    status: 'error',
    message: result.code === 'NAP_INIT_INVALID_NPUB' ? 'bad request' : 'internal error',
  });
}

function clientIpOf(req: Request, options: NapExpressOptions): string | undefined {
  return options.getClientIp ? options.getClientIp(req) : req.ip;
}

export function createNapExpressJsonParser(bodyLimit: string | number = '1kb'): RequestHandler {
  return express.json({
    limit: bodyLimit,
    verify(req, _res, buf) {
      setRawBody(req, new Uint8Array(buf));
    },
  });
}

export function createNapExpressInitHandler(options: NapExpressOptions): RequestHandler {
  assertOneAudienceSource(options);

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
          clientIp: clientIpOf(req, options),
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
  assertOneAudienceSource(options);
  assertCookieNamesAgree(options);

  return async (req, res, next) => {
    try {
      const rawBody = rawBodyOf(req, options);

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
          clientIp: clientIpOf(req, options),
        },
        options.server
      );

      if (isMalformedRequestFailure(result)) {
        res.status(result.publicResponse.status).json(result.publicResponse.body);
        return;
      }

      if (isVerifyFailure(result)) {
        if (result.code === 'NAP_COMPLETE_RATE_LIMITED') {
          rateLimited(res, result.retryAfterSeconds);
          return;
        }

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

      res.clearCookie(
        options.cookieName ?? 'session',
        options.clearCookieOptions ?? setCookieAttrsOf(options.writeSuccess) ?? { path: '/' }
      );
      res.status(204).end();
    } catch (error) {
      next(error);
    }
  };
}

/**
 * `POST /auth/refresh` — exchanges a rotating refresh token for a new access
 * token (RFC §14.1). The token is read from `Authorization: Bearer`, never a
 * cookie: a cookie would be attached by the browser to any request to the
 * origin, which is exactly what a credential this long-lived must not be.
 *
 * Registered only when `refreshTtlSeconds` is configured.
 */
export function createNapExpressRefreshHandler(options: NapExpressOptions): RequestHandler {
  assertRefreshIsWirable(options);

  return async (req, res, next) => {
    try {
      const result = await refreshSession(
        {
          refreshToken: bearerTokenOf(req),
          clientIp: clientIpOf(req, options),
        },
        options.server
      );

      if (!result.ok) {
        if (result.code === 'NAP_REFRESH_RATE_LIMITED') {
          rateLimited(res, result.retryAfterSeconds);
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

export function createNapExpressRouter(options: NapExpressOptions): Router {
  const router = express.Router();

  router.use(createNapExpressJsonParser(options.bodyLimit));
  router.post('/init', createNapExpressInitHandler(options));
  router.post('/complete', createNapExpressCompleteHandler(options));
  router.get('/session', createNapExpressSessionHandler(options));
  router.post('/logout', createNapExpressLogoutHandler(options));

  if (options.server.refreshTtlSeconds) {
    router.post('/refresh', createNapExpressRefreshHandler(options));
  }

  return router;
}

export function requirePermission(
  permission: string,
  options: NapExpressGuardOptions
): RequestHandler {
  REGISTERED_PERMISSIONS.add(permission);

  return async (req, res, next) => {
    try {
      const context = await loadGuardContext(req, options);

      if (!context.ok) {
        await denyGuard(res, options, context.code, context.session, () => unauthorized(res), {
          permission,
        });
        return;
      }

      if (!context.acl.permissions.includes(permission)) {
        await denyGuard(
          res,
          options,
          GUARD_DENIAL_CODES.PERMISSION_DENIED,
          context.session,
          () => forbidden(res),
          { permission }
        );
        return;
      }

      // `stepUp: true` on the registry definition is enforced here rather than
      // needing requireStepUp() chained at every call site, where forgetting it
      // is silent.
      if (
        requiresStepUp(permission, options.registry) &&
        !hasValidStepUpToken(req, context.session, options)
      ) {
        await denyGuard(
          res,
          options,
          GUARD_DENIAL_CODES.STEP_UP_REQUIRED,
          context.session,
          () => forbidden(res, 'step-up required'),
          { permission }
        );
        return;
      }

      next();
    } catch (error) {
      next(error);
    }
  };
}

/**
 * Guard a route on role membership.
 *
 * **Prefer `requirePermission()`.** Roles are already expanded into
 * `session.permissions` by the ACL resolver, so any role check is expressible as
 * a permission check — and the two differ in which direction maintenance flows.
 * Guarding on `voucher:issue` means a new role that should have access is one
 * registry edit; guarding on `merchant` means editing every guard site that
 * should now also accept it. The registry exists to centralise that mapping, and
 * role guards route around it.
 *
 * Reach for this when the role genuinely is the thing being authorised —
 * break-glass or staff-only routes — rather than as the default.
 *
 * Pass an array for any-of semantics (`['admin', 'owner']`). Chaining middleware
 * gives you AND, so OR is otherwise unexpressible without a hand-rolled check
 * that skips the startup validation below.
 *
 * Registered roles are checked against the registry by `validatePermissions()`,
 * so a typo fails at startup rather than silently 403ing forever.
 *
 * Without `aclResolver` in the guard options the check runs against
 * `session.roles`, a login-time snapshot: a role revoked mid-session still
 * passes until the session TTL expires. Pass the resolver to re-read the ACL per
 * request.
 */
export function requireRole(
  role: string | string[],
  options: NapExpressGuardOptions
): RequestHandler {
  const accepted = Array.isArray(role) ? role : [role];
  accepted.forEach((entry) => REGISTERED_ROLES.add(entry));

  return async (req, res, next) => {
    try {
      const context = await loadGuardContext(req, options);

      if (!context.ok) {
        await denyGuard(res, options, context.code, context.session, () => unauthorized(res), {
          roles: accepted,
        });
        return;
      }

      if (!accepted.some((entry) => context.acl.roles.includes(entry))) {
        await denyGuard(
          res,
          options,
          GUARD_DENIAL_CODES.ROLE_DENIED,
          context.session,
          () => forbidden(res),
          { roles: accepted }
        );
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
        await denyGuard(res, options, GUARD_DENIAL_CODES.NO_SESSION, undefined, () =>
          unauthorized(res)
        );
        return;
      }

      if (!hasValidStepUpToken(req, session, options)) {
        await denyGuard(res, options, GUARD_DENIAL_CODES.STEP_UP_REQUIRED, session, () =>
          forbidden(res, 'step-up required')
        );
        return;
      }

      next();
    } catch (error) {
      next(error);
    }
  };
}

/**
 * Guard a route on nothing more than a valid session — the caller is logged in.
 *
 * The authentication-only guard, for routes that are for signed-in users
 * generally and have no permission that distinguishes them. Without it the way
 * to express that is a placeholder permission granted to everyone, which puts a
 * key in the registry that gates nothing and reads, to everyone after you, as
 * though it does.
 *
 * Loads the same context as `requirePermission()` rather than only the session,
 * so passing `aclResolver` denies a principal the ACL has since suspended.
 * Without it the check is the login-time snapshot — session exists, is
 * unrevoked, has not expired — and a suspension lands only when the session
 * does.
 */
export function requireSession(options: NapExpressGuardOptions): RequestHandler {
  return async (req, res, next) => {
    try {
      const context = await loadGuardContext(req, options);

      if (!context.ok) {
        await denyGuard(res, options, context.code, context.session, () => unauthorized(res));
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

  const declaredRoles = new Set(registry.roles.map((role) => role.key));
  const unknownRoles = Array.from(REGISTERED_ROLES).filter((role) => !declaredRoles.has(role));

  if (unknownRoles.length > 0) {
    throw new Error(`Roles used in middleware but missing from registry: ${unknownRoles.join(', ')}`);
  }
}

export function resetPermissionValidationState(): void {
  REGISTERED_PERMISSIONS.clear();
  REGISTERED_ROLES.clear();
}

export function createPermissionsRouter(registry: PermissionRegistry): Router {
  const router = express.Router();
  router.get('/permissions', (_req, res) => {
    res.status(200).json(registry);
  });
  return router;
}

/**
 * Puts the access token in a cookie and replies `{ status: 'ok' }`, so no credential
 * reaches script.
 *
 * That default is incompatible with refresh tokens, and deliberately so: the refresh
 * token would be dropped along with the access token, and `/auth/refresh` reads
 * `Authorization: Bearer`, which a cookie-only browser client cannot produce. The
 * combination is refused at startup rather than left to mint credentials nothing can
 * spend — pass a `transformBody` that returns `refresh_token` if the client really is
 * holding it, or leave `refreshTtlSeconds` unset.
 */
export function writeNapCookieSuccess(
  cookieName: string,
  cookieOptions?: CookieOptions,
  transformBody?: (body: ReturnType<typeof toPublicAuthSuccess>) => unknown
): NapExpressOptions['writeSuccess'] {
  // Snapshotted here, and used by both the set below and the logout clear that reads the
  // stamp. Holding the caller's object instead would let a mutation after wiring move one
  // of the two without the other — the drift this whole pairing exists to prevent.
  const attrs = cookieOptions ? { ...cookieOptions } : undefined;

  const write: NonNullable<NapExpressOptions['writeSuccess']> = ({ res, body }) => {
    if (attrs) {
      res.cookie(cookieName, body.access_token, attrs);
    } else {
      res.cookie(cookieName, body.access_token);
    }
    res.status(200).json(transformBody ? transformBody(body) : { status: 'ok' });
  };

  // A `transformBody` is the caller taking the body over, so only the default is marked.
  if (!transformBody) {
    Object.defineProperty(write, DISCARDS_TOKENS, { value: true });
  }

  // So the logout handler can clear with what the set used, instead of guessing `path: '/'`.
  if (attrs) {
    Object.defineProperty(write, COOKIE_ATTRS, { value: attrs });
  }

  Object.defineProperty(write, COOKIE_NAME, { value: cookieName });

  return write;
}

/**
 * Derives the audience from the incoming request, restricted to hosts you name.
 *
 * `Host` is client-supplied, and whatever this returns *is* the audience every
 * NIP-98 proof is checked against, so an unrestricted version is a request
 * header deciding a security parameter. WebAuthn L3 §13.5.9 forbids the
 * equivalent for origins; the allowlist is the same answer.
 *
 * Entries are exact hosts (`api.example.com`, with the port when it is not the
 * scheme default), optionally scheme-pinned (`https://api.example.com` — the
 * only way to stop a believed `X-Forwarded-Proto` from downgrading the audience
 * to `http`), and optionally subdomain wildcards (`*.example.com`, opt-in per
 * entry because §13.5.8's default is no).
 *
 * A pinned constant (`() => 'https://api.example.com'`) is still the simplest
 * correct answer when the deployment answers on exactly one host. See §9.4 of
 * docs/NAP-INTEGRATION-GUIDE.md.
 */
export function createRequestDerivedBaseUrlResolver(
  allowedHosts: readonly string[]
): (req: Request) => string {
  const allow = createAudienceHostAllowlist(allowedHosts);

  return (req) => allow(req.get('host'), req.protocol);
}
