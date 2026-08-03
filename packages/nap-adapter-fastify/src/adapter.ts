import type { SerializeOptions } from 'cookie';
import { serialize } from 'cookie';
import type {
  FastifyInstance,
  FastifyPluginAsync,
  FastifyReply,
  FastifyRequest,
  RouteHandlerMethod,
  preHandlerHookHandler,
} from 'fastify';
import {
  resolveEffectiveAcl,
  toPublicAuthFailure,
  toPublicAuthSuccess,
  toPublicSessionView,
  validatePermissionRegistry,
  issueChallenge,
  isMalformedRequestFailure,
  isVerifyFailure,
  verifyCompletion,
  type AclResolver,
  type Clock,
  type EffectiveAcl,
  type IssueChallengeResult,
  type NapServerOptions,
  type PermissionRegistry,
  type SessionStore,
} from '@imani/nap-server';
import type { SessionRecord, VerifyCompleteFailure } from '@imani/nap-core';

const RAW_BODY_SYMBOL = Symbol.for('nap.fastify.rawBody');
const REGISTERED_PERMISSIONS = new Set<string>();
const REGISTERED_ROLES = new Set<string>();

function currentEpochSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

export interface NapFastifyRequest extends FastifyRequest {
  [RAW_BODY_SYMBOL]?: Uint8Array;
}

export interface NapFastifyOptions {
  server: NapServerOptions;
  routePrefix?: string;
  getExternalBaseUrl(req: FastifyRequest): string;
  /** Cookie carrying the access token, read by `/auth/session` and cleared by `/auth/logout`. Defaults to `session`. */
  cookieName?: string;
  /** Attributes used when clearing the cookie on logout. Must match those used to set it, or the browser keeps it. Defaults to `{ path: '/' }`. */
  clearCookieOptions?: SerializeOptions;
  /**
   * Maximum accepted body size on the NAP routes, in bytes. Defaults to 1024.
   *
   * A valid `/auth/complete` body is around 40 bytes and `/auth/init` under
   * 100; Fastify's own default is 1 MB, which on an unauthenticated endpoint is
   * 1 MB of parsing an anonymous caller can buy per request. Oversized bodies
   * are rejected with a 413.
   */
  bodyLimitBytes?: number;
  /**
   * Caller address for rate limiting and the per-IP outstanding-challenge cap.
   *
   * Defaults to `req.ip`, which honours `X-Forwarded-For` only when the app has
   * set Fastify's `trustProxy` — so it is correct behind a configured proxy and
   * correct on a direct connection, and wrong exactly when `trustProxy` is
   * wrong. Return `undefined` to opt out: the per-IP cap is then skipped rather
   * than enforced against a value anyone can forge.
   */
  getClientIp?: (req: FastifyRequest) => string | undefined;
  writeSuccess?: (ctx: {
    req: FastifyRequest;
    reply: FastifyReply;
    body: ReturnType<typeof toPublicAuthSuccess>;
  }) => void | Promise<void>;
  writeFailure?: (ctx: {
    req: FastifyRequest;
    reply: FastifyReply;
    result: VerifyCompleteFailure;
  }) => void | Promise<void>;
}

export interface NapFastifyGuardOptions {
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
  clock?: Clock;
}

function setRawBody(req: FastifyRequest, rawBody: Uint8Array): void {
  (req as NapFastifyRequest)[RAW_BODY_SYMBOL] = rawBody;
}

function getRawBody(req: FastifyRequest): Uint8Array | null {
  return (req as NapFastifyRequest)[RAW_BODY_SYMBOL] ?? null;
}

function normalizeBaseUrl(value: string): string {
  return value.endsWith('/') ? value.slice(0, -1) : value;
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
  req: FastifyRequest,
  options: NapFastifyGuardOptions
): Promise<Awaited<ReturnType<SessionStore['getByAccessToken']>>> {
  const authorization = req.headers.authorization;
  const bearerToken = authorization?.startsWith('Bearer ')
    ? authorization.slice('Bearer '.length).trim()
    : null;
  const cookieToken = parseCookieValue(
    typeof req.headers.cookie === 'string' ? req.headers.cookie : undefined,
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

function unauthorized(reply: FastifyReply): void {
  const failure = toPublicAuthFailure();
  reply.status(failure.status).send(failure.body);
}

function forbidden(reply: FastifyReply, reason = 'forbidden'): void {
  reply.status(403).send({
    status: 'error',
    message: reason,
  });
}

function rateLimited(reply: FastifyReply, retryAfterSeconds?: number): void {
  if (retryAfterSeconds !== undefined) {
    reply.header('retry-after', String(retryAfterSeconds));
  }

  const failure = toPublicAuthFailure();
  reply.status(429).send(failure.body);
}

function hasValidStepUpToken(req: FastifyRequest, session: SessionRecord): boolean {
  const providedToken = req.headers['x-step-up-token'];
  const stepUpToken = Array.isArray(providedToken) ? providedToken[0] : providedToken;

  return Boolean(
    stepUpToken &&
      session.step_up_token &&
      session.step_up_token === stepUpToken &&
      session.step_up_expires_at &&
      session.step_up_expires_at > currentEpochSeconds()
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
  req: FastifyRequest,
  options: NapFastifyGuardOptions
): Promise<{ session: SessionRecord; acl: EffectiveAcl } | null> {
  const session = await loadSession(req, options);

  if (!session) {
    return null;
  }

  const acl = await resolveEffectiveAcl(session, {
    aclResolver: options.aclResolver,
    sessionStore: options.sessionStore,
    clock: options.clock,
  });

  return acl ? { session, acl } : null;
}

function authCompleteUrl(req: FastifyRequest, options: NapFastifyOptions): string {
  return `${normalizeBaseUrl(options.getExternalBaseUrl(req))}/auth/complete`;
}

function clientIpOf(req: FastifyRequest, options: NapFastifyOptions): string | undefined {
  return options.getClientIp ? options.getClientIp(req) : req.ip;
}

function issueChallengeFailure(reply: FastifyReply, result: Exclude<IssueChallengeResult, { ok: true }>): void {
  if (result.code === 'NAP_INIT_RATE_LIMITED') {
    rateLimited(reply, result.retryAfterSeconds);
    return;
  }

  const status = result.code === 'NAP_INIT_INVALID_NPUB' ? 400 : 500;
  reply.status(status).send({
    status: 'error',
    message: result.code === 'NAP_INIT_INVALID_NPUB' ? 'bad request' : 'internal error',
  });
}

function defaultWriteFailure(reply: FastifyReply): void {
  const failure = toPublicAuthFailure();
  reply.status(failure.status).send(failure.body);
}

/**
 * Derives the audience from the incoming request. Contains no trust policy:
 * `Host` is read raw, and whether `X-Forwarded-Proto` is believed is entirely
 * Fastify's `trustProxy` setting. Prefer a pinned constant
 * (`() => 'https://api.example.com'`) or a Host allowlist. See §9.4 of
 * docs/NAP-INTEGRATION-GUIDE.md.
 */
export function createRequestDerivedBaseUrlResolver(): NapFastifyOptions['getExternalBaseUrl'] {
  return (req) => {
    const host = req.headers.host;

    if (!host) {
      throw new Error('Unable to resolve external host for NAP request');
    }

    return `${req.protocol}://${host}`;
  };
}

export function writeNapCookieSuccess(
  cookieName: string,
  cookieOptions?: SerializeOptions,
  transformBody?: (body: ReturnType<typeof toPublicAuthSuccess>) => unknown
): NapFastifyOptions['writeSuccess'] {
  return ({ reply, body }) => {
    reply.header('set-cookie', serialize(cookieName, body.access_token, cookieOptions));
    reply.status(200).send(transformBody ? transformBody(body) : { status: 'ok' });
  };
}

export function createNapFastifyInitHandler(options: NapFastifyOptions): RouteHandlerMethod {
  return async (req, reply) => {
    const npub = (req.body as Record<string, unknown> | undefined)?.npub;

    if (typeof npub !== 'string') {
      reply.status(400).send({
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
      issueChallengeFailure(reply, result);
      return;
    }

    reply.status(200).send(result.value);
  };
}

export function createNapFastifyCompleteHandler(options: NapFastifyOptions): RouteHandlerMethod {
  return async (req, reply) => {
    const rawBody = getRawBody(req);

    if (!rawBody) {
      throw new Error('nap-adapter-fastify requires raw body capture for /auth/complete');
    }

    const result = await verifyCompletion(
      {
        authorization: req.headers.authorization,
        method: req.method,
        url: authCompleteUrl(req, options),
        rawBody,
        clientIp: clientIpOf(req, options),
      },
      options.server
    );

    if (isMalformedRequestFailure(result)) {
      reply.status(result.publicResponse.status).send(result.publicResponse.body);
      return;
    }

    if (isVerifyFailure(result)) {
      if (result.code === 'NAP_COMPLETE_RATE_LIMITED') {
        rateLimited(reply, result.retryAfterSeconds);
        return;
      }

      if (options.writeFailure) {
        await options.writeFailure({ req, reply, result });
        return;
      }

      defaultWriteFailure(reply);
      return;
    }

    const body = toPublicAuthSuccess(result.session);

    if (options.writeSuccess) {
      await options.writeSuccess({ req, reply, body });
      return;
    }

    reply.status(200).send(body);
  };
}

function installNapJsonParser(instance: FastifyInstance, bodyLimitBytes = 1024): void {
  instance.addContentTypeParser(
    'application/json',
    { parseAs: 'buffer', bodyLimit: bodyLimitBytes },
    (req, body, done) => {
      try {
        const rawBody =
          typeof body === 'string'
            ? new TextEncoder().encode(body)
            : new Uint8Array(body);

        setRawBody(req, rawBody);

        const text = body.toString('utf8');
        const parsed = text.length === 0 ? {} : JSON.parse(text);
        done(null, parsed);
      } catch (error) {
        done(error as Error, undefined);
      }
    }
  );
}

/**
 * `GET /auth/session` — returns the current session, or 401 if there is none.
 *
 * The body omits `access_token` (see `toPublicSessionView`): in cookie mode the
 * token is HttpOnly, and echoing it here would hand it to any script on the
 * page.
 */
export function createNapFastifySessionHandler(options: NapFastifyOptions): RouteHandlerMethod {
  return async (req, reply) => {
    const session = await loadSession(req, {
      sessionStore: options.server.sessionStore,
      cookieName: options.cookieName,
    });

    if (!session) {
      unauthorized(reply);
      return;
    }

    reply.status(200).send(toPublicSessionView(session));
  };
}

/**
 * `POST /auth/logout` — revokes the current session and clears the cookie.
 *
 * Idempotent: returns 204 whether or not a session was found, so a client
 * clearing local state never has to distinguish "logged out" from "was already
 * logged out".
 */
export function createNapFastifyLogoutHandler(options: NapFastifyOptions): RouteHandlerMethod {
  return async (req, reply) => {
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

    reply.header(
      'set-cookie',
      serialize(options.cookieName ?? 'session', '', {
        path: '/',
        ...options.clearCookieOptions,
        maxAge: 0,
      })
    );
    reply.status(204).send();
  };
}

export const napFastifyPlugin: FastifyPluginAsync<NapFastifyOptions> = async (fastify, options) => {
  installNapJsonParser(fastify, options.bodyLimitBytes);

  const prefix = normalizeBaseUrl(options.routePrefix ?? '');

  fastify.post(`${prefix}/init`, createNapFastifyInitHandler(options));
  fastify.post(`${prefix}/complete`, createNapFastifyCompleteHandler(options));
  fastify.get(`${prefix}/session`, createNapFastifySessionHandler(options));
  fastify.post(`${prefix}/logout`, createNapFastifyLogoutHandler(options));
};

export function requirePermission(
  permission: string,
  options: NapFastifyGuardOptions
): preHandlerHookHandler {
  REGISTERED_PERMISSIONS.add(permission);

  return async (req, reply) => {
    const context = await loadGuardContext(req, options);

    if (!context) {
      unauthorized(reply);
      return;
    }

    if (!context.acl.permissions.includes(permission)) {
      forbidden(reply);
      return;
    }

    // `stepUp: true` on the registry definition is enforced here rather than
    // needing requireStepUp() chained at every call site, where forgetting it
    // is silent.
    if (
      requiresStepUp(permission, options.registry) &&
      !hasValidStepUpToken(req, context.session)
    ) {
      forbidden(reply, 'step-up required');
      return;
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
 * Pass an array for any-of semantics (`['admin', 'owner']`). Chaining hooks
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
  options: NapFastifyGuardOptions
): preHandlerHookHandler {
  const accepted = Array.isArray(role) ? role : [role];
  accepted.forEach((entry) => REGISTERED_ROLES.add(entry));

  return async (req, reply) => {
    const context = await loadGuardContext(req, options);

    if (!context) {
      unauthorized(reply);
      return;
    }

    if (!accepted.some((entry) => context.acl.roles.includes(entry))) {
      forbidden(reply);
      return;
    }
  };
}

export function requireStepUp(options: NapFastifyGuardOptions): preHandlerHookHandler {
  return async (req, reply) => {
    const session = await loadSession(req, options);

    if (!session) {
      unauthorized(reply);
      return;
    }

    if (!hasValidStepUpToken(req, session)) {
      forbidden(reply, 'step-up required');
      return;
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

export const permissionsFastifyPlugin = (registry: PermissionRegistry): FastifyPluginAsync => {
  return async (fastify) => {
    fastify.get('/permissions', async () => registry);
  };
};
