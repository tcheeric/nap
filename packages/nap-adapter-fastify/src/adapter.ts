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
  toPublicAuthFailure,
  toPublicAuthSuccess,
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

const RAW_BODY_SYMBOL = Symbol.for('nap.fastify.rawBody');
const REGISTERED_PERMISSIONS = new Set<string>();

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

function authCompleteUrl(req: FastifyRequest, options: NapFastifyOptions): string {
  return `${normalizeBaseUrl(options.getExternalBaseUrl(req))}/auth/complete`;
}

function issueChallengeFailure(reply: FastifyReply, result: Exclude<IssueChallengeResult, { ok: true }>): void {
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

export function createTrustedProxyAwareBaseUrlResolver(): NapFastifyOptions['getExternalBaseUrl'] {
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
      },
      options.server
    );

    if (isMalformedRequestFailure(result)) {
      reply.status(result.publicResponse.status).send(result.publicResponse.body);
      return;
    }

    if (isVerifyFailure(result)) {
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

function installNapJsonParser(instance: FastifyInstance): void {
  instance.addContentTypeParser(
    'application/json',
    { parseAs: 'buffer' },
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

export const napFastifyPlugin: FastifyPluginAsync<NapFastifyOptions> = async (fastify, options) => {
  installNapJsonParser(fastify);

  const prefix = normalizeBaseUrl(options.routePrefix ?? '');

  fastify.post(`${prefix}/init`, createNapFastifyInitHandler(options));
  fastify.post(`${prefix}/complete`, createNapFastifyCompleteHandler(options));
};

export function requirePermission(
  permission: string,
  options: NapFastifyGuardOptions
): preHandlerHookHandler {
  REGISTERED_PERMISSIONS.add(permission);

  return async (req, reply) => {
    const session = await loadSession(req, options);

    if (!session) {
      const failure = toPublicAuthFailure();
      reply.status(failure.status).send(failure.body);
      return;
    }

    if (!session.permissions.includes(permission)) {
      reply.status(403).send({
        status: 'error',
        message: 'forbidden',
      });
      return;
    }
  };
}

export function requireStepUp(options: NapFastifyGuardOptions): preHandlerHookHandler {
  return async (req, reply) => {
    const session = await loadSession(req, options);

    if (!session) {
      const failure = toPublicAuthFailure();
      reply.status(failure.status).send(failure.body);
      return;
    }

    const providedToken = req.headers['x-step-up-token'];
    const stepUpToken = Array.isArray(providedToken) ? providedToken[0] : providedToken;

    if (
      !stepUpToken ||
      !session.step_up_token ||
      session.step_up_token !== stepUpToken ||
      !session.step_up_expires_at ||
      session.step_up_expires_at <= currentEpochSeconds()
    ) {
      reply.status(403).send({
        status: 'error',
        message: 'step-up required',
      });
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
}

export function resetPermissionValidationState(): void {
  REGISTERED_PERMISSIONS.clear();
}

export const permissionsFastifyPlugin = (registry: PermissionRegistry): FastifyPluginAsync => {
  return async (fastify) => {
    fastify.get('/permissions', async () => registry);
  };
};
