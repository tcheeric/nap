import express, { type CookieOptions, type Request, type RequestHandler, type Response, type Router } from 'express';
import {
  issueChallenge,
  isMalformedRequestFailure,
  isVerifyFailure,
  toPublicAuthFailure,
  toPublicAuthSuccess,
  verifyCompletion,
  type IssueChallengeResult,
  type NapServerOptions,
} from '@imani/nap-server';
import type { VerifyCompleteFailure } from '@imani/nap-core';

const RAW_BODY_SYMBOL = Symbol.for('nap.rawBody');

export interface NapExpressOptions {
  server: NapServerOptions;
  getExternalBaseUrl(req: Request): string;
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

export function createNapExpressRouter(options: NapExpressOptions): Router {
  const router = express.Router();

  router.use(createNapExpressJsonParser());
  router.post('/init', createNapExpressInitHandler(options));
  router.post('/complete', createNapExpressCompleteHandler(options));

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

export function createTrustedProxyAwareBaseUrlResolver(): NapExpressOptions['getExternalBaseUrl'] {
  return (req) => {
    const host = req.get('host');

    if (!host) {
      throw new Error('Unable to resolve external host for NAP request');
    }

    return `${req.protocol}://${host}`;
  };
}
