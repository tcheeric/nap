import type { EventTemplate } from 'nostr-tools';
import type { Nip98Event } from '@imani/nap-core';

/**
 * Extension 0002 — cross-origin signer. The wire shared by both ends.
 *
 * Every message carries `nap: CROSS_ORIGIN_PROTOCOL`, so a page that also talks
 * to other windows (analytics, payment iframes) cannot mistake their traffic for
 * ours, and a future `/2` can be told apart without guessing.
 *
 * The sender's origin is NEVER in a message. It is whatever the browser reports
 * as `MessageEvent.origin`, which the page that sent it cannot choose. That is
 * the whole point of the extension: RFC §7.1 says the refusal has to come from a
 * signer that knows who is really asking, and the page composes everything
 * except that one field.
 */
export const CROSS_ORIGIN_PROTOCOL = 'nap-cross-origin-signer/1';

/** Default path of the signer page on the key origin. */
export const DEFAULT_SIGNER_PATH = '/nap/signer';

/** Upper bound on a grant's lifetime, matching the default session TTL (§14, §28.4). */
export const MAX_GRANT_TTL_SECONDS = 900;

/** Clock skew tolerated on `created_at` before the signer refuses to sign. */
export const DEFAULT_CREATED_AT_SKEW_SECONDS = 300;

export type CrossOriginErrorCode =
  /** No signer answered: wrong URL, origin not allowed, or the page never loaded. Deliberately one code (§19). */
  | 'NOT_AVAILABLE'
  /** `window.open` returned null. Call `connectCrossOrigin` from a user gesture. */
  | 'POPUP_BLOCKED'
  /** The user said no, to the connection or to one signature. */
  | 'DECLINED'
  /** Outside the grant or the policy: kind, audience, `u` tag, `created_at`, or a malformed request. One code for all of them. */
  | 'REFUSED'
  /** The grant outlived its TTL. Connect again. */
  | 'GRANT_EXPIRED'
  /** The key origin ended the grant: locked, logged out, identity changed, or the user disconnected. */
  | 'REVOKED'
  /** The signer window was closed. Connect again, from a user gesture. */
  | 'CHANNEL_CLOSED'
  /** No answer in time. */
  | 'TIMEOUT'
  /** The signer failed, or returned an event that does not match what was asked for. */
  | 'SIGNER_ERROR';

export class CrossOriginSignerError extends Error {
  readonly code: CrossOriginErrorCode;

  constructor(code: CrossOriginErrorCode, message?: string, options?: { cause?: unknown }) {
    super(message ?? code, options);
    this.name = 'CrossOriginSignerError';
    this.code = code;
  }
}

/** What both sides know about a live grant. Contains no secret: `grantId` names it, it does not unlock it. */
export interface GrantInfo {
  grantId: string;
  pubkey: string;
  kinds: number[];
  audiences: string[];
  /** Unix seconds. */
  expiresAt: number;
}

export type CrossOriginMessage =
  | { nap: typeof CROSS_ORIGIN_PROTOCOL; type: 'ready' }
  | {
      nap: typeof CROSS_ORIGIN_PROTOCOL;
      type: 'connect';
      id: string;
      kinds: number[];
      audiences: string[];
      expectedPubkey?: string;
    }
  | { nap: typeof CROSS_ORIGIN_PROTOCOL; type: 'connected'; id: string; grant: GrantInfo }
  | { nap: typeof CROSS_ORIGIN_PROTOCOL; type: 'sign'; id: string; grantId: string; template: EventTemplate }
  | { nap: typeof CROSS_ORIGIN_PROTOCOL; type: 'signed'; id: string; event: Nip98Event }
  | { nap: typeof CROSS_ORIGIN_PROTOCOL; type: 'error'; id?: string; code: CrossOriginErrorCode }
  | { nap: typeof CROSS_ORIGIN_PROTOCOL; type: 'revoked'; grantId: string }
  | { nap: typeof CROSS_ORIGIN_PROTOCOL; type: 'disconnect'; grantId: string };

/** The slice of `Window` this extension posts to. */
export interface WindowLike {
  postMessage(message: unknown, targetOrigin: string): void;
  readonly closed?: boolean;
}

/** The slice of `MessageEvent` this extension reads. */
export interface MessageEventLike {
  data: unknown;
  origin: string;
  source: unknown;
}

export interface MessageTarget {
  addEventListener(type: 'message', listener: (event: MessageEventLike) => void): void;
  removeEventListener(type: 'message', listener: (event: MessageEventLike) => void): void;
}

const ERROR_CODES: ReadonlySet<string> = new Set<CrossOriginErrorCode>([
  'NOT_AVAILABLE',
  'POPUP_BLOCKED',
  'DECLINED',
  'REFUSED',
  'GRANT_EXPIRED',
  'REVOKED',
  'CHANNEL_CLOSED',
  'TIMEOUT',
  'SIGNER_ERROR',
]);

const HEX64 = /^[0-9a-f]{64}$/;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isId(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= 128;
}

function isKindList(value: unknown): value is number[] {
  return (
    Array.isArray(value) &&
    value.length > 0 &&
    value.length <= 32 &&
    value.every((kind) => Number.isInteger(kind) && kind >= 0 && kind <= 65535)
  );
}

function isStringList(value: unknown): value is string[] {
  return (
    Array.isArray(value) &&
    value.length > 0 &&
    value.length <= 32 &&
    value.every((entry) => typeof entry === 'string' && entry.length <= 512)
  );
}

export function isEventTemplate(value: unknown): value is EventTemplate {
  if (!isRecord(value)) return false;
  const { kind, created_at, content, tags } = value;
  return (
    Number.isInteger(kind) &&
    Number.isInteger(created_at) &&
    typeof content === 'string' &&
    content.length <= 65536 &&
    Array.isArray(tags) &&
    tags.length <= 64 &&
    tags.every(
      (tag) =>
        Array.isArray(tag) &&
        tag.length > 0 &&
        tag.length <= 16 &&
        tag.every((part) => typeof part === 'string' && part.length <= 4096)
    )
  );
}

function isGrantInfo(value: unknown): value is GrantInfo {
  if (!isRecord(value)) return false;
  return (
    isId(value.grantId) &&
    typeof value.pubkey === 'string' &&
    HEX64.test(value.pubkey) &&
    isKindList(value.kinds) &&
    isStringList(value.audiences) &&
    Number.isInteger(value.expiresAt)
  );
}

/**
 * Parse an untrusted message. Returns `null` for anything that is not exactly a
 * message of this protocol, so callers have one branch for "ignore it".
 *
 * Structured clone means `data` can be any object graph, including ones with
 * getters that throw. Every field is read once, type-checked, and copied into a
 * fresh object, so nothing the other side sent is held by reference.
 */
export function parseMessage(data: unknown): CrossOriginMessage | null {
  try {
    if (!isRecord(data) || data.nap !== CROSS_ORIGIN_PROTOCOL || typeof data.type !== 'string') {
      return null;
    }
    const nap = CROSS_ORIGIN_PROTOCOL;

    switch (data.type) {
      case 'ready':
        return { nap, type: 'ready' };
      case 'connect': {
        if (!isId(data.id) || !isKindList(data.kinds) || !isStringList(data.audiences)) return null;
        if (data.expectedPubkey !== undefined && !(typeof data.expectedPubkey === 'string' && HEX64.test(data.expectedPubkey))) {
          return null;
        }
        return {
          nap,
          type: 'connect',
          id: data.id,
          kinds: [...data.kinds],
          audiences: [...data.audiences],
          ...(data.expectedPubkey ? { expectedPubkey: data.expectedPubkey } : {}),
        };
      }
      case 'connected':
        if (!isId(data.id) || !isGrantInfo(data.grant)) return null;
        return {
          nap,
          type: 'connected',
          id: data.id,
          grant: {
            grantId: data.grant.grantId,
            pubkey: data.grant.pubkey,
            kinds: [...data.grant.kinds],
            audiences: [...data.grant.audiences],
            expiresAt: data.grant.expiresAt,
          },
        };
      case 'sign':
        if (!isId(data.id) || !isId(data.grantId) || !isEventTemplate(data.template)) return null;
        return {
          nap,
          type: 'sign',
          id: data.id,
          grantId: data.grantId,
          template: {
            kind: data.template.kind,
            created_at: data.template.created_at,
            content: data.template.content,
            tags: data.template.tags.map((tag) => [...tag]),
          },
        };
      case 'signed': {
        if (!isId(data.id) || !isRecord(data.event)) return null;
        const raw = data.event;
        if (!isEventTemplate(raw)) return null;
        const event = raw as EventTemplate & { id?: unknown; pubkey?: unknown; sig?: unknown };
        if (
          typeof event.id !== 'string' ||
          typeof event.pubkey !== 'string' ||
          typeof event.sig !== 'string'
        ) {
          return null;
        }
        return {
          nap,
          type: 'signed',
          id: data.id,
          event: {
            id: event.id,
            pubkey: event.pubkey,
            sig: event.sig,
            kind: event.kind,
            created_at: event.created_at,
            content: event.content,
            tags: event.tags.map((tag) => [...tag]),
          } as Nip98Event,
        };
      }
      case 'error':
        if (typeof data.code !== 'string' || !ERROR_CODES.has(data.code)) return null;
        if (data.id !== undefined && !isId(data.id)) return null;
        return {
          nap,
          type: 'error',
          code: data.code as CrossOriginErrorCode,
          ...(data.id ? { id: data.id } : {}),
        };
      case 'revoked':
      case 'disconnect':
        if (!isId(data.grantId)) return null;
        return { nap, type: data.type, grantId: data.grantId };
      default:
        return null;
    }
  } catch {
    return null;
  }
}

/**
 * Normalise an origin: scheme + host + non-default port, nothing else.
 *
 * Throws on anything that is not a bare http(s) origin. A path, query or
 * fragment in a policy entry means somebody thought it would be matched, and it
 * would not be, so that is a wiring error rather than something to strip.
 */
export function normalizeOrigin(value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`'${value}' is not an origin`);
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new Error(`'${value}' must use http or https`);
  }
  if (url.username || url.password || (url.pathname !== '/' && url.pathname !== '') || url.search || url.hash) {
    throw new Error(`'${value}' must be an origin (scheme://host[:port]) with no path, query, userinfo or fragment`);
  }
  if (value.trim().replace(/\/$/, '') !== url.origin) {
    // `new URL` silently fixes things like a trailing dot or uppercase; insist on the canonical form
    // so what an operator reads in the policy is exactly what is compared.
    throw new Error(`'${value}' is not in canonical form; use '${url.origin}'`);
  }
  return url.origin;
}

/** The origin of an event's single `u` tag, or `null` if there is not exactly one parseable http(s) `u` tag. */
export function audienceOf(template: EventTemplate): string | null {
  const uTags = template.tags.filter((tag) => tag[0] === 'u');
  if (uTags.length !== 1 || typeof uTags[0][1] !== 'string') return null;
  try {
    const url = new URL(uTags[0][1]);
    if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;
    if (url.username || url.password) return null;
    return url.origin;
  } catch {
    return null;
  }
}

export function randomId(): string {
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}
