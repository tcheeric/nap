import type { EventTemplate } from 'nostr-tools';
import { nip19 } from 'nostr-tools';
import type { Nip98Event } from '@imani/nap-core';
import type { SessionSigner } from './types.js';
import {
  CROSS_ORIGIN_PROTOCOL,
  DEFAULT_CREATED_AT_SKEW_SECONDS,
  MAX_GRANT_TTL_SECONDS,
  audienceOf,
  normalizeOrigin,
  parseMessage,
  randomId,
  type CrossOriginErrorCode,
  type CrossOriginMessage,
  type GrantInfo,
  type MessageEventLike,
  type MessageTarget,
  type WindowLike,
} from './crossOriginProtocol.js';

/** What one relying origin may ask for. Everything not listed is refused. */
export interface CrossOriginPolicyEntry {
  /** Event kinds this origin may have signed. Usually `[27235]` (NAP completion and NIP-98). */
  kinds: number[];
  /**
   * Origins the signed events may be addressed to, matched exactly against the
   * origin of the event's single `u` tag. Usually just the relying origin
   * itself, plus its API host if that is separate.
   */
  audiences: string[];
  /** Cap on this origin's grants, in seconds. Never above `MAX_GRANT_TTL_SECONDS`. */
  maxTtlSeconds?: number;
}

/** Keyed by relying origin, exactly as the browser reports it (`https://shop.example`). */
export type CrossOriginPolicy = Record<string, CrossOriginPolicyEntry>;

export interface ConsentRequest {
  origin: string;
  pubkey: string;
  npub: string;
  kinds: number[];
  audiences: string[];
  /** The identity the relying origin expected, when it said. Show a mismatch to the user. */
  expectedPubkey?: string;
}

export interface SignRequest {
  origin: string;
  grant: GrantInfo;
  template: EventTemplate;
  /**
   * `'completion'`: a NAP completion proof (it carries a `challenge` tag) after
   * the one the connection was approved for. That is a step-up or a re-login,
   * and RFC §10.3 says only a signer that prompts can make step-up mean
   * anything. `'request'`: anything else inside the grant.
   */
  reason: 'completion' | 'request';
}

/**
 * Remembered "yes" answers, so a returning user is not asked again. Holds no
 * secret: an origin, a pubkey and a scope. Revoking one is the "Connected
 * sites" screen.
 */
export interface ConsentStore {
  has(origin: string, pubkey: string, scope: string): boolean | Promise<boolean>;
  remember(origin: string, pubkey: string, scope: string): void | Promise<void>;
  forget(origin: string, pubkey?: string): void | Promise<void>;
  list(): ConsentRecord[] | Promise<ConsentRecord[]>;
}

export interface ConsentRecord {
  origin: string;
  pubkey: string;
  scope: string;
}

export type RevocationReason = 'lock' | 'logout' | 'identity-changed' | 'user' | 'shutdown';

export interface CrossOriginSignerOptions {
  /** Which relying origins may connect, and to what. Validated now: a bad entry throws. */
  policy: CrossOriginPolicy;
  /**
   * The signer that holds (or reaches) the key. Any `SessionSigner`: an in-page
   * key, NIP-07, or NIP-46.
   */
  signer: SessionSigner;
  /** Ask the user. Resolve `true` to approve. Not called when `consentStore` already has a matching yes. */
  onConsent(request: ConsentRequest): Promise<boolean>;
  /**
   * Approve one signature. Called for every completion proof after the first one
   * in a grant (step-up, re-login). Optional for everything else: if it is set it
   * is called for `'request'` signatures too and may approve them silently.
   *
   * When it is not set, a second completion proof is refused rather than signed.
   */
  onSign?(request: SignRequest): Promise<boolean>;
  /** Make sure the key can sign before asking for consent: show the unlock UI if it is locked. Throw to refuse. */
  ensureUnlocked?(): Promise<void>;
  consentStore?: ConsentStore;
  /** Fired whenever the set of live grants changes, for a "Connected sites" view. */
  onGrantsChanged?(grants: readonly LiveGrant[]): void;
  /** The window that opened this page. Defaults to `window.opener`. */
  opener?: WindowLike | null;
  /** Where messages arrive. Defaults to `window`. */
  target?: MessageTarget;
  /**
   * True when this page is inside a frame. Defaults to `window.top !== window`.
   * A framed signer page answers nothing: consent in a frame can be clickjacked.
   */
  isFramed?: boolean;
  /** Seconds. Defaults to `Date.now() / 1000`. */
  now?: () => number;
  createdAtSkewSeconds?: number;
  /**
   * The `BroadcastChannel` the key origin's own `createNapSession` publishes on
   * (its `broadcast.channelName`, default `'nap-session'`). A `lock`, `logout`,
   * `shutdown` or `identity-changed` there ends every grant, so locking the
   * wallet in another tab reaches the popup too. `false` to wire it yourself
   * with `revokeAll()`.
   */
  sessionChannel?: string | false;
}

export interface LiveGrant extends GrantInfo {
  origin: string;
}

export interface CrossOriginSignerHandle {
  /** Live grants, for a "Connected sites" view. */
  grants(): LiveGrant[];
  /** End one grant, or every grant for an origin. The relying origin is told. */
  revoke(grantIdOrOrigin: string, reason?: RevocationReason): void;
  /**
   * End every grant. Call it from the key origin's lock and logout handlers:
   * a grant must not outlive the unlocked key it signs with (§28.4).
   */
  revokeAll(reason: RevocationReason): void;
  /** Stop listening and end every grant. */
  close(): void;
}

interface GrantState extends LiveGrant {
  /** The connection's own completion proof is covered by the consent; this tracks whether it was used. */
  completionUsed: boolean;
  source: unknown;
}

function scopeKey(kinds: number[], audiences: string[]): string {
  return `${[...kinds].sort((a, b) => a - b).join(',')}|${[...audiences].sort().join(',')}`;
}

function sameEvent(template: EventTemplate, event: Nip98Event): boolean {
  return (
    event.kind === template.kind &&
    event.created_at === template.created_at &&
    event.content === template.content &&
    JSON.stringify(event.tags) === JSON.stringify(template.tags)
  );
}

function pubkeyOfNpub(npub: string): string {
  const decoded = nip19.decode(npub);
  if (decoded.type !== 'npub') {
    throw new Error('signer returned something other than an npub');
  }
  return decoded.data as string;
}

function validatePolicy(policy: CrossOriginPolicy): Map<string, CrossOriginPolicyEntry> {
  const entries = Object.entries(policy ?? {});
  if (entries.length === 0) {
    // No empty-policy escape hatch: "everyone" is the state this extension exists to make unrepresentable.
    throw new Error('Cross-origin signer policy must name at least one relying origin');
  }

  const result = new Map<string, CrossOriginPolicyEntry>();
  for (const [origin, entry] of entries) {
    const normalized = normalizeOrigin(origin);
    if (!Array.isArray(entry.kinds) || entry.kinds.length === 0 || !entry.kinds.every(Number.isInteger)) {
      throw new Error(`Cross-origin signer policy for ${origin} needs a non-empty list of integer kinds`);
    }
    if (!Array.isArray(entry.audiences) || entry.audiences.length === 0) {
      throw new Error(`Cross-origin signer policy for ${origin} needs a non-empty list of audiences`);
    }
    const ttl = entry.maxTtlSeconds ?? MAX_GRANT_TTL_SECONDS;
    if (!Number.isInteger(ttl) || ttl <= 0 || ttl > MAX_GRANT_TTL_SECONDS) {
      throw new Error(`Cross-origin signer policy for ${origin}: maxTtlSeconds must be 1..${MAX_GRANT_TTL_SECONDS}`);
    }
    result.set(normalized, {
      kinds: [...entry.kinds],
      audiences: entry.audiences.map(normalizeOrigin),
      maxTtlSeconds: ttl,
    });
  }
  return result;
}

/**
 * Run the key-origin end of extension 0002 on a signer page.
 *
 * Mount this on a dedicated page of the key origin (e.g. `/nap/signer`) that a
 * relying origin opens as a popup. The page answers only:
 *
 * - its opener, and only when the opener's browser-reported origin is in the policy;
 * - for kinds and `u`-tag audiences that the policy and the grant both allow;
 * - while it is a top-level window, never inside a frame.
 *
 * Everything else is ignored without a reply, so a stranger cannot tell a
 * missing signer page from a refusal (§19).
 */
export function mountCrossOriginSigner(options: CrossOriginSignerOptions): CrossOriginSignerHandle {
  const policy = validatePolicy(options.policy);
  const now = options.now ?? (() => Math.floor(Date.now() / 1000));
  const skew = options.createdAtSkewSeconds ?? DEFAULT_CREATED_AT_SKEW_SECONDS;
  const browserWindow = typeof window === 'undefined' ? undefined : window;
  const opener =
    options.opener !== undefined ? options.opener : ((browserWindow?.opener as WindowLike | null | undefined) ?? null);
  const target = options.target ?? (browserWindow as unknown as MessageTarget | undefined);
  const isFramed = options.isFramed ?? (browserWindow ? browserWindow.top !== browserWindow.self : false);
  const grants = new Map<string, GrantState>();
  let closed = false;

  const inert: CrossOriginSignerHandle = {
    grants: () => [],
    revoke() {},
    revokeAll() {},
    close() {},
  };

  if (isFramed || !opener || !target) {
    // Framed: consent could be clickjacked. No opener: opened directly, nobody to answer.
    return inert;
  }

  const reply = (origin: string, message: CrossOriginMessage) => {
    try {
      // Always the exact origin we checked, never '*'.
      opener.postMessage(message, origin);
    } catch {
      // The opener navigated away or closed. Nothing to tell.
    }
  };

  const fail = (origin: string, id: string | undefined, code: CrossOriginErrorCode) =>
    reply(origin, { nap: CROSS_ORIGIN_PROTOCOL, type: 'error', code, ...(id ? { id } : {}) });

  const snapshot = (): LiveGrant[] =>
    [...grants.values()].map(({ grantId, origin, pubkey, kinds, audiences, expiresAt }) => ({
      grantId,
      origin,
      pubkey,
      kinds: [...kinds],
      audiences: [...audiences],
      expiresAt,
    }));

  const changed = () => options.onGrantsChanged?.(snapshot());

  const dropGrant = (grant: GrantState, notify: boolean) => {
    grants.delete(grant.grantId);
    if (notify) {
      reply(grant.origin, { nap: CROSS_ORIGIN_PROTOCOL, type: 'revoked', grantId: grant.grantId });
    }
  };

  const revokeAll = (_reason: RevocationReason) => {
    if (grants.size === 0) return;
    for (const grant of [...grants.values()]) dropGrant(grant, true);
    changed();
  };

  async function handleConnect(origin: string, source: unknown, message: Extract<CrossOriginMessage, { type: 'connect' }>) {
    const entry = policy.get(origin)!;
    let audiences: string[];
    try {
      audiences = message.audiences.map(normalizeOrigin);
    } catch {
      return fail(origin, message.id, 'REFUSED');
    }
    const kinds = [...new Set(message.kinds)];
    audiences = [...new Set(audiences)];

    if (!kinds.every((kind) => entry.kinds.includes(kind)) || !audiences.every((a) => entry.audiences.includes(a))) {
      return fail(origin, message.id, 'REFUSED');
    }

    try {
      await options.ensureUnlocked?.();
    } catch {
      return fail(origin, message.id, 'DECLINED');
    }

    let pubkey: string;
    let npub: string;
    try {
      npub = await options.signer.getNpub();
      pubkey = pubkeyOfNpub(npub);
    } catch {
      return fail(origin, message.id, 'SIGNER_ERROR');
    }

    const scope = scopeKey(kinds, audiences);
    let approved = false;
    try {
      approved = (await options.consentStore?.has(origin, pubkey, scope)) ?? false;
      if (!approved) {
        approved = await options.onConsent({
          origin,
          pubkey,
          npub,
          kinds: [...kinds],
          audiences: [...audiences],
          ...(message.expectedPubkey ? { expectedPubkey: message.expectedPubkey } : {}),
        });
        if (approved) await options.consentStore?.remember(origin, pubkey, scope);
      }
    } catch {
      approved = false;
    }
    if (closed) return;
    if (!approved) return fail(origin, message.id, 'DECLINED');

    // The user may have approved while looking at "you're signed in as B". Approving does not
    // make B into A: the relying origin asked for A, and silently handing it B is the
    // privilege transfer the identity guard exists to stop.
    if (message.expectedPubkey && message.expectedPubkey !== pubkey) {
      return fail(origin, message.id, 'REFUSED');
    }

    const grant: GrantState = {
      grantId: randomId(),
      origin,
      pubkey,
      kinds,
      audiences,
      expiresAt: now() + (entry.maxTtlSeconds ?? MAX_GRANT_TTL_SECONDS),
      completionUsed: false,
      source,
    };
    grants.set(grant.grantId, grant);
    changed();

    const { grantId, expiresAt } = grant;
    reply(origin, {
      nap: CROSS_ORIGIN_PROTOCOL,
      type: 'connected',
      id: message.id,
      grant: { grantId, pubkey, kinds: [...kinds], audiences: [...audiences], expiresAt },
    });
  }

  async function handleSign(origin: string, source: unknown, message: Extract<CrossOriginMessage, { type: 'sign' }>) {
    const grant = grants.get(message.grantId);
    // A grant id from another origin, or another window, is the same as no grant: one answer.
    if (!grant || grant.origin !== origin || grant.source !== source) {
      return fail(origin, message.id, 'REVOKED');
    }
    if (now() >= grant.expiresAt) {
      dropGrant(grant, false);
      changed();
      return fail(origin, message.id, 'GRANT_EXPIRED');
    }

    const { template } = message;
    const audience = audienceOf(template);
    if (
      !grant.kinds.includes(template.kind) ||
      audience === null ||
      !grant.audiences.includes(audience) ||
      Math.abs(template.created_at - now()) > skew
    ) {
      return fail(origin, message.id, 'REFUSED');
    }

    const isCompletion = template.tags.some((tag) => tag[0] === 'challenge');
    const needsPrompt = isCompletion && grant.completionUsed;
    if (isCompletion && !grant.completionUsed) {
      // Claimed before the await, so two racing completion requests cannot both ride the consent.
      grant.completionUsed = true;
    }

    if (needsPrompt || options.onSign) {
      if (!options.onSign) return fail(origin, message.id, 'REFUSED');
      let ok = false;
      try {
        ok = await options.onSign({
          origin,
          grant: { grantId: grant.grantId, pubkey: grant.pubkey, kinds: [...grant.kinds], audiences: [...grant.audiences], expiresAt: grant.expiresAt },
          template,
          reason: needsPrompt ? 'completion' : 'request',
        });
      } catch {
        ok = false;
      }
      if (!ok) return fail(origin, message.id, 'DECLINED');
      if (!grants.has(grant.grantId)) return fail(origin, message.id, 'REVOKED');
    }

    let event: Nip98Event;
    try {
      event = await options.signer.signEvent(template);
    } catch {
      return fail(origin, message.id, 'SIGNER_ERROR');
    }
    if (!grants.has(grant.grantId)) return fail(origin, message.id, 'REVOKED');

    if (event.pubkey !== grant.pubkey) {
      // The key behind the signer changed (account switch, re-paired bunker). Every grant
      // names the old identity, so none of them can stand.
      fail(origin, message.id, 'REVOKED');
      revokeAll('identity-changed');
      return;
    }
    if (!sameEvent(template, event)) {
      return fail(origin, message.id, 'SIGNER_ERROR');
    }

    reply(origin, { nap: CROSS_ORIGIN_PROTOCOL, type: 'signed', id: message.id, event });
  }

  const listener = (event: MessageEventLike) => {
    if (closed || event.source !== opener) return;
    const origin = event.origin;
    if (!policy.has(origin)) return;
    const message = parseMessage(event.data);
    if (!message) return;

    switch (message.type) {
      case 'connect':
        void handleConnect(origin, event.source, message);
        return;
      case 'sign':
        void handleSign(origin, event.source, message);
        return;
      case 'disconnect': {
        const grant = grants.get(message.grantId);
        if (grant && grant.origin === origin) {
          dropGrant(grant, false);
          changed();
        }
        return;
      }
      default:
        return;
    }
  };

  target.addEventListener('message', listener);

  let sessionBus: BroadcastChannel | undefined;
  const channelName = options.sessionChannel ?? 'nap-session';
  if (channelName !== false && typeof BroadcastChannel !== 'undefined') {
    sessionBus = new BroadcastChannel(channelName);
    sessionBus.addEventListener('message', (event: MessageEvent<unknown>) => {
      // Bare string or `{type}`: the two shapes `broadcast.ts` sends.
      const data = event.data as unknown;
      const type = typeof data === 'string' ? data : (data as { type?: unknown } | null)?.type;
      if (type === 'lock' || type === 'logout' || type === 'shutdown' || type === 'identity-changed') {
        revokeAll(type);
      }
    });
  }

  // Announce to the opener, once per policy origin. The browser drops each post whose
  // target origin is not the opener's, so a stranger who opened this page hears nothing.
  for (const origin of policy.keys()) {
    reply(origin, { nap: CROSS_ORIGIN_PROTOCOL, type: 'ready' });
  }

  return {
    grants: snapshot,
    revoke(grantIdOrOrigin, _reason = 'user') {
      const matched = [...grants.values()].filter(
        (grant) => grant.grantId === grantIdOrOrigin || grant.origin === grantIdOrOrigin
      );
      if (matched.length === 0) return;
      for (const grant of matched) dropGrant(grant, true);
      changed();
    },
    revokeAll,
    close() {
      if (closed) return;
      revokeAll('shutdown');
      closed = true;
      target.removeEventListener('message', listener);
      sessionBus?.close();
    },
  };
}

/**
 * A `ConsentStore` over Web Storage (`localStorage` by default).
 *
 * Fine to keep in plain storage because there is nothing secret in it: knowing
 * that `alice` once allowed `shop.example` lets nobody sign anything. What it
 * buys is a returning user not being asked twice.
 */
export function createStorageConsentStore(
  storage: Pick<Storage, 'getItem' | 'setItem'> = globalThis.localStorage,
  key = 'nap-cross-origin-consent'
): ConsentStore {
  const read = (): ConsentRecord[] => {
    try {
      const parsed = JSON.parse(storage.getItem(key) ?? '[]') as unknown;
      return Array.isArray(parsed)
        ? parsed.filter(
            (record): record is ConsentRecord =>
              typeof record?.origin === 'string' && typeof record?.pubkey === 'string' && typeof record?.scope === 'string'
          )
        : [];
    } catch {
      return [];
    }
  };
  const write = (records: ConsentRecord[]) => {
    try {
      storage.setItem(key, JSON.stringify(records));
    } catch {
      // Storage full or blocked: the user is simply asked again next time.
    }
  };

  return {
    has: (origin, pubkey, scope) =>
      read().some((record) => record.origin === origin && record.pubkey === pubkey && record.scope === scope),
    remember(origin, pubkey, scope) {
      const records = read().filter((record) => !(record.origin === origin && record.pubkey === pubkey));
      records.push({ origin, pubkey, scope });
      write(records);
    },
    forget(origin, pubkey) {
      write(read().filter((record) => !(record.origin === origin && (pubkey === undefined || record.pubkey === pubkey))));
    },
    list: read,
  };
}
