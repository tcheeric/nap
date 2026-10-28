import { nip19, verifyEvent, type EventTemplate } from 'nostr-tools';
import type { Nip98Event } from '@imani/nap-core';
import type { SessionSigner } from './types.js';
import {
  CROSS_ORIGIN_PROTOCOL,
  CrossOriginSignerError,
  DEFAULT_SIGNER_PATH,
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

export interface ConnectCrossOriginOptions {
  /** The origin that holds the key, e.g. `https://wallet.example`. */
  keyOrigin: string;
  /** Event kinds to ask for. Usually `[27235]`. */
  kinds: number[];
  /** Origins the signed events will be addressed to (`u` tag). Usually this page's own origin. */
  audiences: string[];
  /**
   * The identity this page expects, as hex, e.g. from a `?pubkey=` hint. The key
   * origin refuses to connect as anyone else, so a wallet signed in as B never
   * silently acts for A.
   */
  expectedPubkey?: string;
  /** Path of the signer page on the key origin. Default `/nap/signer`. */
  signerPath?: string;
  /** Third argument to `window.open`. Default a small popup. */
  windowFeatures?: string;
  /** How long to wait for the signer page to load and announce itself. Default 15_000. */
  readyTimeoutMs?: number;
  /** How long the user may take over unlock and consent. Default 300_000. */
  connectTimeoutMs?: number;
  /** Bound on one signature, including any prompt on the key origin. Default 120_000. */
  requestTimeoutMs?: number;
  /** Injectable for tests. Defaults to `window.open`. */
  open?: (url: string, target: string, features: string) => WindowLike | null;
  /** Where messages arrive. Defaults to `window`. */
  target?: MessageTarget;
  /** Seconds. Defaults to `Date.now() / 1000`. */
  now?: () => number;
  /** How often to look for a closed popup, in ms. Default 500. */
  closedPollMs?: number;
}

export interface CrossOriginGrant {
  readonly info: GrantInfo;
  /** A `SessionSigner` for `createNapSession`. Holds no key: every signature is made on the key origin. */
  readonly signer: SessionSigner;
  /** False once revoked, expired, disconnected, or the signer window closed. */
  isActive(): boolean;
  /** Called once, when the grant stops being usable, with the reason. */
  onEnd(listener: (code: CrossOriginErrorCode) => void): () => void;
  /** Tell the key origin to drop the grant and close the signer window. */
  disconnect(): void;
}

const DEFAULT_FEATURES = 'popup=yes,width=420,height=640';

interface Pending {
  resolve(message: CrossOriginMessage): void;
  reject(error: CrossOriginSignerError): void;
  timer: ReturnType<typeof setTimeout>;
}

function sameTemplate(template: EventTemplate, event: Nip98Event): boolean {
  return (
    event.kind === template.kind &&
    event.created_at === template.created_at &&
    event.content === template.content &&
    JSON.stringify(event.tags) === JSON.stringify(template.tags)
  );
}

/**
 * Open the key origin's signer page and get a signing grant from it
 * (extension 0002).
 *
 * **Call this from a user gesture** (a click handler), before any `await`:
 * `window.open` runs synchronously here, and a popup opened after an await is
 * blocked by every browser.
 *
 * The popup must stay open while the grant is used. After login, the NAP
 * session cookie is what the page relies on, so `disconnect()` once you no
 * longer need fresh signatures.
 *
 * ```ts
 * button.onclick = async () => {
 *   const grant = await connectCrossOrigin({
 *     keyOrigin: 'https://wallet.example',
 *     kinds: [27235],
 *     audiences: [location.origin],
 *   });
 *   const session = createNapSession({ baseUrl: location.origin, signer: grant.signer });
 *   await session.login();
 * };
 * ```
 */
export function connectCrossOrigin(options: ConnectCrossOriginOptions): Promise<CrossOriginGrant> {
  let keyOrigin: string;
  let audiences: string[];
  try {
    keyOrigin = normalizeOrigin(options.keyOrigin);
    audiences = options.audiences.map(normalizeOrigin);
  } catch (error) {
    return Promise.reject(error);
  }
  if (!options.kinds.length || !audiences.length) {
    return Promise.reject(new Error('connectCrossOrigin needs at least one kind and one audience'));
  }

  const now = options.now ?? (() => Math.floor(Date.now() / 1000));
  const readyTimeoutMs = options.readyTimeoutMs ?? 15_000;
  const connectTimeoutMs = options.connectTimeoutMs ?? 300_000;
  const requestTimeoutMs = options.requestTimeoutMs ?? 120_000;
  const target = options.target ?? (globalThis as unknown as MessageTarget);
  const open =
    options.open ??
    ((url: string, name: string, features: string) =>
      (globalThis.open?.(url, name, features) as unknown as WindowLike | null) ?? null);

  const pending = new Map<string, Pending>();
  const endListeners = new Set<(code: CrossOriginErrorCode) => void>();
  let popup: WindowLike | null = null;
  let grant: GrantInfo | null = null;
  let ended: CrossOriginErrorCode | null = null;
  let readyResolve: (() => void) | null = null;
  let ready = false;
  let closedPoll: ReturnType<typeof setInterval> | undefined;

  const post = (message: CrossOriginMessage) => {
    // Exact target origin: if the popup has navigated somewhere else, the browser drops it.
    popup?.postMessage(message, keyOrigin);
  };

  const end = (code: CrossOriginErrorCode) => {
    if (ended) return;
    ended = code;
    if (closedPoll) clearInterval(closedPoll);
    target.removeEventListener('message', listener);
    for (const [id, entry] of pending) {
      clearTimeout(entry.timer);
      entry.reject(new CrossOriginSignerError(code));
      pending.delete(id);
    }
    for (const notify of endListeners) {
      try {
        notify(code);
      } catch {
        // A listener that throws must not stop the others.
      }
    }
    endListeners.clear();
  };

  const request = (message: CrossOriginMessage & { id: string }, timeoutMs: number): Promise<CrossOriginMessage> =>
    new Promise((resolve, reject) => {
      if (ended) {
        reject(new CrossOriginSignerError(ended));
        return;
      }
      const timer = setTimeout(() => {
        pending.delete(message.id);
        reject(new CrossOriginSignerError('TIMEOUT'));
      }, timeoutMs);
      pending.set(message.id, { resolve, reject, timer });
      post(message);
    });

  function listener(event: MessageEventLike) {
    // Only the window we opened, and only while it is still showing the key origin.
    if (!popup || event.source !== popup || event.origin !== keyOrigin) return;
    const message = parseMessage(event.data);
    if (!message) return;

    switch (message.type) {
      case 'ready':
        if (!ready) {
          ready = true;
          readyResolve?.();
        } else if (grant) {
          // The signer page reloaded: its grants lived in memory and are gone.
          end('REVOKED');
        }
        return;
      case 'revoked':
        if (grant && message.grantId === grant.grantId) end('REVOKED');
        return;
      case 'connected':
      case 'signed':
      case 'error': {
        if (!message.id) {
          return;
        }
        const entry = pending.get(message.id);
        if (!entry) return;
        pending.delete(message.id);
        clearTimeout(entry.timer);
        if (message.type === 'error') {
          entry.reject(new CrossOriginSignerError(message.code));
          if (message.code === 'REVOKED' || message.code === 'GRANT_EXPIRED') end(message.code);
        } else {
          entry.resolve(message);
        }
        return;
      }
      default:
        return;
    }
  }

  target.addEventListener('message', listener);

  const url = new URL(options.signerPath ?? DEFAULT_SIGNER_PATH, keyOrigin).toString();
  // Synchronous, before any await, so the caller's user gesture still counts.
  popup = open(url, '_blank', options.windowFeatures ?? DEFAULT_FEATURES);
  if (!popup) {
    target.removeEventListener('message', listener);
    return Promise.reject(new CrossOriginSignerError('POPUP_BLOCKED'));
  }

  closedPoll = setInterval(() => {
    if (popup?.closed) end('CHANNEL_CLOSED');
  }, options.closedPollMs ?? 500);

  const isActive = () => !ended && grant !== null && now() < grant.expiresAt;

  const signer: SessionSigner = {
    getNpub() {
      if (!grant || !isActive()) {
        throw new CrossOriginSignerError(ended ?? 'GRANT_EXPIRED');
      }
      return nip19.npubEncode(grant.pubkey);
    },
    async signEvent(template: EventTemplate): Promise<Nip98Event> {
      if (!grant || ended) throw new CrossOriginSignerError(ended ?? 'REVOKED');
      if (now() >= grant.expiresAt) {
        end('GRANT_EXPIRED');
        throw new CrossOriginSignerError('GRANT_EXPIRED');
      }
      const reply = await request(
        { nap: CROSS_ORIGIN_PROTOCOL, type: 'sign', id: randomId(), grantId: grant.grantId, template },
        requestTimeoutMs
      );
      if (reply.type !== 'signed') throw new CrossOriginSignerError('SIGNER_ERROR');
      const event = reply.event;
      // Trust nothing from the other window: it is a different origin, and a signer page
      // that misbehaves must not get a forged or substituted event past this point.
      if (event.pubkey !== grant.pubkey || !sameTemplate(template, event) || !verifyEvent(event as never)) {
        throw new CrossOriginSignerError('SIGNER_ERROR');
      }
      return event;
    },
  };

  const handle: CrossOriginGrant = {
    get info() {
      return grant!;
    },
    signer,
    isActive,
    onEnd(notify) {
      if (ended) {
        notify(ended);
        return () => {};
      }
      endListeners.add(notify);
      return () => endListeners.delete(notify);
    },
    disconnect() {
      if (grant && !ended) {
        post({ nap: CROSS_ORIGIN_PROTOCOL, type: 'disconnect', grantId: grant.grantId });
      }
      end('REVOKED');
      try {
        (popup as { close?: () => void } | null)?.close?.();
      } catch {
        // Already gone.
      }
    },
  };

  return (async () => {
    try {
      await new Promise<void>((resolve, reject) => {
        if (ready) return resolve();
        const timer = setTimeout(() => reject(new CrossOriginSignerError('NOT_AVAILABLE')), readyTimeoutMs);
        readyResolve = () => {
          clearTimeout(timer);
          resolve();
        };
        endListeners.add((code) => {
          clearTimeout(timer);
          reject(new CrossOriginSignerError(code));
        });
      });

      const reply = await request(
        {
          nap: CROSS_ORIGIN_PROTOCOL,
          type: 'connect',
          id: randomId(),
          kinds: [...options.kinds],
          audiences,
          ...(options.expectedPubkey ? { expectedPubkey: options.expectedPubkey } : {}),
        },
        connectTimeoutMs
      );
      if (reply.type !== 'connected') throw new CrossOriginSignerError('SIGNER_ERROR');

      const info = reply.grant;
      const granted =
        info.kinds.every((kind) => options.kinds.includes(kind)) &&
        info.audiences.every((audience) => audiences.includes(audience)) &&
        (!options.expectedPubkey || info.pubkey === options.expectedPubkey);
      if (!granted) throw new CrossOriginSignerError('SIGNER_ERROR');

      grant = info;
      endListeners.clear();
      return handle;
    } catch (error) {
      const code = error instanceof CrossOriginSignerError ? error.code : 'SIGNER_ERROR';
      end(code);
      try {
        (popup as { close?: () => void } | null)?.close?.();
      } catch {
        // Already gone.
      }
      throw error instanceof CrossOriginSignerError ? error : new CrossOriginSignerError('SIGNER_ERROR', undefined, { cause: error });
    }
  })();
}
