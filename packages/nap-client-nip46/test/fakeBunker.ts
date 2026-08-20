import {
  finalizeEvent,
  generateSecretKey,
  getPublicKey,
  nip44,
  type Event,
  type EventTemplate,
  type Filter,
} from 'nostr-tools';
import type { AbstractSimplePool } from 'nostr-tools/abstract-pool';

const NOSTR_CONNECT_KIND = 24133;

interface Subscriber {
  filter: Filter;
  onevent?: (event: Event) => void;
  onclose?: (reasons: string[]) => void;
  closed: boolean;
}

export type FakeBunkerMode =
  | 'ok'
  /** Accepts requests but never answers — exercises the per-call timeouts. */
  | 'silent'
  /** Every relay publish rejects — exercises UNREACHABLE. */
  | 'unreachable'
  /** Answers `connect` with something that is neither `ack` nor the secret. */
  | 'wrongSecret'
  /** Answers `sign_event` with a refusal. */
  | 'declineSign';

export interface FakeBunkerOptions {
  mode?: FakeBunkerMode;
  /** Reply to the first `sign_event` with an `auth_url` instead of a signature. */
  authUrl?: string;
  /**
   * Deliver events from inside `subscribe()` rather than on a microtask, the way
   * a pool with a replay buffer might. A real `SimplePool` never does this, which
   * is exactly why it hides bugs in code that assumes it cannot.
   */
  synchronousDelivery?: boolean;
}

/**
 * A bunker on the other end of a fake relay pool.
 *
 * It speaks real NIP-44 over real kind-24133 events, so the production
 * `BunkerSigner` code path — encryption, subscription filters, request framing —
 * runs unmodified. Only the relay transport is replaced.
 */
export class FakeBunker {
  readonly secretKey = generateSecretKey();
  readonly pubkey = getPublicKey(this.secretKey);
  userSecretKey = generateSecretKey();
  userPubkey = getPublicKey(this.userSecretKey);

  readonly requests: Array<{ method: string; params: string[] }> = [];

  /** How many times someone called `destroy()` on this bunker's pool. */
  destroyCount = 0;

  private readonly subscribers: Subscriber[] = [];
  private readonly buffered: Array<{ clientPubkey: string; event: Event }> = [];
  private readonly options: FakeBunkerOptions;
  private cachedPool: AbstractSimplePool | null = null;
  private pendingAuth: (() => void) | null = null;
  private authUrlSent = false;

  constructor(options: FakeBunkerOptions = {}) {
    this.options = options;
  }

  get mode(): FakeBunkerMode {
    return this.options.mode ?? 'ok';
  }

  /**
   * The pool handed to `BunkerSigner`. Cast because only the two methods the
   * signer actually calls are implemented; a full `AbstractSimplePool` stub
   * would be dead weight in a test double.
   */
  get pool(): AbstractSimplePool {
    this.cachedPool ??= {
      subscribe: (_relays: string[], filter: Filter, params: {
        onevent?: (event: Event) => void;
        onclose?: (reasons: string[]) => void;
      }) => {
        const subscriber: Subscriber = {
          filter,
          onevent: params.onevent,
          onclose: params.onclose,
          closed: false,
        };
        this.subscribers.push(subscriber);
        // Anything emitted before this subscription existed lands now, from
        // inside subscribe() itself — see `synchronousDelivery`.
        this.flush();
        return {
          close: () => {
            subscriber.closed = true;
          },
        };
      },
      publish: (_relays: string[], event: Event): Array<Promise<string>> => {
        if (this.mode === 'unreachable') {
          return [Promise.reject(new Error('relay connection failed'))];
        }

        this.handleRequest(event);
        return [Promise.resolve('ok')];
      },
      destroy: () => {
        this.destroyCount += 1;
      },
    } as unknown as AbstractSimplePool;

    return this.cachedPool;
  }

  /** Stop answering, mid-session: the phone went flat after pairing succeeded. */
  goSilent(): void {
    this.options.mode = 'silent';
  }

  /**
   * The same bunker, now speaking for a different user — what a re-pairing looks
   * like from the client's side. The pairing itself survives; only the identity
   * behind it changes, which is precisely the case the session guard exists for.
   */
  rotateUser(): void {
    this.userSecretKey = generateSecretKey();
    this.userPubkey = getPublicKey(this.userSecretKey);
  }

  /** Release a request that was parked behind an `auth_url` challenge. */
  approve(): void {
    const pending = this.pendingAuth;
    this.pendingAuth = null;
    pending?.();
  }

  /**
   * The client-initiated (`nostrconnect://`) direction: the bunker reaches out
   * unprompted, echoing the secret from the URI to prove it read it.
   */
  announceNostrConnect(clientPubkey: string, secret: string): void {
    this.emit(clientPubkey, { id: 'nostrconnect', result: secret });
  }

  /** The same direction, but the signer wants the user to approve on the web first. */
  announceAuthUrl(clientPubkey: string, url: string): void {
    this.emit(clientPubkey, { id: 'nostrconnect', result: 'auth_url', error: url });
  }

  /** The user tapped Reject: an error with no result, addressed to us. */
  declineNostrConnect(clientPubkey: string, reason = 'user rejected'): void {
    this.emit(clientPubkey, { id: 'nostrconnect', error: reason });
  }

  private handleRequest(event: Event): void {
    const conversationKey = nip44.getConversationKey(this.secretKey, event.pubkey);
    const request = JSON.parse(nip44.decrypt(event.content, conversationKey)) as {
      id: string;
      method: string;
      params: string[];
    };

    this.requests.push({ method: request.method, params: request.params });

    if (this.mode === 'silent') {
      return;
    }

    const respond = (): void => {
      this.emit(event.pubkey, { id: request.id, ...this.reply(request.method, request.params) });
    };

    if (this.options.authUrl && request.method === 'sign_event' && !this.authUrlSent) {
      this.authUrlSent = true;
      this.pendingAuth = respond;
      this.emit(event.pubkey, { id: request.id, result: 'auth_url', error: this.options.authUrl });
      return;
    }

    respond();
  }

  private reply(method: string, params: string[]): { result?: string; error?: string } {
    switch (method) {
      case 'connect':
        return this.mode === 'wrongSecret'
          ? { result: 'not-the-secret' }
          : { result: 'ack' };
      case 'get_public_key':
        return { result: this.userPubkey };
      case 'ping':
        return { result: 'pong' };
      case 'sign_event': {
        if (this.mode === 'declineSign') {
          return { error: 'User rejected the signing request' };
        }

        const template = JSON.parse(params[0]) as EventTemplate;
        return { result: JSON.stringify(finalizeEvent(template, this.userSecretKey)) };
      }
      default:
        return { error: `unsupported method: ${method}` };
    }
  }

  private emit(clientPubkey: string, payload: Record<string, unknown>): void {
    const conversationKey = nip44.getConversationKey(this.secretKey, clientPubkey);
    const event = finalizeEvent(
      {
        kind: NOSTR_CONNECT_KIND,
        tags: [['p', clientPubkey]],
        content: nip44.encrypt(JSON.stringify(payload), conversationKey),
        created_at: Math.floor(Date.now() / 1000),
      },
      this.secretKey
    );

    if (this.options.synchronousDelivery) {
      this.buffered.push({ clientPubkey, event });
      this.flush();
      return;
    }

    // Microtask rather than a timer so the delivery still happens under the
    // fake timers the timeout tests install.
    queueMicrotask(() => {
      this.deliver(clientPubkey, event);
    });
  }

  /** Anything nobody was listening for yet stays buffered for the next subscriber. */
  private flush(): void {
    for (const entry of this.buffered.splice(0)) {
      if (!this.deliver(entry.clientPubkey, entry.event)) {
        this.buffered.push(entry);
      }
    }
  }

  private deliver(clientPubkey: string, event: Event): boolean {
    let delivered = false;

    for (const subscriber of this.subscribers) {
      // A real relay honours the `#p` filter. Without it, a second signer on
      // the same fake pool receives ciphertext it cannot decrypt.
      if (!subscriber.closed && subscriber.filter['#p']?.includes(clientPubkey)) {
        subscriber.onevent?.(event);
        delivered = true;
      }
    }

    return delivered;
  }
}
