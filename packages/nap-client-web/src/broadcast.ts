export type BroadcastMessageType =
  | 'logout'
  | 'lock'
  | 'unlock'
  | 'shutdown'
  /** A signer presented a different identity; every tab must drop the session. */
  | 'identity-changed';

const MESSAGE_TYPES: readonly BroadcastMessageType[] = [
  'logout',
  'lock',
  'unlock',
  'shutdown',
  'identity-changed',
];

export interface IdentityChangedDetail {
  expectedPubkey: string;
  actualPubkey: string;
}

export interface BroadcastBus {
  publish(type: BroadcastMessageType, detail?: IdentityChangedDetail): void;
  close(): void;
}

function isMessageType(value: unknown): value is BroadcastMessageType {
  return MESSAGE_TYPES.includes(value as BroadcastMessageType);
}

export function createBroadcastBus(
  enabled: boolean,
  channelName: string,
  onMessage: (type: BroadcastMessageType, detail?: IdentityChangedDetail) => void
): BroadcastBus {
  if (!enabled || typeof BroadcastChannel === 'undefined') {
    return {
      publish() {},
      close() {},
    };
  }

  const channel = new BroadcastChannel(channelName);
  channel.addEventListener('message', (event: MessageEvent<unknown>) => {
    // Bare strings are the pre-`identity-changed` wire format, and still what
    // `publish` sends for every detail-free type — so this branch carries both
    // old→new and new→new traffic. See `publish` for why it is not the object.
    if (isMessageType(event.data)) {
      onMessage(event.data);
      return;
    }

    const message = event.data as { type?: unknown; detail?: IdentityChangedDetail } | null;
    if (isMessageType(message?.type)) {
      onMessage(message.type, message.detail);
    }
  });

  return {
    publish(type, detail) {
      // The bare string is the pre-0.8 wire format, and both builds read it —
      // the listener above still accepts it. Only `identity-changed` carries a
      // payload, and that is a type older tabs do not know regardless, so
      // sending the string whenever there is no detail restores cross-version
      // `lock` / `logout` / `shutdown` without posting each message twice.
      //
      // This matters beyond tidiness: a tab on the older build that drops a
      // `lock` keeps its decrypted in-page key live after the session was
      // locked everywhere else, which is the whole point of the broadcast.
      channel.postMessage(detail === undefined ? type : { type, detail });
    },
    close() {
      channel.close();
    },
  };
}
