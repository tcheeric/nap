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
    // Bare strings are what pre-`identity-changed` tabs post. Reading them keeps
    // old→new working; new→old does not, and cannot without posting both shapes
    // — which would make every new tab handle its own messages twice. So a tab
    // still running the old build misses a logout broadcast until it reloads.
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
      channel.postMessage({ type, detail });
    },
    close() {
      channel.close();
    },
  };
}
