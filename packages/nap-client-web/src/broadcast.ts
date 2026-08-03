export type BroadcastMessageType = 'logout' | 'lock' | 'unlock' | 'shutdown';

export interface BroadcastBus {
  publish(type: BroadcastMessageType): void;
  close(): void;
}

export function createBroadcastBus(
  enabled: boolean,
  channelName: string,
  onMessage: (type: BroadcastMessageType) => void
): BroadcastBus {
  if (!enabled || typeof BroadcastChannel === 'undefined') {
    return {
      publish() {},
      close() {},
    };
  }

  const channel = new BroadcastChannel(channelName);
  channel.addEventListener('message', (event: MessageEvent<BroadcastMessageType>) => {
    if (event.data === 'logout' || event.data === 'lock' || event.data === 'unlock' || event.data === 'shutdown') {
      onMessage(event.data);
    }
  });

  return {
    publish(type) {
      channel.postMessage(type);
    },
    close() {
      channel.close();
    },
  };
}
