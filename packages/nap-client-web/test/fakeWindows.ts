import type { MessageEventLike, MessageTarget, WindowLike } from '../src/crossOriginProtocol.js';

/**
 * Two windows on two origins, wired the way a browser wires an opener and its
 * popup: `postMessage(data, targetOrigin)` is delivered only when
 * `targetOrigin` matches the receiver's origin (or is `'*'`), the receiver sees
 * the SENDER's origin in `event.origin` (which the sender cannot choose), and
 * `event.source` is the receiver's handle on the sender. Data is structured-
 * cloned and delivery is asynchronous, as it is in a browser.
 */
export class FakeWindow implements MessageTarget {
  readonly origin: string;
  private readonly listeners = new Set<(event: MessageEventLike) => void>();
  /** Every message this window received, for asserting what a stranger heard. */
  readonly received: MessageEventLike[] = [];

  constructor(origin: string) {
    this.origin = origin;
  }

  addEventListener(_type: 'message', listener: (event: MessageEventLike) => void): void {
    this.listeners.add(listener);
  }

  removeEventListener(_type: 'message', listener: (event: MessageEventLike) => void): void {
    this.listeners.delete(listener);
  }

  deliver(event: MessageEventLike): void {
    this.received.push(event);
    for (const listener of [...this.listeners]) listener(event);
  }
}

export interface WindowHandle extends WindowLike {
  closed: boolean;
  close(): void;
  /** Every `targetOrigin` this handle was posted to with. */
  readonly targetOrigins: string[];
}

/**
 * `from` gets a handle on `to`. Messages posted through it arrive at `to` with
 * `origin = from.origin` and `source = back`, the handle `to` holds on `from`.
 */
export function link(from: FakeWindow, to: FakeWindow): { forward: WindowHandle; back: WindowHandle } {
  let open = true;
  const make = (sender: FakeWindow, receiver: FakeWindow): WindowHandle => {
    const handle: WindowHandle = {
      closed: false,
      targetOrigins: [],
      postMessage(message: unknown, targetOrigin: string) {
        handle.targetOrigins.push(targetOrigin);
        if (!open) return;
        if (targetOrigin !== '*' && targetOrigin !== receiver.origin) return;
        const data = structuredClone(message);
        setTimeout(() => {
          if (!open) return;
          receiver.deliver({ data, origin: sender.origin, source: sender === from ? back : forward });
        }, 0);
      },
      close() {
        open = false;
        forward.closed = true;
        back.closed = true;
      },
    };
    return handle;
  };
  const forward = make(from, to);
  const back = make(to, from);
  return { forward, back };
}

/** Let every queued delivery and the promises behind it settle. */
export async function flush(rounds = 10): Promise<void> {
  for (let i = 0; i < rounds; i += 1) {
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
}
