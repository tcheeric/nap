import { describe, expect, it, vi } from 'vitest';
import { createBroadcastBus } from '../src/broadcast.js';

/**
 * The wire format is a cross-version contract, so these assert on what actually
 * goes over the channel rather than on end-to-end behaviour between two buses.
 */
function capturePosts() {
  const posted: unknown[] = [];

  class RecordingChannel {
    addEventListener(): void {}
    postMessage(data: unknown): void {
      posted.push(data);
    }
    close(): void {}
  }

  vi.stubGlobal('BroadcastChannel', RecordingChannel);
  return posted;
}

describe('broadcast wire format', () => {
  // A tab on the older build only matches `event.data === 'lock'`. When publish
  // switched to posting {type, detail} unconditionally, those tabs silently
  // dropped every lock and logout — so an older tab kept its decrypted in-page
  // key live after the session was locked everywhere else.
  it.each(['lock', 'logout', 'unlock', 'shutdown'] as const)(
    'posts %s as a bare string, which both builds read',
    (type) => {
      const posted = capturePosts();
      createBroadcastBus(true, 'ch', () => {}).publish(type);

      expect(posted).toEqual([type]);
    }
  );

  it('posts identity-changed as an object, because it carries a payload', () => {
    const posted = capturePosts();
    const detail = { expectedPubkey: 'a', actualPubkey: 'b' };

    createBroadcastBus(true, 'ch', () => {}).publish('identity-changed', detail);

    // Older tabs do not know this type at all, so nothing is lost by the shape.
    expect(posted).toEqual([{ type: 'identity-changed', detail }]);
  });

  it('reads both shapes back', () => {
    const seen: Array<[string, unknown]> = [];
    let listener: ((event: MessageEvent<unknown>) => void) | null = null;

    class ListeningChannel {
      addEventListener(_: string, fn: (event: MessageEvent<unknown>) => void): void {
        listener = fn;
      }
      postMessage(): void {}
      close(): void {}
    }
    vi.stubGlobal('BroadcastChannel', ListeningChannel);

    createBroadcastBus(true, 'ch', (type, detail) => seen.push([type, detail]));

    listener!({ data: 'lock' } as MessageEvent<unknown>);
    listener!({
      data: { type: 'identity-changed', detail: { expectedPubkey: 'a', actualPubkey: 'b' } },
    } as MessageEvent<unknown>);
    listener!({ data: 'not-a-message-type' } as MessageEvent<unknown>);

    expect(seen).toEqual([
      ['lock', undefined],
      ['identity-changed', { expectedPubkey: 'a', actualPubkey: 'b' }],
    ]);
  });
});
