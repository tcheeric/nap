import { describe, expect, it, vi } from 'vitest';
import type { Event, Filter } from 'nostr-tools';
import { DEFAULT_PERMISSIONS, connectWithBunkerToken } from '../src/connection.js';
import { createNip46Signer } from '../src/signer.js';
import { FakeBunker } from './fakeBunker.js';

/**
 * Every other test hands the connection a pool, which is the case where the
 * sockets are not ours to close. The default — no `pool` option at all — is the
 * one real applications take, and the only way to watch it is to stand in for
 * `SimplePool` itself.
 *
 * `BunkerSigner.close()` closes its subscription and nothing else, so a pool
 * that is never destroyed is a pool whose relay sockets stay open forever.
 */
const pools: Array<{ destroyed: boolean }> = [];
let backing: FakeBunker | null = null;

vi.mock('nostr-tools', async (importOriginal) => {
  const actual = await importOriginal<typeof import('nostr-tools')>();

  class TrackingPool {
    private readonly record = { destroyed: false };

    constructor() {
      pools.push(this.record);
    }

    subscribe(relays: string[], filter: Filter, params: object): { close: () => void } {
      return (backing as FakeBunker).pool.subscribe(relays, filter, params as never);
    }

    publish(relays: string[], event: Event): Array<Promise<string>> {
      return (backing as FakeBunker).pool.publish(relays, event);
    }

    destroy(): void {
      this.record.destroyed = true;
    }
  }

  return { ...actual, SimplePool: TrackingPool };
});

const RELAY = 'wss://relay.example';

function bunkerUrl(bunker: FakeBunker): string {
  return `bunker://${bunker.pubkey}?relay=${RELAY}&secret=pairing-secret`;
}

describe('relay pool ownership', () => {
  it('destroys the pool it created when the signer disconnects', async () => {
    backing = new FakeBunker();
    pools.length = 0;

    const signer = createNip46Signer({ connectionToken: bunkerUrl(backing), connectTimeoutMs: 500 });

    await signer.connect();
    expect(pools).toHaveLength(1);
    expect(pools[0].destroyed).toBe(false);

    await signer.disconnect();

    expect(pools[0].destroyed).toBe(true);
  });

  it('destroys the pool when the pairing never establishes', async () => {
    // The caller gets an exception, not a connection handle — so if the failure
    // path does not clean up, nothing ever can. A returning visitor with a dead
    // stored pairing would leak one pool per page load.
    backing = new FakeBunker({ mode: 'silent' });
    pools.length = 0;

    await expect(
      connectWithBunkerToken(bunkerUrl(backing), {
        permissions: DEFAULT_PERMISSIONS,
        connectTimeoutMs: 20,
      })
    ).rejects.toMatchObject({ code: 'TIMEOUT' });

    expect(pools).toHaveLength(1);
    expect(pools[0].destroyed).toBe(true);
  });

  it('leaves a caller-supplied pool alone', async () => {
    const bunker = new FakeBunker();
    backing = bunker;
    pools.length = 0;

    const signer = createNip46Signer({
      connectionToken: bunkerUrl(bunker),
      pool: bunker.pool,
      connectTimeoutMs: 500,
    });

    await signer.connect();
    await signer.disconnect();

    expect(pools).toHaveLength(0);
    expect(bunker.destroyCount).toBe(0);
  });
});
