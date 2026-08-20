import { describe, expect, it } from 'vitest';
import { nip19 } from 'nostr-tools';
import { createNip46Signer } from '../src/signer.js';
import { createWebCryptoSecretStore } from '@imani/nap-client-web';
import { FakeBunker } from './fakeBunker.js';

const RELAY = 'wss://relay.example';

function bunkerUrl(bunker: FakeBunker): string {
  return `bunker://${bunker.pubkey}?relay=${RELAY}&secret=pairing-secret`;
}

function memoryStorage(): Pick<Storage, 'getItem' | 'setItem' | 'removeItem'> & {
  size(): number;
} {
  const entries = new Map<string, string>();

  return {
    getItem: (key) => entries.get(key) ?? null,
    setItem: (key, value) => {
      entries.set(key, value);
    },
    removeItem: (key) => {
      entries.delete(key);
    },
    size: () => entries.size,
  };
}

function challengeTemplate() {
  return {
    kind: 27235,
    tags: [['u', 'https://merchant.example.com/auth/complete'], ['method', 'POST']],
    content: '',
    created_at: 1_710_000_000,
  };
}

describe('nip-46 signer', () => {
  it('connects, reports the remote identity, and signs', async () => {
    const bunker = new FakeBunker();
    const signer = createNip46Signer({
      connectionToken: bunkerUrl(bunker),
      pool: bunker.pool,
      connectTimeoutMs: 500,
    });

    expect(signer.getStatus()).toBe('disconnected');

    await signer.connect();
    expect(signer.getStatus()).toBe('connected');

    await expect(signer.getNpub()).resolves.toBe(nip19.npubEncode(bunker.userPubkey));

    const event = await signer.signEvent(challengeTemplate());
    expect(event.pubkey).toBe(bunker.userPubkey);
    expect(event.kind).toBe(27235);
    expect(event.sig).toBeTruthy();
  });

  it('never sees the user key — the signature comes back over the wire', async () => {
    const bunker = new FakeBunker();
    const signer = createNip46Signer({
      connectionToken: bunkerUrl(bunker),
      pool: bunker.pool,
      connectTimeoutMs: 500,
    });

    await signer.connect();
    await signer.signEvent(challengeTemplate());

    expect(bunker.requests.map((request) => request.method)).toContain('sign_event');
  });

  it('refuses to sign before a connection exists', async () => {
    const signer = createNip46Signer({ connectionToken: 'bunker://x', relays: [RELAY] });

    await expect(signer.signEvent(challengeTemplate())).rejects.toMatchObject({
      code: 'UNREACHABLE',
    });
  });

  it('reports a refused signature as DECLINED', async () => {
    const bunker = new FakeBunker({ mode: 'declineSign' });
    const signer = createNip46Signer({
      connectionToken: bunkerUrl(bunker),
      pool: bunker.pool,
      connectTimeoutMs: 500,
    });

    await signer.connect();

    await expect(signer.signEvent(challengeTemplate())).rejects.toMatchObject({
      code: 'DECLINED',
    });

    // A refusal is not a disconnection; the user may approve the next attempt.
    expect(signer.getStatus()).toBe('connected');
  });

  it('surfaces an auth_url challenge instead of failing', async () => {
    const bunker = new FakeBunker({ authUrl: 'https://signer.example/approve' });
    const seen: string[] = [];
    const signer = createNip46Signer({
      connectionToken: bunkerUrl(bunker),
      pool: bunker.pool,
      connectTimeoutMs: 500,
      signTimeoutMs: 500,
      onAuthUrl: (url) => {
        seen.push(url);
        bunker.approve();
      },
    });

    await signer.connect();
    const event = await signer.signEvent(challengeTemplate());

    expect(seen).toEqual(['https://signer.example/approve']);
    expect(event.pubkey).toBe(bunker.userPubkey);
  });

  it('gives signing its own, longer bound than connecting', async () => {
    // Parked behind an auth_url that is never approved: the request is alive on
    // the wire, so only the sign timeout can end it.
    const bunker = new FakeBunker({ authUrl: 'https://signer.example/approve' });
    const signer = createNip46Signer({
      connectionToken: bunkerUrl(bunker),
      pool: bunker.pool,
      connectTimeoutMs: 500,
      signTimeoutMs: 20,
      onAuthUrl: () => {},
    });

    await signer.connect();

    await expect(signer.signEvent(challengeTemplate())).rejects.toMatchObject({
      code: 'TIMEOUT',
    });
  });

  it('bounds getNpub too, so a dead signer cannot hang login', async () => {
    // `session.ts` awaits getNpub() as its pre-flight identity check, before any
    // network call. Unbounded, a signer that stops answering does not fail the
    // login — it hangs it, with nothing for the UI to catch.
    // A silent bunker never acks `connect` either, so pair against a live one
    // and take it away afterwards.
    const bunker = new FakeBunker();
    const signer = createNip46Signer({
      connectionToken: bunkerUrl(bunker),
      pool: bunker.pool,
      connectTimeoutMs: 20,
    });

    await signer.connect();
    bunker.goSilent();

    await expect(signer.getNpub()).rejects.toMatchObject({ code: 'TIMEOUT' });
  });

  it('re-reads the remote identity rather than caching the first answer', async () => {
    // BunkerSigner.getPublicKey() memoises. Going through it would leave the
    // session's identity guard reporting a re-paired bunker's old user forever.
    const bunker = new FakeBunker();
    const signer = createNip46Signer({
      connectionToken: bunkerUrl(bunker),
      pool: bunker.pool,
      connectTimeoutMs: 500,
    });

    await signer.connect();
    await expect(signer.getNpub()).resolves.toBe(nip19.npubEncode(bunker.userPubkey));

    bunker.rotateUser();

    await expect(signer.getNpub()).resolves.toBe(nip19.npubEncode(bunker.userPubkey));
  });

  it('reports its own pairing key, not the bunker or the user', async () => {
    const bunker = new FakeBunker();
    const signer = createNip46Signer({
      connectionToken: bunkerUrl(bunker),
      pool: bunker.pool,
      connectTimeoutMs: 500,
    });

    await signer.connect();

    const client = nip19.decode(signer.getClientPubkey() as string).data;
    expect(client).not.toBe(bunker.pubkey);
    expect(client).not.toBe(bunker.userPubkey);
  });

  it('answers ping with a boolean rather than a throw', async () => {
    const bunker = new FakeBunker();
    const signer = createNip46Signer({
      connectionToken: bunkerUrl(bunker),
      pool: bunker.pool,
      connectTimeoutMs: 500,
      pingTimeoutMs: 500,
    });

    await expect(signer.ping()).resolves.toBe(false);

    await signer.connect();
    await expect(signer.ping()).resolves.toBe(true);

    await signer.disconnect();
    await expect(signer.ping()).resolves.toBe(false);
    expect(signer.getStatus()).toBe('disconnected');
  });

  it('requires a token or relays to connect at all', async () => {
    const signer = createNip46Signer({});

    await expect(signer.connect()).rejects.toMatchObject({ code: 'INVALID_TOKEN' });
  });
});

describe('nip-46 session continuity', () => {
  it('restores a pairing on a later visit with no connection token', async () => {
    const bunker = new FakeBunker();
    const storage = memoryStorage();
    const secretStore = createWebCryptoSecretStore('nap-nip46', { storage, iterations: 1_000 });

    const first = createNip46Signer({
      connectionToken: bunkerUrl(bunker),
      pool: bunker.pool,
      connectTimeoutMs: 500,
      secretStore,
      passphrase: 'passphrase',
    });

    await first.connect();
    const npub = await first.getNpub();

    // A fresh page: no token in hand, only what was persisted.
    const second = createNip46Signer({
      pool: bunker.pool,
      connectTimeoutMs: 500,
      secretStore,
      passphrase: 'passphrase',
    });

    await second.connect();

    expect(second.getStatus()).toBe('connected');
    await expect(second.getNpub()).resolves.toBe(npub);
  });

  it('falls back to pairing when the passphrase is wrong', async () => {
    const bunker = new FakeBunker();
    const storage = memoryStorage();
    const secretStore = createWebCryptoSecretStore('nap-nip46', { storage, iterations: 1_000 });

    const first = createNip46Signer({
      connectionToken: bunkerUrl(bunker),
      pool: bunker.pool,
      connectTimeoutMs: 500,
      secretStore,
      passphrase: 'passphrase',
    });
    await first.connect();

    const second = createNip46Signer({
      connectionToken: bunkerUrl(bunker),
      pool: bunker.pool,
      connectTimeoutMs: 500,
      secretStore,
      passphrase: 'the wrong one',
    });

    // An unreadable record must not be fatal — it just means pair again.
    await expect(second.connect()).resolves.toBeUndefined();
    expect(second.getStatus()).toBe('connected');
  });

  it('stays disconnected on an unreadable record rather than throwing', async () => {
    const storage = memoryStorage();
    const secretStore = createWebCryptoSecretStore('nap-nip46', { storage, iterations: 1_000 });
    await secretStore.save('not a connection record', 'passphrase');

    const signer = createNip46Signer({ secretStore, passphrase: 'passphrase' });

    // The application is meant to notice and ask for a token, not to catch
    // an exception on every returning visit (FR-011a).
    await expect(signer.connect()).resolves.toBeUndefined();
    expect(signer.getStatus()).toBe('disconnected');
  });

  it('still refuses a signer given nothing to connect with', async () => {
    const signer = createNip46Signer({});

    await expect(signer.connect()).rejects.toMatchObject({ code: 'INVALID_TOKEN' });
  });

  it('erases the stored pairing on disconnect', async () => {
    const bunker = new FakeBunker();
    const storage = memoryStorage();
    const secretStore = createWebCryptoSecretStore('nap-nip46', { storage, iterations: 1_000 });

    const signer = createNip46Signer({
      connectionToken: bunkerUrl(bunker),
      pool: bunker.pool,
      connectTimeoutMs: 500,
      secretStore,
      passphrase: 'passphrase',
    });

    await signer.connect();
    expect(storage.size()).toBe(1);

    await signer.disconnect();

    expect(storage.size()).toBe(0);
    await expect(secretStore.has()).resolves.toBe(false);
  });

  it('drops a stored pairing the signer no longer honours', async () => {
    const storage = memoryStorage();
    const secretStore = createWebCryptoSecretStore('nap-nip46', { storage, iterations: 1_000 });

    const live = new FakeBunker();
    const first = createNip46Signer({
      connectionToken: bunkerUrl(live),
      pool: live.pool,
      connectTimeoutMs: 500,
      secretStore,
      passphrase: 'passphrase',
    });
    await first.connect();

    // Same record, but the signer is gone by the time we come back.
    const dead = new FakeBunker({ mode: 'unreachable' });
    const second = createNip46Signer({
      pool: dead.pool,
      connectTimeoutMs: 50,
      secretStore,
      passphrase: 'passphrase',
    });

    await expect(second.connect()).resolves.toBeUndefined();
    expect(second.getStatus()).toBe('disconnected');
    await expect(secretStore.has()).resolves.toBe(false);
  });
});
