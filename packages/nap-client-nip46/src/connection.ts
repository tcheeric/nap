import { SimplePool, generateSecretKey, getPublicKey, nip44 } from 'nostr-tools';
import type { Event, Filter } from 'nostr-tools';
import type { AbstractSimplePool } from 'nostr-tools/abstract-pool';
import {
  BunkerSigner,
  createNostrConnectURI,
  parseBunkerInput,
  type BunkerPointer,
} from 'nostr-tools/nip46';
import { bytesToHex } from '@imani/nap-core';
import { Nip46Error, toNip46Error } from './errors.js';
import { withTimeout } from './timeout.js';

const NOSTR_CONNECT_KIND = 24133;

/**
 * Signing the NIP-98 challenge is the only thing NAP asks permission for.
 * Requesting more would train users to grant a remote signer permissions the
 * protocol never uses.
 *
 * The client also sends `get_public_key` — on every `getNpub()`, since caching
 * it would blind the identity guard — and does not list it. Signers treat
 * reading the public key as always-permitted; one that gates it will prompt on
 * the first call, which is a signer's choice to make and not ours to pre-empt.
 */
export const DEFAULT_PERMISSIONS = ['sign_event:27235'];

export interface ActiveConnection {
  bunker: BunkerSigner;
  pointer: BunkerPointer;
  clientSecretKey: Uint8Array;
  pool: AbstractSimplePool;
  /** False when the caller supplied the pool — then its sockets are not ours to close. */
  ownsPool: boolean;
}

export interface ConnectionOptions {
  pool?: AbstractSimplePool;
  permissions: string[];
  connectTimeoutMs: number;
  onAuthUrl?: (url: string) => void;
}

/**
 * `BunkerSigner.close()` only closes its subscription — the pool underneath it
 * keeps every relay socket open. So whoever created the pool has to destroy it,
 * and that ownership has to survive as far as `disconnect()` and every failure
 * path in between.
 */
function poolFor(options: ConnectionOptions): { pool: AbstractSimplePool; ownsPool: boolean } {
  return options.pool
    ? { pool: options.pool, ownsPool: false }
    : { pool: new SimplePool(), ownsPool: true };
}

/** Tear a connection down: the subscription first, then the sockets we opened. */
export async function closeConnection(connection: ActiveConnection): Promise<void> {
  try {
    await connection.bunker.close();
  } catch {
    // Closing a socket that is already gone is not a failure to report.
  }

  if (connection.ownsPool) {
    connection.pool.destroy();
  }
}

function bunkerParams(options: ConnectionOptions, pool: AbstractSimplePool) {
  return {
    pool,
    onauth: options.onAuthUrl
      ? (url: string) => {
          options.onAuthUrl?.(url);
        }
      : undefined,
  };
}

/**
 * Send `connect` and check what came back.
 *
 * `BunkerSigner.connect()` is not used because it discards the response and
 * sends no permissions. Both matter here: the response is the only proof the
 * bunker actually honoured our secret (FR-013), and the permission list is what
 * keeps the grant scoped to kind 27235 (FR-015).
 */
async function handshake(
  connection: ActiveConnection,
  options: ConnectionOptions
): Promise<ActiveConnection> {
  try {
    let result: string;

    try {
      result = await withTimeout(
        connection.bunker.sendRequest('connect', [
          connection.pointer.pubkey,
          connection.pointer.secret ?? '',
          options.permissions.join(','),
        ]),
        options.connectTimeoutMs,
        'connect'
      );
    } catch (error) {
      throw toNip46Error(error, 'connect failed');
    }

    if (result !== 'ack' && result !== connection.pointer.secret) {
      throw new Nip46Error(
        'SECRET_MISMATCH',
        `bunker answered connect with "${result}" rather than acknowledging the pairing`
      );
    }

    return connection;
  } catch (error) {
    // The caller gets an error, not a handle — so nothing else can ever close
    // these sockets. A dead stored pairing would otherwise leak a pool per load.
    await closeConnection(connection);
    throw error;
  }
}

function openConnection(
  clientSecretKey: Uint8Array,
  pointer: BunkerPointer,
  options: ConnectionOptions
): ActiveConnection {
  const { pool, ownsPool } = poolFor(options);

  return {
    bunker: BunkerSigner.fromBunker(clientSecretKey, pointer, bunkerParams(options, pool)),
    pointer,
    clientSecretKey,
    pool,
    ownsPool,
  };
}

/** Pair from a `bunker://` URL or a NIP-05 identifier that resolves to one. */
export async function connectWithBunkerToken(
  token: string,
  options: ConnectionOptions
): Promise<ActiveConnection> {
  const pointer = await parseBunkerInput(token).catch(() => null);

  if (!pointer) {
    throw new Nip46Error('INVALID_TOKEN', `not a usable bunker connection token: ${token}`);
  }

  if (pointer.relays.length === 0) {
    // Without a relay there is nowhere to send the request, and failing here is
    // far clearer than a connect timeout several seconds later.
    throw new Nip46Error('INVALID_TOKEN', 'bunker token names no relays');
  }

  return handshake(openConnection(generateSecretKey(), pointer, options), options);
}

/** Re-open a pairing that was persisted on an earlier visit. */
export async function restoreConnection(
  clientSecretKey: Uint8Array,
  pointer: BunkerPointer,
  options: ConnectionOptions
): Promise<ActiveConnection> {
  return handshake(openConnection(clientSecretKey, pointer, options), options);
}

export interface NostrConnectOptions extends ConnectionOptions {
  relays: string[];
  /** Called with the URI to display or render as a QR code, before waiting. */
  onUri?: (uri: string) => void;
  metadata?: { name?: string; url?: string; image?: string };
}

/**
 * The client-initiated direction: we publish a `nostrconnect://` URI and wait
 * for a signer to come to us.
 *
 * `BunkerSigner.fromURI` covers this, but it treats a wrong-secret response as
 * noise and waits out the clock, so a hostile or misconfigured signer is
 * indistinguishable from an absent one. Watching the subscription directly lets
 * a mismatched secret be reported as exactly that (FR-013).
 */
export async function connectWithNostrConnect(
  options: NostrConnectOptions
): Promise<ActiveConnection> {
  if (options.relays.length === 0) {
    throw new Nip46Error('INVALID_TOKEN', 'nostrconnect pairing needs at least one relay');
  }

  const clientSecretKey = generateSecretKey();
  const clientPubkey = getPublicKey(clientSecretKey);
  const secret = bytesToHex(generateSecretKey()).slice(0, 32);
  const { pool, ownsPool } = poolFor(options);

  const uri = createNostrConnectURI({
    clientPubkey,
    relays: options.relays,
    secret,
    perms: options.permissions,
    ...options.metadata,
  });

  options.onUri?.(uri);

  let bunkerPubkey: string;

  try {
    bunkerPubkey = await waitForNostrConnect({
      clientSecretKey,
      clientPubkey,
      relays: options.relays,
      secret,
      pool,
      timeoutMs: options.connectTimeoutMs,
      onAuthUrl: options.onAuthUrl,
    });
  } catch (error) {
    // No BunkerSigner exists yet, so there is no closeConnection() to call.
    if (ownsPool) {
      pool.destroy();
    }

    throw error;
  }

  const pointer: BunkerPointer = { pubkey: bunkerPubkey, relays: options.relays, secret };
  const bunker = BunkerSigner.fromBunker(clientSecretKey, pointer, bunkerParams(options, pool));

  // The signer's echo of the secret *is* the connect acknowledgement, and the
  // permissions travelled in the URI — so no second handshake.
  return { bunker, pointer, clientSecretKey, pool, ownsPool };
}

function waitForNostrConnect(input: {
  clientSecretKey: Uint8Array;
  clientPubkey: string;
  relays: string[];
  secret: string;
  pool: AbstractSimplePool;
  timeoutMs: number;
  onAuthUrl?: (url: string) => void;
}): Promise<string> {
  const filter: Filter = {
    kinds: [NOSTR_CONNECT_KIND],
    '#p': [input.clientPubkey],
    limit: 0,
  };

  return new Promise<string>((resolve, reject) => {
    let sawWrongSecret = false;
    /** An unauthenticated `{error}` addressed to us. A hint, not a verdict. */
    let declineReason: string | null = null;
    let settled = false;
    let timer: ReturnType<typeof setTimeout>;
    // Declared before `settle` closes over it: a pool that delivers an event
    // synchronously from subscribe() would otherwise hit the temporal dead zone,
    // and the ReferenceError would be swallowed by the catch in onevent.
    let subscription: { close: () => void } | undefined;

    const settle = (action: () => void): void => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      subscription?.close();
      action();
    };

    subscription = input.pool.subscribe(input.relays, filter, {
      onevent: (event: Event) => {
        try {
          const conversationKey = nip44.getConversationKey(input.clientSecretKey, event.pubkey);
          const payload = JSON.parse(nip44.decrypt(event.content, conversationKey)) as {
            result?: string;
            error?: string;
          };

          if (payload.result === input.secret) {
            settle(() => resolve(event.pubkey));
          } else if (payload.result === 'auth_url') {
            // The signer wants the user to approve in a browser first. There is
            // no BunkerSigner yet to route this through `onauth`, so hand the
            // URL over here and keep waiting for the real answer.
            if (payload.error) {
              input.onAuthUrl?.(payload.error);
            }
          } else if (payload.result === undefined && payload.error !== undefined) {
            // Looks like a decline — but recorded, never settled on.
            //
            // Decrypting proves only that someone encrypted *to* our pubkey, and
            // that pubkey is public: it is in the `#p` filter every relay sees
            // and in the URI the user scans. NIP-44 conversation keys are ECDH,
            // so any party holding it can produce a message we decrypt. Only the
            // `result === input.secret` branch authenticates anything, because
            // only someone who read the URI knows the secret.
            //
            // Aborting here would therefore let any relay operator kill any
            // pairing by publishing `{error}`: we would close the subscription
            // and reject before the real signer's ack arrived. Keeping it as a
            // hint costs a genuine decline nothing but the wait it was already
            // going to have, and downgrades an attacker to changing which error
            // message a failing pairing ends with.
            declineReason ??= payload.error;
          } else {
            sawWrongSecret = true;
          }
        } catch {
          // Anything we cannot decrypt is not addressed to this pairing.
        }
      },
    });

    if (settled) {
      // Settled from inside subscribe() itself, before the handle existed. No
      // timer either: `settle` would ignore it, but an armed one holds the
      // process (and a browser tab) awake for the whole timeout first.
      subscription.close();
      return;
    }

    timer = setTimeout(() => {
      // Classification only, once nothing better has arrived. A decline is the
      // most specific answer and the most likely explanation for the silence
      // that followed it, so it wins — but it can only ever change the error on
      // a pairing that was already going to fail, never abort a live one. See
      // the DECLINED branch above for why it is not trusted to settle.
      settle(() =>
        reject(
          declineReason !== null
            ? new Nip46Error('DECLINED', declineReason)
            : sawWrongSecret
              ? new Nip46Error(
                  'SECRET_MISMATCH',
                  'a signer answered the connection URI without the matching secret'
                )
              : new Nip46Error('TIMEOUT', 'no signer answered the connection URI in time')
        )
      );
    }, input.timeoutMs);
  });
}
