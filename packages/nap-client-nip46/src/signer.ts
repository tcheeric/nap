import { nip19 } from 'nostr-tools';
import type { AbstractSimplePool } from 'nostr-tools/abstract-pool';
import type { SecretStore, SessionSigner } from '@imani/nap-client-web';
import { bytesToHex, hexToBytes } from '@imani/nap-core';
import type { Nip98Event } from '@imani/nap-core';
import {
  DEFAULT_PERMISSIONS,
  closeConnection,
  connectWithBunkerToken,
  connectWithNostrConnect,
  restoreConnection,
  type ActiveConnection,
  type ConnectionOptions,
} from './connection.js';
import { Nip46Error, toNip46Error } from './errors.js';
import {
  DEFAULT_CONNECT_TIMEOUT_MS,
  DEFAULT_PING_TIMEOUT_MS,
  DEFAULT_SIGN_TIMEOUT_MS,
  withTimeout,
} from './timeout.js';
import { loadConnection, saveConnection, toPointer } from './persistence.js';

export type Nip46Status = 'disconnected' | 'connected';

export interface Nip46SignerOptions {
  /** A `bunker://` URL or NIP-05 identifier. Omit to pair via `nostrconnect://`. */
  connectionToken?: string;
  /** Relays to advertise in the `nostrconnect://` URI. */
  relays?: string[];
  /** Where an established pairing is persisted, so a reload need not re-pair. */
  secretStore?: SecretStore;
  /** Required alongside `secretStore`; the store never holds this. */
  passphrase?: string;
  pool?: AbstractSimplePool;
  permissions?: string[];
  connectTimeoutMs?: number;
  signTimeoutMs?: number;
  pingTimeoutMs?: number;
  /** NIP-46 `auth_url` — the signer wants the user to visit a page first. */
  onAuthUrl?: (url: string) => void;
  /** The `nostrconnect://` URI, handed over as soon as it exists. */
  onConnectionUri?: (uri: string) => void;
  metadata?: { name?: string; url?: string; image?: string };
}

export interface Nip46Signer extends SessionSigner {
  connect(): Promise<void>;
  disconnect(): Promise<void>;
  getStatus(): Nip46Status;
  /** `false` rather than a throw — a dead bunker is an answer, not an error. */
  ping(): Promise<boolean>;
  /** The `nostrconnect://` URI, once one has been generated. */
  getConnectionUri(): string | null;
  getClientPubkey(): string | null;
}

/**
 * A `SessionSigner` backed by a remote signer over NIP-46.
 *
 * Interchangeable with the NIP-07 and in-page-key signers: `createNapSession()`
 * sees the same two methods and nothing else. The extra surface here is pairing
 * lifecycle, which happens before a session exists.
 */
export function createNip46Signer(options: Nip46SignerOptions): Nip46Signer {
  let connection: ActiveConnection | null = null;
  let connectionUri: string | null = null;

  const connectionOptions: ConnectionOptions = {
    pool: options.pool,
    permissions: options.permissions ?? DEFAULT_PERMISSIONS,
    connectTimeoutMs: options.connectTimeoutMs ?? DEFAULT_CONNECT_TIMEOUT_MS,
    onAuthUrl: options.onAuthUrl,
  };

  const store = (): { store: SecretStore; passphrase: string } | null =>
    options.secretStore && options.passphrase !== undefined
      ? { store: options.secretStore, passphrase: options.passphrase }
      : null;

  async function restore(): Promise<ActiveConnection | null> {
    const persisted = store();

    if (!persisted) {
      return null;
    }

    const record = await loadConnection(persisted.store, persisted.passphrase);

    if (!record) {
      // Absent, wrong passphrase, or a version this build cannot read. All three
      // mean "no pairing to reuse" — pairing afresh is the recovery (FR-011a).
      return null;
    }

    try {
      return await restoreConnection(
        hexToBytes(record.clientSecretKey),
        toPointer(record),
        connectionOptions
      );
    } catch {
      // The signer moved, revoked us, or is simply down. Either way the stored
      // record is no longer usable; drop it so the next visit pairs cleanly.
      await persisted.store.clear();
      return null;
    }
  }

  async function persist(active: ActiveConnection): Promise<void> {
    const persisted = store();

    if (!persisted) {
      return;
    }

    await saveConnection(persisted.store, persisted.passphrase, {
      bunkerPubkey: active.pointer.pubkey,
      relays: active.pointer.relays,
      secret: active.pointer.secret ?? null,
      clientSecretKey: bytesToHex(active.clientSecretKey),
    });
  }

  function requireConnection(): ActiveConnection {
    if (!connection) {
      throw new Nip46Error('UNREACHABLE', 'no remote signer is connected; call connect() first');
    }

    return connection;
  }

  return {
    async connect(): Promise<void> {
      if (connection) {
        return;
      }

      const restored = await restore();

      if (restored) {
        connection = restored;
        return;
      }

      let established: ActiveConnection;

      if (options.connectionToken) {
        established = await connectWithBunkerToken(options.connectionToken, connectionOptions);
      } else if (options.relays?.length) {
        established = await connectWithNostrConnect({
          ...connectionOptions,
          relays: options.relays,
          metadata: options.metadata,
          onUri: (uri) => {
            connectionUri = uri;
            options.onConnectionUri?.(uri);
          },
        });
      } else if (store()) {
        // A store was configured but had nothing usable in it. That is the
        // ordinary "returning user, expired or unreadable pairing" case: stay
        // disconnected and let the application ask for a token (FR-011a).
        return;
      } else {
        throw new Nip46Error(
          'INVALID_TOKEN',
          'pass connectionToken for a bunker:// pairing or relays for a nostrconnect:// one'
        );
      }

      try {
        await persist(established);
      } catch (error) {
        // Connected but unrememberable — a full quota, say. Tear it down rather
        // than reject while leaving a live pairing the caller cannot reach.
        await closeConnection(established);
        throw error;
      }

      connection = established;
    },

    async getNpub(): Promise<string> {
      const active = requireConnection();

      try {
        return nip19.npubEncode(await active.bunker.getPublicKey());
      } catch (error) {
        throw toNip46Error(error, 'the remote signer would not reveal its public key');
      }
    },

    async signEvent(event): Promise<Nip98Event> {
      const active = requireConnection();

      try {
        return (await withTimeout(
          active.bunker.signEvent(event),
          options.signTimeoutMs ?? DEFAULT_SIGN_TIMEOUT_MS,
          'sign_event'
        )) as Nip98Event;
      } catch (error) {
        throw toNip46Error(error, 'the remote signer did not return a signature');
      }
    },

    async ping(): Promise<boolean> {
      if (!connection) {
        return false;
      }

      try {
        await withTimeout(
          connection.bunker.ping(),
          options.pingTimeoutMs ?? DEFAULT_PING_TIMEOUT_MS,
          'ping'
        );
        return true;
      } catch {
        return false;
      }
    },

    async disconnect(): Promise<void> {
      const active = connection;
      connection = null;
      connectionUri = null;

      if (active) {
        await closeConnection(active);
        active.clientSecretKey.fill(0);
      }

      await store()?.store.clear();
    },

    getStatus(): Nip46Status {
      return connection ? 'connected' : 'disconnected';
    },

    getConnectionUri(): string | null {
      return connectionUri;
    },

    getClientPubkey(): string | null {
      return connection ? nip19.npubEncode(connection.pointer.pubkey) : null;
    },
  };
}
