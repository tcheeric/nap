import type { SecretStore } from '@imani/nap-client-web';
import type { BunkerPointer } from 'nostr-tools/nip46';

export const CONNECTION_RECORD_VERSION = 1;

/**
 * Everything needed to re-open a pairing without asking the user for a URL again.
 *
 * The whole record — not just the key — goes through the `SecretStore`, so there
 * is exactly one encrypted blob and no plaintext half to keep in sync. The relay
 * list is not secret, but encrypting it costs nothing and removes the question.
 */
export interface StoredConnectionRecord {
  version: number;
  bunkerPubkey: string;
  relays: string[];
  secret: string | null;
  /** Hex. Only ever exists inside the store's ciphertext. */
  clientSecretKey: string;
}

export function toPointer(record: StoredConnectionRecord): BunkerPointer {
  return {
    pubkey: record.bunkerPubkey,
    relays: record.relays,
    secret: record.secret,
  };
}

export async function saveConnection(
  store: SecretStore,
  passphrase: string,
  record: Omit<StoredConnectionRecord, 'version'>
): Promise<void> {
  await store.save(
    JSON.stringify({ version: CONNECTION_RECORD_VERSION, ...record }),
    passphrase
  );
}

/**
 * `null` for absent, undecryptable, or written by a version this build does not
 * understand. Every one of those means the same thing to the caller: pair again.
 * Throwing would turn a forgotten passphrase into a dead application (FR-011a).
 */
export async function loadConnection(
  store: SecretStore,
  passphrase: string
): Promise<StoredConnectionRecord | null> {
  const plaintext = await store.load(passphrase);

  if (!plaintext) {
    return null;
  }

  try {
    const record = JSON.parse(plaintext) as StoredConnectionRecord;

    if (
      record.version !== CONNECTION_RECORD_VERSION ||
      typeof record.clientSecretKey !== 'string' ||
      typeof record.bunkerPubkey !== 'string' ||
      !Array.isArray(record.relays)
    ) {
      return null;
    }

    return record;
  } catch {
    return null;
  }
}
