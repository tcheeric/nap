import { decodeBase64Bytes, encodeBase64Bytes } from '@imani/nap-core';
import type { KeyStore } from './keyStore.js';
import type { SecretStore } from './secretStore.js';
import { resolveStorage, type WebStorage } from './storage.js';

const ENVELOPE_VERSION = 1;
const PBKDF2_ITERATIONS = 310_000;
const PBKDF2_HASH = 'SHA-256';
const SALT_BYTES = 16;
const IV_BYTES = 12;
const MIN_ITERATIONS = 1_000;
const MAX_ITERATIONS = 10_000_000;

/**
 * What actually lands in storage. The parameters travel with the ciphertext so
 * raising the iteration count later does not orphan records written today.
 */
interface Envelope {
  version: number;
  kdf: { name: 'PBKDF2'; hash: string; iterations: number; salt: string };
  iv: string;
  ciphertext: string;
}

export interface WebCryptoSecretStoreOptions {
  /** Defaults to `localStorage`. Injectable for tests and for non-DOM hosts. */
  storage?: WebStorage;
  iterations?: number;
}

function requireStorage(options: WebCryptoSecretStoreOptions): WebStorage {
  // Goes through the shared resolver so that a document denied storage access
  // reports absence here rather than throwing SecurityError out of whatever
  // called it — connect() on a NIP-46 signer, in practice.
  const storage = resolveStorage(options.storage);

  if (!storage) {
    throw new Error('No storage available: pass options.storage outside a browser');
  }

  return storage;
}

/**
 * TypeScript models a bare `Uint8Array` as possibly SharedArrayBuffer-backed,
 * which WebCrypto does not accept. Copying is cheaper than threading the
 * narrower type through every helper.
 */
function unshared(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy;
}

/**
 * The envelope carries its own iteration count, so anything able to write that
 * storage key gets to pick it — and `iterations: 2e9` would hang the tab inside
 * `deriveKey` on the next load. Outside the sane band the record is unreadable.
 */
function usableIterations(iterations: unknown): boolean {
  return (
    typeof iterations === 'number' &&
    Number.isInteger(iterations) &&
    iterations >= MIN_ITERATIONS &&
    iterations <= MAX_ITERATIONS
  );
}

/**
 * Anything that parses as JSON. Deliberately *not* version-checked, because it
 * backs `has()`: a record written by a newer build is still a record. Answering
 * "absent" routes the app into re-enrolment, whose `save()` overwrites this key
 * — destroying the only copy of a ciphertext the newer build could still read.
 * Losing key material is far worse than a confusing prompt.
 */
function readStoredEnvelope(
  storageKey: string,
  options: WebCryptoSecretStoreOptions
): Envelope | null {
  const raw = requireStorage(options).getItem(storageKey);

  if (!raw) {
    return null;
  }

  try {
    return JSON.parse(raw) as Envelope;
  } catch {
    return null;
  }
}

/** Present *and* decryptable by this build. Backs `load()`. */
function readUsableEnvelope(
  storageKey: string,
  options: WebCryptoSecretStoreOptions
): Envelope | null {
  const envelope = readStoredEnvelope(storageKey, options);

  if (
    !envelope ||
    envelope.version !== ENVELOPE_VERSION ||
    !usableIterations(envelope.kdf?.iterations)
  ) {
    return null;
  }

  return envelope;
}

async function deriveKey(
  passphrase: string,
  salt: Uint8Array<ArrayBuffer>,
  iterations: number
): Promise<CryptoKey> {
  const material = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(passphrase),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: PBKDF2_HASH },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Passphrase-encrypted `localStorage`, for any secret this library persists.
 *
 * It lives here rather than in `@imani/nap-client-nip46`, where it started,
 * because nothing in it is NIP-46-specific and two consumers now need it: the
 * bunker pairing record, and {@link createWebCryptoKeyStore} below. One
 * implementation, one set of crypto parameters to review.
 *
 * PBKDF2 over the passphrase, AES-GCM with a fresh salt and IV per write. The
 * ceiling is the passphrase: a weak one is offline-guessable regardless of the
 * iteration count. RFC §1181 forbids plaintext key material at rest anywhere,
 * `localStorage` included — this is what "encrypted" has to mean to satisfy it.
 */
export function createWebCryptoSecretStore(
  storageKey = 'nap-nip46-connection',
  options: WebCryptoSecretStoreOptions = {}
): SecretStore {
  const iterations = options.iterations ?? PBKDF2_ITERATIONS;

  // Bounded on the way in, not only on the way out. An out-of-band count would
  // otherwise save happily and then fail `usableIterations` on every load — a
  // store that writes and never reads, discovered on the user's next visit.
  if (!usableIterations(iterations)) {
    throw new RangeError(
      `iterations must be an integer between ${MIN_ITERATIONS} and ${MAX_ITERATIONS}`
    );
  }

  const readStored = (): Envelope | null => readStoredEnvelope(storageKey, options);
  const readUsable = (): Envelope | null => readUsableEnvelope(storageKey, options);

  return {
    async save(plaintext: string, passphrase: string): Promise<void> {
      const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
      const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
      const key = await deriveKey(passphrase, salt, iterations);

      const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        key,
        new TextEncoder().encode(plaintext)
      );

      const envelope: Envelope = {
        version: ENVELOPE_VERSION,
        kdf: {
          name: 'PBKDF2',
          hash: PBKDF2_HASH,
          iterations,
          salt: encodeBase64Bytes(salt),
        },
        iv: encodeBase64Bytes(iv),
        ciphertext: encodeBase64Bytes(new Uint8Array(ciphertext)),
      };

      requireStorage(options).setItem(storageKey, JSON.stringify(envelope));
    },

    async load(passphrase: string): Promise<string | null> {
      const envelope = readUsable();

      if (!envelope) {
        return null;
      }

      try {
        const key = await deriveKey(
          passphrase,
          unshared(decodeBase64Bytes(envelope.kdf.salt)),
          envelope.kdf.iterations
        );

        const plaintext = await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: unshared(decodeBase64Bytes(envelope.iv)) },
          key,
          unshared(decodeBase64Bytes(envelope.ciphertext))
        );

        return new TextDecoder().decode(plaintext);
      } catch {
        // A wrong passphrase and a corrupt record are the same answer: no
        // usable pairing. Never throw here — see SecretStore.
        return null;
      }
    },

    async clear(): Promise<void> {
      requireStorage(options).removeItem(storageKey);
    },

    async has(): Promise<boolean> {
      return readStored() !== null;
    },
  };
}

/**
 * A {@link KeyStore} over the same encrypted `localStorage` record.
 *
 * `KeyStore` shipped as an interface with no implementation because the
 * application owns key enrolment, which left every in-page-key app writing its
 * own — and the predictable failure of writing your own is a plaintext nsec in
 * `localStorage`, which RFC §1181 forbids outright. This is the reference
 * answer. Enrol with the returned `save()`, then hand the store to
 * `createNapSession({ keyStore })` so `reunlock(passphrase)` can restore the key
 * after an idle lock.
 *
 * `KeyStore` is a read-subset of `SecretStore`, so this is an adapter rather
 * than a second implementation. One difference is load-bearing and is the whole
 * reason it is not a cast: `SecretStore.load()` answers `null` for both a wrong
 * passphrase and a corrupt record, while `reunlock()` needs to tell the user
 * "incorrect passphrase". It classifies by *thrown* error, so this throws the
 * `Invalid passphrase` message its `isDecryptionError` matches — otherwise every
 * mistyped passphrase reports as `STORAGE_UNAVAILABLE`, which is both wrong and
 * unactionable.
 *
 * The absent case never reaches here: `reunlock()` checks `hasKey()` first and
 * raises `NO_STORED_KEY` on its own.
 */
export function createWebCryptoKeyStore(
  storageKey = 'nap-key',
  options: WebCryptoSecretStoreOptions = {}
): KeyStore & Pick<SecretStore, 'save' | 'clear'> {
  const store = createWebCryptoSecretStore(storageKey, options);

  return {
    async loadKey(passphrase: string): Promise<string> {
      const key = await store.load(passphrase);

      if (key !== null) {
        return key;
      }

      // Present but unreadable is neither of the two errors reunlock() has good
      // wording for, and picking either does real harm: `Invalid passphrase`
      // tells a user with the right passphrase to keep retyping, and the absent
      // path tells the app to re-enrol, which overwrites the ciphertext a newer
      // build could still read. A third message falls through to
      // STORAGE_UNAVAILABLE, which asks for neither.
      // Stored *and* unusable. A wrong passphrase also lands here with a record
      // present, so testing presence alone would report every mistyped
      // passphrase as a version problem.
      if (
        readStoredEnvelope(storageKey, options) !== null &&
        readUsableEnvelope(storageKey, options) === null
      ) {
        throw new Error('stored key cannot be read by this version');
      }

      throw new Error('Invalid passphrase');
    },

    hasKey(): Promise<boolean> {
      return store.has();
    },

    /** Enrolment. `KeyStore` itself is read-only — see {@link SecretStore}. */
    save: store.save,
    clear: store.clear,
  };
}
