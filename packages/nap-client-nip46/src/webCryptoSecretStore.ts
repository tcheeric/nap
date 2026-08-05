import { decodeBase64Bytes, encodeBase64Bytes } from '@imani/nap-core';
import type { SecretStore } from '@imani/nap-client-web';

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
  storage?: Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>;
  iterations?: number;
}

function requireStorage(
  options: WebCryptoSecretStoreOptions
): Pick<Storage, 'getItem' | 'setItem' | 'removeItem'> {
  const storage = options.storage ?? (globalThis as { localStorage?: Storage }).localStorage;

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
 * Passphrase-encrypted storage for the NIP-46 client secret key.
 *
 * `KeyStore` ships as an interface with no implementation because the
 * application owns key enrolment. This one ships with an implementation for the
 * opposite reason: library code generates the client key during pairing, so
 * without a conforming store the predictable outcome is a plaintext key in
 * `localStorage` (FR-011).
 *
 * PBKDF2 over the passphrase, AES-GCM with a fresh salt and IV per write. The
 * ceiling is the passphrase: a weak one is offline-guessable regardless of the
 * iteration count.
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

  const read = (): Envelope | null => {
    const raw = requireStorage(options).getItem(storageKey);

    if (!raw) {
      return null;
    }

    try {
      return JSON.parse(raw) as Envelope;
    } catch {
      return null;
    }
  };

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
      const envelope = read();

      if (
        !envelope ||
        envelope.version !== ENVELOPE_VERSION ||
        !usableIterations(envelope.kdf?.iterations)
      ) {
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
      return read() !== null;
    },
  };
}
