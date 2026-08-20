/**
 * Which signer the user last authenticated with.
 *
 * A reload keeps the session — the session id is an `HttpOnly` cookie and
 * `resume()` is prompt-free — but it does not keep the `SessionSigner`, which
 * lived in a closure that is now gone. `createNapSession()` needs one before
 * `resume()` can be called at all, so the page has to know which kind to build.
 * Without this it has to ask, and asking on every reload is exactly the prompt
 * `resume()` exists to avoid (FR-024).
 *
 * Nothing here is secret. The kind is a UI discriminator and the npub is public
 * by construction — it is the identity, not a credential. Key material belongs
 * in `createWebCryptoKeyStore()` or a `SecretStore`, encrypted; RFC §1181
 * forbids it at rest in plaintext, and this file must never become the place
 * somebody puts it.
 */
import { resolveStorage, type WebStorage } from './storage.js';

export type SignerKind = 'nip07' | 'nip46' | 'key';

const SIGNER_KINDS: readonly SignerKind[] = ['nip07', 'nip46', 'key'];

export interface SignerPreference {
  kind: SignerKind;
  /** The identity last authenticated. Public; never an nsec. */
  npub: string;
  /** Epoch ms, for expiring a stale preference if you want to. */
  savedAt: number;
}

export interface SignerPreferenceStore {
  read(): SignerPreference | null;
  /** The record persisted, or `null` if storage refused it. */
  write(kind: SignerKind, npub: string): SignerPreference | null;
  clear(): void;
}

export interface SignerPreferenceOptions {
  /** Defaults to `localStorage`. Injectable for tests and non-DOM hosts. */
  storage?: WebStorage;
  /** Clock, for tests. Defaults to `Date.now`. */
  now?: () => number;
}

function isPreference(value: unknown): value is SignerPreference {
  const candidate = value as Partial<SignerPreference> | null;

  return (
    typeof candidate?.npub === 'string' &&
    candidate.npub.startsWith('npub1') &&
    typeof candidate.savedAt === 'number' &&
    SIGNER_KINDS.includes(candidate.kind as SignerKind)
  );
}

/**
 * Reads and writes never throw.
 *
 * Storage is not guaranteed to be there or to work: Safari's private mode has
 * historically thrown on `setItem`, an embedded frame can have storage access
 * denied outright, and there is no `localStorage` at all during SSR. Every one
 * of those means the same thing to a caller — no remembered preference, ask the
 * user — and none of them is worth taking down a login screen for.
 */
export function createSignerPreferenceStore(
  storageKey = 'nap-signer-preference',
  options: SignerPreferenceOptions = {}
): SignerPreferenceStore {
  const now = options.now ?? Date.now;
  const storage = (): WebStorage | null => resolveStorage(options.storage);

  return {
    read(): SignerPreference | null {
      try {
        const raw = storage()?.getItem(storageKey);

        if (!raw) {
          return null;
        }

        const parsed: unknown = JSON.parse(raw);
        // A record written by a newer build, hand-edited, or half-written is
        // not a reason to fail — it is a reason to ask which signer to use.
        return isPreference(parsed) ? parsed : null;
      } catch {
        return null;
      }
    },

    write(kind: SignerKind, npub: string): SignerPreference | null {
      const preference: SignerPreference = { kind, npub, savedAt: now() };

      try {
        const target = storage();

        if (!target) {
          return null;
        }

        target.setItem(storageKey, JSON.stringify(preference));
        // Returned rather than making the caller read it back: a round trip
        // through JSON and the read validator to recover an object we are
        // holding is wasted synchronous storage I/O on the post-login path, and
        // it couples callers to `isPreference()` — tightening that validator
        // would make a successful write report failure.
        return preference;
      } catch {
        // Losing the preference costs one extra click on the next visit.
        return null;
      }
    },

    clear(): void {
      try {
        storage()?.removeItem(storageKey);
      } catch {
        // Same.
      }
    },
  };
}
