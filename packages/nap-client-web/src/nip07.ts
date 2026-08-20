import { nip19, type EventTemplate } from 'nostr-tools';
import type { Nip98Event } from '@imani/nap-core';
import type { SessionSigner } from './types.js';

/** The slice of `window.nostr` (NIP-07) that NAP authentication actually uses. */
export interface Nip07Provider {
  getPublicKey(): Promise<string>;
  signEvent(event: EventTemplate): Promise<Nip98Event>;
}

export type Nip07ErrorCode = 'NOT_AVAILABLE' | 'DECLINED' | 'TIMEOUT' | 'PROVIDER_ERROR';

/**
 * One code per way an extension can fail.
 *
 * "No extension installed", "the user clicked reject", "the user never answered"
 * and "the extension is locked or broke" want four different pieces of UI. A
 * single opaque Error forces the integrator to string-match, which is exactly
 * what this taxonomy exists to stop.
 */
export class Nip07Error extends Error {
  readonly code: Nip07ErrorCode;

  constructor(code: Nip07ErrorCode, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'Nip07Error';
    this.code = code;
  }
}

export interface Nip07DetectOptions {
  /** How long to wait for a provider to be injected. Default 1000. Resolves early on first sight. */
  timeoutMs?: number;
  /** How often to look. Default 50. */
  pollIntervalMs?: number;
  /** Injectable for tests; defaults to `globalThis`. */
  window?: { nostr?: Nip07Provider };
}

export interface Nip07SignerOptions {
  /** Bound on `getPublicKey()` and `signEvent()`. Default 60_000. */
  requestTimeoutMs?: number;
  /**
   * Override the declined-vs-error heuristic for a specific extension.
   * Return `undefined` to fall back to the heuristic.
   */
  classifyError?: (error: unknown) => Nip07ErrorCode | undefined;
}

export const DEFAULT_DETECT_TIMEOUT_MS = 1_000;
export const DEFAULT_REQUEST_TIMEOUT_MS = 60_000;

function isProvider(candidate: unknown): candidate is Nip07Provider {
  const provider = candidate as Partial<Nip07Provider> | undefined;
  return typeof provider?.getPublicKey === 'function' && typeof provider?.signEvent === 'function';
}

/**
 * Wait for a NIP-07 provider to appear.
 *
 * Extensions inject `window.nostr` on their own schedule, and a page that checks
 * once on load reports "no extension" to users who have one. Polling resolves
 * the moment the provider shows up, so the deadline is a worst case, not a wait.
 *
 * Resolves `null` when nothing appeared. Never throws — absence is an answer.
 */
export function detectNip07Provider(options: Nip07DetectOptions = {}): Promise<Nip07Provider | null> {
  const timeoutMs = options.timeoutMs ?? DEFAULT_DETECT_TIMEOUT_MS;
  const pollIntervalMs = options.pollIntervalMs ?? 50;
  const target = options.window ?? (globalThis as { nostr?: Nip07Provider });

  const current = (): Nip07Provider | null => (isProvider(target.nostr) ? target.nostr : null);

  const immediate = current();
  if (immediate) {
    return Promise.resolve(immediate);
  }

  return new Promise((resolve) => {
    let interval: ReturnType<typeof setInterval>;
    let deadline: ReturnType<typeof setTimeout>;

    const settle = (provider: Nip07Provider | null): void => {
      clearInterval(interval);
      clearTimeout(deadline);
      resolve(provider);
    };

    interval = setInterval(() => {
      const provider = current();
      if (provider) {
        settle(provider);
      }
    }, pollIntervalMs);

    deadline = setTimeout(() => settle(current()), timeoutMs);
  });
}

// Wording varies by extension — Alby says "User rejected", nos2x says "denied".
// This is a heuristic with a real ceiling: an extension phrasing a refusal in
// terms this misses lands on PROVIDER_ERROR. `classifyError` is the escape hatch
// rather than growing this pattern for every extension in existence.
const DECLINED_PATTERN = /\b(reject|denied|deny|declin|cancel|refus|not\s+allowed|unauthoriz)/i;

function classify(
  error: unknown,
  override: Nip07SignerOptions['classifyError']
): Nip07ErrorCode {
  const overridden = override?.(error);
  if (overridden) {
    return overridden;
  }

  const message = error instanceof Error ? error.message : String(error ?? '');
  return DECLINED_PATTERN.test(message) ? 'DECLINED' : 'PROVIDER_ERROR';
}

/**
 * Twin of `nap-client-nip46/src/timeout.ts`, kept separate because the rejection
 * has to be a `Nip07Error` — and sharing it would put a dependency between two
 * packages that are meant to be installable one without the other.
 */
function withTimeout<T>(promise: Promise<T>, ms: number, label: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;

  const timeout = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => {
      reject(new Nip07Error('TIMEOUT', `${label} timed out after ${ms}ms`));
    }, ms);
  });

  return Promise.race([promise, timeout]).finally(() => {
    clearTimeout(timer);
  });
}

/**
 * Wrap a NIP-07 provider as a NAP session signer.
 *
 * The key never enters the page, so there is nothing to evict and this is
 * deliberately not an `EvictableSigner` (RFC §28.2, §28.6(4)).
 *
 * `getNpub()` reads the provider every call rather than caching. That is what
 * makes an account switch in the extension detectable: a cached npub would let
 * the session keep reporting the old identity while the extension signed with a
 * new key (FR-021). Reading a public key does not prompt.
 */
export function createNip07Signer(
  nostr: Nip07Provider,
  options: Nip07SignerOptions = {}
): SessionSigner {
  const requestTimeoutMs = options.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;

  const call = async <T>(label: string, run: () => Promise<T>): Promise<T> => {
    try {
      return await withTimeout(run(), requestTimeoutMs, label);
    } catch (error) {
      if (error instanceof Nip07Error) {
        throw error;
      }

      const message = error instanceof Error ? error.message : String(error ?? '');
      throw new Nip07Error(
        classify(error, options.classifyError),
        message || `${label} failed`,
        { cause: error }
      );
    }
  };

  return {
    async getNpub() {
      return nip19.npubEncode(await call('getPublicKey', () => nostr.getPublicKey()));
    },
    signEvent(event: EventTemplate) {
      return call('signEvent', () => nostr.signEvent(event));
    },
  };
}

/**
 * Detect, then wrap. Throws `Nip07Error('NOT_AVAILABLE')` if no provider appears,
 * which is distinct from every signing failure — "install an extension" and
 * "your extension said no" are different messages for the user.
 */
export async function createNip07SignerFromWindow(
  options: Nip07SignerOptions & Nip07DetectOptions = {}
): Promise<SessionSigner> {
  const provider = await detectNip07Provider(options);

  if (!provider) {
    throw new Nip07Error('NOT_AVAILABLE', 'No NIP-07 provider (window.nostr) is available');
  }

  return createNip07Signer(provider, options);
}
