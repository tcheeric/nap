/**
 * Which kinds of signer this page could use — as opposed to which one it used
 * last (`createSignerPreferenceStore()`).
 *
 * `detectNip07Provider()` answers one question: is `window.nostr` here. A login
 * screen that asks only that reports "no signer found" on a desktop that could
 * pair a bunker or take an nsec, which is the mistake WebAuthn replaced with
 * `getClientCapabilities()`.
 *
 * Only `nip07` is detectable. NIP-46 and an in-page key are not features of the
 * browser, they are things the app shipped — `@imani/nap-client-nip46` on the
 * one hand, a `keyStore` on the other — so the app declares them.
 */
import { detectNip07Provider, type Nip07DetectOptions } from './nip07.js';
import type { KeyStore } from './keyStore.js';

export interface SignerCapabilities {
  /** A NIP-07 provider appeared within the detect window. */
  nip07: boolean;
  /**
   * Pairing a bunker is offerable. Says the package is wired, **not** that a
   * bunker will answer — no relay is contacted here, and a pairing can still
   * time out.
   */
  nip46: boolean;
  /** An in-page key can be enrolled and re-unlocked, because a `keyStore` exists. */
  localKey: boolean;
}

export interface SignerCapabilityOptions extends Nip07DetectOptions {
  /** Pass `true` if the app ships `@imani/nap-client-nip46`. Default `false`. */
  nip46?: boolean;
  /** The store you wired, if any. Its presence is what `localKey` reports. */
  keyStore?: KeyStore | null;
}

/**
 * Never throws, and never longer than the NIP-07 detect window.
 */
export async function getSignerCapabilities(
  options: SignerCapabilityOptions = {}
): Promise<SignerCapabilities> {
  return {
    nip07: (await detectNip07Provider(options)) !== null,
    nip46: options.nip46 ?? false,
    localKey: Boolean(options.keyStore),
  };
}
