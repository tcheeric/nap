import { getPublicKey, nip19, finalizeEvent, type EventTemplate } from 'nostr-tools';
import { hexToBytes } from '@imani/nap-core';
import type { Nip98Event } from '@imani/nap-core';
import { SessionLockedError } from './httpClient.js';
import type { EvictableSigner, SessionSigner } from './types.js';

/**
 * Signer backed by a private key held in the page.
 *
 * The key is evictable: `clearKey()` zeroes the bytes and drops the reference,
 * so `session.lock()` genuinely removes it from memory rather than only marking
 * state (RFC §28.6). `getNpub()` keeps working while evicted — a public key is
 * not a secret, and the session still needs an identity to display.
 *
 * Caveat worth knowing: only the `Uint8Array` can be zeroed. The hex *string*
 * you pass in is an immutable JS string and lingers until garbage collection,
 * beyond this library's reach. Keep the window short by reading it straight
 * from your `KeyStore` rather than holding it in application state.
 *
 * Prefer `createNip07Signer` or a NIP-46 remote signer where possible — neither
 * puts a key in the page at all (RFC §28.2).
 */
export function createPrivateKeySessionSigner(privateKeyHex: string): EvictableSigner {
  let privateKey: Uint8Array | null = hexToBytes(privateKeyHex);
  const pubkey = getPublicKey(privateKey);
  const npub = nip19.npubEncode(pubkey);

  return {
    getNpub() {
      return npub;
    },
    async signEvent(template: EventTemplate): Promise<Nip98Event> {
      if (!privateKey) {
        throw new SessionLockedError();
      }

      return finalizeEvent(template, privateKey);
    },
    setKey(nextPrivateKeyHex: string) {
      const next = hexToBytes(nextPrivateKeyHex);

      // Restoring a different identity would leave getNpub() reporting the old
      // one while signatures came from the new key — a silent account swap.
      if (getPublicKey(next) !== pubkey) {
        next.fill(0);
        throw new Error('Restored key does not match this signer identity');
      }

      privateKey?.fill(0);
      privateKey = next;
    },
    clearKey() {
      privateKey?.fill(0);
      privateKey = null;
    },
    hasKey() {
      return privateKey !== null;
    },
  };
}

export function createNip07Signer(nostr: {
  getPublicKey(): Promise<string>;
  signEvent(event: EventTemplate): Promise<Nip98Event>;
}): SessionSigner {
  return {
    async getNpub() {
      return nip19.npubEncode(await nostr.getPublicKey());
    },
    signEvent(event: EventTemplate) {
      return nostr.signEvent(event);
    },
  };
}
