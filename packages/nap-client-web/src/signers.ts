import { getPublicKey, nip19, finalizeEvent, type EventTemplate } from 'nostr-tools';
import { hexToBytes } from '@imani/nap-core';
import type { Nip98Event } from '@imani/nap-core';
import type { SessionSigner } from './types.js';

export function createPrivateKeySessionSigner(privateKeyHex: string): SessionSigner {
  const privateKey = hexToBytes(privateKeyHex);
  const pubkey = getPublicKey(privateKey);
  const npub = nip19.npubEncode(pubkey);

  return {
    getNpub() {
      return npub;
    },
    async signEvent(template: EventTemplate): Promise<Nip98Event> {
      return finalizeEvent(template, privateKey);
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
