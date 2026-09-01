import type { SessionSigner, SignerKind } from '@imani/nap-client-web';

/**
 * What a signer screen hands back. Three fields that travel together because
 * they must never disagree about which signer they describe.
 */
export interface SignerChoice {
  signer: SessionSigner;
  /**
   * Recorded — after a successful login, never on the click that starts one —
   * so the next reload knows which screen to rebuild. Public: a discriminator
   * and an npub, no key material.
   */
  kind: SignerKind;
  /**
   * Whether this signer came out of storage rather than from a choice the user
   * just made in this tab.
   *
   * `resume()` never invokes the signer, which is what makes a reload
   * prompt-free and equally what makes it unable to notice the signer is now
   * somebody else. The cookie outlived the page; the signer did not. Only the
   * screen that rebuilt it knows, so only that screen can ask for the check.
   */
  verifyIdentity: boolean;
}

export type OnSigner = (choice: SignerChoice) => void;
