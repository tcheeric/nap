import {
  createSignerPreferenceStore,
  createWebCryptoKeyStore,
} from '@imani/nap-client-web';

/**
 * One instance, shared by the enrolment screen and the session.
 *
 * Two `createWebCryptoKeyStore('merchant.key')` calls would agree — the record
 * lives in `localStorage` under that name, not in the object — but the storage
 * key is the thing that has to match between whoever enrols and whoever
 * re-unlocks, and a constant nobody has to retype is the cheapest way to keep
 * it matching.
 *
 * What lands in storage is an AES-GCM ciphertext under PBKDF2 over the
 * passphrase. The passphrase itself is never stored, and the store never holds
 * it: it is an argument to `save()` and `loadKey()`, nothing more.
 */
export const keyStore = createWebCryptoKeyStore('merchant.key');

/**
 * Which signer to rebuild after a reload.
 *
 * The session survives on its own — the id is an `HttpOnly` cookie and
 * `resume()` never invokes the signer. What does not survive is the signer
 * object, and `createNapSession()` needs one before `resume()` can be called
 * at all. Without this the page has to ask on every reload, which is the
 * prompt `resume()` exists to avoid.
 *
 * A `'nip07' | 'nip46' | 'key'` discriminator and an npub. Both public, no key
 * material — that lives in `keyStore` above, encrypted. This file must never
 * become the place somebody puts an nsec.
 *
 * Handed to `createNapSession()` as well as read here, so the session can
 * *clear* it when a login has stopped being possible: a terminal
 * `/auth/complete` failure, or the identity guard terminating. A remembered
 * choice the server no longer accepts would otherwise be offered on every
 * reload and fail every time.
 */
export const signerPreference = createSignerPreferenceStore();
