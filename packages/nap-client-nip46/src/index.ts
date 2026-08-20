export { Nip46Error, toNip46Error } from './errors.js';
export type { Nip46ErrorCode } from './errors.js';

export {
  DEFAULT_CONNECT_TIMEOUT_MS,
  DEFAULT_PING_TIMEOUT_MS,
  DEFAULT_SIGN_TIMEOUT_MS,
} from './timeout.js';

export { DEFAULT_PERMISSIONS } from './connection.js';

export { createNip46Signer } from './signer.js';
export type { Nip46Signer, Nip46SignerOptions, Nip46Status } from './signer.js';

// Moved to @imani/nap-client-web — nothing in it was NIP-46-specific, and the
// in-page-key KeyStore needs the same crypto. Re-exported so the pairing docs
// and existing imports keep working.
export { createWebCryptoSecretStore } from '@imani/nap-client-web';
export type { WebCryptoSecretStoreOptions } from '@imani/nap-client-web';

export { CONNECTION_RECORD_VERSION } from './persistence.js';
export type { StoredConnectionRecord } from './persistence.js';
