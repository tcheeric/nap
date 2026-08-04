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

export { createWebCryptoSecretStore } from './webCryptoSecretStore.js';
export type { WebCryptoSecretStoreOptions } from './webCryptoSecretStore.js';

export { CONNECTION_RECORD_VERSION } from './persistence.js';
export type { StoredConnectionRecord } from './persistence.js';
