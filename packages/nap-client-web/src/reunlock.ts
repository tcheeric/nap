import type { KeyStore, KeyHolder } from './keyStore.js';

export type ReunlockErrorCode = 'INVALID_PASSPHRASE' | 'NO_STORED_KEY' | 'STORAGE_UNAVAILABLE';

export class ReunlockError extends Error {
  readonly code: ReunlockErrorCode;

  constructor(code: ReunlockErrorCode, message: string) {
    super(message);
    this.name = 'ReunlockError';
    this.code = code;
  }
}

export interface ReunlockOptions {
  onTimerReset?: () => void;
  onBroadcast?: () => void;
}

export interface ReunlockResult {
  success: true;
}

function isDecryptionError(error: unknown): boolean {
  if (error instanceof DOMException) return true;
  if (error instanceof Error && error.message === 'Invalid passphrase') return true;
  return false;
}

export async function reunlock(
  passphrase: string,
  store: KeyStore,
  holder: KeyHolder,
  options?: ReunlockOptions,
): Promise<ReunlockResult> {
  let hasKey: boolean;
  try {
    hasKey = await store.hasKey();
  } catch {
    throw new ReunlockError('STORAGE_UNAVAILABLE', 'Unable to access stored credentials');
  }

  if (!hasKey) {
    throw new ReunlockError('NO_STORED_KEY', 'No stored key found. Please log out and log back in.');
  }

  let key: string;
  try {
    key = await store.loadKey(passphrase);
  } catch (error) {
    if (isDecryptionError(error)) {
      throw new ReunlockError('INVALID_PASSPHRASE', 'Incorrect passphrase');
    }
    throw new ReunlockError('STORAGE_UNAVAILABLE', 'Unable to access stored credentials');
  }

  if (!key) {
    throw new ReunlockError('NO_STORED_KEY', 'No stored key found. Please log out and log back in.');
  }

  holder.setKey(key);

  options?.onTimerReset?.();

  try {
    options?.onBroadcast?.();
  } catch {
    // FR-11a: BroadcastChannel failures are logged but do not prevent re-unlock
  }

  return { success: true };
}
