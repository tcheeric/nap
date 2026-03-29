export interface KeyStore {
  loadKey(passphrase: string): Promise<string>;
  hasKey(): Promise<boolean>;
}

export interface KeyHolder {
  setKey(key: string): void;
  clearKey(): void;
  hasKey(): boolean;
}
