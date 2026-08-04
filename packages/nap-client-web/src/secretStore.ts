/**
 * Write-capable sibling to {@link KeyStore}.
 *
 * `KeyStore` is read-only by design: the application owns enrolment, and the
 * library only ever loads. A NIP-46 pairing inverts that — the client secret key
 * is generated *by* library code during pairing, so the library is the only
 * thing that can persist it. Adding `save()` to `KeyStore` would change an
 * interface every integrator already implements, so this is a new one beside it.
 *
 * Implementations MUST encrypt with the passphrase. `load()` returns `null`
 * rather than throwing when the record is absent or will not decrypt, so a
 * forgotten passphrase degrades to "pair again" instead of a dead session.
 */
export interface SecretStore {
  save(plaintext: string, passphrase: string): Promise<void>;
  /** `null` when absent or undecryptable — never throws for a wrong passphrase. */
  load(passphrase: string): Promise<string | null>;
  clear(): Promise<void>;
  has(): Promise<boolean>;
}
