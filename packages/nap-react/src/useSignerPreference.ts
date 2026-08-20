import { useCallback, useMemo, useState } from 'react';
import { createSignerPreferenceStore } from '@imani/nap-client-web';
import type {
  SignerKind,
  SignerPreference,
  SignerPreferenceOptions,
} from '@imani/nap-client-web';

export interface UseSignerPreferenceReturn {
  /** What the last visit used, or null on a first visit or after `forget()`. */
  preference: SignerPreference | null;
  /** Record the choice. Call it after a successful `login()`, not before. */
  remember: (kind: SignerKind, npub: string) => void;
  /** Drop it. Call on logout, and on an identity change. */
  forget: () => void;
}

/**
 * Remember which signer the user authenticated with, across reloads.
 *
 * The session survives a reload on its own — the id is an `HttpOnly` cookie and
 * `resume()` never invokes the signer. What does not survive is the signer
 * object, and `createNapSession()` needs one before `resume()` can be called.
 * This is the missing half: read the preference on mount, rebuild that signer,
 * then resume.
 *
 * Only a kind and an npub are stored, both public. Key material goes in
 * `createWebCryptoKeyStore()`, encrypted.
 *
 * `remember()` belongs *after* a successful login, not on the click that starts
 * one. Recording a choice that then fails would send the next visit down a path
 * the user could not complete.
 *
 * The npub is stored so the reload path has something to check against, but the
 * check that matters is `resume({ verifyIdentity: true })` — only the signer can
 * say who it is now, and a plain `resume()` never asks it.
 *
 * @example
 * ```tsx
 * function Boot() {
 *   const { preference, remember, forget } = useSignerPreference();
 *   const { status, provider } = useNip07();
 *
 *   useEffect(() => {
 *     if (preference?.kind !== 'nip07' || !provider) return;
 *     // verifyIdentity, always, on this path: the cookie outlived the page and
 *     // the signer did not, so the user may have switched accounts in the
 *     // extension since. Without it resume() restores the previous account's
 *     // roles under a signer that is now somebody else.
 *     void session.resume({ verifyIdentity: true }).catch(handleIdentityMismatch);
 *   }, [preference, provider]);
 *
 *   // ... on a fresh login:
 *   //   const res = await session.login();
 *   //   remember('nip07', res.principal.npub);
 * }
 * ```
 */
export function useSignerPreference(
  storageKey?: string,
  options?: SignerPreferenceOptions
): UseSignerPreferenceReturn {
  // Built once. A store rebuilt per render is harmless in itself, but it would
  // make every callback below a new identity and push that churn into caller
  // effect deps — the same trap `useNapCallbacks` fell into.
  const store = useMemo(
    () => createSignerPreferenceStore(storageKey, options),
    // eslint-disable-next-line react-hooks/exhaustive-deps -- read once, by design
    [storageKey]
  );

  // Read during initialisation rather than in an effect: the first render is
  // where the login screen decides whether to show a signer picker at all, and
  // an effect would paint the picker before replacing it.
  const [preference, setPreference] = useState<SignerPreference | null>(() => store.read());

  const remember = useCallback(
    (kind: SignerKind, npub: string) => {
      setPreference(store.write(kind, npub));
    },
    [store]
  );

  const forget = useCallback(() => {
    store.clear();
    setPreference(null);
  }, [store]);

  return { preference, remember, forget };
}
