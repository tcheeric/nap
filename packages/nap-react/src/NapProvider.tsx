import {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  useMemo,
  type ReactNode,
} from 'react';
import type { IdentityChangedDetail, NapSession } from '@imani/nap-client-web';
import type { NapSessionState } from './types.js';

const NapContext = createContext<NapSessionState | null>(null);

/** Shared so an unauthenticated render does not allocate a new array each time. */
const NO_GRANTS: readonly string[] = [];

export interface NapProviderProps {
  /** A NapSession instance created via createNapSession(). */
  session: NapSession;
  /**
   * The `identityChange` from `useNapCallbacks()`. Required rather than
   * optional-defaulting-to-null, because the two are indistinguishable at
   * runtime and get opposite handling: an omitted prop would make every account
   * switch reject as `session_expired`, which callers retry, and a silent retry
   * is the privilege transfer the identity guard exists to stop. Polling cannot
   * recover it — a terminated-for-identity session and a logged-out one are the
   * same object state from out here.
   *
   * Pass `null` to opt out deliberately.
   */
  identityChange: IdentityChangedDetail | null;
  children: ReactNode;
}

/**
 * Provides NAP session state to the React tree.
 *
 * The provider syncs the NapSession's imperative state (isAuthenticated, isLocked,
 * isShutdown) into React state so components re-render on transitions.
 *
 * `identityChange` is the exception — it comes from a callback, so it is threaded
 * in from `useNapCallbacks()` rather than read off the session.
 *
 * @example
 * ```tsx
 * import { createNapSession } from '@imani/nap-client-web';
 * import { NapProvider, useNapCallbacks } from '@imani/nap-react';
 *
 * function App() {
 *   const [napState, callbacks] = useNapCallbacks();
 *   const session = useMemo(
 *     () => createNapSession({ ...config, ...callbacks }),
 *     [callbacks]
 *   );
 *
 *   return (
 *     <NapProvider session={session} identityChange={napState.identityChange}>
 *       <MyApp />
 *     </NapProvider>
 *   );
 * }
 * ```
 */
export function NapProvider({ session, identityChange, children }: NapProviderProps) {
  const [isAuthenticated, setIsAuthenticated] = useState(() => session.isAuthenticated());
  const [isLocked, setIsLocked] = useState(() => session.isLocked());
  const [isShutdown, setIsShutdown] = useState(() => session.isShutdown());
  // The whole SessionState, not the two arrays: `getSession()` hands back the
  // same object until the session is actually replaced, so setState bails out
  // on every poll tick that changed nothing. Copying the arrays out here would
  // allocate fresh ones twice a second and re-render every consumer with them.
  const [granted, setGranted] = useState(() => session.getSession());
  const lockRecovery = session.lockRecovery();

  // Sync React state with the imperative NapSession on lifecycle callbacks
  // and on visibility change (tab switch back) to catch external mutations.
  useEffect(() => {
    const sync = () => {
      setIsAuthenticated(session.isAuthenticated());
      setIsLocked(session.isLocked());
      setIsShutdown(session.isShutdown());
      setGranted(session.getSession());
    };

    // Poll on visibility change as a fallback for external mutations.
    document.addEventListener('visibilitychange', sync);

    // Poll on a short interval to catch imperative session changes
    // (e.g., direct session.lock() / session.logout() calls) that bypass
    // the NapProvider's callback-based sync.
    const intervalId = setInterval(sync, 500);

    return () => {
      document.removeEventListener('visibilitychange', sync);
      clearInterval(intervalId);
    };
  }, [session]);

  const roles = granted?.roles ?? NO_GRANTS;
  const permissions = granted?.permissions ?? NO_GRANTS;

  // Derived from state rather than delegated to session.hasRole()/hasPermission(),
  // which read the closure directly and so would give a fresh answer without
  // ever telling React to render it.
  const hasRole = useCallback((role: string) => roles.includes(role), [roles]);
  const hasPermission = useCallback(
    (permission: string) => permissions.includes(permission),
    [permissions]
  );

  const value: NapSessionState = {
    session,
    isAuthenticated,
    isLocked,
    isShutdown,
    lockRecovery,
    identityChange,
    roles,
    permissions,
    hasRole,
    hasPermission,
  };

  return <NapContext.Provider value={value}>{children}</NapContext.Provider>;
}

/**
 * Access the NAP session state from any component inside a NapProvider.
 *
 * @throws Error if used outside a NapProvider.
 */
export function useNapSession(): NapSessionState {
  const ctx = useContext(NapContext);
  if (!ctx) {
    throw new Error('useNapSession must be used within a <NapProvider>');
  }
  return ctx;
}

/**
 * Hook to create state-syncing callbacks for NapClientOptions.
 *
 * Spread the second tuple element into `createNapSession()`. It covers every
 * lifecycle callback the session can fire, including the two that carry
 * information nothing else can recover:
 *
 * - `onIdentityChanged` — the signer became someone else and the session was
 *   terminated. Indistinguishable from a logout by any other means, and it must
 *   not be: the correct response is a fresh login, never a silent retry.
 * - `onSessionExpired` — `resume()` found no live session.
 *
 * The first element is the state those callbacks accumulate. `NapProvider` polls
 * the session for the three booleans, so pass it `identityChange` and read the
 * rest through `useNapSession()`.
 *
 * @example
 * ```tsx
 * function App() {
 *   const [napState, callbacks] = useNapCallbacks();
 *
 *   const session = useMemo(() => createNapSession({
 *     ...config,
 *     ...callbacks,
 *   }), [callbacks]);
 *
 *   return (
 *     <NapProvider session={session} identityChange={napState.identityChange}>
 *       {...}
 *     </NapProvider>
 *   );
 * }
 * ```
 */
export function useNapCallbacks() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLocked, setIsLocked] = useState(false);
  const [isShutdown, setIsShutdown] = useState(false);
  const [identityChange, setIdentityChange] = useState<IdentityChangedDetail | null>(null);

  const onLock = useCallback(() => {
    setIsLocked(true);
  }, []);

  const onUnlock = useCallback(() => {
    setIsLocked(false);
    setIsShutdown(false);
  }, []);

  const onShutdown = useCallback(() => {
    setIsLocked(true);
    setIsShutdown(true);
  }, []);

  const onLogout = useCallback(() => {
    setIsAuthenticated(false);
    setIsLocked(false);
    setIsShutdown(false);
    setIdentityChange(null);
  }, []);

  const onLogin = useCallback((detail?: { via: 'login' | 'resume' }) => {
    setIsAuthenticated(true);
    setIsLocked(false);
    setIsShutdown(false);

    // Only a `login()` clears the identity banner, and the distinction is the
    // whole reason `via` exists. A `login()` is a fresh signature, so whoever
    // holds the signer has just proved who they are and the change is resolved.
    // A `resume()` proves only that a cookie is still valid — and the identity
    // guard sends no /auth/logout, so the terminated identity's cookie is very
    // much still valid. Clearing on resume would drop the banner exactly when
    // the page is authenticated as somebody the signer is not.
    if (detail?.via === 'login') {
      setIdentityChange(null);
    }
  }, []);

  const onSessionExpired = useCallback(() => {
    setIsAuthenticated(false);
    setIsLocked(false);
    setIsShutdown(false);
  }, []);

  const onIdentityChanged = useCallback((detail: IdentityChangedDetail) => {
    // The session is already gone in nap-client-web by the time this fires; the
    // lock and shutdown flags go with it, since neither survives a session that
    // no longer exists.
    setIsAuthenticated(false);
    setIsLocked(false);
    setIsShutdown(false);
    setIdentityChange(detail);
  }, []);

  // `callbacks` must keep its identity across renders or it poisons the pattern
  // this hook exists for: `useMemo(() => createNapSession({...callbacks}),
  // [callbacks])` would re-run on every render, and each new session starts with
  // no session state, its own BroadcastChannel and its own idle timer. Logging
  // in re-renders this hook, so the session would be replaced by an
  // unauthenticated one the instant the user authenticated. Every member is
  // `useCallback([])`-stable, so this holds for the life of the component.
  const callbacks = useMemo(
    () => ({ onLock, onUnlock, onShutdown, onLogout, onLogin, onSessionExpired, onIdentityChanged }),
    [onLock, onUnlock, onShutdown, onLogout, onLogin, onSessionExpired, onIdentityChanged]
  );

  const state = useMemo(
    () => ({ isAuthenticated, isLocked, isShutdown, identityChange }),
    [isAuthenticated, isLocked, isShutdown, identityChange]
  );

  return useMemo(() => [state, callbacks] as const, [state, callbacks]);
}
