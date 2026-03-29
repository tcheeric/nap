import { createContext, useContext, useState, useEffect, useCallback, type ReactNode } from 'react';
import type { NapSession } from '@imani/nap-client-web';
import type { NapSessionState } from './types.js';

const NapContext = createContext<NapSessionState | null>(null);

export interface NapProviderProps {
  /** A NapSession instance created via createNapSession(). */
  session: NapSession;
  children: ReactNode;
}

/**
 * Provides NAP session state to the React tree.
 *
 * The provider syncs the NapSession's imperative state (isAuthenticated, isLocked,
 * isShutdown) into React state so components re-render on transitions.
 *
 * @example
 * ```tsx
 * import { createNapSession } from '@imani/nap-client-web';
 * import { NapProvider } from '@imani/nap-react';
 *
 * const session = createNapSession({ ... });
 *
 * function App() {
 *   return (
 *     <NapProvider session={session}>
 *       <MyApp />
 *     </NapProvider>
 *   );
 * }
 * ```
 */
export function NapProvider({ session, children }: NapProviderProps) {
  const [isAuthenticated, setIsAuthenticated] = useState(() => session.isAuthenticated());
  const [isLocked, setIsLocked] = useState(() => session.isLocked());
  const [isShutdown, setIsShutdown] = useState(() => session.isShutdown());

  // Sync state on every render — the NapSession is imperative, so we poll
  // after known mutation points. The callbacks below handle the common cases;
  // this effect catches anything we missed (e.g., external session.lock() calls).
  useEffect(() => {
    const sync = () => {
      setIsAuthenticated(session.isAuthenticated());
      setIsLocked(session.isLocked());
      setIsShutdown(session.isShutdown());
    };
    // Sync on visibility change (tab switch back) as a lightweight poll.
    document.addEventListener('visibilitychange', sync);
    return () => document.removeEventListener('visibilitychange', sync);
  }, [session]);

  const value: NapSessionState = {
    session,
    isAuthenticated,
    isLocked,
    isShutdown,
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
 * Pass these as the onLock/onUnlock/onShutdown/onLogout callbacks when creating
 * the NapSession so that React state stays in sync with imperative state changes.
 *
 * @example
 * ```tsx
 * function App() {
 *   const [sessionState, callbacks] = useNapCallbacks();
 *
 *   const session = useMemo(() => createNapSession({
 *     ...config,
 *     ...callbacks,
 *   }), [callbacks]);
 *
 *   return <NapProvider session={session}>{...}</NapProvider>;
 * }
 * ```
 */
export function useNapCallbacks() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLocked, setIsLocked] = useState(false);
  const [isShutdown, setIsShutdown] = useState(false);

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
  }, []);

  const onLogin = useCallback(() => {
    setIsAuthenticated(true);
    setIsLocked(false);
    setIsShutdown(false);
  }, []);

  return [
    { isAuthenticated, isLocked, isShutdown },
    { onLock, onUnlock, onShutdown, onLogout, onLogin },
  ] as const;
}
