export interface ActivityLock {
  touch(): void;
  stop(): void;
}

const ACTIVITY_EVENTS = ['mousemove', 'keydown', 'pointerdown', 'touchstart'] as const;

export function createActivityLock(
  enabled: boolean,
  timeoutMs: number,
  onLock: () => void,
  shutdownTimeoutMs?: number,
  onShutdown?: () => void
): ActivityLock {
  if (!enabled || typeof window === 'undefined') {
    return {
      touch() {},
      stop() {},
    };
  }

  let lockTimeoutId: ReturnType<typeof setTimeout> | null = null;
  let shutdownTimeoutId: ReturnType<typeof setTimeout> | null = null;

  const reschedule = (): void => {
    if (lockTimeoutId) {
      clearTimeout(lockTimeoutId);
    }
    lockTimeoutId = setTimeout(onLock, timeoutMs);

    if (shutdownTimeoutMs != null && onShutdown) {
      if (shutdownTimeoutId) {
        clearTimeout(shutdownTimeoutId);
      }
      shutdownTimeoutId = setTimeout(onShutdown, shutdownTimeoutMs);
    }
  };

  const touch = (): void => {
    reschedule();
  };

  for (const eventName of ACTIVITY_EVENTS) {
    window.addEventListener(eventName, touch, { passive: true });
  }

  reschedule();

  return {
    touch,
    stop() {
      if (lockTimeoutId) {
        clearTimeout(lockTimeoutId);
      }
      if (shutdownTimeoutId) {
        clearTimeout(shutdownTimeoutId);
      }

      for (const eventName of ACTIVITY_EVENTS) {
        window.removeEventListener(eventName, touch);
      }
    },
  };
}
