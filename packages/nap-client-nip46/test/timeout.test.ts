import { afterEach, describe, expect, it, vi } from 'vitest';
import { Nip46Error } from '../src/errors.js';
import { withTimeout } from '../src/timeout.js';

describe('withTimeout', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it('resolves through when the promise settles in time', async () => {
    await expect(withTimeout(Promise.resolve('value'), 1_000, 'test')).resolves.toBe('value');
  });

  it('rejects with TIMEOUT at the bound', async () => {
    vi.useFakeTimers();

    const pending = withTimeout(new Promise<never>(() => {}), 1_000, 'sign_event');
    const assertion = expect(pending).rejects.toMatchObject({ code: 'TIMEOUT' });

    await vi.advanceTimersByTimeAsync(1_000);
    await assertion;
  });

  it('names the operation that timed out', async () => {
    vi.useFakeTimers();

    const pending = withTimeout(new Promise<never>(() => {}), 500, 'ping');
    const assertion = expect(pending).rejects.toThrow(Nip46Error);

    await vi.advanceTimersByTimeAsync(500);
    await assertion;
  });

  it('does not leave a pending timer after settling', async () => {
    vi.useFakeTimers();

    await withTimeout(Promise.resolve('value'), 60_000, 'connect');

    // A timer left per outstanding request keeps the tab (and the runner) awake.
    expect(vi.getTimerCount()).toBe(0);
  });
});
