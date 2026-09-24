import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['packages/*/test/**/*.test.ts', 'examples/*/test/**/*.test.ts'],
    // The parity and docs tests drive the real TypeScript compiler per case, and
    // under vitest 4 a cold compile can exceed the 5s default (observed ~9s on
    // the first case of a file). The work is genuinely slow, not hung, so raise
    // the ceiling rather than let unrelated machine speed decide the result.
    testTimeout: 60_000,
    coverage: {
      reporter: ['text', 'html'],
    },
  },
});

