import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  resolve: {
    // Tests run against SOURCE, not dist/. Each package's `exports` points published
    // consumers at dist/, which does not exist until `npm run build`, and testing a
    // stale build would be worse than testing nothing. tsconfig.json says the same
    // thing to the typechecker through the `nap-source` export condition.
    alias: [
      {
        find: /^@imani\/(nap-[a-z0-9-]+)$/,
        replacement: fileURLToPath(new URL('./packages/$1/src/index.ts', import.meta.url)),
      },
    ],
  },
  test: {
    include: [
      'packages/*/test/**/*.test.ts',
      'examples/*/test/**/*.test.ts',
      // The publishing contract (manifests, release staging, browser safety).
      'scripts/**/*.test.ts',
    ],
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

