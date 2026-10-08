#!/usr/bin/env node
// Compiles every package to ESM + .d.ts in its own dist/, in dependency order.
//
//   npm run build                    # all packages
//   npm run build -- nap-core        # one package (its dependencies must be built)
//
// Order matters: each package's tsconfig.build.json resolves sibling packages the
// way a consumer would, through `exports` to dist/index.d.ts, so nap-core's
// declarations must exist before nap-client-http is compiled against them.

import { spawnSync } from 'node:child_process';
import { existsSync, rmSync } from 'node:fs';
import { join, relative } from 'node:path';
import { ROOT, workspacePackages } from './packages.mjs';

const only = process.argv.slice(2);
const tsc = join(ROOT, 'node_modules', 'typescript', 'bin', 'tsc');

for (const pkg of workspacePackages()) {
  if (only.length > 0 && !only.includes(pkg.dirName) && !only.includes(pkg.name)) continue;

  const config = join(pkg.dir, 'tsconfig.build.json');
  if (!existsSync(config)) {
    throw new Error(`${pkg.name} has no tsconfig.build.json`);
  }

  rmSync(join(pkg.dir, 'dist'), { recursive: true, force: true });
  process.stdout.write(`build ${pkg.name}\n`);
  const result = spawnSync(process.execPath, [tsc, '-p', relative(ROOT, config)], {
    cwd: ROOT,
    stdio: 'inherit',
  });
  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}
