#!/usr/bin/env node
// Builds, tests and publishes every package in dependency order.
//
//   npm run release -- --dry-run         # everything except the upload (npm publish --dry-run)
//   npm run release                       # the real thing; needs `npm whoami` to succeed
//   npm run release:pack                  # stage + `npm pack` into .release/tarballs, no publish
//
// Options (flags or environment):
//   --scope <@scope>    NAP_SCOPE       registry scope to publish under (default @398ja)
//   --registry <url>    NAP_REGISTRY    registry to publish to (default: npm's configured one)
//   --tag <dist-tag>    NAP_DIST_TAG    dist-tag (default latest)
//   --dry-run                           npm publish --dry-run for each package
//   --pack                              npm pack each staged package into .release/tarballs
//   --skip-checks                       skip typecheck + tests (CI runs them as their own step)
//   --allow-dirty                       publish from a dirty working tree (never for a real release)
//
// THE SCOPE IS ONE VARIABLE. Source, tests and the compiled dist/ always use the
// `@imani/nap-*` import names. When the scope is anything else, each package is
// published as `<scope>/nap-*`, and its dependencies on sibling packages are written
// as npm aliases that KEEP the import name:
//
//     "@imani/nap-core": "npm:@398ja/nap-core@^0.12.0"
//
// so the published JavaScript needs no rewriting, and a consumer that declares the
// same aliases gets exactly one copy of each package: its own alias and the
// transitive one land on the same node_modules/@imani/nap-* path. With
// `--scope @imani` the aliases disappear and the manifests are plain.
//
// Nothing here edits the workspace: each package is staged into .release/<dir>
// (package.json rewritten, dist/, README) and published from there.

import { spawnSync } from 'node:child_process';
import { builtinModules } from 'node:module';
import {
  cpSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { join } from 'node:path';
import { ROOT, SOURCE_SCOPE, isInternal, readJson, workspacePackages } from './packages.mjs';

/** Packages the browser loads. They must not import a Node built-in. */
export const BROWSER_PACKAGES = [
  '@imani/nap-core',
  '@imani/nap-client-http',
  '@imani/nap-client-web',
  '@imani/nap-client-nip46',
  '@imani/nap-react',
];

const RELEASE_DIR = join(ROOT, '.release');
const TARBALL_DIR = join(RELEASE_DIR, 'tarballs');

function parseArgs(argv) {
  const opts = {
    scope: process.env.NAP_SCOPE || '@398ja',
    registry: process.env.NAP_REGISTRY || '',
    tag: process.env.NAP_DIST_TAG || 'latest',
    dryRun: false,
    pack: false,
    skipChecks: false,
    allowDirty: false,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const value = () => {
      const next = argv[i + 1];
      if (!next || next.startsWith('--')) throw new Error(`${arg} needs a value`);
      i += 1;
      return next;
    };
    if (arg === '--scope') opts.scope = value();
    else if (arg === '--registry') opts.registry = value();
    else if (arg === '--tag') opts.tag = value();
    else if (arg === '--dry-run') opts.dryRun = true;
    else if (arg === '--pack') opts.pack = true;
    else if (arg === '--skip-checks') opts.skipChecks = true;
    else if (arg === '--allow-dirty') opts.allowDirty = true;
    else throw new Error(`unknown option ${arg}`);
  }
  if (!/^@[a-z0-9][a-z0-9-._]*$/.test(opts.scope)) {
    throw new Error(`--scope must look like @name, got ${opts.scope}`);
  }
  return opts;
}

function run(cmd, args, options = {}) {
  process.stdout.write(`$ ${[cmd, ...args].join(' ')}\n`);
  const result = spawnSync(cmd, args, { cwd: ROOT, stdio: 'inherit', ...options });
  if (result.status !== 0) {
    throw new Error(`${cmd} ${args.join(' ')} exited with ${result.status}`);
  }
}

function capture(cmd, args, options = {}) {
  const result = spawnSync(cmd, args, { cwd: ROOT, encoding: 'utf8', ...options });
  return { status: result.status, stdout: (result.stdout ?? '').trim(), stderr: result.stderr ?? '' };
}

/** `@imani/nap-core` -> `@398ja/nap-core`. */
export function publishedName(name, scope) {
  return isInternal(name) ? `${scope}/${name.slice(SOURCE_SCOPE.length + 1)}` : name;
}

/** The manifest as it goes to the registry. Pure, so it is unit-testable. */
export function publishManifest(manifest, scope) {
  const out = structuredClone(manifest);
  out.name = publishedName(manifest.name, scope);

  for (const field of ['dependencies', 'peerDependencies', 'optionalDependencies']) {
    const deps = out[field];
    if (!deps) continue;
    for (const [dep, range] of Object.entries(deps)) {
      if (!isInternal(dep)) continue;
      if (range.startsWith('workspace:') || range.startsWith('file:') || range === '*') {
        throw new Error(`${manifest.name}: ${field}.${dep} is "${range}", not a version range`);
      }
      deps[dep] = scope === SOURCE_SCOPE ? range : `npm:${publishedName(dep, scope)}@${range}`;
    }
  }

  // The `nap-source` condition points at src/, which is not shipped. It exists so the
  // workspace's own typecheck and tests read sources; a consumer must never see it.
  for (const entry of Object.values(out.exports ?? {})) {
    if (entry && typeof entry === 'object') delete entry['nap-source'];
  }

  // Development-only fields, and devDependencies that name sibling packages by their
  // workspace name, mean nothing to a consumer.
  delete out.devDependencies;
  delete out.scripts;
  out.publishConfig = { ...(out.publishConfig ?? {}), access: 'public' };
  return out;
}

function assertCleanTree(opts) {
  if (opts.allowDirty) return;
  const status = capture('git', ['status', '--porcelain']);
  if (status.status !== 0) throw new Error('git status failed');
  if (status.stdout) {
    throw new Error(`working tree is dirty; commit first or pass --allow-dirty\n${status.stdout}`);
  }
}

function assertVersions(packages) {
  const version = readJson(join(ROOT, 'package.json')).version;
  for (const pkg of packages) {
    if (pkg.manifest.version !== version) {
      throw new Error(`${pkg.name} is ${pkg.manifest.version}, the workspace is ${version}`);
    }
  }
  return version;
}

function walk(dir) {
  return readdirSync(dir).flatMap((entry) => {
    const path = join(dir, entry);
    return statSync(path).isDirectory() ? walk(path) : [path];
  });
}

/** No browser package may reach a Node built-in, directly in its compiled output. */
export function nodeBuiltinImports(distDir) {
  const builtins = new Set(builtinModules.flatMap((m) => [m, `node:${m}`]));
  const found = [];
  for (const file of walk(distDir).filter((f) => f.endsWith('.js'))) {
    const source = readFileSync(file, 'utf8');
    for (const match of source.matchAll(/(?:from\s*|import\s*\(\s*|import\s+|require\s*\(\s*)['"]([^'"]+)['"]/g)) {
      const spec = match[1];
      if (builtins.has(spec) || spec.startsWith('node:')) found.push(`${file}: ${spec}`);
    }
  }
  return found;
}

function stage(pkg, scope) {
  const dist = join(pkg.dir, 'dist');
  if (!existsSync(join(dist, 'index.js')) || !existsSync(join(dist, 'index.d.ts'))) {
    throw new Error(`${pkg.name}: dist/ is missing; run npm run build`);
  }
  if (BROWSER_PACKAGES.includes(pkg.name)) {
    const hits = nodeBuiltinImports(dist);
    if (hits.length > 0) {
      throw new Error(`${pkg.name} is loaded by browsers but imports Node built-ins:\n${hits.join('\n')}`);
    }
  }

  const out = join(RELEASE_DIR, pkg.dirName);
  rmSync(out, { recursive: true, force: true });
  mkdirSync(out, { recursive: true });
  cpSync(dist, join(out, 'dist'), { recursive: true });
  // README is always packed by npm; anything else would be dropped by `files: ["dist"]`.
  if (existsSync(join(pkg.dir, 'README.md'))) cpSync(join(pkg.dir, 'README.md'), join(out, 'README.md'));
  writeFileSync(join(out, 'package.json'), `${JSON.stringify(publishManifest(pkg.manifest, scope), null, 2)}\n`);
  return out;
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  const packages = workspacePackages();
  const version = assertVersions(packages);
  const registryArgs = opts.registry ? ['--registry', opts.registry] : [];

  process.stdout.write(
    `nap ${version}: ${packages.length} packages as ${opts.scope}/nap-*` +
      `${opts.dryRun ? ' (dry run)' : ''}${opts.pack ? ' (pack only)' : ''}\n` +
      `order: ${packages.map((p) => p.dirName).join(' -> ')}\n`
  );

  const publishing = !opts.dryRun && !opts.pack;
  if (publishing) {
    assertCleanTree(opts);
    const who = capture('npm', ['whoami', ...registryArgs]);
    if (who.status !== 0) {
      throw new Error('npm is not authenticated for this registry (npm whoami failed); log in or set NODE_AUTH_TOKEN');
    }
    process.stdout.write(`publishing as ${who.stdout}\n`);
  }

  if (!opts.skipChecks) {
    run('npm', ['run', 'typecheck']);
    run('npm', ['test']);
  }
  run(process.execPath, [join(ROOT, 'scripts', 'build.mjs')]);

  rmSync(RELEASE_DIR, { recursive: true, force: true });
  const staged = packages.map((pkg) => ({ pkg, dir: stage(pkg, opts.scope) }));

  if (opts.pack) mkdirSync(TARBALL_DIR, { recursive: true });

  for (const { pkg, dir } of staged) {
    const name = publishedName(pkg.name, opts.scope);
    if (opts.pack) {
      run('npm', ['pack', '--pack-destination', TARBALL_DIR], { cwd: dir });
      continue;
    }
    if (publishing) {
      const existing = capture('npm', ['view', `${name}@${version}`, 'version', ...registryArgs]);
      if (existing.status === 0 && existing.stdout === version) {
        // Re-running after a partial failure must resume, not fail on the first
        // package that already made it.
        process.stdout.write(`skip ${name}@${version}: already published\n`);
        continue;
      }
    }
    run(
      'npm',
      ['publish', '--access', 'public', '--tag', opts.tag, ...(opts.dryRun ? ['--dry-run'] : []), ...registryArgs],
      { cwd: dir }
    );
  }

  process.stdout.write(
    opts.pack
      ? `tarballs in ${TARBALL_DIR}\n`
      : `${opts.dryRun ? 'dry run complete' : 'published'}: ${staged.map(({ pkg }) => `${publishedName(pkg.name, opts.scope)}@${version}`).join(', ')}\n`
  );
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`release: ${error.message}\n`);
    process.exit(1);
  }
}
