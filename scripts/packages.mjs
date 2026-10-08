// The publishable workspace packages, in dependency order.
//
// Shared by scripts/build.mjs and scripts/release.mjs so that the order a package
// is compiled in and the order it is published in can never disagree: both must
// put nap-core before anything that imports it, or a consumer installing in the
// window between two publishes resolves a dependency that does not exist yet.

import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
export const PACKAGES_DIR = join(ROOT, 'packages');

/** The name every package is imported by, whatever registry scope it ships under. */
export const SOURCE_SCOPE = '@imani';

export function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

/** Every workspace package under packages/, sorted so dependencies come first. */
export function workspacePackages() {
  const all = readdirSync(PACKAGES_DIR, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => {
      const dir = join(PACKAGES_DIR, entry.name);
      const manifest = readJson(join(dir, 'package.json'));
      return { dir, dirName: entry.name, name: manifest.name, manifest };
    });

  const byName = new Map(all.map((pkg) => [pkg.name, pkg]));
  const ordered = [];
  const state = new Map();

  const visit = (pkg, trail) => {
    if (state.get(pkg.name) === 'done') return;
    if (state.get(pkg.name) === 'visiting') {
      throw new Error(`dependency cycle: ${[...trail, pkg.name].join(' -> ')}`);
    }
    state.set(pkg.name, 'visiting');
    // Runtime and peer edges only. devDependencies do not constrain publish order
    // (nap-voucher's tests import nap-server, but nap-voucher itself does not).
    const deps = {
      ...pkg.manifest.dependencies,
      ...pkg.manifest.peerDependencies,
    };
    for (const dep of Object.keys(deps).sort()) {
      const internal = byName.get(dep);
      if (internal) visit(internal, [...trail, pkg.name]);
    }
    state.set(pkg.name, 'done');
    ordered.push(pkg);
  };

  for (const pkg of [...all].sort((a, b) => a.name.localeCompare(b.name))) {
    visit(pkg, []);
  }
  return ordered;
}

export function isInternal(name) {
  return name.startsWith(`${SOURCE_SCOPE}/nap-`);
}
