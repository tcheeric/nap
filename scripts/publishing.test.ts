/**
 * The publishing contract: what every package manifest promises a consumer, and
 * what scripts/release.mjs rewrites on the way to the registry.
 *
 * These run in `npm test`, so a package added without `files`, a sibling pinned
 * to a stale version, or a Node built-in creeping into a browser package fails
 * the PR rather than the release.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { builtinModules } from 'node:module';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
// @ts-expect-error -- plain .mjs, no declarations
import { ROOT, workspacePackages } from './packages.mjs';
// @ts-expect-error -- plain .mjs, no declarations
import { BROWSER_PACKAGES, publishManifest, publishedName } from './release.mjs';

type Manifest = Record<string, any>;
type Pkg = { dir: string; dirName: string; name: string; manifest: Manifest };

const packages: Pkg[] = workspacePackages();
const version: string = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')).version;
const byName = new Map(packages.map((pkg) => [pkg.name, pkg]));

function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((entry) => {
    const path = join(dir, entry);
    return statSync(path).isDirectory() ? sources(path) : /\.tsx?$/.test(path) ? [path] : [];
  });
}

function bareImports(pkg: Pkg): Set<string> {
  const found = new Set<string>();
  for (const file of sources(join(pkg.dir, 'src'))) {
    // Comments drop out first: JSDoc examples quote imports that the module does not make.
    const text = readFileSync(file, 'utf8')
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/^\s*\/\/.*$/gm, '');
    for (const match of text.matchAll(/(?:^|[\s;}])(?:from|import)\s*\(?\s*['"]([^'".][^'"]*)['"]/g)) {
      found.add(match[1]!);
    }
  }
  return found;
}

/** `nostr-tools/nip46` -> `nostr-tools`, `@noble/hashes/sha2.js` -> `@noble/hashes`. */
function packageOf(specifier: string): string {
  const parts = specifier.split('/');
  return specifier.startsWith('@') ? parts.slice(0, 2).join('/') : parts[0]!;
}

describe('workspace order', () => {
  it('puts every package after the packages it depends on', () => {
    const seen = new Set<string>();
    for (const pkg of packages) {
      for (const dep of Object.keys(pkg.manifest.dependencies ?? {})) {
        if (byName.has(dep)) expect(seen, `${pkg.name} before ${dep}`).toContain(dep);
      }
      seen.add(pkg.name);
    }
    expect(packages[0]!.name).toBe('@imani/nap-core');
  });
});

describe.each(packages.map((pkg) => [pkg.name, pkg] as const))('%s manifest', (_name, pkg) => {
  const m = pkg.manifest;

  it('ships only compiled output, as ESM with declarations', () => {
    expect(m.version).toBe(version);
    expect(m.type).toBe('module');
    expect(m.files).toEqual(['dist']);
    expect(m.main).toBe('./dist/index.js');
    expect(m.module).toBe('./dist/index.js');
    expect(m.types).toBe('./dist/index.d.ts');
    expect(m.exports['.']).toMatchObject({
      types: './dist/index.d.ts',
      import: './dist/index.js',
      default: './dist/index.js',
    });
    // `types` must come before `import`/`default`: conditions match in order.
    const keys = Object.keys(m.exports['.']).filter((k) => k !== 'nap-source');
    expect(keys[0]).toBe('types');
    expect(m.sideEffects).toBe(false);
    expect(m.publishConfig).toEqual({ access: 'public' });
  });

  it('depends on sibling packages by a range that includes this version', () => {
    for (const field of ['dependencies', 'devDependencies'] as const) {
      for (const [dep, range] of Object.entries<string>(m[field] ?? {})) {
        if (!dep.startsWith('@imani/nap-')) continue;
        expect(range, `${field}.${dep}`).toBe(`^${version}`);
      }
    }
  });

  it('declares every bare import, and shares nostr-tools, @noble/* and react as peers', () => {
    const declared = {
      ...m.dependencies,
      ...m.peerDependencies,
    };
    const imported = [...bareImports(pkg)]
      .filter((spec) => !spec.startsWith('node:') && !builtinModules.includes(spec))
      .map(packageOf);
    for (const dep of new Set(imported)) {
      expect(declared, `${pkg.name} imports ${dep}`).toHaveProperty(dep);
    }
    for (const dep of new Set(imported)) {
      if (/^(nostr-tools|react|@noble\/)/.test(dep)) {
        expect(m.dependencies ?? {}, `${dep} must be a peer`).not.toHaveProperty(dep);
        expect(m.peerDependencies, `${dep} must be a peer`).toHaveProperty(dep);
        // Peers are not installed by the workspace for the package itself.
        expect(m.devDependencies, `${dep} must be a devDependency too`).toHaveProperty(dep);
      }
    }
  });
});

describe('browser packages', () => {
  it('are exactly the wallet-facing client packages', () => {
    expect(BROWSER_PACKAGES).toEqual([
      '@imani/nap-core',
      '@imani/nap-client-http',
      '@imani/nap-client-web',
      '@imani/nap-client-nip46',
      '@imani/nap-react',
    ]);
  });

  it.each(BROWSER_PACKAGES)('%s imports no Node built-in, and depends only on browser packages', (name: string) => {
    const pkg = byName.get(name)!;
    const builtins = new Set(builtinModules);
    const nodeImports = [...bareImports(pkg)].filter(
      (spec) => spec.startsWith('node:') || builtins.has(packageOf(spec))
    );
    expect(nodeImports).toEqual([]);
    for (const dep of Object.keys(pkg.manifest.dependencies ?? {})) {
      if (dep.startsWith('@imani/nap-')) expect(BROWSER_PACKAGES).toContain(dep);
    }
  });
});

describe('publishManifest', () => {
  const core = byName.get('@imani/nap-core')!.manifest;
  const web = byName.get('@imani/nap-client-web')!.manifest;

  it('renames into the publish scope and aliases siblings so import names survive', () => {
    const out = publishManifest(web, '@398ja');
    expect(out.name).toBe('@398ja/nap-client-web');
    expect(out.dependencies).toEqual({
      '@imani/nap-client-http': `npm:@398ja/nap-client-http@^${version}`,
      '@imani/nap-core': `npm:@398ja/nap-core@^${version}`,
    });
    expect(out.peerDependencies['nostr-tools']).toBe(web.peerDependencies['nostr-tools']);
  });

  it('publishes plain ranges when the scope is the import scope', () => {
    const out = publishManifest(web, '@imani');
    expect(out.name).toBe('@imani/nap-client-web');
    expect(out.dependencies['@imani/nap-core']).toBe(`^${version}`);
  });

  it('strips what only the workspace needs', () => {
    const out = publishManifest(core, '@398ja');
    expect(out.exports['.']).not.toHaveProperty('nap-source');
    expect(out).not.toHaveProperty('devDependencies');
    expect(out).not.toHaveProperty('scripts');
    expect(out.files).toEqual(['dist']);
    expect(out.publishConfig.access).toBe('public');
    // The workspace manifest is untouched.
    expect(core.exports['.']).toHaveProperty('nap-source');
  });

  it('refuses a workspace link in a published manifest', () => {
    const linked = { ...web, dependencies: { '@imani/nap-core': 'workspace:*' } };
    expect(() => publishManifest(linked, '@398ja')).toThrow(/not a version range/);
  });

  it('keeps the MIT licence field', () => {
    for (const pkg of workspacePackages()) {
      expect(pkg.manifest.license, pkg.name).toBe('MIT');
      expect(publishManifest(pkg.manifest, '@398ja').license, pkg.name).toBe('MIT');
    }
    expect(readFileSync(join(ROOT, 'LICENSE'), 'utf8')).toMatch(/^MIT License\n/);
  });

  it('maps only nap packages', () => {
    expect(publishedName('@imani/nap-react', '@398ja')).toBe('@398ja/nap-react');
    expect(publishedName('nostr-tools', '@398ja')).toBe('nostr-tools');
  });
});
