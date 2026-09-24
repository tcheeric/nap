/**
 * Type-checks every documented TypeScript block for this package, read from the
 * documents themselves.
 *
 * `readmeExample.test.ts` runs the wiring, but it is a *hand-copy*: if a
 * document drifts, that test keeps passing and the documentation silently rots.
 * Verifying a snippet by copying it into a test proves the copy compiles, not
 * the document. These read the source files, so drift is caught mechanically.
 *
 * Covers the package README **and integration guide §3.5**, which is the
 * operator-facing account of mint-backed authorisation. That section is the one
 * an integrator actually follows, so a stale call signature there is worse than
 * a stale one in the README.
 *
 * The blocks are illustrative fragments — they reference a `credential`, a
 * `secret`, and so on that a real caller would have in scope — so they are
 * compiled against a small preamble supplying those names. What is checked is
 * what actually rots: the imported names must exist, and every call must match
 * the real signature and argument types.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import ts from 'typescript';
import { describe, expect, it } from 'vitest';

const here = dirname(fileURLToPath(import.meta.url));

/**
 * Every document carrying runnable examples of this package's API, with the
 * minimum number of blocks each must contain. A document that quietly loses its
 * examples would otherwise start passing by checking nothing.
 */
const DOCUMENTED = [
  { label: 'package README', path: resolve(here, '../README.md'), minBlocks: 3 },
  {
    label: 'integration guide §3.5',
    path: resolve(here, '../../../docs/NAP-INTEGRATION-GUIDE.md'),
    minBlocks: 3,
    // The guide documents the whole of NAP; only §3.5 is about this package.
    section: { from: '### 3.5 Mint-backed authorisation', to: '## 4. TypeScript package map' },
  },
] as const;

/** The ambient values the README's fragments assume a caller already has. */
const PREAMBLE = `
import type { DleqProof, MintAllowlist } from '${resolve(here, '../src/index.ts').replace(/\.ts$/, '.js')}';
declare const credential: {
  mint_url: string;
  keyset_id: string;
  amount: number;
  secret: string;
};
declare const secret: string;
declare const C: string;
declare const dleq: DleqProof & { r: string };
`;

/** Narrow a document to one section, when only part of it concerns this package. */
function sliceSection(
  markdown: string,
  section?: { from: string; to: string }
): string {
  if (!section) {
    return markdown;
  }

  const start = markdown.indexOf(section.from);
  const end = markdown.indexOf(section.to, start + 1);

  if (start < 0 || end < 0) {
    // The headings moved or were renamed. Failing loudly beats silently
    // checking an empty string.
    throw new Error(`section '${section.from}' .. '${section.to}' not found`);
  }

  return markdown.slice(start, end);
}

function extractTsBlocks(markdown: string): string[] {
  const blocks: string[] = [];
  const pattern = /```ts\n([\s\S]*?)```/g;
  let match: RegExpExecArray | null;

  while ((match = pattern.exec(markdown)) !== null) {
    blocks.push(match[1]!);
  }

  return blocks;
}

/**
 * Rewrite the package-name import to the source path, so the block is checked
 * against this working tree rather than an installed copy.
 */
function resolveImports(block: string): string {
  const entry = resolve(here, '../src/index.ts').replace(/\.ts$/, '.js');

  return block.replace(/from '@imani\/nap-voucher'/g, `from '${entry}'`);
}

function typeCheck(source: string): ts.Diagnostic[] {
  const fileName = resolve(here, '__readme_block__.ts');
  const host = ts.createCompilerHost({}, true);
  const original = host.getSourceFile.bind(host);

  host.getSourceFile = (name, languageVersion, onError, shouldCreate) =>
    name === fileName
      ? ts.createSourceFile(name, source, languageVersion, true)
      : original(name, languageVersion, onError, shouldCreate);
  host.fileExists = (name) => (name === fileName ? true : ts.sys.fileExists(name));
  host.readFile = (name) => (name === fileName ? source : ts.sys.readFile(name));

  const program = ts.createProgram({
    rootNames: [fileName],
    options: {
      noEmit: true,
      strict: true,
      target: ts.ScriptTarget.ES2022,
      module: ts.ModuleKind.ESNext,
      moduleResolution: ts.ModuleResolutionKind.Bundler,
      skipLibCheck: true,
      // The fragments are illustrative: an unused `strict` binding or a
      // top-level await is not drift. Missing names and wrong argument types
      // are, and those are still errors.
      noUnusedLocals: false,
      allowImportingTsExtensions: true,
    },
    host,
  });

  return [
    ...program.getSemanticDiagnostics(),
    ...program.getSyntacticDiagnostics(),
  ];
}

describe.each(DOCUMENTED)('$label code blocks type-check against the real source', (doc) => {
  const blocks = extractTsBlocks(
    sliceSection(readFileSync(doc.path, 'utf8'), 'section' in doc ? doc.section : undefined)
  );

  it('finds the documented blocks', () => {
    // If a document stops having runnable examples, that is itself a
    // regression worth failing on rather than silently checking nothing.
    expect(blocks.length).toBeGreaterThanOrEqual(doc.minBlocks);
  });

  it.each(blocks.map((block, index) => [index + 1, block] as const))(
    'block %i compiles against the current API',
    (_index, block) => {
      // Only supply `mints` to blocks that do not declare it themselves, so the
      // preamble never collides with the README's own bindings.
      const declaresMints = /\bconst mints\b/.test(block);
      const source = [
        PREAMBLE,
        declaresMints ? '' : 'declare const mints: MintAllowlist;',
        resolveImports(block),
      ].join('\n');
      const errors = typeCheck(source)
        // Top-level await is legal in the ESM this package ships; the harness
        // compiles a standalone file, so ignore only that.
        .filter((diagnostic) => diagnostic.code !== 1378)
        .map((diagnostic) =>
          `TS${diagnostic.code}: ${ts.flattenDiagnosticMessageText(diagnostic.messageText, ' ')}`
        );

      expect(errors).toEqual([]);
    }
  );
});
