import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';
import { describe, expect, it } from 'vitest';

const here = dirname(fileURLToPath(import.meta.url));
const RFC = resolve(here, '../../../docs/NAP-v2-RFC.md');

/**
 * The RFC's §25 interface listing, checked against the real types.
 *
 * §25 is the normative description of what an implementation must expose, and
 * it is the document another implementation reads to build a compatible one.
 * Nothing verified it. Both `doccheck` and `docsTypecheck` skip it: the former
 * checks links and class references, the latter covers the README and the
 * integration guide.
 *
 * That gap let two real defects through in a single session:
 *
 * - `AclDecision` in §25.3 listed three fields while the type had five.
 *   `revoke_sessions` had been missing for some time; `expires_at` was added
 *   and not mirrored. An implementer following the RFC would have built a
 *   resolver that cannot revoke sessions or bound one.
 * - `AclResolver.resolve` was documented with two parameters after gaining an
 *   optional third.
 *
 * The check is **structural rather than textual**. Comparing prose would fail on
 * a reworded comment, which trains everyone to update the fixture without
 * reading it.
 *
 * It compares **key sets**, not assignability. Assignability was the obvious
 * approach and is useless here: an interface missing an optional field is still
 * assignable in both directions, so a two-field RFC and a five-field type look
 * identical to it. Verified by deleting `expires_at` from the RFC and watching
 * an assignability-based version pass. Since every field this drifted on was
 * optional, that version would have caught nothing it was written for.
 */

/** Pulls a named `export interface` block out of the RFC's fenced TypeScript. */
function rfcInterface(name: string): string {
  const doc = readFileSync(RFC, 'utf8');
  const start = doc.indexOf(`export interface ${name} {`);

  expect(start, `the RFC should declare ${name}`).toBeGreaterThan(-1);

  // Interfaces here are one level deep, so the first line that is exactly '}'
  // closes the block.
  const end = doc.indexOf('\n}', start);

  expect(end, `${name} should be a closed block`).toBeGreaterThan(start);

  return doc.slice(start, end + 2);
}

/**
 * Type-checks a snippet against the real source, returning diagnostics.
 *
 * Mirrors the approach in `nap-voucher/test/docsTypecheck.test.ts`, against the
 * server's own types rather than the voucher package's.
 */
function typeCheck(source: string): string[] {
  const fileName = resolve(here, '__rfc_parity__.ts');
  const host = ts.createCompilerHost({});
  const original = host.getSourceFile.bind(host);

  host.getSourceFile = (name, languageVersion, onError, shouldCreate) =>
    name === fileName
      ? ts.createSourceFile(name, source, languageVersion, true)
      : original(name, languageVersion, onError, shouldCreate);

  host.fileExists = (name) => (name === fileName ? true : ts.sys.fileExists(name));
  host.readFile = (name) => (name === fileName ? source : ts.sys.readFile(name));

  const program = ts.createProgram([fileName], {
    noEmit: true,
    strict: true,
    skipLibCheck: true,
    target: ts.ScriptTarget.ES2022,
    module: ts.ModuleKind.ESNext,
    moduleResolution: ts.ModuleResolutionKind.Bundler,
  }, host);

  return ts
    .getPreEmitDiagnostics(program)
    .filter((diagnostic) => diagnostic.file?.fileName === fileName)
    .map(
      (diagnostic) =>
        `TS${diagnostic.code}: ${ts.flattenDiagnosticMessageText(diagnostic.messageText, ' ')}`
    );
}

const REAL = resolve(here, '../src/index.ts').replace(/\.ts$/, '.js');

describe('the RFC §25 interfaces match the implementation', () => {
  it.each(['AclDecision', 'AclResolutionContext'])(
    'declares the same %s the server actually uses',
    (name) => {
      // Key sets in both directions, plus assignability. The key check is what
      // catches a dropped optional field; assignability catches a retyped or
      // renamed one.
      const diagnostics = typeCheck(`
      import type { ${name} as Real, VoucherCredential } from '${REAL}';

      ${rfcInterface(name)}

      // Assigning the key difference to \`never\` is what makes this bite. The
      // obvious \`const x: Diff[] = [] as never[]\` compiles whatever Diff is,
      // because never[] is assignable to every array -- a vacuous check that
      // passed against a deliberately drifted RFC. This form fails, and the
      // error names the drifted field.
      declare const missingFromRfc: Exclude<keyof Real, keyof ${name}>;
      declare const missingFromImplementation: Exclude<keyof ${name}, keyof Real>;

      export const rfcIsComplete: never = missingFromRfc;
      export const implementationIsComplete: never = missingFromImplementation;

      declare const fromRfc: ${name};
      declare const fromImplementation: Real;

      export const a: Real = fromRfc;
      export const b: ${name} = fromImplementation;
    `);

      expect(diagnostics).toEqual([]);
    }
  );

  it('declares an AclResolver the real one satisfies', () => {
    // One direction only, and deliberately. A resolver written against the RFC
    // must be usable where the implementation expects one; the reverse would
    // forbid the implementation from ever widening the signature additively,
    // which is exactly what extension 0001 did.
    const diagnostics = typeCheck(`
      import type { AclResolver as Real, VoucherCredential } from '${REAL}';

      ${rfcInterface('AclDecision')}

      ${rfcInterface('AclResolutionContext')}

      ${rfcInterface('AclResolver')}

      declare const writtenAgainstTheRfc: AclResolver;

      export const usable: Real = writtenAgainstTheRfc;

      // Assignability alone would accept a two-parameter RFC signature, since a
      // function taking fewer arguments is assignable to one taking more. So
      // the parameter list is compared directly.
      type RfcParams = Parameters<AclResolver['resolve']>;
      type RealParams = Parameters<Real['resolve']>;

      export const sameArity: RfcParams = [] as unknown as RealParams;
      export const sameArityBack: RealParams = [] as unknown as RfcParams;
    `);

    expect(diagnostics).toEqual([]);
  });

  it('still finds the blocks it claims to check', () => {
    // Guards the extractor itself: if §25 were renamed or reformatted, the
    // tests above would silently check an empty string and pass.
    for (const name of ['AclDecision', 'AclResolutionContext', 'AclResolver']) {
      expect(rfcInterface(name)).toContain(`export interface ${name} {`);
    }
  });
});
