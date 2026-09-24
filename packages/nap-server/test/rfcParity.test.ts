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

/** The §25 section, so an interface declared elsewhere in the RFC is not mistaken for one. */
function coreInterfacesSection(): string {
  const doc = readFileSync(RFC, 'utf8');
  const start = doc.indexOf('## 25. Core Library Interfaces');
  const end = doc.indexOf('## 26. Deterministic Error Code Registry');

  expect(start, 'the RFC should have a §25').toBeGreaterThan(-1);
  expect(end, 'the RFC should have a §26 after it').toBeGreaterThan(start);

  return doc.slice(start, end);
}

/**
 * Every interface §25 declares, discovered rather than listed.
 *
 * Listing them by hand is how this check would rot: a new interface added to
 * the RFC would simply never be compared, and the file would keep passing while
 * covering less of the section every year.
 */
function declaredInterfaces(): string[] {
  return [...coreInterfacesSection().matchAll(/^export interface ([A-Za-z]+)/gm)].map(
    (match) => match[1]!
  );
}

/** Pulls a named `export interface` block out of the RFC's fenced TypeScript. */
function rfcInterface(name: string): string {
  const doc = readFileSync(RFC, 'utf8');
  // Matches both `interface X {` and `interface X<T = unknown> {`; anchoring on
  // the brace missed every generic, which is how two of them went unchecked.
  const start = doc.search(new RegExp(`^export interface ${name}[<{ ]`, 'm'));

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
const CORE = resolve(here, '../../nap-core/src/index.ts').replace(/\.ts$/, '.js');

/** Types the RFC lists under §25 that are declared in `@imani/nap-core`. */
const IMPORTS: Record<string, string> = {
  ChallengeRecord: CORE,
  ChallengeState: CORE,
  SessionRecord: CORE,
  VerifyCompleteSuccess: CORE,
  VerifyCompleteFailure: CORE,
};

/**
 * Interfaces taking a type parameter, compared with it applied.
 *
 * `keyof AudienceResolver` on the bare name is a compile error rather than a
 * comparison, so these need instantiating. Excluding them entirely was the
 * first instinct and the wrong one: both had drifted -- wrong method names
 * *and* wrong return types -- and skipping them would have preserved exactly
 * the defect this file exists to find.
 */
const GENERIC = new Set(['AudienceResolver', 'RawBodyExtractor']);

/**
 * Types the RFC's blocks refer to but do not declare inline.
 *
 * Imported wholesale so a block naming one compiles. They are supporting cast:
 * the assertion is always about the interface under test, and a block that
 * referenced something genuinely undeclared would still fail here.
 */
const SUPPORTING_CORE = [
  'ChallengeRecord',
  'ChallengeState',
  'NapErrorCode',
  'SessionRecord',
  'VoucherCredential',
];
const SUPPORTING_SERVER = [
  'OutstandingChallengeFilter',
  'RateLimitKey',
  'RateLimitDecision',
  'RecordChallengeFailureResult',
  'RotateRefreshTokenParams',
];

/**
 * Imports for the types an RFC block names but does not declare inline.
 *
 * The interface under test is excluded, since the block declares it and a
 * duplicate import is a compile error rather than a finding.
 */
function supporting(name: string): string {
  const core = SUPPORTING_CORE.filter((type) => type !== name);
  const server = SUPPORTING_SERVER.filter((type) => type !== name);

  return [
    `import type { ${core.join(', ')} } from '${CORE}';`,
    `import type { ${server.join(', ')} } from '${REAL}';`,
  ].join('\n      ');
}

/** Every §25 interface, minus the resolver checked separately and the generics. */
const NON_GENERIC_INTERFACES = declaredInterfaces().filter(
  (name) => name !== 'AclResolver' && !GENERIC.has(name)
);

describe('the RFC §25 interfaces match the implementation', () => {
  it.each(NON_GENERIC_INTERFACES)(
    'declares the same %s the server actually uses',
    (name) => {
      // Key sets in both directions, plus assignability. The key check is what
      // catches a dropped optional field; assignability catches a retyped or
      // renamed one.
      const diagnostics = typeCheck(`
      import type { ${name} as Real } from '${IMPORTS[name] ?? REAL}';
      ${supporting(name)}

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

  it.each([...GENERIC])('declares the same %s once its type parameter is applied', (name) => {
    const diagnostics = typeCheck(`
      import type { ${name} as RealGeneric } from '${REAL}';

      ${rfcInterface(name)}

      type Real = RealGeneric<{ probe: true }>;
      type FromRfc = ${name}<{ probe: true }>;

      declare const missingFromRfc: Exclude<keyof Real, keyof FromRfc>;
      declare const missingFromImplementation: Exclude<keyof FromRfc, keyof Real>;

      export const rfcIsComplete: never = missingFromRfc;
      export const implementationIsComplete: never = missingFromImplementation;

      declare const fromRfc: FromRfc;
      declare const fromImplementation: Real;

      export const a: Real = fromRfc;
      export const b: FromRfc = fromImplementation;
    `);

    expect(diagnostics).toEqual([]);
  });

  it('still finds the blocks it claims to check', () => {
    // Guards the extractor itself: if §25 were renamed or reformatted, the
    // tests above would silently check an empty string and pass.
    const declared = declaredInterfaces();

    // Every §25 interface is either compared directly, compared as a generic,
    // or is the resolver with its own case. Nothing is quietly skipped.
    expect(declared.length).toBeGreaterThanOrEqual(13);
    expect(new Set([...NON_GENERIC_INTERFACES, ...GENERIC, 'AclResolver'])).toEqual(
      new Set(declared)
    );

    for (const name of declared) {
      expect(rfcInterface(name)).toContain(`export interface ${name}`);
    }
  });
});
