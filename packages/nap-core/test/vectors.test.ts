import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { sha256Hex, utf8Bytes, verifyNip98Completion } from '../src/index.js';

const VECTOR_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'test-vectors');

function load<T>(file: string): T {
  return JSON.parse(readFileSync(join(VECTOR_DIR, file), 'utf8')) as T;
}

interface PayloadHashVectors {
  cases: { name: string; body: string; sha256: string }[];
}

interface Nip98Vectors {
  cases: {
    name: string;
    request: { method: string; url: string; body: string };
    now: number;
    authorization: string;
    expect: { ok: boolean; code?: string };
  }[];
}

// The flow vectors need a challenge store and a clock, which live in
// `@imani/nap-server` — a package `nap-core` must not depend on. They are
// exercised by `packages/nap-server/test/vectors.test.ts`; this file covers the
// two files decidable by the core validator alone.
describe('official test vectors (RFC §20.3)', () => {
  const payloadHash = load<PayloadHashVectors>('payload-hash.json');
  const nip98 = load<Nip98Vectors>('nip98.json');

  it.each(payloadHash.cases)('payload hash: $name', ({ body, sha256 }) => {
    expect(sha256Hex(utf8Bytes(body))).toBe(sha256);
  });

  it.each(nip98.cases)('nip98: $name', ({ request, now, authorization, expect: expected }) => {
    const rawBody = utf8Bytes(request.body);
    const outcome = verifyNip98Completion({
      authorization,
      method: request.method,
      url: request.url,
      rawBody,
      body: JSON.parse(request.body),
      now,
    });

    expect(outcome.ok).toBe(expected.ok);

    if (!outcome.ok) {
      expect(outcome.code).toBe(expected.code);
    }
  });
});
