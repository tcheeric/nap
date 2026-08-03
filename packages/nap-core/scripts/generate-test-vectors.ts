/**
 * Regenerates `packages/nap-core/test-vectors/` (RFC §20.3).
 *
 * Run with `npx tsx packages/nap-core/scripts/generate-test-vectors.ts`. Every
 * input is fixed — keys, timestamps, challenge strings — so a regeneration that
 * changes a byte means a behavioural change, and the diff is the review.
 *
 * The vectors are consumed by `packages/nap-core/test/vectors.test.ts` here and
 * by the JVM implementation in the `nap-java` repository. Adding a case means
 * adding it to both consumers, not just this file.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { finalizeEvent, getPublicKey, nip19 } from 'nostr-tools';
import { encodeBase64String, hexToBytes, sha256Hex, utf8Bytes } from '../src/index.js';

const OUT_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'test-vectors');

const AUTH_URL = 'https://api.example.com/auth/complete';
const NOW = 1_710_000_000;

/** Principal the challenges are issued to. */
const KEY_A = '1111111111111111111111111111111111111111111111111111111111111111';
/** A different principal, for the pubkey/npub mismatch case. */
const KEY_B = '2222222222222222222222222222222222222222222222222222222222222222';

const PUBKEY_A = getPublicKey(hexToBytes(KEY_A));
const PUBKEY_B = getPublicKey(hexToBytes(KEY_B));
const NPUB_A = nip19.npubEncode(PUBKEY_A);

const CHALLENGE_ID = 'chal-0000000000000000';
const CHALLENGE = 'Zm9yLXRlc3QtdmVjdG9ycy1vbmx5LW5vdC1yYW5kb20';
const BODY = JSON.stringify({ challenge_id: CHALLENGE_ID });

function authorizationFor(
  privateKeyHex: string,
  tags: string[][],
  opts: { createdAt?: number; content?: string } = {}
): string {
  const event = finalizeEvent(
    {
      kind: 27235,
      created_at: opts.createdAt ?? NOW,
      tags,
      content: opts.content ?? '',
    },
    hexToBytes(privateKeyHex)
  );

  return `Nostr ${encodeBase64String(JSON.stringify(event))}`;
}

/** The tag set a well-formed completion carries, before any case mangles it. */
function baseTags(overrides: Partial<Record<string, string>> = {}): string[][] {
  const values: Record<string, string> = {
    u: AUTH_URL,
    method: 'POST',
    payload: sha256Hex(utf8Bytes(BODY)),
    challenge: CHALLENGE,
    challenge_id: CHALLENGE_ID,
    ...overrides,
  };

  return Object.entries(values).map(([name, value]) => [name, value]);
}

const request = { method: 'POST', url: AUTH_URL, body: BODY };

const payloadHash = {
  description:
    'sha256 of the raw request body, hex-encoded — the value of the NIP-98 `payload` tag. ' +
    'Hash the bytes as received; never a reserialized copy.',
  cases: [
    { name: 'empty-body', body: '', sha256: sha256Hex(utf8Bytes('')) },
    { name: 'completion-body', body: BODY, sha256: sha256Hex(utf8Bytes(BODY)) },
    {
      name: 'whitespace-is-significant',
      body: '{ "challenge_id": "chal-0000000000000000" }',
      sha256: sha256Hex(utf8Bytes('{ "challenge_id": "chal-0000000000000000" }')),
    },
    {
      name: 'non-ascii-utf8',
      body: JSON.stringify({ note: 'ünïcödé — ☕' }),
      sha256: sha256Hex(utf8Bytes(JSON.stringify({ note: 'ünïcödé — ☕' }))),
    },
  ],
};

const nip98 = {
  description:
    'Cases decided by the NIP-98 header validator alone, with no challenge store involved. ' +
    'Feed `authorization`, `request`, and `now` to the validator and compare the outcome.',
  cases: [
    {
      name: 'exact-url-match/accepted',
      rfc: '§20.3 exact URL matching',
      description: 'The signed `u` tag is byte-identical to the URL the server computed.',
      now: NOW,
      authorization: authorizationFor(KEY_A, baseTags()),
      request,
      expect: { ok: true },
    },
    {
      name: 'exact-url-match/different-host',
      rfc: '§20.3 exact URL matching',
      description: 'A proof signed for another host is not a proof for this one.',
      now: NOW,
      authorization: authorizationFor(KEY_A, baseTags({ u: 'https://evil.example.com/auth/complete' })),
      request,
      expect: { ok: false, code: 'NAP_COMPLETE_URL_MISMATCH' },
    },
    {
      name: 'exact-url-match/trailing-slash',
      rfc: '§20.3 exact URL matching',
      description:
        'Matching is exact, not normalising: a trailing slash is a different URL. ' +
        'An implementation that canonicalises paths will wrongly accept this.',
      now: NOW,
      authorization: authorizationFor(KEY_A, baseTags({ u: `${AUTH_URL}/` })),
      request,
      expect: { ok: false, code: 'NAP_COMPLETE_URL_MISMATCH' },
    },
    {
      name: 'exact-url-match/query-string-appended',
      rfc: '§20.3 exact URL matching',
      description: 'A query string the server did not compute is a mismatch, not a detail to strip.',
      now: NOW,
      authorization: authorizationFor(KEY_A, baseTags({ u: `${AUTH_URL}?x=1` })),
      request,
      expect: { ok: false, code: 'NAP_COMPLETE_URL_MISMATCH' },
    },
    {
      name: 'payload-hash/mismatch',
      rfc: '§20.3 payload hash generation',
      description:
        'The body was altered — or reserialized — after signing. This is what a global JSON ' +
        'body parser in front of the NAP router produces.',
      now: NOW,
      authorization: authorizationFor(KEY_A, baseTags({ payload: sha256Hex(utf8Bytes('{}')) })),
      request,
      expect: { ok: false, code: 'NAP_COMPLETE_PAYLOAD_MISMATCH' },
    },
    {
      name: 'duplicate-tag/u',
      rfc: '§20.3 duplicate tag rejection',
      description:
        'Two `u` tags: rejected outright rather than resolved by picking one. Picking the first ' +
        'or the last lets a signer present one audience to the verifier and another to a reader.',
      now: NOW,
      authorization: authorizationFor(KEY_A, [...baseTags(), ['u', 'https://evil.example.com/auth/complete']]),
      request,
      expect: { ok: false, code: 'NAP_COMPLETE_INVALID_EVENT_JSON' },
    },
    {
      name: 'duplicate-tag/payload',
      rfc: '§20.3 duplicate tag rejection',
      description: 'Two `payload` tags, one of which hashes the body actually sent.',
      now: NOW,
      authorization: authorizationFor(KEY_A, [...baseTags({ payload: sha256Hex(utf8Bytes('{}')) }), ['payload', sha256Hex(utf8Bytes(BODY))]]),
      request,
      expect: { ok: false, code: 'NAP_COMPLETE_MISSING_PAYLOAD' },
    },
    {
      name: 'duplicate-tag/challenge-id',
      rfc: '§20.3 duplicate tag rejection',
      description: 'Two `challenge_id` tags, one of which matches the body.',
      now: NOW,
      authorization: authorizationFor(KEY_A, [...baseTags(), ['challenge_id', 'chal-1111111111111111']]),
      request,
      expect: { ok: false, code: 'NAP_COMPLETE_MISSING_CHALLENGE_ID' },
    },
  ],
};

/** The challenge row a flow vector seeds its store with. */
function challengeRecord(overrides: Record<string, unknown> = {}) {
  return {
    challenge_id: CHALLENGE_ID,
    challenge: CHALLENGE,
    npub: NPUB_A,
    pubkey: PUBKEY_A,
    auth_url: AUTH_URL,
    auth_method: 'POST',
    issued_at: NOW - 30,
    expires_at: NOW + 30,
    state: 'issued',
    ...overrides,
  };
}

const flow = {
  description:
    'Cases that need challenge state. Seed the challenge store with `challenge`, set the clock to ' +
    'each step\'s `now`, and run the steps in order against one server instance. ' +
    '`same_session_as_step` on an expected result names the earlier step whose session it must equal.',
  cases: [
    {
      name: 'expired-challenge',
      rfc: '§20.3 expired challenge rejection',
      description:
        'The challenge expired 10 seconds ago while the signature is still inside the clock-skew ' +
        'window — so this reaches the expiry check rather than failing earlier on `created_at`.',
      challenge: challengeRecord({ issued_at: NOW - 40, expires_at: NOW - 10 }),
      steps: [
        {
          now: NOW,
          authorization: authorizationFor(KEY_A, baseTags(), { createdAt: NOW - 35 }),
          request,
          expect: { ok: false, code: 'NAP_COMPLETE_EXPIRED_CHALLENGE' },
        },
      ],
    },
    {
      name: 'retry-same-completion',
      rfc: '§20.3 retrying the same valid completion request',
      description:
        'A retried completion returns the session the first attempt minted, rather than a second ' +
        'session or a replay error (RFC §13.3). Both steps send byte-identical requests.',
      challenge: challengeRecord(),
      steps: [
        { now: NOW, authorization: authorizationFor(KEY_A, baseTags()), request, expect: { ok: true } },
        {
          now: NOW + 1,
          authorization: authorizationFor(KEY_A, baseTags()),
          request,
          expect: { ok: true, same_session_as_step: 0 },
        },
      ],
    },
    {
      name: 'pubkey-npub-mismatch',
      rfc: '§20.3 pubkey/npub mismatch',
      description:
        'The challenge was issued to key A; the proof is signed by key B. The proof is valid — it ' +
        'just proves the wrong key. Rejected before any failure budget is spent, because a ' +
        '`challenge_id` is not a secret and burning a victim\'s challenge must not be free.',
      challenge: challengeRecord(),
      steps: [
        {
          now: NOW,
          authorization: authorizationFor(KEY_B, baseTags()),
          request,
          expect: { ok: false, code: 'NAP_COMPLETE_PRINCIPAL_MISMATCH' },
        },
      ],
    },
  ],
};

const index = {
  version: 1,
  rfc: 'docs/NAP-v2-RFC.md §20.3',
  generator: 'packages/nap-core/scripts/generate-test-vectors.ts',
  principals: {
    a: { private_key: KEY_A, pubkey: PUBKEY_A, npub: NPUB_A },
    b: { private_key: KEY_B, pubkey: PUBKEY_B, npub: nip19.npubEncode(PUBKEY_B) },
  },
  files: [
    { file: 'payload-hash.json', covers: 'payload hash generation' },
    { file: 'nip98.json', covers: 'exact URL matching, payload hash generation, duplicate tag rejection' },
    { file: 'flow.json', covers: 'expired challenge rejection, retrying the same valid completion, pubkey/npub mismatch' },
  ],
};

mkdirSync(OUT_DIR, { recursive: true });

for (const [file, value] of [
  ['index.json', index],
  ['payload-hash.json', payloadHash],
  ['nip98.json', nip98],
  ['flow.json', flow],
] as const) {
  writeFileSync(join(OUT_DIR, file), `${JSON.stringify(value, null, 2)}\n`);
  process.stdout.write(`wrote test-vectors/${file}\n`);
}
