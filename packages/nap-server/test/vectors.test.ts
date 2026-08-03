import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import type { ChallengeRecord } from '@imani/nap-core';
import { utf8Bytes } from '@imani/nap-core';
import {
  InMemoryChallengeStore,
  InMemorySessionStore,
  verifyCompletion,
  type NapServerOptions,
} from '../src/index.js';

const VECTOR_DIR = join(
  dirname(fileURLToPath(import.meta.url)),
  '..',
  '..',
  'nap-core',
  'test-vectors'
);

interface FlowVectors {
  cases: {
    name: string;
    challenge: ChallengeRecord;
    steps: {
      now: number;
      authorization: string;
      request: { method: string; url: string; body: string };
      expect: { ok: boolean; code?: string; same_session_as_step?: number };
    }[];
  }[];
}

const vectors: FlowVectors = JSON.parse(readFileSync(join(VECTOR_DIR, 'flow.json'), 'utf8'));

describe('official test vectors, challenge flow (RFC §20.3)', () => {
  it.each(vectors.cases)('$name', async ({ challenge, steps }) => {
    let now = steps[0].now;
    const challengeStore = new InMemoryChallengeStore();
    await challengeStore.create(challenge);

    const options: NapServerOptions = {
      challengeStore,
      sessionStore: new InMemorySessionStore(),
      aclResolver: {
        async resolve() {
          return { allowed: true, roles: ['member'], permissions: [] };
        },
      },
      minAuthResponseMillis: 0,
      responseJitterMillis: 0,
      clock: { nowUnix: () => now },
    };

    const sessionIds: (string | undefined)[] = [];

    for (const step of steps) {
      now = step.now;
      const outcome = await verifyCompletion(
        {
          authorization: step.authorization,
          method: step.request.method,
          url: step.request.url,
          rawBody: utf8Bytes(step.request.body),
        },
        options
      );

      expect(outcome.ok).toBe(step.expect.ok);

      if (!outcome.ok) {
        expect('code' in outcome && outcome.code).toBe(step.expect.code);
        sessionIds.push(undefined);
        continue;
      }

      sessionIds.push(outcome.session.session_id);

      if (step.expect.same_session_as_step !== undefined) {
        expect(outcome.session.session_id).toBe(sessionIds[step.expect.same_session_as_step]);
      }
    }
  });
});
