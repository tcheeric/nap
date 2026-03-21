import { verifyEvent } from 'nostr-tools';
import { failure } from './errors.js';
import { parseNostrAuthorizationHeader } from './header.js';
import { sha256Hex } from './hash.js';
import type {
  Nip98Event,
  VerifyCompleteFailure,
  VerifiedNip98Completion,
  VerifyNip98CompletionInput,
} from './types.js';
import { exactUrlMatch } from './url.js';

function getSingleTag(event: Nip98Event, tagName: string): string | VerifyCompleteFailure {
  const matches = event.tags.filter((tag) => tag[0] === tagName);

  if (matches.length !== 1 || typeof matches[0]?.[1] !== 'string') {
    if (tagName === 'payload') {
      return failure('NAP_COMPLETE_MISSING_PAYLOAD');
    }

    if (tagName === 'challenge_id') {
      return failure('NAP_COMPLETE_MISSING_CHALLENGE_ID');
    }

    return failure('NAP_COMPLETE_INVALID_EVENT_JSON');
  }

  return matches[0][1];
}

export function validateCreatedAtWindow(
  createdAt: number,
  now: number,
  maxClockSkewSeconds = 60
): true | VerifyCompleteFailure {
  if (Math.abs(now - createdAt) > maxClockSkewSeconds) {
    return failure('NAP_COMPLETE_CREATED_AT_OUT_OF_RANGE');
  }

  return true;
}

export function validateChallengeBoundCreatedAt(
  createdAt: number,
  issuedAt: number,
  expiresAt: number,
  lowerBoundGraceSeconds = 30,
  upperBoundGraceSeconds = 5
): true | VerifyCompleteFailure {
  if (createdAt < issuedAt - lowerBoundGraceSeconds || createdAt > expiresAt + upperBoundGraceSeconds) {
    return failure('NAP_COMPLETE_CREATED_AT_OUT_OF_RANGE');
  }

  return true;
}

export function verifyNip98Completion(
  input: VerifyNip98CompletionInput
): { ok: true; value: VerifiedNip98Completion } | VerifyCompleteFailure {
  if (!input.authorization) {
    return failure('NAP_COMPLETE_MISSING_AUTH_HEADER');
  }

  if (!input.authorization.startsWith('Nostr ')) {
    return failure('NAP_COMPLETE_INVALID_AUTH_SCHEME');
  }

  const event = parseNostrAuthorizationHeader(input.authorization);

  if (!event) {
    return failure('NAP_COMPLETE_INVALID_EVENT_JSON');
  }

  if (event.kind !== 27235) {
    return failure('NAP_COMPLETE_INVALID_KIND');
  }

  if (event.content !== '') {
    return failure('NAP_COMPLETE_INVALID_EVENT_JSON');
  }

  if (!verifyEvent(event)) {
    return failure('NAP_COMPLETE_INVALID_SIGNATURE');
  }

  const timeWindow = validateCreatedAtWindow(
    event.created_at,
    input.now,
    input.maxClockSkewSeconds
  );

  if (timeWindow !== true) {
    return timeWindow;
  }

  const urlTag = getSingleTag(event, 'u');

  if (typeof urlTag !== 'string') {
    return urlTag;
  }

  if (!exactUrlMatch(urlTag, input.url)) {
    return failure('NAP_COMPLETE_URL_MISMATCH');
  }

  const methodTag = getSingleTag(event, 'method');

  if (typeof methodTag !== 'string') {
    return methodTag;
  }

  if (methodTag !== input.method.toUpperCase()) {
    return failure('NAP_COMPLETE_METHOD_MISMATCH');
  }

  const payloadTag = getSingleTag(event, 'payload');

  if (typeof payloadTag !== 'string') {
    return payloadTag;
  }

  if (payloadTag !== sha256Hex(input.rawBody)) {
    return failure('NAP_COMPLETE_PAYLOAD_MISMATCH');
  }

  const challengeIdTag = getSingleTag(event, 'challenge_id');

  if (typeof challengeIdTag !== 'string') {
    return challengeIdTag;
  }

  if (!input.body.challenge_id || challengeIdTag !== input.body.challenge_id) {
    return failure('NAP_COMPLETE_MISSING_CHALLENGE_ID');
  }

  const challengeTag = getSingleTag(event, 'challenge');

  if (typeof challengeTag !== 'string') {
    return failure('NAP_COMPLETE_CHALLENGE_MISMATCH');
  }

  return {
    ok: true,
    value: {
      event,
      challenge: challengeTag,
      challengeId: challengeIdTag,
      payload: payloadTag,
    },
  };
}

