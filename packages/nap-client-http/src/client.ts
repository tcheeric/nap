import { finalizeEvent, type EventTemplate } from 'nostr-tools';
import {
  encodeBase64String,
  hexToBytes,
  sha256Hex,
  utf8Bytes,
  type AuthCompleteRequest,
  type AuthInitResponse,
  type Nip98Event,
} from '@imani/nap-core';

export interface EventSigner {
  signEvent(template: EventTemplate): Promise<Nip98Event>;
}

export interface BuildAuthCompleteRequestInput {
  challenge: AuthInitResponse;
  signer: EventSigner;
  createdAt?: number;
}

export interface BuiltAuthCompleteRequest {
  method: 'POST';
  url: string;
  body: AuthCompleteRequest;
  rawBody: Uint8Array;
  payloadHash: string;
  event: Nip98Event;
  authorization: string;
}

export function serializeAuthCompleteBody(body: AuthCompleteRequest): Uint8Array {
  return utf8Bytes(JSON.stringify(body));
}

export function createPrivateKeySigner(privateKeyHex: string): EventSigner {
  const privateKey = hexToBytes(privateKeyHex);

  return {
    async signEvent(template: EventTemplate): Promise<Nip98Event> {
      return finalizeEvent(template, privateKey);
    },
  };
}

export async function buildAuthCompleteRequest(
  input: BuildAuthCompleteRequestInput
): Promise<BuiltAuthCompleteRequest> {
  const body: AuthCompleteRequest = {
    challenge_id: input.challenge.challenge_id,
  };
  const rawBody = serializeAuthCompleteBody(body);
  const payloadHash = sha256Hex(rawBody);
  const event = await input.signer.signEvent({
    kind: 27235,
    created_at: input.createdAt ?? Math.floor(Date.now() / 1000),
    tags: [
      ['u', input.challenge.auth_url],
      ['method', input.challenge.auth_method],
      ['payload', payloadHash],
      ['challenge', input.challenge.challenge],
      ['challenge_id', input.challenge.challenge_id],
    ],
    content: '',
  });

  return {
    method: input.challenge.auth_method,
    url: input.challenge.auth_url,
    body,
    rawBody,
    payloadHash,
    event,
    authorization: `Nostr ${encodeBase64String(JSON.stringify(event))}`,
  };
}
