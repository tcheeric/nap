import { finalizeEvent, type EventTemplate } from 'nostr-tools';
import {
  encodeBase64String,
  hexToBytes,
  sha256Hex,
  utf8Bytes,
  type AuthCompleteRequest,
  type VoucherCredential,
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
  /**
   * Ask for a step-up token on the resulting session.
   *
   * Goes in the body, so it is covered by the `payload` hash and cannot be
   * added or stripped in transit — unlike a `?step_up=true` query parameter,
   * which the signed `u` tag does not cover.
   */
  stepUp?: boolean;
  /**
   * A voucher to present as this session's authorization (extension 0001).
   *
   * Goes in the body for the same reason `stepUp` does, and with more at stake:
   * the `payload` hash covers it, so a credential swapped in transit changes
   * the hash and the completion fails with `NAP_COMPLETE_PAYLOAD_MISMATCH`.
   *
   * The event must be signed by the key the voucher is P2PK-locked to. That
   * equality is what makes a stolen voucher useless, so pass the signer for `K`
   * rather than the holder's identity key.
   */
  voucher?: VoucherCredential;
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
    ...(input.stepUp ? { step_up: true } : {}),
    ...(input.voucher ? { voucher: input.voucher } : {}),
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
