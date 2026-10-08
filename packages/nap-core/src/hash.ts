// `sha2.js`, not `sha256`: the bare `sha256` subpath exists only in @noble/hashes 1.x,
// and @noble/hashes is a peer dependency that may resolve to 2.x in the consumer.
// `sha2.js` is exported by both majors.
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from './codec.js';

export function utf8Bytes(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

export function sha256Hex(value: Uint8Array): string {
  return bytesToHex(sha256(value));
}
