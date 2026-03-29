import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from './codec.js';

export function utf8Bytes(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

export function sha256Hex(value: Uint8Array): string {
  return bytesToHex(sha256(value));
}
