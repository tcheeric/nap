import { createHash } from 'node:crypto';

export function utf8Bytes(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

export function sha256Hex(value: Uint8Array): string {
  return createHash('sha256').update(value).digest('hex');
}

