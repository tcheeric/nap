import { decodeBase64Bytes, encodeBase64Bytes } from './codec.js';

export function encodeBase64String(value: string): string {
  return encodeBase64Bytes(new TextEncoder().encode(value));
}

export function decodeBase64String(value: string): string {
  return new TextDecoder().decode(decodeBase64Bytes(value));
}
