const BASE64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

function buildBase64Lookup(): Map<string, number> {
  return new Map(Array.from(BASE64_ALPHABET, (char, index) => [char, index]));
}

const BASE64_LOOKUP = buildBase64Lookup();

export function hexToBytes(hex: string): Uint8Array {
  const normalized = hex.trim().toLowerCase();

  if (normalized.length % 2 !== 0) {
    throw new Error('Hex input must have an even number of characters');
  }

  const bytes = new Uint8Array(normalized.length / 2);

  for (let index = 0; index < normalized.length; index += 2) {
    const value = Number.parseInt(normalized.slice(index, index + 2), 16);

    if (Number.isNaN(value)) {
      throw new Error(`Invalid hex byte at index ${index}`);
    }

    bytes[index / 2] = value;
  }

  return bytes;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('');
}

export function encodeBase64Bytes(bytes: Uint8Array): string {
  let result = '';

  for (let index = 0; index < bytes.length; index += 3) {
    const byte1 = bytes[index] ?? 0;
    const byte2 = bytes[index + 1] ?? 0;
    const byte3 = bytes[index + 2] ?? 0;
    const chunk = (byte1 << 16) | (byte2 << 8) | byte3;

    result += BASE64_ALPHABET[(chunk >> 18) & 63];
    result += BASE64_ALPHABET[(chunk >> 12) & 63];
    result += index + 1 < bytes.length ? BASE64_ALPHABET[(chunk >> 6) & 63] : '=';
    result += index + 2 < bytes.length ? BASE64_ALPHABET[chunk & 63] : '=';
  }

  return result;
}

export function decodeBase64Bytes(value: string): Uint8Array {
  const sanitized = value.replace(/\s+/g, '');

  if (sanitized.length === 0) {
    return new Uint8Array();
  }

  if (sanitized.length % 4 !== 0) {
    throw new Error('Invalid base64 length');
  }

  const padding = sanitized.endsWith('==') ? 2 : sanitized.endsWith('=') ? 1 : 0;
  const output = new Uint8Array((sanitized.length / 4) * 3 - padding);
  let outputIndex = 0;

  for (let index = 0; index < sanitized.length; index += 4) {
    const char1 = sanitized[index];
    const char2 = sanitized[index + 1];
    const char3 = sanitized[index + 2];
    const char4 = sanitized[index + 3];
    const value1 = BASE64_LOOKUP.get(char1);
    const value2 = BASE64_LOOKUP.get(char2);
    const value3 = char3 === '=' ? 0 : BASE64_LOOKUP.get(char3);
    const value4 = char4 === '=' ? 0 : BASE64_LOOKUP.get(char4);

    if (
      value1 === undefined ||
      value2 === undefined ||
      (char3 !== '=' && value3 === undefined) ||
      (char4 !== '=' && value4 === undefined)
    ) {
      throw new Error('Invalid base64 character');
    }

    const chunk = (value1 << 18) | (value2 << 12) | ((value3 ?? 0) << 6) | (value4 ?? 0);
    output[outputIndex] = (chunk >> 16) & 255;
    outputIndex += 1;

    if (char3 !== '=') {
      output[outputIndex] = (chunk >> 8) & 255;
      outputIndex += 1;
    }

    if (char4 !== '=') {
      output[outputIndex] = chunk & 255;
      outputIndex += 1;
    }
  }

  return output;
}

export function encodeBase64UrlBytes(bytes: Uint8Array): string {
  return encodeBase64Bytes(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
