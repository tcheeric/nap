import type { Nip98Event } from './types.js';
import { decodeBase64String } from './base64.js';

function isStringArrayArray(value: unknown): value is string[][] {
  return Array.isArray(value) && value.every((entry) => {
    return Array.isArray(entry) && entry.every((part) => typeof part === 'string');
  });
}

export function parseNostrAuthorizationHeader(header?: string): Nip98Event | null {
  if (!header || !header.startsWith('Nostr ')) {
    return null;
  }

  const payload = header.slice('Nostr '.length).trim();

  if (!payload) {
    return null;
  }

  try {
    const decoded = decodeBase64String(payload);
    const parsed = JSON.parse(decoded) as Record<string, unknown>;

    if (
      typeof parsed.id !== 'string' ||
      typeof parsed.pubkey !== 'string' ||
      typeof parsed.created_at !== 'number' ||
      typeof parsed.kind !== 'number' ||
      typeof parsed.content !== 'string' ||
      typeof parsed.sig !== 'string' ||
      !isStringArrayArray(parsed.tags)
    ) {
      return null;
    }

    return {
      id: parsed.id,
      pubkey: parsed.pubkey,
      created_at: parsed.created_at,
      kind: parsed.kind,
      tags: parsed.tags,
      content: parsed.content,
      sig: parsed.sig,
    };
  } catch {
    return null;
  }
}

