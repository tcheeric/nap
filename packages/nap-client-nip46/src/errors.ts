export type Nip46ErrorCode =
  | 'INVALID_TOKEN'
  | 'UNREACHABLE'
  | 'TIMEOUT'
  | 'DECLINED'
  | 'SECRET_MISMATCH'
  | 'PROVIDER_ERROR';

/**
 * Every failure a remote signer can produce, as its own code.
 *
 * The point is the same as the NIP-07 taxonomy: "the signer said no" and "the
 * signer never answered" call for different UI, and collapsing them into a bare
 * Error leaves an integrator guessing.
 */
export class Nip46Error extends Error {
  readonly code: Nip46ErrorCode;

  constructor(code: Nip46ErrorCode, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'Nip46Error';
    this.code = code;
  }
}

const DECLINED_PATTERN = /\b(reject|denied|deny|declin|refus|not\s+authorized|unauthoriz)/i;

/**
 * Map whatever the bunker or the transport threw onto a code.
 *
 * A bunker rejects a request by returning an `error` string, which nostr-tools
 * surfaces as a rejection whose value may be a plain string rather than an
 * Error — hence the widened input.
 */
export function toNip46Error(cause: unknown, fallbackMessage: string): Nip46Error {
  if (cause instanceof Nip46Error) {
    return cause;
  }

  const message = cause instanceof Error ? cause.message : String(cause ?? '');

  // Checked before the refusal pattern: an AggregateError from a failed publish
  // says "All promises were rejected", which would otherwise read as a decline.
  // nostr-tools throws it when every relay publish failed, and that is the only
  // signal available that nothing on the other end is live.
  // `connection` is qualified deliberately: a bare match would swallow
  // "user denied the connection", which is a decline, not a dead transport.
  if (
    cause instanceof AggregateError ||
    /relay|websocket|connection (refused|closed|failed|error)|ECONNREFUSED/i.test(message)
  ) {
    return new Nip46Error('UNREACHABLE', message || fallbackMessage, { cause });
  }

  if (DECLINED_PATTERN.test(message)) {
    return new Nip46Error('DECLINED', message, { cause });
  }

  return new Nip46Error('PROVIDER_ERROR', message || fallbackMessage, { cause });
}
