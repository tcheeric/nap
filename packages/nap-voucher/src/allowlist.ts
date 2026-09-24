/**
 * Mint and issuer allowlists for voucher-bound authorization.
 *
 * Extension 0001 §4.3. This is the highest-severity surface in the extension,
 * so the reasoning is written down rather than left to review.
 *
 * Any mint can sign a voucher whose tags claim `issuer: acme` and whose
 * metadata implies `role: admin`. A valid signature says the mint signed it and
 * nothing whatever about whether that mint has authority to make claims this
 * server honours. Without an allowlist, "present a voucher" becomes "choose
 * your own permissions", because the attacker picks the mint.
 *
 * The credential carries `mint_url`, and it is client-supplied. A request field
 * choosing the mint that the credential is then verified against is the same
 * vulnerability class as a request header choosing the NIP-98 audience — the
 * flaw `createAudienceHostAllowlist` exists to prevent, and which WebAuthn L3
 * §13.5.9 is normative about: "the Relying Party MUST NOT accept unexpected
 * values of origin". Every pattern it sanctions is an allowlist. So the
 * supplied `mint_url` is *matched against* the list, never trusted to select
 * from it, and never used to reach the network before it has matched.
 *
 * Deliberately dependency-free (§11 step 2): the verification client is built
 * standalone and testable with no NAP dependency, so this module imports
 * nothing.
 */

/** A mint origin this server will verify vouchers against. */
export interface AllowedMint {
  /** Always `https`. Normalized, lowercase. */
  scheme: 'https';
  /** Lowercase host, including a non-default port. */
  host: string;
  /** The canonical `https://host[:port]` form, which is what comparisons use. */
  origin: string;
}

export interface AllowedIssuer {
  /** Canonical origin of the mint this issuer is trusted on. */
  mint: string;
  /** Lowercase hex issuer public key. */
  issuerPubkey: string;
}

/** A `(mint, issuerPubkey)` pair as callers supply it, before normalization. */
export interface IssuerAllowlistEntry {
  mint: string;
  issuerPubkey: string;
}

const HEX_64 = /^[0-9a-f]{64}$/;

/**
 * Parse one mint entry into its canonical origin.
 *
 * Scheme-pinned to `https` with no opt-out. The audience allowlist permits
 * `http` because a deployment may legitimately terminate TLS elsewhere and
 * speak plaintext on a trusted internal hop. Nothing analogous applies here:
 * this is an outbound call this server initiates to a third party, carrying a
 * credential, and the response decides an authorization. Plaintext would let
 * anyone on the path forge an `UNSPENT` state check.
 *
 * No paths, queries, userinfo, or wildcards. A wildcard would mean "trust any
 * subdomain to mint authorization claims", and unlike the audience case — where
 * a wildcard names hosts *this* deployment answers on — the entries here are
 * third parties. There is no version of that which is safe by default.
 */
function parseMintEntry(entry: string): AllowedMint {
  if (typeof entry !== 'string') {
    throw new Error('NAP voucher mint allowlist entries must be strings');
  }

  const raw = entry.trim();

  if (!raw) {
    throw new Error('NAP voucher mint allowlist contains an empty entry');
  }

  if (raw.includes('*')) {
    throw new Error(
      `NAP voucher mint allowlist entry '${entry}' must be an exact origin: wildcards would trust any subdomain to mint authorization claims`
    );
  }

  let url: URL;

  try {
    url = new URL(raw);
  } catch {
    throw new Error(
      `NAP voucher mint allowlist entry '${entry}' is not an absolute URL: pass a scheme-pinned origin, e.g. "https://mint.example.com"`
    );
  }

  if (url.protocol !== 'https:') {
    throw new Error(
      `NAP voucher mint allowlist entry '${entry}' must use https: the state check decides an authorization, and over plaintext anyone on the path can forge it`
    );
  }

  if (url.username || url.password) {
    throw new Error(
      `NAP voucher mint allowlist entry '${entry}' must not carry userinfo`
    );
  }

  // A path is silently ignored by origin comparison, so an operator who writes
  // `https://mint.example.com/v1` would believe they had scoped the entry when
  // they had not. Refuse rather than quietly widen.
  if (url.pathname !== '/' || url.search || url.hash) {
    throw new Error(
      `NAP voucher mint allowlist entry '${entry}' must be a bare origin with no path, query, or fragment`
    );
  }

  return { scheme: 'https', host: url.host.toLowerCase(), origin: url.origin.toLowerCase() };
}

/**
 * Canonicalize a client-supplied `mint_url` for comparison, or `null` when it
 * is not a usable https URL.
 *
 * Returns `null` rather than throwing: a malformed `mint_url` is a client
 * error that must produce the same generic 401 as every other voucher failure,
 * not an exception that distinguishes itself by shape or timing.
 */
export function canonicalizeMintUrl(mintUrl: string): string | null {
  if (typeof mintUrl !== 'string' || !mintUrl.trim()) {
    return null;
  }

  try {
    const url = new URL(mintUrl.trim());

    if (url.protocol !== 'https:' || url.username || url.password) {
      return null;
    }

    return url.origin.toLowerCase();
  } catch {
    return null;
  }
}

export interface MintAllowlist {
  /**
   * The canonical origin when `mintUrl` is allowed, else `null`.
   *
   * Returns the *server's* stored origin rather than the caller's string, so
   * everything downstream — the keyset fetch, the state check, the issuer pair
   * lookup — uses a value that came from configuration and never from the
   * request.
   */
  resolve(mintUrl: string): string | null;
  /** The configured origins, for logging and tests. */
  readonly origins: readonly string[];
}

/**
 * Build the mint allowlist.
 *
 * There is no empty-list escape hatch and no default. An allowlist that allows
 * every mint is the state this exists to make unrepresentable, so it throws
 * here, at wiring time, rather than as a uniform 401 per request — the same
 * property `createAudienceHostAllowlist` has.
 */
export function createMintAllowlist(allowedMints: readonly string[]): MintAllowlist {
  if (!Array.isArray(allowedMints) || allowedMints.length === 0) {
    throw new Error(
      'NAP voucher authorization requires a non-empty mint allowlist: pass the exact mint origins this server honours, e.g. ["https://mint.example.com"]. Any mint can sign a voucher claiming any role, so there is no safe default.'
    );
  }

  const parsed = allowedMints.map(parseMintEntry);
  const origins = parsed.map((mint) => mint.origin);
  const byOrigin = new Map(origins.map((origin) => [origin, origin]));

  // Duplicates are harmless to matching but always mean the operator believes
  // two entries differ when they do not — usually a trailing slash or a
  // spelled-out default port.
  if (byOrigin.size !== origins.length) {
    throw new Error(
      `NAP voucher mint allowlist contains duplicate origins after normalization: ${origins.join(', ')}`
    );
  }

  return {
    origins: Object.freeze([...origins]),
    resolve(mintUrl: string): string | null {
      const candidate = canonicalizeMintUrl(mintUrl);

      if (!candidate) {
        return null;
      }

      // Returns the configured string, not the candidate. They are equal here,
      // but the habit is the point: nothing downstream should ever hold a value
      // that arrived in the request.
      return byOrigin.get(candidate) ?? null;
    },
  };
}

export interface IssuerAllowlist {
  /** Whether this server honours vouchers from `issuerPubkey` on `mintOrigin`. */
  allows(mintOrigin: string, issuerPubkey: string): boolean;
  readonly entries: readonly AllowedIssuer[];
}

/**
 * Build the issuer allowlist.
 *
 * A second, narrower list, keyed on the *pair*: a trusted mint may still carry
 * vouchers from issuers this server does not honour, and trusting the mint is
 * not trusting everyone who ever used it. Keying on the issuer alone would let
 * an issuer trusted on one mint be honoured on another.
 *
 * Every entry's mint must already be in the mint allowlist. An issuer pinned to
 * a mint that is not honoured is dead configuration that reads as though it
 * grants something, and the operator who wrote it believes a route is open that
 * is closed — or, worse, removes the mint later and believes the pair still
 * constrains anything.
 */
export function createIssuerAllowlist(
  allowedIssuers: readonly IssuerAllowlistEntry[],
  mintAllowlist: MintAllowlist
): IssuerAllowlist {
  if (!Array.isArray(allowedIssuers) || allowedIssuers.length === 0) {
    throw new Error(
      'NAP voucher authorization requires a non-empty issuer allowlist: pass the (mint, issuerPubkey) pairs this server honours. A trusted mint may still carry vouchers from issuers you do not trust.'
    );
  }

  const entries = allowedIssuers.map((entry) => {
    if (!entry || typeof entry !== 'object') {
      throw new Error('NAP voucher issuer allowlist entries must be objects');
    }

    const mint = mintAllowlist.resolve(entry.mint);

    if (!mint) {
      throw new Error(
        `NAP voucher issuer allowlist entry names mint '${entry.mint}', which is not in the mint allowlist (${mintAllowlist.origins.join(', ')})`
      );
    }

    const issuerPubkey = typeof entry.issuerPubkey === 'string'
      ? entry.issuerPubkey.trim().toLowerCase()
      : '';

    // A malformed key can never match a real one, so it is dead configuration
    // that silently grants nothing while reading as though it grants something.
    if (!HEX_64.test(issuerPubkey)) {
      throw new Error(
        `NAP voucher issuer allowlist entry for '${mint}' has issuerPubkey '${entry.issuerPubkey}', which is not 32 bytes of lowercase hex`
      );
    }

    return { mint, issuerPubkey } satisfies AllowedIssuer;
  });

  const keys = entries.map((entry) => `${entry.mint}|${entry.issuerPubkey}`);
  const index = new Set(keys);

  if (index.size !== keys.length) {
    throw new Error('NAP voucher issuer allowlist contains duplicate (mint, issuerPubkey) pairs');
  }

  return {
    entries: Object.freeze(entries.map((entry) => Object.freeze({ ...entry }))),
    allows(mintOrigin: string, issuerPubkey: string): boolean {
      if (typeof mintOrigin !== 'string' || typeof issuerPubkey !== 'string') {
        return false;
      }

      return index.has(`${mintOrigin.toLowerCase()}|${issuerPubkey.trim().toLowerCase()}`);
    },
  };
}
