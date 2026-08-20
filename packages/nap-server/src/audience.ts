/**
 * Host allowlisting for request-derived audiences.
 *
 * The audience is whatever the resolver returns, and `Host` is a client-supplied
 * header. WebAuthn L3 §13.5.9 is normative about the equivalent decision — "the
 * Relying Party MUST validate the origin member of the client data. The Relying
 * Party MUST NOT accept unexpected values of origin" — and every pattern it
 * sanctions is an allowlist. §13.5.8 adds that an RP by default SHOULD NOT
 * accept subdomain origins, which is why a wildcard here is per-entry and opt-in
 * rather than a flag over the whole list.
 *
 * Lives in `nap-server` rather than in either adapter because both adapters need
 * exactly this and neither should own a second copy of the trust policy.
 */

interface AllowedHost {
  host: string;
  /** `undefined` means "whatever scheme the request arrived on". */
  scheme?: string;
  /** Match `*.suffix`, not the bare suffix. */
  wildcard: boolean;
}

function parseEntry(entry: string): AllowedHost {
  const raw = entry.trim().toLowerCase();

  if (!raw) {
    throw new Error('NAP audience allowlist contains an empty entry');
  }

  const schemeMatch = /^([a-z][a-z0-9+.-]*):\/\//.exec(raw);
  const scheme = schemeMatch?.[1];
  const host = scheme ? raw.slice(schemeMatch![0].length) : raw;

  if (scheme && scheme !== 'http' && scheme !== 'https') {
    throw new Error(`NAP audience allowlist entry '${entry}' must use http or https`);
  }

  if (/[/?#@\s]/.test(host)) {
    throw new Error(
      `NAP audience allowlist entry '${entry}' must be a host (optionally scheme-prefixed), not a URL with a path, query, or userinfo`
    );
  }

  const wildcard = host.startsWith('*.');
  const bare = wildcard ? host.slice(2) : host;

  if (!bare || bare.includes('*')) {
    throw new Error(
      `NAP audience allowlist entry '${entry}' is not a host: a wildcard is only valid as a leading '*.'`
    );
  }

  // ponytail: no public-suffix list, so `*.co.uk` is accepted and `*.com` is
  // not. One dot is the cheap guard against the catastrophic case; pin exact
  // hosts if the registry boundary matters to you.
  if (wildcard && !bare.includes('.')) {
    throw new Error(
      `NAP audience allowlist entry '${entry}' is too broad: a wildcard needs at least one dot in its suffix`
    );
  }

  return { host: bare, scheme, wildcard };
}

function matches(allowed: AllowedHost, host: string): boolean {
  return allowed.wildcard
    ? host.endsWith(`.${allowed.host}`) && host.length > allowed.host.length + 1
    : host === allowed.host;
}

/**
 * Turn an allowlist into `(host, protocol) => baseUrl`.
 *
 * Entries are exact hosts (`api.example.com`, port included when it is not the
 * scheme default), optionally scheme-pinned (`https://api.example.com`), and
 * optionally subdomain wildcards (`*.example.com`, which matches
 * `a.example.com` but not `example.com`). A scheme-pinned entry ignores the
 * request's protocol, which is the only way to stop an `X-Forwarded-Proto` a
 * misconfigured `trust proxy` believes from downgrading the audience to `http`.
 *
 * There is no empty-list escape hatch: an allowlist that allows everything is
 * the state this exists to make unrepresentable. Throws here, at wiring time,
 * rather than as a uniform 401 per request.
 */
export function createAudienceHostAllowlist(
  allowedHosts: readonly string[]
): (host: string | undefined, protocol: string) => string {
  if (!Array.isArray(allowedHosts) || allowedHosts.length === 0) {
    throw new Error(
      'NAP audience resolution requires a non-empty host allowlist: pass the exact hosts this deployment answers on, e.g. ["api.example.com"]'
    );
  }

  const allowed = allowedHosts.map(parseEntry);

  return (host, protocol) => {
    if (!host) {
      throw new Error('Unable to resolve external host for NAP request');
    }

    const normalized = host.trim().toLowerCase();
    const match = allowed.find((entry) => matches(entry, normalized));

    if (!match) {
      throw new Error(`NAP audience host '${host}' is not in the allowlist`);
    }

    return `${match.scheme ?? protocol}://${normalized}`;
  };
}
