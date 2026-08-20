import { describe, expect, it } from 'vitest';
import { createAudienceHostAllowlist } from '../src/audience.js';

describe('createAudienceHostAllowlist', () => {
  it('refuses to be built without hosts', () => {
    expect(() => createAudienceHostAllowlist([])).toThrow(/non-empty host allowlist/);
  });

  it('rejects entries that are not hosts', () => {
    expect(() => createAudienceHostAllowlist(['https://api.example.com/auth'])).toThrow(/path/);
    expect(() => createAudienceHostAllowlist(['ftp://api.example.com'])).toThrow(/http or https/);
    expect(() => createAudienceHostAllowlist(['user@api.example.com'])).toThrow(/userinfo/);
    expect(() => createAudienceHostAllowlist(['api.*.example.com'])).toThrow(/leading/);
    expect(() => createAudienceHostAllowlist(['  '])).toThrow(/empty entry/);
    // The catastrophic wildcard, which is the whole reason the list exists.
    expect(() => createAudienceHostAllowlist(['*.com'])).toThrow(/too broad/);
  });

  it('takes the scheme from the request unless the entry pins one', () => {
    const allow = createAudienceHostAllowlist(['api.example.com', 'https://pinned.example.com']);

    expect(allow('api.example.com', 'http')).toBe('http://api.example.com');
    // An X-Forwarded-Proto a misconfigured trust proxy believed cannot
    // downgrade a pinned entry.
    expect(allow('pinned.example.com', 'http')).toBe('https://pinned.example.com');
  });

  it('matches hosts case-insensitively, ports included', () => {
    const allow = createAudienceHostAllowlist(['API.example.com:8443']);

    expect(allow('api.example.com:8443', 'https')).toBe('https://api.example.com:8443');
    // A port is part of the host: allowlisting one does not allowlist another.
    expect(() => allow('api.example.com', 'https')).toThrow(/not in the allowlist/);
  });

  it('rejects a host nobody allowlisted', () => {
    const allow = createAudienceHostAllowlist(['api.example.com']);

    expect(() => allow('evil.example', 'https')).toThrow(/not in the allowlist/);
    expect(() => allow('api.example.com.evil.example', 'https')).toThrow(/not in the allowlist/);
    expect(() => allow(undefined, 'https')).toThrow(/Unable to resolve external host/);
  });

  it('opts into subdomains per entry, and only below the suffix', () => {
    const allow = createAudienceHostAllowlist(['*.example.com']);

    expect(allow('a.example.com', 'https')).toBe('https://a.example.com');
    expect(allow('deep.a.example.com', 'https')).toBe('https://deep.a.example.com');
    // §13.5.8: the wildcard is for subdomains. The apex is a separate entry.
    expect(() => allow('example.com', 'https')).toThrow(/not in the allowlist/);
    expect(() => allow('notexample.com', 'https')).toThrow(/not in the allowlist/);
  });
});
