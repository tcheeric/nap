# Security

## Reporting a vulnerability

Do not open a public issue for an exploitable vulnerability in NAP. Report it privately
through GitHub's [private vulnerability reporting][pvr] on this repository, or to the
maintainer directly.

NAP is an authentication protocol implementation, so a flaw here is a flaw in every
deployment that depends on it. Please include the version, whether the issue is in the
protocol or in one adapter, and a reproduction if you have one.

[pvr]: https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability

## Automated checks

Three run in CI and are visible in the repository:

| Check | Where | Gates a PR? |
| --- | --- | --- |
| Dependency audit (production tree) | `.github/workflows/ci.yml` | Yes, at `--audit-level=high` |
| Dependency audit (all, incl. dev) | `.github/workflows/ci.yml` | No, advisory only |
| CodeQL (`security-extended`) | `.github/workflows/codeql.yml` | Findings surface in the Security tab |

The production/dev split is deliberate. A dev-only advisory (a test runner, a bundler)
should not wedge every unrelated pull request, because a check developers learn to click
past has negative value. The production tree is small, actionable, and should always be
green.

## Settings that cannot live in this file

These are repository settings rather than files, so they have to be enabled in the GitHub
UI. They are listed here because a control nobody wrote down is a control nobody turns
back on after it is disabled.

**Secret scanning and push protection**
`Settings > Code security and analysis > Secret scanning`, both the scan and push
protection. A manual scan of the tree found nothing committed as of the 0.10.1 audit,
which is the right moment to turn the guard on rather than the reason to skip it.

**Private vulnerability reporting**
`Settings > Code security and analysis > Private vulnerability reporting`. Without it a
reporter's only options are a public issue or nothing, and the first is worse.

**Dependabot alerts and security updates**
`Settings > Code security and analysis`. `.github/dependabot.yml` schedules version
updates; alerts are the separate switch that surfaces a CVE between scheduled runs.

**Branch protection on the default branch**
Require the `Validate` and `Dependency audit` checks to pass before merge. Without this
the CI jobs are advisory in practice no matter what they return.

## Scope notes for anyone auditing this repository

Worth knowing before you start, from the 0.10.1 audit:

- **The audience binding is the highest-severity surface.** `createAudienceHostAllowlist()`
  and `createRequestDerivedBaseUrlResolver()` decide what every NIP-98 proof is checked
  against, from a client-supplied `Host` header. Both refuse an empty allowlist at wiring
  time rather than per request; that is deliberate and should stay that way.
- **The voucher extension reaches the network.** `nap-voucher` makes outbound calls to
  mint URLs that arrive in the request body. The ordering in `resolver.ts` (allowlist
  first, always) is a security property, not a style choice.
- **Retention is not yet solved for SQL stores.** The in-memory stores evict; the Postgres
  store has no `DELETE` path. See the open issue on store retention.
- **The response floor is load-bearing.** `padAuthResponse()` exists so a failed
  authentication cannot be distinguished by latency. Anything that returns early, throws,
  or answers on a different schedule undermines it, which is how the malformed `u` tag bug
  (a 500 escaping the floor, unaudited) mattered more than it first looked.
