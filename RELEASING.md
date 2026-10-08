# Releasing

Every package shares one version, and a release publishes all ten together, in dependency
order (`nap-core` first, so no published package ever points at a sibling that is not on the
registry yet).

## The scope

The code imports `@imani/nap-*` everywhere: sources, tests, docs and the compiled `dist/`.
The scope the packages are **published** under is a separate choice, made in one place:

| `NAP_SCOPE` | Published as | Sibling dependency in the published manifest |
| --- | --- | --- |
| `@398ja` (default) | `@398ja/nap-core`, ... | `"@imani/nap-core": "npm:@398ja/nap-core@^0.12.0"` |
| `@imani` | `@imani/nap-core`, ... | `"@imani/nap-core": "^0.12.0"` |

With `@398ja` the published packages depend on each other through npm aliases, so the
`@imani/nap-*` import names keep working with no rewrite of the JavaScript. A consumer
declares the same aliases:

```json
"@imani/nap-client-web": "npm:@398ja/nap-client-web@^0.12.0",
"@imani/nap-react": "npm:@398ja/nap-react@^0.12.0"
```

and npm installs one copy of each: the consumer's alias and the transitive one resolve to the
same `node_modules/@imani/nap-*` path.

`@398ja` is the default because it is the publishing account's own scope and is guaranteed
to accept the publish. Use `@imani` only once the account is confirmed to own the `@imani`
npm org: the org exists on the registry, with a user named `imani` as its owner.

## Commands

```bash
npm ci
npm run release:pack       # build + stage + npm pack -> .release/tarballs/. No credentials.
npm run release:dry-run    # typecheck + test + build + `npm publish --dry-run` per package.

# The real release. Needs a clean tree on the release commit and an npm login or token.
NODE_AUTH_TOKEN=... npm run release                 # publishes @398ja/nap-*@<version>
NAP_SCOPE=@imani npm run release                    # publishes @imani/nap-*@<version>
```

Options: `--scope`, `--registry <url>`, `--tag <dist-tag>`, `--skip-checks`, `--allow-dirty`.
The same values can be set as `NAP_SCOPE`, `NAP_REGISTRY` and `NAP_DIST_TAG`.

`npm run release` refuses to start unless `npm whoami` succeeds, and refuses a dirty tree. It
skips any package whose version is already on the registry, so re-running after a partial
failure resumes where it stopped.

Using a token without writing it to disk: npm reads `${NODE_AUTH_TOKEN}` from an `.npmrc` line.

```bash
printf '//registry.npmjs.org/:_authToken=${NODE_AUTH_TOKEN}\n' > "$RUNNER_TEMP/npmrc"
NPM_CONFIG_USERCONFIG="$RUNNER_TEMP/npmrc" NODE_AUTH_TOKEN=... npm run release
```

## What ships

Each tarball contains `package.json`, `README.md` and `dist/` (ESM `.js` + `.d.ts`), nothing
else. The staged manifest drops `devDependencies`, `scripts` and the `nap-source` export
condition. `scripts/publishing.test.ts` (part of `npm test`) holds the contract:

- `files`, `exports`, `main`, `module`, `types`, `sideEffects: false`, `publishConfig.access`.
- Sibling ranges are `^<version>`, and a `workspace:`/`file:` range fails staging.
- `nostr-tools`, `@noble/*` and `react` are peer dependencies, so a consumer gets one copy.
- The browser packages (`nap-core`, `nap-client-http`, `nap-client-web`, `nap-client-nip46`,
  `nap-react`) import no Node built-in. Staging re-checks the compiled `dist/`.

## Checklist

1. Bump `version` in the root and every `packages/*/package.json` (and the `^x.y.z` sibling
   ranges); `npm install` to refresh the lockfile.
2. Move `[Unreleased]` in `CHANGELOG.md` under the new version; update `UPGRADING.md`.
3. Merge, tag `vX.Y.Z` on the merge commit, and run `npm run release` from that commit.
