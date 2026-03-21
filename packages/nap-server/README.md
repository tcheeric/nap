# @imani/nap-server

Stateful server-side NAP flow built on `@imani/nap-core`.

## Includes

- challenge issuance
- challenge/session store interfaces
- in-memory test stores
- retry-safe completion verification
- public auth response helpers
- `createNapServer()` convenience factory

## Example

```ts
import {
  createNapServer,
  InMemoryChallengeStore,
  InMemorySessionStore,
} from '@imani/nap-server';

const nap = createNapServer({
  challengeStore: new InMemoryChallengeStore(),
  sessionStore: new InMemorySessionStore(),
  aclResolver: {
    async resolve() {
      return { allowed: true, roles: [], permissions: [] };
    },
  },
});
```
