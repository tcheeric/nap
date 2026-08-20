# @imani/nap-adapter-fastify

Fastify adapter for `@imani/nap-server`.

## Includes

- encapsulated JSON parser with raw-body capture
- `/auth/init` and `/auth/complete` routes
- plugin registration
- cookie-mode helper
- base URL resolver helper

## Example

```ts
import Fastify from 'fastify';
import {
  createRequestDerivedBaseUrlResolver,
  napFastifyPlugin,
} from '@imani/nap-adapter-fastify';

const app = Fastify({ trustProxy: true });

await app.register(napFastifyPlugin, {
  routePrefix: '/auth',
  server: napServerOptions,
  getExternalBaseUrl: createRequestDerivedBaseUrlResolver(['api.example.com']),
});
```
