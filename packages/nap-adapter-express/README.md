# @imani/nap-adapter-express

Express adapter for `@imani/nap-server`.

## Includes

- JSON parser with raw-body capture
- `/auth/init` and `/auth/complete` handlers
- router factory
- cookie-mode helper
- base URL resolver helper

## Example

```ts
import express from 'express';
import {
  createNapExpressRouter,
  createRequestDerivedBaseUrlResolver,
} from '@imani/nap-adapter-express';

const app = express();

app.use(
  '/auth',
  createNapExpressRouter({
    server: napServerOptions,
    getExternalBaseUrl: createRequestDerivedBaseUrlResolver(['api.example.com']),
  })
);
```
