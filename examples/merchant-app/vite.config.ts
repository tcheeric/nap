import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

const API = process.env.MERCHANT_API ?? 'http://localhost:3000';

export default defineConfig({
  plugins: [react()],
  // Read the workspace packages from source (their `nap-source` export condition)
  // rather than from dist/, which exists only after `npm run build`. An app
  // installing the published packages needs nothing here.
  resolve: { conditions: ['nap-source'] },
  server: {
    port: 5173,
    // Same-origin from the browser's point of view. Which matters twice over:
    // the session cookie is SameSite=Lax, and the NIP-98 audience is whatever
    // URL the browser actually called — so the server must be started with
    // NAP_BASE_URL pointing at *this* origin, not at the API's own port.
    proxy: {
      '/auth': API,
      '/api': API,
      '/permissions': API,
    },
  },
});
