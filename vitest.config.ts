import { defineConfig } from 'vitest/config';
import path from 'node:path';

const vendor = (p: string) => path.resolve(__dirname, 'vendor/maestro-validation', p);

export default defineConfig({
  test: { environment: 'node' },
  resolve: {
    alias: [
      { find: /^@\/lib\/validation\/(.*)$/, replacement: `${vendor('lib')}/$1` },
      { find: /^@\/data\/validation\/(.*)$/, replacement: `${vendor('data')}/$1` },
      { find: /^@\/data\/maestro$/, replacement: vendor('data/maestro') },
    ],
  },
});
