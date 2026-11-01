import { expect, test } from 'bun:test';
import { betterAuth } from 'better-auth';
import type { BetterAuthInstance } from '../lib/types';

const auth = betterAuth({ secret: 'type-test-secret-that-is-long-enough-32', baseURL: 'http://localhost' });

// The real check is `bun run typecheck`: this assignment fails to compile if better-auth drifts.
const structural: BetterAuthInstance = auth;

test('a real betterAuth() instance satisfies BetterAuthInstance', () => {
  expect(typeof structural.handler).toBe('function');
  expect(typeof structural.api.getSession).toBe('function');
});
