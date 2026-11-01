import { expect, test } from 'bun:test';

// @ts-expect-error route-mark plumbing is not part of the public entry
import type { GuardRouteMark } from '../index';

export type RemovedGuardRouteMark = GuardRouteMark;

const PUBLIC_VALUES = [
  'AUTH_GUARD_MIDDLEWARE_NAME',
  'AUTH_GUARD_NAME',
  'AUTH_REGISTRY_NAME',
  'AsenaAuthService',
  'Auth',
  'AuthGuard',
  'AuthGuardMiddleware',
  'AuthProviderRegistry',
  'AuthSessionMiddleware',
  'AuthWebSocketMiddleware',
  'BetterAuth',
  'BetterAuthController',
  'BetterAuthService',
  'MemoryAuthStore',
  'WS_TOKEN_SUBPROTOCOL',
  'applySessionCookie',
  'authComponents',
  'clearSessionCookie',
  'defaultRolesResolver',
  'generateToken',
  'getRawRequest',
  'hashPassword',
  'hashToken',
  'verifyPassword',
  'withSubprotocolToken',
];

test('the package entry exports exactly the public allowlist, so internals never leak through a barrel', async () => {
  expect(Object.keys(await import('../index')).sort()).toEqual([...PUBLIC_VALUES].sort());
});
