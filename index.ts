export { AsenaAuthService } from './lib/AsenaAuthService';
export type { SessionCookieOptions } from './lib/AsenaAuthService';

export { Auth } from './lib/decorators';

export { authComponents } from './lib/authComponents';

export { BetterAuth, BetterAuthController, BetterAuthService } from './lib/better-auth';

export { AuthGuard, AuthGuardMiddleware, AuthProviderRegistry } from './lib/guard';

export { AuthSessionMiddleware, AuthWebSocketMiddleware } from './lib/middleware';

export { MemoryAuthStore } from './lib/store';
export type { AuthSessionStore, StoredSession } from './lib/store';

export { generateToken, hashToken, hashPassword, verifyPassword } from './lib/crypto';

export {
  applySessionCookie,
  clearSessionCookie,
  getRawRequest,
  withSubprotocolToken,
  defaultRolesResolver,
} from './lib/helpers';
export type { SessionCookieSource } from './lib/helpers';

export { AUTH_REGISTRY_NAME, AUTH_GUARD_NAME, AUTH_GUARD_MIDDLEWARE_NAME, WS_TOKEN_SUBPROTOCOL } from './lib/types';
export type {
  AuthOptions,
  AuthDecoratorOptions,
  AuthProviderRegistryLike,
  BetterAuthInstance,
  BetterAuthOptions,
  BetterAuthDecoratorOptions,
  CookieOptions,
  HashingOptions,
  PasswordAlgorithm,
} from './lib/types';
