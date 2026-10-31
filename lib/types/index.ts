import type { AsenaAuthProvider, AuthUser, RolesResolver } from '@asenajs/asena/auth';
import type { AuthSessionStore } from '../store/AuthSessionStore';

export const AUTH_REGISTRY_NAME = 'AsenaAuthProviderRegistry';
export const AUTH_GUARD_NAME = 'AsenaAuthGuard';
export const AUTH_GUARD_MIDDLEWARE_NAME = 'AsenaAuthGuardMiddleware';
export const WS_TOKEN_SUBPROTOCOL = 'bearer';

/**
 * The slice of a Better Auth instance this package calls. Structural on purpose: `better-auth`
 * is never imported, so an app without it installs and runs this package unchanged.
 */
export interface BetterAuthInstance {
  handler: (request: Request) => Promise<Response>;
  api: {
    getSession: (opts: {
      headers: Headers;
      returnHeaders: true;
    }) => Promise<{ headers: Headers; response: { session: any; user: any } | null }>;
  };
}

/** What the session and WebSocket middlewares inject by name instead of the registry class. */
export interface AuthProviderRegistryLike {
  readonly providers: ReadonlyMap<string, AsenaAuthProvider>;
  select(name?: string): AsenaAuthProvider;
}

export interface CookieOptions {
  /** Default `asena_session`. */
  name?: string;
  /** Default `/`. */
  path?: string;
  /** Default `true`. */
  secure?: boolean;
  /** Default `lax`. */
  sameSite?: 'strict' | 'lax' | 'none';
  domain?: string;
}

export type PasswordAlgorithm = 'bcrypt' | 'argon2id' | 'argon2d' | 'argon2i';

export interface HashingOptions {
  /** Default `bcrypt`. */
  algorithm?: PasswordAlgorithm;
  /** bcrypt work factor, default 12. Ignored by the argon2 algorithms. */
  cost?: number;
}

export interface AuthOptions<TUser extends AuthUser = AuthUser> {
  /** Provider used by guards and middlewares that name none, when more than one provider is registered. */
  primary?: boolean;
  /** Replaces the default resolver (`user.roles` array, else comma-split `user.role`). */
  roles?: RolesResolver<TUser>;
  cookie?: CookieOptions;
  /** Accept `Authorization: Bearer <token>`. Default `true`. */
  header?: boolean;
  /** Session lifetime in seconds. Default 604800 (7 days). */
  sessionTtl?: number;
  /** Extend the session when less than half of its lifetime is left. Default `true`. */
  sliding?: boolean;
  /** Random bytes per token. Default 32. */
  tokenBytes?: number;
  hashing?: HashingOptions;
  /** Defaults to a `MemoryAuthStore`. */
  store?: AuthSessionStore<TUser>;
  /** Sweep interval of the default `MemoryAuthStore`. Default 60000. */
  sweepIntervalMs?: number;
}

export type AuthDecoratorOptions<TUser extends AuthUser = AuthUser> = AuthOptions<TUser> & { name?: string };

export interface BetterAuthOptions<TUser extends AuthUser = AuthUser> {
  primary?: boolean;
  roles?: RolesResolver<TUser>;
  auth: BetterAuthInstance;
}

export type BetterAuthDecoratorOptions<TUser extends AuthUser = AuthUser> = BetterAuthOptions<TUser> & {
  name?: string;
};
