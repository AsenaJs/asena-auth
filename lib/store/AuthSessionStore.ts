import type { AuthUser } from '@asenajs/asena/auth';

export interface StoredSession<TUser = AuthUser> {
  /** `sha256(token)` hex - the raw token is never stored. */
  id: string;
  userId: string;
  /** Snapshot taken at `createSession` time with `structuredClone`, so it must be plain data (no functions). */
  user: TUser;
  /** Epoch milliseconds. */
  createdAt: number;
  /** Epoch milliseconds. */
  expiresAt: number;
}

/**
 * Persistence for native sessions. `get` may return an expired row; the service checks expiry.
 * A store that needs DI is set from a subclass's `onStart()` via `setStore(...)` before `super.onStart()`.
 */
export interface AuthSessionStore<TUser = AuthUser> {
  create(session: StoredSession<TUser>): Promise<void>;
  get(id: string): Promise<StoredSession<TUser> | null>;
  delete(id: string): Promise<void>;
  deleteByUser(userId: string): Promise<void>;
  touch(id: string, expiresAt: number): Promise<void>;
  onStart?(): void | Promise<void>;
  onStop?(): void | Promise<void>;
}
