import { OnStart, OnStop } from '@asenajs/asena/decorators/ioc';
import type { AsenaAuthProvider, AuthSession, AuthUser } from '@asenajs/asena/auth';
import { generateToken, hashPassword, hashToken, verifyPassword } from './crypto';
import { defaultRolesResolver } from './helpers/roles';
import type { AuthSessionStore, StoredSession } from './store';
import type { AuthOptions } from './types';

const DEFAULT_TTL_SECONDS = 604_800;
const DEFAULT_COOKIE_NAME = 'asena_session';

export interface SessionCookieOptions {
  httpOnly: true;
  sameSite: 'strict' | 'lax' | 'none';
  secure: boolean;
  path: string;
  domain?: string;
  maxAge: number;
}

/**
 * Native opaque-session provider. Extend it and decorate the subclass with `@Auth(...)`.
 * Tokens travel as `Authorization: Bearer` (wins) or the session cookie; only their SHA-256 is stored.
 */
export abstract class AsenaAuthService<TUser extends AuthUser = AuthUser> implements AsenaAuthProvider<TUser> {
  protected options: AuthOptions<TUser> | null = null;

  protected store: AuthSessionStore<TUser> | null = null;

  @OnStart()
  public async onStart(): Promise<void> {
    if (!this.options || !this.store) {
      throw new Error(
        `${this.constructor.name}: auth options not initialized. Decorate the class with @Auth({...}) and extend AsenaAuthService.`,
      );
    }

    await this.store.onStart?.();
  }

  @OnStop()
  public async onStop(): Promise<void> {
    await this.store?.onStop?.();
  }

  public get primary(): boolean {
    return this.getOptions().primary === true;
  }

  public get cookieName(): string {
    return this.getOptions().cookie?.name ?? DEFAULT_COOKIE_NAME;
  }

  public get cookieOptions(): SessionCookieOptions {
    const cookie = this.getOptions().cookie ?? {};
    const options: SessionCookieOptions = {
      httpOnly: true,
      sameSite: cookie.sameSite ?? 'lax',
      secure: cookie.secure ?? true,
      path: cookie.path ?? '/',
      maxAge: this.ttlSeconds,
    };

    if (cookie.domain !== undefined) {
      options.domain = cookie.domain;
    }

    return options;
  }

  public async createSession(user: TUser): Promise<{ token: string; session: AuthSession<TUser> }> {
    const token = generateToken(this.getOptions().tokenBytes ?? 32);
    const now = Date.now();
    const stored: StoredSession<TUser> = {
      id: hashToken(token),
      userId: user.id,
      user,
      createdAt: now,
      expiresAt: now + this.ttlSeconds * 1000,
    };

    await this.getStore().create(stored);

    return { token, session: this.toAuthSession(stored) };
  }

  public async getSession(request: Request): Promise<AuthSession<TUser> | null> {
    const token = this.readToken(request);

    if (!token) {
      return null;
    }

    const store = this.getStore();
    const stored = await store.get(hashToken(token));
    const now = Date.now();

    if (!stored || stored.expiresAt <= now) {
      return null;
    }

    const ttlMs = this.ttlSeconds * 1000;

    if (this.getOptions().sliding !== false && stored.expiresAt - now < ttlMs / 2) {
      const expiresAt = now + ttlMs;

      await store.touch(stored.id, expiresAt);

      return this.toAuthSession({ ...stored, expiresAt });
    }

    return this.toAuthSession(stored);
  }

  public getRoles(session: AuthSession<TUser>): string[] {
    const resolver = this.getOptions().roles;

    return resolver ? resolver(session) : defaultRolesResolver(session);
  }

  public async revokeSession(token: string): Promise<void> {
    await this.getStore().delete(hashToken(token));
  }

  public async revokeUserSessions(userId: string): Promise<void> {
    await this.getStore().deleteByUser(userId);
  }

  public async hashPassword(password: string): Promise<string> {
    return hashPassword(password, this.getOptions().hashing);
  }

  public async verifyPassword(password: string, hash: string): Promise<boolean> {
    return verifyPassword(password, hash);
  }

  protected setAuthOptions(options: AuthOptions<TUser>): void {
    this.options = options;
  }

  protected setStore(store: AuthSessionStore<TUser>): void {
    this.store = store;
  }

  private get ttlSeconds(): number {
    return this.getOptions().sessionTtl ?? DEFAULT_TTL_SECONDS;
  }

  private readToken(request: Request): string | null {
    if (this.getOptions().header !== false) {
      const match = /^bearer\s+(\S+)\s*$/i.exec(request.headers.get('authorization') ?? '');

      if (match) {
        return match[1];
      }
    }

    return this.readCookie(request.headers.get('cookie'));
  }

  private readCookie(header: string | null): string | null {
    if (!header) {
      return null;
    }

    const prefix = `${this.cookieName}=`;

    for (const part of header.split(';')) {
      const pair = part.trim();

      if (pair.startsWith(prefix)) {
        return pair.slice(prefix.length) || null;
      }
    }

    return null;
  }

  private toAuthSession(stored: StoredSession<TUser>): AuthSession<TUser> {
    return {
      user: stored.user,
      session: {
        id: stored.id,
        userId: stored.userId,
        createdAt: new Date(stored.createdAt),
        expiresAt: new Date(stored.expiresAt),
      },
    };
  }

  private getOptions(): AuthOptions<TUser> {
    if (!this.options) {
      throw new Error(`${this.constructor.name}: auth options not initialized. Decorate the class with @Auth({...}).`);
    }

    return this.options;
  }

  private getStore(): AuthSessionStore<TUser> {
    if (!this.store) {
      throw new Error(`${this.constructor.name}: no session store. Decorate the class with @Auth({...}).`);
    }

    return this.store;
  }
}
