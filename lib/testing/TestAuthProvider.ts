import 'reflect-metadata';
import { AUTH_PROVIDER_KEY } from '@asenajs/asena/auth';
import type { AsenaAuthProvider, AuthSession, AuthUser } from '@asenajs/asena/auth';
import { Service } from '@asenajs/asena/decorators';
import { Implements } from '@asenajs/asena/decorators/ioc';
import { defaultRolesResolver } from '../helpers/roles';

export interface TestAuthOptions<TUser extends AuthUser = AuthUser> {
  /** Header value -> user. Read on every request, so a test may change it between requests. */
  users: Record<string, TUser>;
  /** Default `x-test-user`. */
  header?: string;
  primary?: boolean;
  name?: string;
}

/**
 * A provider for tests: the request header (`x-test-user` by default) names a key of `users`, and that
 * user is the session. A missing header or unknown key is no session. Decorate the subclass with `@TestAuth`.
 */
export abstract class TestAuthProvider<TUser extends AuthUser = AuthUser> implements AsenaAuthProvider<TUser> {
  protected options: TestAuthOptions<TUser> | null = null;

  public get primary(): boolean {
    return this.options?.primary === true;
  }

  public async getSession(request: Request): Promise<AuthSession<TUser> | null> {
    const users = this.options?.users ?? {};
    const key = request.headers.get(this.options?.header ?? 'x-test-user');

    if (key === null || !Object.hasOwn(users, key)) {
      return null;
    }

    const user = users[key]!;

    return {
      user,
      session: {
        id: `test:${key}`,
        userId: user.id,
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 3_600_000),
      },
    };
  }

  public getRoles(session: AuthSession<TUser>): string[] {
    return defaultRolesResolver(session);
  }

  protected setTestOptions(options: TestAuthOptions<TUser>): void {
    this.options = options;
  }
}

/** Registers a class extending {@link TestAuthProvider} as an auth provider, like `@Auth` does. */
export function TestAuth(options: TestAuthOptions<any>) {
  return function <T extends new (...args: any[]) => TestAuthProvider<any>>(target: T): T {
    @Service(options.name ?? target.name)
    class TestAuthProviderClass extends (target as unknown as typeof TestAuthProvider) {
      public constructor() {
        // eslint-disable-next-line constructor-super
        super();

        this.setTestOptions(options);
      }
    }

    Object.defineProperty(TestAuthProviderClass, 'name', {
      value: target.name,
      writable: false,
      configurable: true,
    });

    Implements(AUTH_PROVIDER_KEY)(TestAuthProviderClass);

    return TestAuthProviderClass as unknown as T;
  };
}
