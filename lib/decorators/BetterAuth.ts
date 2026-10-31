import 'reflect-metadata';
import { AUTH_PROVIDER_KEY } from '@asenajs/asena/auth';
import { Service } from '@asenajs/asena/decorators';
import { Implements } from '@asenajs/asena/decorators/ioc';
import type { BetterAuthService } from '../better-auth/BetterAuthService';
import type { BetterAuthDecoratorOptions, BetterAuthOptions } from '../types';

/**
 * Registers a class extending {@link BetterAuthService} as an auth provider backed by Better Auth.
 *
 * `options` may be a thunk resolved at construction - the usual form, since `betterAuth({...})`
 * reads the environment. A thunk registers under the class's own name; use the object form's `name` to choose one.
 */
export function BetterAuth(options: BetterAuthDecoratorOptions | (() => BetterAuthOptions)) {
  return function <T extends new (...args: any[]) => BetterAuthService<any>>(target: T): T {
    const serviceName = typeof options === 'function' ? target.name : (options.name ?? target.name);

    @Service(serviceName)
    class BetterAuthServiceClass extends (target as unknown as typeof BetterAuthService) {
      public constructor() {
        // eslint-disable-next-line constructor-super
        super();

        this.setBetterAuth(typeof options === 'function' ? options() : options);
      }
    }

    Object.defineProperty(BetterAuthServiceClass, 'name', {
      value: target.name,
      writable: false,
      configurable: true,
    });

    Implements(AUTH_PROVIDER_KEY)(BetterAuthServiceClass);

    return BetterAuthServiceClass as unknown as T;
  };
}
