import 'reflect-metadata';
import { AUTH_PROVIDER_KEY } from '@asenajs/asena/auth';
import { Service } from '@asenajs/asena/decorators';
import { Implements } from '@asenajs/asena/decorators/ioc';
import type { AsenaAuthService } from '../AsenaAuthService';
import { MemoryAuthStore } from '../store';
import type { AuthDecoratorOptions, AuthOptions } from '../types';

/**
 * Registers a class extending {@link AsenaAuthService} as a native auth provider.
 *
 * `options` may be a thunk resolved at construction, so environment-dependent values are read at
 * runtime. A thunk registers under the class's own name; use the object form's `name` to choose one.
 */
export function Auth(options: AuthDecoratorOptions | (() => AuthOptions)) {
  return function <T extends new (...args: any[]) => AsenaAuthService<any>>(target: T): T {
    const serviceName = typeof options === 'function' ? target.name : (options.name ?? target.name);

    @Service(serviceName)
    class AuthServiceClass extends (target as unknown as typeof AsenaAuthService) {
      public constructor() {
        // eslint-disable-next-line constructor-super
        super();

        const resolved = typeof options === 'function' ? options() : options;

        this.setAuthOptions(resolved);
        this.setStore(resolved.store ?? new MemoryAuthStore(resolved.sweepIntervalMs));
      }
    }

    Object.defineProperty(AuthServiceClass, 'name', {
      value: target.name,
      writable: false,
      configurable: true,
    });

    Implements(AUTH_PROVIDER_KEY)(AuthServiceClass);

    return AuthServiceClass as unknown as T;
  };
}
