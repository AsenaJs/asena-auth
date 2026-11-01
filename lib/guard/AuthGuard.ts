import { collectGuardMetadata, effectiveGuardMark } from '@asenajs/asena/auth';
import type { CollectedGuardMetadata, GuardMark } from '@asenajs/asena/auth';
import { PostProcessor } from '@asenajs/asena/decorators';
import { Inject } from '@asenajs/asena/decorators/ioc';
import { ComponentConstants } from '@asenajs/asena/ioc/constants';
import { ICoreServiceNames } from '@asenajs/asena/ioc/types';
import type { ComponentPostProcessor } from '@asenajs/asena/ioc/types';
import type { ServerLogger } from '@asenajs/asena/logger';
import {
  defineTypedMetadata,
  getChainedTypedMetadata,
  getOwnTypedMetadata,
  getTypedMetadata,
  isController,
} from '@asenajs/asena/utils';
import { AUTH_GUARD_MIDDLEWARE_NAME, AUTH_GUARD_NAME } from '../types';
import { AuthGuardMiddleware } from './AuthGuardMiddleware';
import { routeKey } from './routeKey';

/** A protected route's mark plus where it came from, for lookups and boot-time error messages. */
export type GuardRouteMark = GuardMark & { controller: string; method: string };

/**
 * Enforces `@Protected` / `@Public` / `@Roles` by rewriting route metadata: protected routes get
 * {@link AuthGuardMiddleware} prepended, so it runs before the route's own middlewares and its
 * validator. Global and controller middlewares still run first. Handlers are never wrapped.
 */
@PostProcessor(AUTH_GUARD_NAME)
export class AuthGuard implements ComponentPostProcessor {
  /**
   * Protected routes by `METHOD /normalized/path`; validated by `AuthProviderRegistry` at boot.
   * @internal
   */
  public readonly marks = new Map<string, GuardRouteMark>();

  @Inject(ICoreServiceNames.SERVER_LOGGER)
  protected logger!: ServerLogger;

  public postProcess<T>(instance: T, Class: any): T {
    const collected = collectGuardMetadata(Class);
    const marked = collected.classMark !== undefined || collected.methods.size > 0;

    if (!isController(Class)) {
      if (marked) {
        this.logger.warn(
          `[asena-auth] ${Class.name} carries @Protected/@Public/@Roles but is not a @Controller - the marks are ignored.`,
        );
      }

      return instance;
    }

    if (marked) {
      this.guardRoutes(Class, collected);
    }

    return instance;
  }

  private guardRoutes(Class: any, collected: CollectedGuardMetadata): void {
    // Every route gets an own entry, guarded or not: the chain is read after all post-processing,
    // so a subclass without one would inherit whatever was written onto its base.
    const chained = getChainedTypedMetadata<Record<string, any>>(ComponentConstants.RouteKey, Class);
    const own = { ...(getOwnTypedMetadata<Record<string, any>>(ComponentConstants.RouteKey, Class) ?? {}) };
    const prefix = getOwnTypedMetadata<string>(ComponentConstants.PathKey, Class) ?? '';
    const controller = getTypedMetadata<string>(ComponentConstants.NameKey, Class) ?? Class.name;
    let guarded = false;

    for (const [method, entry] of Object.entries(chained)) {
      const mark = effectiveGuardMark(collected, method);
      const userMiddlewares = (entry.middlewares ?? []).filter((m: unknown) => m !== AuthGuardMiddleware);

      if (mark?.access === 'protected') {
        own[method] = { ...entry, middlewares: [AuthGuardMiddleware, ...userMiddlewares] };
        this.marks.set(routeKey(entry.method, prefix, entry.path), { ...mark, controller, method });
        guarded = true;
      } else {
        own[method] = { ...entry, middlewares: userMiddlewares };
      }
    }

    defineTypedMetadata(ComponentConstants.RouteKey, own, Class);

    if (guarded) {
      this.declareSoftDependency(Class);
    }
  }

  /** What core's `defineMiddleware` (not exported) records for every route middleware. */
  private declareSoftDependency(Class: any): void {
    const deps = getOwnTypedMetadata<Record<string, string>>(ComponentConstants.SoftDependencyKey, Class) ?? {};

    deps[AUTH_GUARD_MIDDLEWARE_NAME] = AUTH_GUARD_MIDDLEWARE_NAME;
    defineTypedMetadata(ComponentConstants.SoftDependencyKey, deps, Class);
  }
}
