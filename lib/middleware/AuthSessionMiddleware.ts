import type { AsenaContext, AsenaNextHandler } from '@asenajs/asena/adapter';
import { Middleware } from '@asenajs/asena/decorators';
import { Inject, OnStart } from '@asenajs/asena/decorators/ioc';
import { AsenaMiddlewareService } from '@asenajs/asena/middleware';
import { getRawRequest } from '../helpers/context';
import { AUTH_REGISTRY_NAME } from '../types';
import type { AuthProviderRegistryLike } from '../types';
import { flushSlidCookie, resolveSession } from './resolveSession';
import { selectAtBoot } from './selectAtBoot';

/**
 * Resolves the session once, early, into `authSession` (`null` when anonymous) and never rejects -
 * guards decide. Uses the primary (or sole) provider; a subclass may set `providerName`.
 */
@Middleware()
export class AuthSessionMiddleware extends AsenaMiddlewareService {
  @Inject(AUTH_REGISTRY_NAME)
  protected registry!: AuthProviderRegistryLike;

  protected providerName?: string;

  @OnStart()
  public onStart(): void {
    selectAtBoot(this.registry, 'AuthSessionMiddleware', this.providerName);
  }

  public async handle(ctx: AsenaContext<any, any>, next: AsenaNextHandler): Promise<void> {
    const provider = this.registry.select(this.providerName);

    await resolveSession(ctx, provider, getRawRequest(ctx));

    try {
      await next();
    } finally {
      await flushSlidCookie(ctx, provider);
    }
  }
}
