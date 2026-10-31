import type { AsenaContext, AsenaNextHandler } from '@asenajs/asena/adapter';
import { Middleware } from '@asenajs/asena/decorators';
import { Inject, OnStart } from '@asenajs/asena/decorators/ioc';
import { AsenaMiddlewareService } from '@asenajs/asena/middleware';
import { getRawRequest } from '../helpers/context';
import { AUTH_REGISTRY_NAME } from '../types';
import type { AuthProviderRegistryLike } from '../types';
import { resolveSession } from './resolveSession';

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
    this.registry.select(this.providerName);
  }

  public async handle(ctx: AsenaContext<any, any>, next: AsenaNextHandler): Promise<void> {
    await resolveSession(ctx, this.registry.select(this.providerName), getRawRequest(ctx));
    await next();
  }
}
