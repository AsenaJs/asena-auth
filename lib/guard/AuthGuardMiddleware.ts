import { HttpException } from '@asenajs/asena/adapter';
import type { AsenaContext, AsenaNextHandler } from '@asenajs/asena/adapter';
import { AUTH_SESSION_CONTEXT_KEY } from '@asenajs/asena/auth';
import type { AuthSession } from '@asenajs/asena/auth';
import { Middleware } from '@asenajs/asena/decorators';
import { Inject } from '@asenajs/asena/decorators/ioc';
import { ICoreServiceNames } from '@asenajs/asena/ioc/types';
import type { ServerLogger } from '@asenajs/asena/logger';
import { AsenaMiddlewareService } from '@asenajs/asena/middleware';
import { AsenaAuthService } from '../AsenaAuthService';
import { applySessionCookie, getRawRequest } from '../helpers/context';
import { AUTH_GUARD_MIDDLEWARE_NAME, AUTH_GUARD_NAME, AUTH_REGISTRY_NAME } from '../types';
import type { AuthProviderRegistryLike } from '../types';
import type { AuthGuard } from './AuthGuard';
import { requestKeys } from './routeKey';

/** Answers 401 / 403 for the route mark `AuthGuard` recorded; prepended to protected routes only. */
@Middleware({ name: AUTH_GUARD_MIDDLEWARE_NAME })
export class AuthGuardMiddleware extends AsenaMiddlewareService {
  @Inject(AUTH_GUARD_NAME)
  protected guard!: Pick<AuthGuard, 'marks'>;

  @Inject(AUTH_REGISTRY_NAME)
  protected registry!: AuthProviderRegistryLike;

  @Inject(ICoreServiceNames.SERVER_LOGGER)
  protected logger!: ServerLogger;

  public async handle(ctx: AsenaContext<any, any>, next: AsenaNextHandler): Promise<void> {
    const keys = requestKeys(ctx);
    const mark = keys.map((key) => this.guard.marks.get(key)).find(Boolean);

    if (!mark) {
      const route = `${getRawRequest(ctx).method} ${ctx.routePattern}`;

      this.logger.error(`[asena-auth] No guard mark recorded for ${route} (tried ${keys.join(', ') || 'nothing'}).`);

      throw new HttpException(500, 'Internal Server Error');
    }

    const provider = this.registry.select(mark.provider);
    let session: AuthSession | null | undefined = ctx.getValue(AUTH_SESSION_CONTEXT_KEY);

    if (session === undefined) {
      const request = getRawRequest(ctx);

      session = (await provider.getSession(request)) ?? null;
      ctx.setValue(AUTH_SESSION_CONTEXT_KEY, session);

      const slidToken = provider instanceof AsenaAuthService ? provider.slidCookieToken(request) : null;

      if (slidToken) {
        await applySessionCookie(ctx, provider as AsenaAuthService, slidToken);
      }
    }

    if (!session) {
      throw new HttpException(401, 'Unauthorized');
    }

    if (mark.roles?.length) {
      const held = provider.getRoles(session);

      if (!mark.roles.some((role) => held.includes(role))) {
        throw new HttpException(403, 'Forbidden');
      }
    }

    await next();
  }
}
