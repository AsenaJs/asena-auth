import type { AsenaContext, AsenaNextHandler } from '@asenajs/asena/adapter';
import { AUTH_SESSION_CONTEXT_KEY } from '@asenajs/asena/auth';
import { Middleware } from '@asenajs/asena/decorators';
import { Inject, OnStart } from '@asenajs/asena/decorators/ioc';
import { AsenaMiddlewareService } from '@asenajs/asena/middleware';
import { getRawRequest, withSubprotocolToken } from '../helpers/context';
import { AUTH_REGISTRY_NAME } from '../types';
import type { AuthProviderRegistryLike } from '../types';
import { resolveSession } from './resolveSession';

/**
 * Rejects a WebSocket upgrade without a session (401, before the upgrade) and puts the session into
 * `ws.data.values.authSession`. Browsers send the token as `new WebSocket(url, ['bearer', token])`.
 */
@Middleware()
export class AuthWebSocketMiddleware extends AsenaMiddlewareService {
  @Inject(AUTH_REGISTRY_NAME)
  protected registry!: AuthProviderRegistryLike;

  protected providerName?: string;

  @OnStart()
  public onStart(): void {
    // authComponents registers this middleware even when unused, and several providers without a primary are valid then.
    if (this.providerName === undefined && this.registry.providers.size > 1) {
      return;
    }

    this.registry.select(this.providerName);
  }

  public async handle(ctx: AsenaContext<any, any>, next: AsenaNextHandler): Promise<Response | undefined> {
    const raw = getRawRequest(ctx);
    const request = withSubprotocolToken(raw);
    // A global session middleware saw the upgrade without the subprotocol token; its null is not final.
    const session = await resolveSession(ctx, this.registry.select(this.providerName), request, request === raw);

    if (!session) {
      return new Response(null, { status: 401 });
    }

    // Both adapters replace the socket value on every write, so keep what earlier middlewares stored.
    ctx.setWebSocketValue({ ...(ctx.getWebSocketValue() ?? {}), [AUTH_SESSION_CONTEXT_KEY]: session });
    await next();

    return undefined;
  }
}
