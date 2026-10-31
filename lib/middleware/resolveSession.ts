import type { AsenaContext } from '@asenajs/asena/adapter';
import { AUTH_SESSION_CONTEXT_KEY } from '@asenajs/asena/auth';
import type { AsenaAuthProvider, AuthSession } from '@asenajs/asena/auth';
import { AsenaAuthService } from '../AsenaAuthService';
import { applySessionCookie } from '../helpers/context';

/**
 * The request's session, asking `provider` at most once per request: a value already in the
 * context (`null` = resolved anonymous) is returned as is. A native cookie session that slid gets
 * its cookie re-issued. Pass `reuseAnonymous: false` to ask again over an earlier `null`.
 */
export async function resolveSession(
  ctx: AsenaContext<any, any>,
  provider: AsenaAuthProvider,
  request: Request,
  reuseAnonymous = true,
): Promise<AuthSession | null> {
  const known: AuthSession | null | undefined = ctx.getValue(AUTH_SESSION_CONTEXT_KEY);

  if (known || (known === null && reuseAnonymous)) {
    return known;
  }

  const session = (await provider.getSession(request)) ?? null;

  ctx.setValue(AUTH_SESSION_CONTEXT_KEY, session);

  if (provider instanceof AsenaAuthService) {
    const slidToken = provider.slidCookieToken(request);

    if (slidToken) {
      await applySessionCookie(ctx, provider, slidToken);
    }
  }

  return session;
}
