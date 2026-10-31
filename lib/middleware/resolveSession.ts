import type { AsenaContext } from '@asenajs/asena/adapter';
import { AUTH_SESSION_CONTEXT_KEY } from '@asenajs/asena/auth';
import type { AsenaAuthProvider, AuthSession } from '@asenajs/asena/auth';
import { AsenaAuthService } from '../AsenaAuthService';
import { applySessionCookie, getRawRequest } from '../helpers/context';

const resolvedBy = new WeakMap<Request, AsenaAuthProvider>();

/**
 * The request's session, asking `provider` at most once per request: a value already in the
 * context (`null` = resolved anonymous) is returned as is, unless another provider resolved it.
 * A native cookie session that slid gets its cookie re-issued. Pass `reuse: false` when `request`
 * carries credentials the earlier resolution did not see, to ask again whatever the context holds.
 */
export async function resolveSession(
  ctx: AsenaContext<any, any>,
  provider: AsenaAuthProvider,
  request: Request,
  reuse = true,
): Promise<AuthSession | null> {
  const raw = getRawRequest(ctx);
  const known: AuthSession | null | undefined = ctx.getValue(AUTH_SESSION_CONTEXT_KEY);
  const owner = resolvedBy.get(raw);
  const reusable = reuse && (owner === undefined || owner === provider);

  if (reusable && known !== undefined) {
    return known;
  }

  const session = (await provider.getSession(request)) ?? null;

  ctx.setValue(AUTH_SESSION_CONTEXT_KEY, session);
  resolvedBy.set(raw, provider);

  if (provider instanceof AsenaAuthService) {
    const slidToken = provider.slidCookieToken(request);

    if (slidToken) {
      await applySessionCookie(ctx, provider, slidToken);
    }
  }

  return session;
}
