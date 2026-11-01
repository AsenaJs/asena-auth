import type { AsenaContext } from '@asenajs/asena/adapter';
import { AUTH_SESSION_CONTEXT_KEY } from '@asenajs/asena/auth';
import type { AsenaAuthProvider, AuthSession } from '@asenajs/asena/auth';
import { AsenaAuthService } from '../AsenaAuthService';
import { BetterAuthService } from '../better-auth/BetterAuthService';
import { forwardSetCookies, getRawRequest } from '../helpers/context';

const resolvedBy = new WeakMap<Request, AsenaAuthProvider>();

/**
 * The request's session, asking `provider` at most once per request: a value already in the
 * context (`null` = resolved anonymous) is returned as is, unless another provider resolved it.
 * The cookies Better Auth answered with (a session refresh) are forwarded; a native slide is re-issued
 * later by {@link flushSlidCookie}. Pass `reuse: false` when `request`
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

  if (provider instanceof BetterAuthService) {
    await forwardSetCookies(ctx, provider.responseCookies(request));
  }

  return session;
}

/** Re-issues the cookie a native provider slid in `resolveSession`; run it after the handler. */
export async function flushSlidCookie(ctx: AsenaContext<any, any>, provider: AsenaAuthProvider): Promise<void> {
  if (provider instanceof AsenaAuthService) {
    await provider.flushSlidCookie(ctx);
  }
}
