import type { AsenaContext } from '@asenajs/asena/adapter';

/** The cookie surface of a native provider that the cookie helpers need. */
export interface SessionCookieSource {
  readonly cookieName: string;
  readonly cookieOptions: { path?: string; domain?: string };
}

/** The web `Request` behind a context: `ctx.req` on ergenecore, `ctx.req.raw` on hono. */
export function getRawRequest(ctx: AsenaContext<any, any>): Request {
  const req = ctx.req as any;

  return typeof req?.raw === 'object' && req.raw !== null ? req.raw : req;
}

export async function applySessionCookie(
  ctx: AsenaContext<any, any>,
  service: SessionCookieSource,
  token: string,
): Promise<void> {
  await ctx.setCookie(service.cookieName, token, { extraOptions: service.cookieOptions });
}

export async function clearSessionCookie(ctx: AsenaContext<any, any>, service: SessionCookieSource): Promise<void> {
  const { path, domain } = service.cookieOptions;

  await ctx.deleteCookie(service.cookieName, { extraOptions: { path, domain } });
}
