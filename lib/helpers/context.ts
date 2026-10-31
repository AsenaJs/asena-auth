import type { AsenaContext } from '@asenajs/asena/adapter';
import { WS_TOKEN_SUBPROTOCOL } from '../types';

/** The cookie surface of a native provider that the cookie helpers need. */
export interface SessionCookieSource {
  readonly cookieName: string;
  readonly cookieOptions: { path?: string; domain?: string; secure?: boolean; sameSite?: 'strict' | 'lax' | 'none' };
}

/** The web `Request` behind a context: `ctx.req` on ergenecore, `ctx.req.raw` on hono. */
export function getRawRequest(ctx: AsenaContext<any, any>): Request {
  const req = ctx.req as any;

  return typeof req?.raw === 'object' && req.raw !== null ? req.raw : req;
}

/**
 * A copy of a WebSocket upgrade request carrying `Authorization: Bearer <token>` when the client
 * sent `Sec-WebSocket-Protocol: bearer, <token>` and no `Authorization` header; otherwise `request` itself.
 */
export function withSubprotocolToken(request: Request): Request {
  if (request.headers.has('authorization')) {
    return request;
  }

  const [scheme, token] = (request.headers.get('sec-websocket-protocol') ?? '').split(',').map((p) => p.trim());

  if (scheme?.toLowerCase() !== WS_TOKEN_SUBPROTOCOL || !token) {
    return request;
  }

  const headers = new Headers(request.headers);

  headers.set('authorization', `Bearer ${token}`);

  return new Request(request, { headers });
}

export async function applySessionCookie(
  ctx: AsenaContext<any, any>,
  service: SessionCookieSource,
  token: string,
): Promise<void> {
  await ctx.setCookie(service.cookieName, token, { extraOptions: service.cookieOptions });
}

export async function clearSessionCookie(ctx: AsenaContext<any, any>, service: SessionCookieSource): Promise<void> {
  const { path, domain, secure, sameSite } = service.cookieOptions;

  await ctx.deleteCookie(service.cookieName, { extraOptions: { path, domain, secure, sameSite } });
}
