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

/** Writes raw `Set-Cookie` values through `ctx.setCookie`, the only cookie path both adapters support. */
export async function forwardSetCookies(ctx: AsenaContext<any, any>, setCookies: string[]): Promise<void> {
  for (const header of setCookies) {
    const { name, value, ...attributes } = Bun.Cookie.parse(header).toJSON();
    const extraOptions = Object.fromEntries(Object.entries(attributes).filter(([, v]) => v !== undefined));

    // Both adapters encodeURIComponent the value and Bun.Cookie.parse does not decode it.
    await ctx.setCookie(name, decodeURIComponent(value), { extraOptions });
  }
}

export async function clearSessionCookie(ctx: AsenaContext<any, any>, service: SessionCookieSource): Promise<void> {
  const { path, domain, secure, sameSite } = service.cookieOptions;

  await ctx.deleteCookie(service.cookieName, { extraOptions: { path, domain, secure, sameSite } });
}
