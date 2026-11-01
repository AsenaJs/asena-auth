import type { AsenaContext } from '@asenajs/asena/adapter';
import { getRawRequest } from '../helpers/context';

/** Leading slash, no duplicate or trailing slash: ergenecore reports `/a/`, hono `/a` for the same route. */
export function normalizeRoutePath(routePath: string): string {
  const slashed = `/${routePath}`.replace(/\/{2,}/g, '/');

  return slashed.length > 1 ? slashed.replace(/\/+$/, '') : slashed;
}

/** The key of a route as registered: controller prefix + route path, normalized like a reported pattern. */
export function routeKey(method: string, prefix: string, routePath: string): string {
  return `${method.toUpperCase()} ${normalizeRoutePath(`${prefix}/${routePath}`.replace(/\\/g, '/'))}`;
}

/**
 * Candidate keys for the matched route of a request, most specific first. `HEAD` is served by a
 * `GET` route and an `@All` route reports the concrete request method, on both adapters.
 */
export function requestKeys(ctx: AsenaContext<any, any>): string[] {
  const pattern = ctx.routePattern;

  if (typeof pattern !== 'string') {
    return [];
  }

  const method = getRawRequest(ctx).method.toUpperCase();
  const routePath = normalizeRoutePath(pattern);
  const keys = [`${method} ${routePath}`];

  if (method === 'HEAD') {
    keys.push(`GET ${routePath}`);
  }

  keys.push(`ALL ${routePath}`);

  return keys;
}
