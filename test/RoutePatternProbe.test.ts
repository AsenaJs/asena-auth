import { describe, expect, test } from 'bun:test';
import { Controller, Middleware } from '@asenajs/asena/decorators';
import { All, Get, Post } from '@asenajs/asena/decorators/http';
import { ComponentConstants } from '@asenajs/asena/ioc/constants';
import { AsenaMiddlewareService } from '@asenajs/asena/middleware';
import { createTestApp, silentLogger } from '@asenajs/asena/test';
import { getChainedTypedMetadata, getOwnTypedMetadata } from '@asenajs/asena/utils';
import { Context as ErgeneContext, createErgenecoreAdapter } from '@asenajs/ergenecore';
import { Context as HonoContext, createHonoAdapter } from '@asenajs/hono-adapter';
import { z } from 'zod';
import { requestKeys, routeKey } from '../lib/guard/routeKey';
import { getRawRequest } from '../lib/helpers';

/**
 * The guard finds a route's mark by `METHOD + ctx.routePattern` at request time, against a key
 * computed from route metadata at post-process time. This pins, per adapter, what `routePattern`
 * really is and that both sides meet after normalization - an adapter change fails here first.
 */

let seen: { raw: string; keys: string[] }[] = [];

@Middleware()
class Probe extends AsenaMiddlewareService {
  public async handle(ctx: any, next: () => Promise<void>) {
    seen.push({ raw: `${getRawRequest(ctx).method} ${ctx.routePattern}`, keys: requestKeys(ctx) });
    await next();
  }
}

@Controller('/api/users')
class Users {
  @Get({ path: '/', middlewares: [Probe] })
  list(ctx: any) {
    return ctx.send('list');
  }

  @Get({ path: '/:id', middlewares: [Probe] })
  one(ctx: any) {
    return ctx.send('one');
  }

  @Post({ path: '/', middlewares: [Probe] })
  create(ctx: any) {
    return ctx.send('create');
  }

  @Get({ path: '/x/', middlewares: [Probe] })
  trailing(ctx: any) {
    return ctx.send('trailing');
  }

  @All({ path: '/any', middlewares: [Probe] })
  any(ctx: any) {
    return ctx.send('any');
  }
}

@Controller('/api/admins')
class Admins extends Users {}

@Controller('/api/slash')
class NoTrailing {
  @Get({ path: '/x', middlewares: [Probe] })
  x(ctx: any) {
    return ctx.send('x');
  }
}

@Controller('plain')
class NoLeadingSlash {
  @Get({ path: 'y', middlewares: [Probe] })
  y(ctx: any) {
    return ctx.send('y');
  }
}

class ErgeneBody extends ErgeneContext.define({ body: z.object({ name: z.string() }) }) {}

class HonoBody extends HonoContext.define({ body: z.object({ name: z.string() }) }) {}

@Controller('/contract')
class ErgeneContract {
  @Post({ path: '/:id', middlewares: [Probe] })
  create(ctx: ErgeneBody) {
    return ctx.send({ name: ctx.input.body.name });
  }
}

@Controller('/contract')
class HonoContract {
  @Post({ path: '/:id', middlewares: [Probe] })
  create(ctx: HonoBody) {
    return ctx.send({ name: ctx.input.body.name });
  }
}

const keyOf = (Class: Function, method: string) => {
  const route = getChainedTypedMetadata<any>(ComponentConstants.RouteKey, Class)[method];

  return routeKey(route.method, getOwnTypedMetadata<string>(ComponentConstants.PathKey, Class) ?? '', route.path);
};

type Case = [
  label: string,
  method: string,
  url: string,
  Class: Function,
  handler: string,
  ergene: string,
  hono: string,
];

const cases: Case[] = [
  ['root route', 'GET', '/api/users', Users, 'list', 'GET /api/users/', 'GET /api/users'],
  ['param route', 'GET', '/api/users/7', Users, 'one', 'GET /api/users/:id', 'GET /api/users/:id'],
  ['POST with route middlewares', 'POST', '/api/users', Users, 'create', 'POST /api/users/', 'POST /api/users'],
  ['trailing-slash route', 'GET', '/api/users/x', Users, 'trailing', 'GET /api/users/x/', 'GET /api/users/x'],
  ['inherited root route', 'GET', '/api/admins', Admins, 'list', 'GET /api/admins/', 'GET /api/admins'],
  ['inherited param route', 'GET', '/api/admins/7', Admins, 'one', 'GET /api/admins/:id', 'GET /api/admins/:id'],
  [
    'no trailing slash (separate controller)',
    'GET',
    '/api/slash/x',
    NoTrailing,
    'x',
    'GET /api/slash/x',
    'GET /api/slash/x',
  ],
  ['HEAD on a GET route', 'HEAD', '/api/users/7', Users, 'one', 'HEAD /api/users/:id', 'HEAD /api/users/:id'],
  ['@All route, GET', 'GET', '/api/users/any', Users, 'any', 'GET /api/users/any', 'GET /api/users/any'],
  ['@All route, DELETE', 'DELETE', '/api/users/any', Users, 'any', 'DELETE /api/users/any', 'DELETE /api/users/any'],
];

const adapters = [
  {
    name: 'ergenecore',
    make: () => createErgenecoreAdapter({ logger: silentLogger }),
    Contract: ErgeneContract,
    extra: [] as Function[],
  },
  {
    name: 'hono',
    make: () => createHonoAdapter({ logger: silentLogger })[0],
    Contract: HonoContract,
    extra: [NoLeadingSlash] as Function[],
  },
];

describe.each(adapters)('routePattern on $name', ({ name, make, Contract, extra }) => {
  const boot = () =>
    createTestApp({
      adapter: make(),
      logger: silentLogger,
      components: [Probe, Users, Admins, NoTrailing, Contract, ...(extra as any[])],
    });

  test.each(cases)('%s', async (_label, method, url, Class, handler, ergene, hono) => {
    await using app = await boot();

    seen = [];

    const res = await fetch(`${app.baseUrl}${url}`, { method });

    expect(res.status).toBe(200);
    expect(seen).toHaveLength(1);
    expect(seen[0].raw).toBe(name === 'hono' ? hono : ergene);
    expect(seen[0].keys).toContain(keyOf(Class, handler));
  });

  test('Context.define route: a contract context still carries routePattern and the raw request', async () => {
    await using app = await boot();

    seen = [];

    const res = await fetch(`${app.baseUrl}/contract/1`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'a' }),
    });

    expect(res.status).toBe(200);
    expect(seen[0].raw).toBe('POST /contract/:id');
    expect(seen[0].keys).toContain(keyOf(Contract, 'create'));
  });

  if (name === 'hono') {
    test('a prefix without a leading slash: hono adds one, the key normalizes the same way', async () => {
      await using app = await boot();

      seen = [];

      const res = await fetch(`${app.baseUrl}/plain/y`);

      expect(res.status).toBe(200);
      expect(seen[0].raw).toBe('GET /plain/y');
      expect(seen[0].keys).toContain(keyOf(NoLeadingSlash, 'y'));
    });
  }
});
