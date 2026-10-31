import { afterEach, describe, expect, test } from 'bun:test';
import { Protected, Public, Roles, getAuthSession } from '@asenajs/asena/auth';
import { Controller, Middleware } from '@asenajs/asena/decorators';
import { Get, Post } from '@asenajs/asena/decorators/http';
import { AsenaMiddlewareService } from '@asenajs/asena/middleware';
import { createTestApp, silentLogger } from '@asenajs/asena/test';
import { ValidationService, createErgenecoreAdapter } from '@asenajs/ergenecore';
import { z } from 'zod';
import { AsenaAuthService } from '../lib/AsenaAuthService';
import { Auth } from '../lib/decorators';
import { AuthGuard, AuthGuardMiddleware, AuthProviderRegistry } from '../lib/guard';

const calls: string[] = [];

@Auth({ sessionTtl: 3600 })
class AppAuth extends AsenaAuthService {}

@Middleware({ validator: true })
class ItemValidator extends ValidationService {
  json() {
    return z.object({ name: z.string() }).superRefine(() => {
      calls.push('validator');
    });
  }
}

@Middleware()
class Recorder extends AsenaMiddlewareService {
  async handle(_ctx: any, next: () => Promise<void>) {
    calls.push('recorder');
    await next();
  }
}

@Protected()
@Controller('/items')
class Items {
  @Get('/')
  list(ctx: any) {
    return ctx.send({ user: getAuthSession(ctx)?.user.id });
  }

  @Post({ path: '/', validator: ItemValidator, middlewares: [Recorder] })
  create(ctx: any) {
    calls.push('handler');

    return ctx.send({ ok: true });
  }

  @Public()
  @Get('/public')
  open(ctx: any) {
    return ctx.send({ open: true });
  }

  @Roles('admin')
  @Get('/admin')
  admin(ctx: any) {
    return ctx.send({ admin: true });
  }
}

@Protected()
@Controller('/users')
class Users {
  @Get('/')
  list(ctx: any) {
    return ctx.send('users');
  }
}

@Public()
@Controller('/open-users')
class OpenUsers extends Users {}

afterEach(() => {
  calls.length = 0;
});

const boot = () =>
  createTestApp({
    adapter: createErgenecoreAdapter({ logger: silentLogger }),
    logger: silentLogger,
    components: [AppAuth, ItemValidator, Recorder, Items, Users, OpenUsers],
    imports: [AuthGuard, AuthGuardMiddleware, AuthProviderRegistry],
  });

const tokenFor = async (app: Awaited<ReturnType<typeof boot>>, roles: string[] = []) => {
  const auth = await app.resolve<AppAuth>('AppAuth');

  return (await auth.createSession({ id: 'u1', roles })).token;
};

const auth = (token: string) => ({ authorization: `Bearer ${token}` });

describe('guard on ergenecore', () => {
  test('401 anonymous, 200 with a Bearer token, the session reaches the handler', async () => {
    await using app = await boot();
    const token = await tokenFor(app);

    expect((await fetch(`${app.baseUrl}/items`)).status).toBe(401);

    const res = await fetch(`${app.baseUrl}/items`, { headers: auth(token) });

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ user: 'u1' });
  });

  test('an anonymous request never reaches the route middlewares, the validator or the handler', async () => {
    await using app = await boot();

    const res = await fetch(`${app.baseUrl}/items`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'x' }),
    });

    expect(res.status).toBe(401);
    expect(calls).toEqual([]);
  });

  test('authenticated: route middleware, then validator, then handler', async () => {
    await using app = await boot();
    const token = await tokenFor(app);

    const res = await fetch(`${app.baseUrl}/items`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...auth(token) },
      body: JSON.stringify({ name: 'x' }),
    });

    expect(res.status).toBe(200);
    expect(calls).toEqual(['recorder', 'validator', 'handler']);
  });

  test('@Public method on a @Protected controller is open', async () => {
    await using app = await boot();

    expect((await fetch(`${app.baseUrl}/items/public`)).status).toBe(200);
  });

  test('@Roles: 403 without the role, 200 with it', async () => {
    await using app = await boot();

    expect((await fetch(`${app.baseUrl}/items/admin`, { headers: auth(await tokenFor(app, ['user'])) })).status).toBe(
      403,
    );
    expect((await fetch(`${app.baseUrl}/items/admin`, { headers: auth(await tokenFor(app, ['admin'])) })).status).toBe(
      200,
    );
  });

  test('HEAD on a protected GET route is guarded, not a 500', async () => {
    await using app = await boot();

    expect((await fetch(`${app.baseUrl}/items`, { method: 'HEAD' })).status).toBe(401);
  });

  test('@Public subclass of a @Protected controller is open while the base stays guarded', async () => {
    await using app = await boot();

    expect((await fetch(`${app.baseUrl}/users`)).status).toBe(401);
    expect((await fetch(`${app.baseUrl}/open-users`)).status).toBe(200);
  });
});
