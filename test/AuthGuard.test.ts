import { describe, expect, mock, test } from 'bun:test';
import { Protected, Public, Roles } from '@asenajs/asena/auth';
import { Controller, Middleware, Service } from '@asenajs/asena/decorators';
import { Get, Post } from '@asenajs/asena/decorators/http';
import { ComponentConstants } from '@asenajs/asena/ioc/constants';
import { AsenaMiddlewareService } from '@asenajs/asena/middleware';
import { getChainedTypedMetadata, getOwnTypedMetadata } from '@asenajs/asena/utils';
import { AuthGuard, AuthGuardMiddleware } from '../lib/guard';
import { AUTH_GUARD_MIDDLEWARE_NAME } from '../lib/types';

@Middleware()
class Mw extends AsenaMiddlewareService {
  async handle(_ctx: any, next: () => Promise<void>) {
    await next();
  }
}

const makeGuard = () => {
  const guard = new AuthGuard();
  const logger = { info: mock(), warn: mock(), error: mock(), profile: mock() };

  (guard as any).logger = logger;

  return { guard, logger };
};

const own = (Class: Function) => getOwnTypedMetadata<Record<string, any>>(ComponentConstants.RouteKey, Class) ?? {};

const chained = (Class: Function) => getChainedTypedMetadata<any>(ComponentConstants.RouteKey, Class);

const hasGuard = (entry: any) => entry.middlewares.includes(AuthGuardMiddleware);

describe('AuthGuard.postProcess', () => {
  test('prepends the guard middleware to protected routes only, before the user route middlewares', async () => {
    @Protected()
    @Controller('/c')
    class C {
      @Get('/')
      list() {}

      @Public()
      @Get('/pub')
      pub() {}

      @Roles('admin')
      @Get('/admin')
      admin() {}

      @Post({ path: '/mw', middlewares: [Mw] })
      withMw() {}
    }

    const { guard } = makeGuard();
    const instance = new C();

    expect(await guard.postProcess(instance, C)).toBe(instance);

    const routes = own(C);

    expect(routes.list.middlewares).toEqual([AuthGuardMiddleware]);
    expect(routes.admin.middlewares).toEqual([AuthGuardMiddleware]);
    expect(routes.withMw.middlewares).toEqual([AuthGuardMiddleware, Mw]);
    expect(routes.pub.middlewares).toEqual([]);
    expect(routes.withMw.path).toBe('mw');
    expect(routes.withMw.method).toBe('post');
  });

  test('records a mark per protected route, keyed like the adapter reports it', async () => {
    @Protected({ provider: 'Native' })
    @Controller('/c')
    class C {
      @Get('/')
      list() {}

      @Public()
      @Get('/pub')
      pub() {}

      @Roles('admin')
      @Get('/admin')
      admin() {}
    }

    const { guard } = makeGuard();

    await guard.postProcess(new C(), C);

    expect([...guard.marks.keys()].sort()).toEqual(['GET /c', 'GET /c/admin']);
    expect(guard.marks.get('GET /c')).toEqual({
      access: 'protected',
      provider: 'Native',
      controller: 'C',
      method: 'list',
    });
    expect(guard.marks.get('GET /c/admin')).toEqual({
      access: 'protected',
      roles: ['admin'],
      provider: 'Native',
      controller: 'C',
      method: 'admin',
    });
  });

  test('keeps every other field of the route entry (validator, summary, ...)', async () => {
    @Middleware({ validator: true })
    class V {
      json() {
        return {};
      }
    }

    @Controller('/c')
    class C {
      @Protected()
      @Post({ path: '/', validator: V as any, summary: 'Create', description: 'Creates', middlewares: [Mw] })
      create() {}
    }

    const before = { ...chained(C).create };
    const { guard } = makeGuard();

    await guard.postProcess(new C(), C);

    expect(own(C).create).toEqual({ ...before, middlewares: [AuthGuardMiddleware, Mw] });
  });

  test('declares the guard middleware as a soft dependency of the controller', async () => {
    @Protected()
    @Controller('/c')
    class C {
      @Get('/')
      list() {}
    }

    const { guard } = makeGuard();

    await guard.postProcess(new C(), C);

    expect(getOwnTypedMetadata<Record<string, string>>(ComponentConstants.SoftDependencyKey, C)).toMatchObject({
      [AUTH_GUARD_MIDDLEWARE_NAME]: AUTH_GUARD_MIDDLEWARE_NAME,
    });
  });

  test('a controller without guard metadata anywhere in its chain is left untouched', async () => {
    @Controller('/open')
    class Open {
      @Get({ path: '/', middlewares: [Mw] })
      list() {}
    }

    const routesBefore = own(Open);
    const entryBefore = routesBefore.list;
    const { guard } = makeGuard();

    await guard.postProcess(new Open(), Open);

    expect(own(Open)).toBe(routesBefore);
    expect(own(Open).list).toBe(entryBefore);
    expect(guard.marks.size).toBe(0);
  });

  test('an inherited route gets its own guarded entry on the subclass, under the subclass prefix', async () => {
    @Protected()
    @Controller('/users')
    class Users {
      @Get('/:id')
      one() {}
    }

    @Controller('/admins')
    class Admins extends Users {}

    const { guard } = makeGuard();

    await guard.postProcess(new Admins(), Admins);

    expect(Object.keys(own(Admins))).toEqual(['one']);
    expect(hasGuard(own(Admins).one)).toBe(true);
    expect(guard.marks.get('GET /admins/:id')).toMatchObject({ controller: 'Admins', method: 'one' });
  });

  const publicSubclassOfProtectedBase = () => {
    @Protected()
    @Controller('/users')
    class Users {
      @Get('/')
      list() {}

      @Get({ path: '/:id', middlewares: [Mw] })
      one() {}
    }

    @Public()
    @Controller('/open-users')
    class OpenUsers extends Users {}

    return { Users, OpenUsers };
  };

  test.each([
    ['base first', true],
    ['subclass first', false],
  ])('@Public subclass of a @Protected base stays public (%s)', async (_label, baseFirst) => {
    const { Users, OpenUsers } = publicSubclassOfProtectedBase();
    const { guard } = makeGuard();
    const order = baseFirst ? [Users, OpenUsers] : [OpenUsers, Users];

    for (const Class of order) {
      await guard.postProcess(new (Class as any)(), Class);
    }

    for (const entry of Object.values(chained(OpenUsers))) {
      expect(hasGuard(entry)).toBe(false);
    }

    expect(chained(OpenUsers).one.middlewares).toEqual([Mw]);

    for (const entry of Object.values(chained(Users))) {
      expect(hasGuard(entry)).toBe(true);
    }

    expect([...guard.marks.keys()].sort()).toEqual(['GET /users', 'GET /users/:id']);
  });

  test.each([
    ['base first', true],
    ['subclass first', false],
  ])('@Protected subclass of a @Public base guards only the subclass (%s)', async (_label, baseFirst) => {
    @Public()
    @Controller('/open')
    class Open {
      @Get('/')
      list() {}
    }

    @Protected()
    @Controller('/closed')
    class Closed extends Open {}

    const { guard } = makeGuard();
    const order = baseFirst ? [Open, Closed] : [Closed, Open];

    for (const Class of order) {
      await guard.postProcess(new (Class as any)(), Class);
    }

    expect(hasGuard(chained(Closed).list)).toBe(true);
    expect(hasGuard(chained(Open).list)).toBe(false);
    expect([...guard.marks.keys()]).toEqual(['GET /closed']);
  });

  test('a non-controller carrying a guard mark is skipped with a warning', async () => {
    @Protected()
    @Service()
    class NotAController {}

    const { guard, logger } = makeGuard();
    const instance = new NotAController();

    expect(await guard.postProcess(instance, NotAController)).toBe(instance);
    expect(logger.warn).toHaveBeenCalledTimes(1);
    expect(String(logger.warn.mock.calls[0][0])).toContain('NotAController');
    expect(guard.marks.size).toBe(0);
  });

  test('a non-controller without guard marks is skipped silently', async () => {
    @Service()
    class Plain {}

    const { guard, logger } = makeGuard();

    await guard.postProcess(new Plain(), Plain);

    expect(logger.warn).not.toHaveBeenCalled();
  });

  test('post-processing the same class twice yields the same entries', async () => {
    @Protected()
    @Controller('/c')
    class C {
      @Get({ path: '/', middlewares: [Mw] })
      list() {}
    }

    const { guard } = makeGuard();

    await guard.postProcess(new C(), C);

    const first = structuredClone(Object.keys(own(C)));
    const firstMw = [...own(C).list.middlewares];

    await guard.postProcess(new C(), C);

    expect(Object.keys(own(C))).toEqual(first);
    expect(own(C).list.middlewares).toEqual(firstMw);
    expect(own(C).list.middlewares).toEqual([AuthGuardMiddleware, Mw]);
    expect(guard.marks.size).toBe(1);
  });
});
