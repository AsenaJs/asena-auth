import { describe, expect, mock, test } from 'bun:test';
import { AUTH_SESSION_CONTEXT_KEY } from '@asenajs/asena/auth';
import type { AsenaAuthProvider, AuthSession } from '@asenajs/asena/auth';
import { HttpException } from '@asenajs/asena/adapter';
import { AuthGuardMiddleware } from '../lib/guard';
import type { GuardRouteMark } from '../lib/guard';

const session = (roles: string[] = []): AuthSession => ({
  user: { id: 'u1', roles },
  session: { id: 's1', userId: 'u1', createdAt: new Date(), expiresAt: new Date(Date.now() + 60_000) },
});

const makeCtx = (method: string, routePattern: string | undefined, preset?: AuthSession | null) => {
  const values = new Map<string, unknown>();

  if (preset !== undefined) {
    values.set(AUTH_SESSION_CONTEXT_KEY, preset);
  }

  return {
    req: new Request('http://localhost/x', { method }),
    routePattern,
    getValue: (key: string) => values.get(key),
    setValue: (key: string, value: unknown) => values.set(key, value),
    values,
  };
};

const setup = (marks: Record<string, GuardRouteMark>, resolved: AuthSession | null = session()) => {
  const provider: AsenaAuthProvider = {
    getSession: mock(async () => resolved),
    getRoles: mock((s: AuthSession) => s.user.roles ?? []),
  };
  const select = mock((_name?: string) => provider);
  const logger = { info: mock(), warn: mock(), error: mock(), profile: mock() };
  const middleware = new AuthGuardMiddleware();

  Object.assign(middleware as any, {
    guard: { marks: new Map(Object.entries(marks)) },
    registry: { select, providers: new Map() },
    logger,
  });

  return { middleware, provider, select, logger };
};

const mark = (extra: Partial<GuardRouteMark> = {}): GuardRouteMark => ({
  access: 'protected',
  controller: 'Users',
  method: 'list',
  ...extra,
});

const statusOf = async (promise: Promise<unknown>) => {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(HttpException);

    return (error as HttpException).status;
  }

  return 'no throw';
};

describe('AuthGuardMiddleware', () => {
  test('401 when the provider resolves no session, and next() is not called', async () => {
    const { middleware } = setup({ 'GET /users': mark() }, null);
    const ctx = makeCtx('GET', '/users');
    const next = mock(async () => {});

    expect(await statusOf(middleware.handle(ctx as any, next))).toBe(401);
    expect(next).not.toHaveBeenCalled();
    expect(ctx.values.get(AUTH_SESSION_CONTEXT_KEY)).toBeNull();
  });

  test('passes and stores the session when authenticated', async () => {
    const resolved = session();
    const { middleware, provider } = setup({ 'GET /users': mark() }, resolved);
    const ctx = makeCtx('GET', '/users');
    const next = mock(async () => {});

    await middleware.handle(ctx as any, next);

    expect(next).toHaveBeenCalledTimes(1);
    expect(ctx.values.get(AUTH_SESSION_CONTEXT_KEY)).toBe(resolved);
    expect((provider.getSession as any).mock.calls[0][0]).toBe(ctx.req);
  });

  test('normalizes the reported pattern (ergenecore keeps the trailing slash)', async () => {
    const { middleware } = setup({ 'GET /users': mark() });
    const next = mock(async () => {});

    await middleware.handle(makeCtx('GET', '/users/') as any, next);

    expect(next).toHaveBeenCalledTimes(1);
  });

  test('403 when the session has none of the required roles', async () => {
    const { middleware } = setup({ 'GET /users': mark({ roles: ['admin'] }) }, session(['user']));
    const next = mock(async () => {});

    expect(await statusOf(middleware.handle(makeCtx('GET', '/users') as any, next))).toBe(403);
    expect(next).not.toHaveBeenCalled();
  });

  test('roles are any-of, read through the provider', async () => {
    const { middleware, provider } = setup({ 'GET /users': mark({ roles: ['admin', 'ops'] }) }, session(['ops']));
    const next = mock(async () => {});

    await middleware.handle(makeCtx('GET', '/users') as any, next);

    expect(provider.getRoles).toHaveBeenCalledTimes(1);
    expect(next).toHaveBeenCalledTimes(1);
  });

  test('asks the provider the mark names', async () => {
    const { middleware, select } = setup({ 'GET /users': mark({ provider: 'AppBA' }) });

    await middleware.handle(
      makeCtx('GET', '/users') as any,
      mock(async () => {}),
    );

    expect(select).toHaveBeenCalledWith('AppBA');
  });

  test('a session already on the context is reused - the provider is not asked again', async () => {
    const preset = session();
    const { middleware, provider } = setup({ 'GET /users': mark() });
    const next = mock(async () => {});

    await middleware.handle(makeCtx('GET', '/users', preset) as any, next);

    expect(provider.getSession).not.toHaveBeenCalled();
    expect(next).toHaveBeenCalledTimes(1);
  });

  test('a null sentinel (resolved anonymous) is a 401 without asking the provider', async () => {
    const { middleware, provider } = setup({ 'GET /users': mark() });

    expect(
      await statusOf(
        middleware.handle(
          makeCtx('GET', '/users', null) as any,
          mock(async () => {}),
        ),
      ),
    ).toBe(401);
    expect(provider.getSession).not.toHaveBeenCalled();
  });

  test('HEAD on a guarded GET route is guarded by the GET mark', async () => {
    const { middleware } = setup({ 'GET /users': mark() }, null);

    expect(
      await statusOf(
        middleware.handle(
          makeCtx('HEAD', '/users') as any,
          mock(async () => {}),
        ),
      ),
    ).toBe(401);
  });

  test('an @All route is found under ALL for any request method', async () => {
    const { middleware } = setup({ 'ALL /any': mark() }, null);

    expect(
      await statusOf(
        middleware.handle(
          makeCtx('DELETE', '/any') as any,
          mock(async () => {}),
        ),
      ),
    ).toBe(401);
  });

  test('a route without a recorded mark fails closed: 500 and an error log naming the route', async () => {
    const { middleware, logger, provider } = setup({ 'GET /users': mark() });
    const next = mock(async () => {});

    expect(await statusOf(middleware.handle(makeCtx('POST', '/users') as any, next))).toBe(500);
    expect(next).not.toHaveBeenCalled();
    expect(provider.getSession).not.toHaveBeenCalled();
    expect(String(logger.error.mock.calls[0][0])).toContain('POST /users');
  });

  test('a context without routePattern fails closed too', async () => {
    const { middleware } = setup({ 'GET /users': mark() });

    expect(
      await statusOf(
        middleware.handle(
          makeCtx('GET', undefined) as any,
          mock(async () => {}),
        ),
      ),
    ).toBe(500);
  });
});
