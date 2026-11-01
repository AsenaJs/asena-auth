import { describe, expect, test } from 'bun:test';
import { Protected, Roles, getAuthSession } from '@asenajs/asena/auth';
import { Controller, WebSocket as WebSocketNamespace } from '@asenajs/asena/decorators';
import { Get } from '@asenajs/asena/decorators/http';
import { createTestApp, createWebTest, silentLogger } from '@asenajs/asena/test';
import { AsenaWebSocketService } from '@asenajs/asena/web-socket';
import { createErgenecoreAdapter } from '@asenajs/ergenecore';
import { createHonoAdapter } from '@asenajs/hono-adapter';
import { AuthWebSocketMiddleware, authComponents } from '../index';
import { TestAuth, TestAuthProvider } from '../testing';
import { connect } from './wsClient';

const users = {
  ada: { id: 'u1', roles: ['admin'] },
  bob: { id: 'u2', roles: ['user'] },
};

@TestAuth({ users })
class AppTestAuth extends TestAuthProvider {}

@Protected()
@Controller('/me')
class Me {
  @Get('/')
  me(ctx: any) {
    return ctx.send({ user: getAuthSession(ctx)?.user.id });
  }

  @Roles('admin')
  @Get('/admin')
  admin(ctx: any) {
    return ctx.send({ admin: true });
  }
}

const adapters = [
  { name: 'ergenecore', make: () => createErgenecoreAdapter({ logger: silentLogger }) },
  { name: 'hono', make: () => createHonoAdapter({ logger: silentLogger })[0] },
];

describe.each(adapters)('TestAuthProvider under createWebTest on $name', ({ make }) => {
  test('the x-test-user header alone drives @Protected and @Roles', async () => {
    const { app } = await createWebTest({
      adapter: make(),
      logger: silentLogger,
      controllers: [Me],
      components: [...authComponents, AppTestAuth],
    });

    try {
      await app.get('/me').expectStatus(401);
      await app.get('/me', { headers: { 'x-test-user': 'nobody' } }).expectStatus(401);
      await app.get('/me', { headers: { 'x-test-user': 'constructor' } }).expectStatus(401);
      await app
        .get('/me', { headers: { 'x-test-user': 'ada' } })
        .expectStatus(200)
        .expectJson({ user: 'u1' });
      await app.get('/me/admin', { headers: { 'x-test-user': 'ada' } }).expectStatus(200);
      await app.get('/me/admin', { headers: { 'x-test-user': 'bob' } }).expectStatus(403);
    } finally {
      await app.stop();
    }
  });
});

describe.each(adapters)('TestAuthProvider under createTestApp on $name', ({ make }) => {
  @TestAuth({ users: { ada: users.ada }, primary: true })
  class PrimaryTestAuth extends TestAuthProvider {}

  @TestAuth({ users: { bob: users.bob }, name: 'Partner' })
  class PartnerTestAuth extends TestAuthProvider {}

  @Protected({ provider: 'Partner' })
  @Controller('/partner')
  class PartnerRoutes {
    @Get('/')
    me(ctx: any) {
      return ctx.send({ user: getAuthSession(ctx)?.user.id });
    }
  }

  @WebSocketNamespace({ path: '/chat', name: 'TestChat', middlewares: [AuthWebSocketMiddleware] })
  class Chat extends AsenaWebSocketService {
    protected onOpen(ws: any) {
      ws.send(JSON.stringify(ws.data.values));
    }
  }

  const boot = (components: any[]) =>
    createTestApp({ adapter: make() as any, logger: silentLogger, components, imports: [...authComponents] });

  test('the header drives @Protected and @Roles routes', async () => {
    await using app = await boot([AppTestAuth, Me]);
    const as = (key: string, path = '/me') => fetch(`${app.baseUrl}${path}`, { headers: { 'x-test-user': key } });

    expect((await fetch(`${app.baseUrl}/me`)).status).toBe(401);
    expect(await (await as('ada')).json()).toEqual({ user: 'u1' });
    expect((await as('ada', '/me/admin')).status).toBe(200);
    expect((await as('bob', '/me/admin')).status).toBe(403);
  });

  test('primary: true serves unnamed routes, name registers the provider a route can name', async () => {
    await using app = await boot([PrimaryTestAuth, PartnerTestAuth, Me, PartnerRoutes]);
    const as = (key: string, path: string) => fetch(`${app.baseUrl}${path}`, { headers: { 'x-test-user': key } });

    expect(await (await as('ada', '/me')).json()).toEqual({ user: 'u1' });
    expect((await as('bob', '/me')).status).toBe(401);
    expect(await (await as('bob', '/partner')).json()).toEqual({ user: 'u2' });
    expect((await as('ada', '/partner')).status).toBe(401);
  });

  test('a WebSocket route behind AuthWebSocketMiddleware opens for a known header only', async () => {
    await using app = await boot([AppTestAuth, Chat]);

    const opened = await connect(app.wsUrl('/chat'), { headers: { 'x-test-user': 'ada' } });

    expect(opened.opened).toBe(true);

    if (opened.opened) {
      expect(opened.message.authSession.user.id).toBe('u1');
    }

    expect(await connect(app.wsUrl('/chat'), { headers: { 'x-test-user': 'nobody' } })).toEqual({ opened: false });
    expect(await connect(app.wsUrl('/chat'))).toEqual({ opened: false });
  });
});

describe('TestAuthProvider', () => {
  test('the header name is configurable, and users is read on every request', async () => {
    const live: Record<string, { id: string }> = {};

    @TestAuth({ users: live, header: 'x-as' })
    class Custom extends TestAuthProvider {}

    const provider = new (Custom as any)() as TestAuthProvider;
    const as = (key: string, header = 'x-as') => new Request('http://localhost/', { headers: { [header]: key } });

    expect(await provider.getSession(as('carol'))).toBeNull();

    live.carol = { id: 'u3' };

    expect((await provider.getSession(as('carol')))?.user.id).toBe('u3');
    expect((await provider.getSession(as('carol')))?.session.userId).toBe('u3');
    expect(await provider.getSession(as('carol', 'x-test-user'))).toBeNull();
  });

  test('is published only as the testing subpath, never from the package entry', async () => {
    expect(Object.keys(await import('../index'))).not.toContain('TestAuthProvider');
    expect(Object.keys(await import('../index'))).not.toContain('TestAuth');
    const pkg = await Bun.file(new URL('../package.json', import.meta.url)).json();

    expect(pkg.exports['./testing']).toEqual({ types: './dist/testing.d.ts', import: './dist/testing.js' });
    expect(await Bun.file(new URL('../testing.ts', import.meta.url)).exists()).toBe(true);
  });
});
