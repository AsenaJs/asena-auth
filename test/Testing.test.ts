import { describe, expect, test } from 'bun:test';
import { Protected, Roles, getAuthSession } from '@asenajs/asena/auth';
import { Controller } from '@asenajs/asena/decorators';
import { Get } from '@asenajs/asena/decorators/http';
import { createWebTest, silentLogger } from '@asenajs/asena/test';
import { createErgenecoreAdapter } from '@asenajs/ergenecore';
import { createHonoAdapter } from '@asenajs/hono-adapter';
import { authComponents } from '../index';
import { TestAuth, TestAuthProvider } from '../testing';

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
