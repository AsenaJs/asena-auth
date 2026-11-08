import { describe, expect, test } from 'bun:test';
import { AUTH_GUARD_CLASS_KEY, AUTH_GUARD_METHODS_KEY, Protected } from '@asenajs/asena/auth';
import { Controller } from '@asenajs/asena/decorators';
import { Get } from '@asenajs/asena/decorators/http';
import { createTestApp, silentLogger } from '@asenajs/asena/test';
import { defineTypedMetadata } from '@asenajs/asena/utils';
import { createErgenecoreAdapter } from '@asenajs/ergenecore';
import { createHonoAdapter } from '@asenajs/hono-adapter';
import { AsenaAuthService, Auth, AuthGuard, AuthGuardMiddleware, AuthProviderRegistry } from '../index';
import { bootFake, contextShapes } from './support/fakeAdapter';

@Auth({})
class MarkAuth extends AsenaAuthService {}

const adapters = [
  { name: 'ergenecore', make: () => createErgenecoreAdapter({ logger: silentLogger }) },
  { name: 'hono', make: () => createHonoAdapter({ logger: silentLogger })[0] },
];

describe.each(adapters)('guard marks at boot on $name', ({ make }) => {
  const boot = (components: any[]) =>
    createTestApp({
      adapter: make() as any,
      logger: silentLogger,
      components,
      imports: [AuthGuard, AuthGuardMiddleware, AuthProviderRegistry],
    });

  test.each([
    ['class', { access: 'restricted' }, "access 'restricted'"],
    ['method', { access: 'restricted' }, "access 'restricted'"],
    ['class', { access: 'protected', permissions: ['read'] }, "key 'permissions'"],
    ['method', { access: 'protected', permissions: ['read'] }, "key 'permissions'"],
  ] as const)('a %s mark %j this version cannot enforce fails the boot', async (level, mark, what) => {
    @Controller('/forged')
    class Forged {
      @Get('/')
      get(ctx: any) {
        return ctx.send('x');
      }
    }

    if (level === 'class') {
      defineTypedMetadata(AUTH_GUARD_CLASS_KEY, mark, Forged);
    } else {
      defineTypedMetadata(AUTH_GUARD_METHODS_KEY, new Map([['get', mark]]), Forged);
    }

    const error: any = await boot([MarkAuth, Forged]).then(
      async (app) => {
        await app.stop();

        return null;
      },
      (e) => e,
    );
    const messages: string[] = [];

    for (let e = error; e; e = e.cause) {
      messages.push(String(e.message));
    }

    expect(messages.join(' <- ')).toContain(what);
    expect(messages.join(' <- ')).toContain('upgrade @asenajs/asena-auth');
  });
});

describe.each(contextShapes)('guard marks at boot on the %s context', (shape) => {
  test('@Protected({ provider: undefined }) boots and guards like @Protected()', async () => {
    @Protected({ provider: undefined })
    @Controller('/plain')
    class Plain {
      @Get('/')
      get(ctx: any) {
        return ctx.send('ok');
      }
    }

    await using app = await bootFake({
      shape,
      components: [MarkAuth, Plain],
      imports: [AuthGuard, AuthGuardMiddleware, AuthProviderRegistry],
    });
    const auth = await app.resolve<MarkAuth>('MarkAuth');
    const { token } = await auth.createSession({ id: 'u1' });

    expect((await app.fetch('/plain')).status).toBe(401);
    expect((await app.fetch('/plain', { headers: { authorization: `Bearer ${token}` } })).status).toBe(200);
  });
});
