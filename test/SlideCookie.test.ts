import { afterEach, describe, expect, setSystemTime, test } from 'bun:test';
import { Protected, Roles } from '@asenajs/asena/auth';
import { Config, Controller } from '@asenajs/asena/decorators';
import { Post } from '@asenajs/asena/decorators/http';
import { Inject } from '@asenajs/asena/decorators/ioc';
import { createTestApp, silentLogger } from '@asenajs/asena/test';
import { createErgenecoreAdapter } from '@asenajs/ergenecore';
import { createHonoAdapter } from '@asenajs/hono-adapter';
import {
  AsenaAuthService,
  Auth,
  AuthGuard,
  AuthGuardMiddleware,
  AuthProviderRegistry,
  AuthSessionMiddleware,
} from '../index';

@Auth({ sessionTtl: 100, absoluteTtl: 120 })
class SlideAuth extends AsenaAuthService {}

@Protected()
@Controller('/s')
class Slid {
  @Inject(SlideAuth)
  private readonly auth!: SlideAuth;

  @Post('/touch')
  touch(ctx: any) {
    return ctx.send({ ok: true });
  }

  @Post('/logout')
  async logout(ctx: any) {
    await this.auth.logout(ctx);

    return ctx.send({ ok: true });
  }

  @Post('/rotate')
  async rotate(ctx: any) {
    return ctx.send({ token: await this.auth.rotateSession(ctx) });
  }

  @Roles('admin')
  @Post('/admin')
  admin(ctx: any) {
    return ctx.send({ ok: true });
  }
}

@Config()
class GlobalSession {
  globalMiddlewares() {
    return [AuthSessionMiddleware];
  }
}

const adapters = [
  { name: 'ergenecore', make: () => createErgenecoreAdapter({ logger: silentLogger }) },
  { name: 'hono', make: () => createHonoAdapter({ logger: silentLogger })[0] },
];

afterEach(() => {
  setSystemTime();
});

describe.each(adapters)('slid session cookie on $name', ({ name, make }) => {
  describe.each([
    ['guard only', []],
    ['global AuthSessionMiddleware too', [GlobalSession]],
  ])('%s', (_case, extra) => {
    const boot = () =>
      createTestApp({
        adapter: make() as any,
        logger: silentLogger,
        components: [SlideAuth, Slid, ...extra],
        imports: [AuthGuard, AuthGuardMiddleware, AuthProviderRegistry, AuthSessionMiddleware],
      });

    const slidRequest = async (app: Awaited<ReturnType<typeof boot>>, path: string, elapsed: number) => {
      const auth = await app.resolve<SlideAuth>('SlideAuth');
      const t0 = Date.now();

      setSystemTime(new Date(t0));

      const { token, session } = await auth.createSession({ id: 'u1', roles: ['user'] });

      setSystemTime(new Date(t0 + elapsed * 1000));

      const res = await fetch(`${app.baseUrl}/s/${path}`, {
        method: 'POST',
        headers: { cookie: `asena_session=${token}` },
      });

      return { res, token, session, auth, setCookies: res.headers.getSetCookie().map((c) => Bun.Cookie.parse(c)) };
    };

    test('a slide re-issues the cookie once, its Max-Age capped at the remaining absolute lifetime', async () => {
      await using app = await boot();
      const { res, token, setCookies } = await slidRequest(app, 'touch', 60);

      expect(res.status).toBe(200);
      expect(setCookies).toHaveLength(1);
      expect(setCookies[0]?.value).toBe(token);
      expect(setCookies[0]?.maxAge).toBe(60);
    });

    test('logout in a request that slid answers with the deletion cookie only', async () => {
      await using app = await boot();
      const { res, setCookies } = await slidRequest(app, 'logout', 60);

      expect(res.status).toBe(200);
      expect(setCookies).toHaveLength(1);
      expect(setCookies[0]?.name).toBe('asena_session');
      expect(setCookies[0]?.value).toBe('');
    });

    test('rotateSession in a request that slid answers with the new cookie only', async () => {
      await using app = await boot();
      const { res, token, setCookies } = await slidRequest(app, 'rotate', 60);
      const { token: next } = (await res.json()) as { token: string };

      expect(next).not.toBe(token);
      expect(setCookies).toHaveLength(1);
      expect(setCookies[0]?.value).toBe(next);
    });

    test('a slid request the guard answers 403 still carries the re-issued cookie', async () => {
      await using app = await boot();
      const { res, token, setCookies } = await slidRequest(app, 'admin', 60);

      expect(res.status).toBe(403);

      // hono-adapter 5.0.2 builds its error response without the cookies the request had set.
      if (name === 'hono') {
        expect(setCookies).toEqual([]);

        return;
      }

      expect(setCookies).toHaveLength(1);
      expect(setCookies[0]?.value).toBe(token);
      expect(setCookies[0]?.maxAge).toBe(60);
    });
  });
});
