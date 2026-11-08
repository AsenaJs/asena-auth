import { afterEach, describe, expect, setSystemTime, test } from 'bun:test';
import { Protected, Roles, getAuthSession } from '@asenajs/asena/auth';
import { Config, Controller, WebSocket as WebSocketNamespace } from '@asenajs/asena/decorators';
import { Post } from '@asenajs/asena/decorators/http';
import { Inject } from '@asenajs/asena/decorators/ioc';
import { createTestApp, silentLogger } from '@asenajs/asena/test';
import { AsenaWebSocketService } from '@asenajs/asena/web-socket';
import { createErgenecoreAdapter } from '@asenajs/ergenecore';
import { createHonoAdapter } from '@asenajs/hono-adapter';
import {
  AsenaAuthService,
  Auth,
  AuthGuard,
  AuthGuardMiddleware,
  AuthProviderRegistry,
  AuthSessionMiddleware,
  AuthWebSocketMiddleware,
  applySessionCookie,
  clearSessionCookie,
  hashToken,
} from '../index';
import { FAKE_ORIGIN, bootFake, contextShapes } from './support/fakeAdapter';

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
    const token = await this.auth.rotateSession(ctx);

    return ctx.send({ token, sessionId: getAuthSession(ctx)?.session.id });
  }

  @Post('/login')
  async login(ctx: any) {
    const { token } = await this.auth.createSession({ id: 'u2', roles: ['user'] });

    await applySessionCookie(ctx, this.auth, token);

    return ctx.send({ token });
  }

  @Post('/clear')
  async clear(ctx: any) {
    await clearSessionCookie(ctx, this.auth);

    return ctx.send({ ok: true });
  }

  @Roles('admin')
  @Post('/admin')
  admin(ctx: any) {
    return ctx.send({ ok: true });
  }
}

@WebSocketNamespace({ path: '/slid-chat', name: 'SlidChat', middlewares: [AuthWebSocketMiddleware] })
class SlidChat extends AsenaWebSocketService {
  protected onOpen(ws: any) {
    ws.send(JSON.stringify({ ok: true }));
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

const setups: [string, any[]][] = [
  ['guard only', []],
  ['global AuthSessionMiddleware too', [GlobalSession]],
];

const imports = [AuthGuard, AuthGuardMiddleware, AuthProviderRegistry, AuthSessionMiddleware];

type Send = (path: string, init: RequestInit) => Promise<Response>;

const slidRequest = async (
  app: { resolve: <T>(name: string) => Promise<T> },
  send: Send,
  { path, elapsed }: { path: string; elapsed: number },
) => {
  const auth = await app.resolve<SlideAuth>('SlideAuth');
  const t0 = Date.now();

  setSystemTime(new Date(t0));

  const { token, session } = await auth.createSession({ id: 'u1', roles: ['user'] });

  setSystemTime(new Date(t0 + elapsed * 1000));

  const res = await send(`/s/${path}`, { method: 'POST', headers: { cookie: `asena_session=${token}` } });

  return { res, token, session, auth, setCookies: res.headers.getSetCookie().map((c) => Bun.Cookie.parse(c)) };
};

afterEach(() => {
  setSystemTime();
});

describe.each(adapters)('slid session cookie on $name', ({ name, make }) => {
  describe.each(setups)('%s', (_case, extra) => {
    const boot = () =>
      createTestApp({ adapter: make() as any, logger: silentLogger, components: [SlideAuth, Slid, ...extra], imports });

    test('a slid request the guard answers 403 still carries the re-issued cookie', async () => {
      await using app = await boot();
      const send: Send = (path, init) => fetch(`${app.baseUrl}${path}`, init);
      const { res, token, setCookies } = await slidRequest(app, send, { path: 'admin', elapsed: 60 });

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

describe.each(contextShapes)('slid session cookie on the %s context', (shape) => {
  describe.each(setups)('%s', (_case, extra) => {
    const boot = () => bootFake({ shape, components: [SlideAuth, Slid, ...extra], imports });

    test('a slide re-issues the cookie once, its Max-Age capped at the remaining absolute lifetime', async () => {
      await using app = await boot();
      const { res, token, setCookies } = await slidRequest(app, app.fetch, { path: 'touch', elapsed: 60 });

      expect(res.status).toBe(200);
      expect(setCookies).toHaveLength(1);
      expect(setCookies[0]?.value).toBe(token);
      expect(setCookies[0]?.maxAge).toBe(60);
    });

    test('logout in a request that slid answers with the deletion cookie only', async () => {
      await using app = await boot();
      const { res, setCookies } = await slidRequest(app, app.fetch, { path: 'logout', elapsed: 60 });

      expect(res.status).toBe(200);
      expect(setCookies).toHaveLength(1);
      expect(setCookies[0]?.name).toBe('asena_session');
      expect(setCookies[0]?.value).toBe('');
    });

    test('rotateSession in a request that slid answers with the new cookie only', async () => {
      await using app = await boot();
      const { res, token, setCookies } = await slidRequest(app, app.fetch, { path: 'rotate', elapsed: 60 });
      const { token: next, sessionId } = (await res.json()) as { token: string; sessionId: string };

      expect(next).not.toBe(token);
      expect(setCookies).toHaveLength(1);
      expect(setCookies[0]?.value).toBe(next);
      expect(sessionId).toBe(hashToken(next));
    });

    test('a handler that logs in another user in a slid request answers with its new cookie only', async () => {
      await using app = await boot();
      const { res, token, setCookies } = await slidRequest(app, app.fetch, { path: 'login', elapsed: 60 });
      const { token: next } = (await res.json()) as { token: string };

      expect(next).not.toBe(token);
      expect(setCookies).toHaveLength(1);
      expect(setCookies[0]?.value).toBe(next);
    });

    test('clearSessionCookie in a slid request answers with the deletion cookie only', async () => {
      await using app = await boot();
      const { res, setCookies } = await slidRequest(app, app.fetch, { path: 'clear', elapsed: 60 });

      expect(res.status).toBe(200);
      expect(setCookies).toHaveLength(1);
      expect(setCookies[0]?.name).toBe('asena_session');
      expect(setCookies[0]?.value).toBe('');
    });

    test('a WebSocket upgrade whose cookie session slides still opens, and the slide is stored', async () => {
      await using app = await bootFake({
        shape,
        components: [SlideAuth, SlidChat, ...extra],
        imports: [AuthProviderRegistry, AuthSessionMiddleware, AuthWebSocketMiddleware],
      });
      const auth = await app.resolve<SlideAuth>('SlideAuth');
      const t0 = Date.now();

      setSystemTime(new Date(t0));

      const { token, session } = await auth.createSession({ id: 'u1' });

      setSystemTime(new Date(t0 + 60_000));

      const ws = await app.connect('/slid-chat', {
        headers: { cookie: `asena_session=${token}`, origin: FAKE_ORIGIN },
      });

      expect(ws.opened).toBe(true);
      expect((await auth.listUserSessions('u1'))[0]?.session.expiresAt.getTime()).toBe(
        session.session.createdAt.getTime() + 120_000,
      );
    });
  });
});
