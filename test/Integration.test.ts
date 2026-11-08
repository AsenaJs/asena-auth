import { afterEach, describe, expect, test } from 'bun:test';
import {
  AUTH_GUARD_CLASS_KEY,
  AUTH_GUARD_METHODS_KEY,
  AUTH_PROVIDER_KEY,
  Protected,
  Public,
  Roles,
  getAuthSession,
} from '@asenajs/asena/auth';
import type { AsenaAuthProvider, AuthSession } from '@asenajs/asena/auth';
import { Config, Controller, Middleware, Service, WebSocket as WebSocketNamespace } from '@asenajs/asena/decorators';
import { Get, Post } from '@asenajs/asena/decorators/http';
import { Implements, Inject } from '@asenajs/asena/decorators/ioc';
import { AsenaMiddlewareService } from '@asenajs/asena/middleware';
import { createTestApp, silentLogger } from '@asenajs/asena/test';
import { defineTypedMetadata } from '@asenajs/asena/utils';
import { AsenaWebSocketService } from '@asenajs/asena/web-socket';
import {
  Context as ErgeneContext,
  ValidationService as ErgeneValidation,
  createErgenecoreAdapter,
} from '@asenajs/ergenecore';
import { Context as HonoContext, ValidationService as HonoValidation, createHonoAdapter } from '@asenajs/hono-adapter';
import { z } from 'zod';
import {
  AsenaAuthService,
  Auth,
  AuthGuard,
  AuthGuardMiddleware,
  AuthProviderRegistry,
  AuthSessionMiddleware,
  AuthWebSocketMiddleware,
  BetterAuth,
  BetterAuthController,
  BetterAuthService,
  applySessionCookie,
  authComponents,
} from '../index';
import type { BetterAuthInstance } from '../index';
import { FAKE_ORIGIN, bootFake, contextShapes } from './support/fakeAdapter';
import { stringFields } from './support/schema';
import { connect } from './wsClient';

const calls: string[] = [];

afterEach(() => {
  calls.length = 0;
});

const hour = 3_600_000;

const mockBetterAuth: BetterAuthInstance = {
  handler: async (req) =>
    new Response(JSON.stringify({ path: new URL(req.url).pathname, method: req.method }), { status: 201 }),
  api: {
    getSession: async ({ headers }) => {
      if (headers.get('authorization') !== 'Bearer ba-token') {
        return { headers: new Headers(), response: null };
      }

      const refreshed = new Headers();

      if (headers.get('x-refresh') === '1') {
        refreshed.append('set-cookie', baRefreshCookie);
      }

      return {
        headers: refreshed,
        response: {
          session: { id: 'bs1', userId: 'b1', createdAt: new Date(), expiresAt: new Date(Date.now() + hour) },
          user: { id: 'b1', role: 'admin,user' },
        },
      };
    },
  },
};

const baRefreshCookie = 'better-auth.session_token=ba-token.sig%2Bx%3D; Max-Age=604800; Path=/; HttpOnly; SameSite=Lax';

@Auth({ primary: true, sessionTtl: 3600, csrf: { trustedOrigins: ['https://app.example'] } })
class AppAuth extends AsenaAuthService {
  public override async getSession(request: Request) {
    calls.push('provider');

    return super.getSession(request);
  }
}

@BetterAuth({ auth: mockBetterAuth })
class AppBA extends BetterAuthService {}

@Service('Keycloak')
@Implements(AUTH_PROVIDER_KEY)
class Keycloak implements AsenaAuthProvider {
  async getSession(request: Request): Promise<AuthSession | null> {
    if (request.headers.get('authorization') !== 'Bearer kc-token') {
      return null;
    }

    return {
      user: { id: 'kc1' },
      session: { id: 'kcs', userId: 'kc1', createdAt: new Date(), expiresAt: new Date(Date.now() + hour) },
    };
  }

  getRoles(): string[] {
    return [];
  }
}

@Controller('/auth')
class Login {
  @Inject(AppAuth)
  private readonly auth!: AppAuth;

  @Post('/login')
  async login(ctx: any) {
    const { id, roles } = await ctx.getBody();
    const { token } = await this.auth.createSession({ id, roles });

    await applySessionCookie(ctx, this.auth, token);

    return ctx.send({ token });
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
}

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

  @Public()
  @Get('/public')
  open(ctx: any) {
    return ctx.send({ user: getAuthSession(ctx)?.user.id ?? null });
  }
}

@Protected({ provider: 'AppBA' })
@Controller('/ba')
class BaRoutes {
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

@Protected({ provider: 'Keycloak' })
@Controller('/kc')
class KcRoutes {
  @Get('/')
  me(ctx: any) {
    return ctx.send({ user: getAuthSession(ctx)?.user.id });
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

@Controller('/api/auth')
class AuthCtrl extends BetterAuthController {
  @Inject(AppBA)
  protected readonly authService!: AppBA;
}

@WebSocketNamespace({ path: '/chat', name: 'Chat', middlewares: [AuthWebSocketMiddleware] })
class Chat extends AsenaWebSocketService {
  protected onOpen(ws: any) {
    ws.send(JSON.stringify(ws.data.values));
  }
}

@Config()
class SessionConfig {
  globalMiddlewares() {
    return [AuthSessionMiddleware];
  }
}

const sharedComponents = [AppAuth, AppBA, Keycloak, Login, Me, BaRoutes, KcRoutes, Users, OpenUsers, AuthCtrl, Chat];

const adapterRoutes = (Validation: typeof ErgeneValidation | typeof HonoValidation, Ctx: any) => {
  @Middleware({ validator: true })
  class ItemValidator extends (Validation as typeof ErgeneValidation) {
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

  class ItemBody extends Ctx.define({ body: z.object({ name: z.string() }) }) {}

  @Protected()
  @Controller('/items')
  class Items {
    @Post({ path: '/', validator: ItemValidator, middlewares: [Recorder] })
    create(ctx: any) {
      calls.push('handler');

      return ctx.send({ ok: true });
    }

    @Post('/contract/:id')
    contract(ctx: ItemBody) {
      return (ctx as any).send({ name: (ctx as any).input.body.name, user: getAuthSession(ctx as any)?.user.id });
    }
  }

  return [ItemValidator, Recorder, Items];
};

const adapters = [
  {
    name: 'ergenecore',
    make: () => createErgenecoreAdapter({ logger: silentLogger }),
    routes: adapterRoutes(ErgeneValidation, ErgeneContext),
  },
  {
    name: 'hono',
    make: () => createHonoAdapter({ logger: silentLogger })[0],
    routes: adapterRoutes(HonoValidation, HonoContext),
  },
];

@Middleware({ validator: true })
class ItemValidator {
  json() {
    return stringFields('name');
  }
}

@Protected()
@Controller('/items')
class Items {
  @Post({ path: '/', validator: ItemValidator })
  create(ctx: any) {
    return ctx.send({ ok: true });
  }
}

const bearer = (token: string) => ({ authorization: `Bearer ${token}` });

const json = (body: unknown, headers: Record<string, string> = {}) => ({
  method: 'POST',
  headers: { 'content-type': 'application/json', ...headers },
  body: JSON.stringify(body),
});

describe.each(adapters)('asena-auth end to end on $name', ({ name, make, routes }) => {
  const boot = (extra: any[] = []) =>
    createTestApp({
      adapter: make(),
      logger: silentLogger,
      components: [...sharedComponents, ...routes, ...extra],
      imports: [...authComponents],
    });

  type App = Awaited<ReturnType<typeof boot>>;

  const login = async (app: App, roles: string[] = []) => {
    const res = await fetch(`${app.baseUrl}/auth/login`, json({ id: 'u1', roles }));

    return { res, token: ((await res.json()) as { token: string }).token };
  };

  test('login returns a token and sets an HttpOnly, SameSite=Lax session cookie on /', async () => {
    await using app = await boot();
    const { res, token } = await login(app);
    const cookie = res.headers.get('set-cookie') ?? '';

    expect(res.status).toBe(200);
    expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(cookie).toContain(`asena_session=${token}`);
    expect(cookie).toContain('HttpOnly');
    expect(cookie).toMatch(/SameSite=Lax/i);
    expect(cookie).toContain('Path=/');
  });

  test('logout ends the current session at once and clears the cookie with its attributes', async () => {
    await using app = await boot();
    const { token } = await login(app);
    const other = (await login(app)).token;

    const res = await fetch(`${app.baseUrl}/auth/logout`, { method: 'POST', headers: bearer(token) });
    const cleared = Bun.Cookie.parse(res.headers.getSetCookie()[0] ?? '');

    expect(res.status).toBe(200);
    expect(cleared.name).toBe('asena_session');
    expect(cleared.value).toBe('');
    expect(cleared.maxAge === 0 || (cleared.expires?.getTime() ?? Infinity) <= Date.now()).toBe(true);
    expect(cleared.path).toBe('/');
    expect(cleared.sameSite).toBe('lax');

    // ergenecore 5.0.1's deleteCookie forwards only path and domain to Bun's cookie map.
    if (name === 'hono') {
      expect(cleared.secure).toBe(true);
    }

    expect((await fetch(`${app.baseUrl}/me`, { headers: bearer(token) })).status).toBe(401);
    expect((await fetch(`${app.baseUrl}/me`, { headers: bearer(other) })).status).toBe(200);
  });

  test('order: the guard rejects before the route middleware and the validator ever run', async () => {
    await using app = await boot();
    const { token } = await login(app);

    calls.length = 0;

    expect((await fetch(`${app.baseUrl}/items`, json({ name: 'x' }))).status).toBe(401);
    expect(calls).toEqual(['provider']);

    calls.length = 0;

    expect((await fetch(`${app.baseUrl}/items`, json({ name: 1 }, bearer(token)))).status).toBe(400);
    expect(calls).toEqual(['provider', 'recorder']);

    calls.length = 0;

    expect((await fetch(`${app.baseUrl}/items`, json({ name: 'x' }, bearer(token)))).status).toBe(200);
    expect(calls).toEqual(['provider', 'recorder', 'validator', 'handler']);
  });

  test('a @Protected Context.define route rejects before its contract validates the body', async () => {
    await using app = await boot();
    const { token } = await login(app);

    expect((await fetch(`${app.baseUrl}/items/contract/1`, json({ name: 1 }))).status).toBe(401);
    expect((await fetch(`${app.baseUrl}/items/contract/1`, json({ name: 1 }, bearer(token)))).status).toBe(400);

    const ok = await fetch(`${app.baseUrl}/items/contract/1`, json({ name: 'x' }, bearer(token)));

    expect(ok.status).toBe(200);
    expect(await ok.json()).toEqual({ name: 'x', user: 'u1' });
  });

  test('WebSocket: subprotocol token opens and echoes `bearer`; Authorization header opens; no token never opens', async () => {
    await using app = await boot();
    const { token } = await login(app);

    const viaProtocol = await connect(app.wsUrl('/chat'), ['bearer', token]);

    expect(viaProtocol.opened).toBe(true);

    if (viaProtocol.opened) {
      expect(viaProtocol.protocol).toBe('bearer');
      expect(viaProtocol.message.authSession.user.id).toBe('u1');
    }

    const viaHeader = await connect(app.wsUrl('/chat'), { headers: bearer(token) });

    expect(viaHeader.opened).toBe(true);

    if (viaHeader.opened) {
      expect(viaHeader.message.authSession.user.id).toBe('u1');
    }

    expect(await connect(app.wsUrl('/chat'))).toEqual({ opened: false });
  });
});

describe.each(contextShapes)('asena-auth end to end on the %s context', (shape) => {
  const boot = (extra: any[] = []) =>
    bootFake({
      shape,
      components: [...sharedComponents, ItemValidator, Items, ...extra],
      imports: [...authComponents],
    });

  type App = Awaited<ReturnType<typeof boot>>;

  const login = async (app: App, roles: string[] = [], id = 'u1') => {
    const res = await app.fetch('/auth/login', json({ id, roles }));

    return { res, token: ((await res.json()) as { token: string }).token };
  };

  test('@Protected: 401 anonymous, 200 by Bearer and by cookie, 401 once revoked', async () => {
    await using app = await boot();
    const { token } = await login(app);

    const anonymous = await app.fetch('/me');

    expect(anonymous.status).toBe(401);
    expect(anonymous.headers.get('www-authenticate')).toBe('Bearer');

    const viaBearer = await app.fetch('/me', { headers: bearer(token) });

    expect(viaBearer.status).toBe(200);
    expect(await viaBearer.json()).toEqual({ user: 'u1' });
    expect((await app.fetch('/me', { headers: { cookie: `asena_session=${token}` } })).status).toBe(200);

    await (await app.resolve<AppAuth>('AppAuth')).revokeSession(token);

    expect((await app.fetch('/me', { headers: bearer(token) })).status).toBe(401);
  });

  test('logout by cookie revokes that session; logout without a session still answers and clears', async () => {
    await using app = await boot();
    const { token } = await login(app);
    const cookie = { cookie: `asena_session=${token}` };

    expect((await app.fetch('/auth/logout', { method: 'POST', headers: cookie })).status).toBe(200);
    expect((await app.fetch('/me', { headers: cookie })).status).toBe(401);

    const anonymous = await app.fetch('/auth/logout', { method: 'POST' });

    expect(anonymous.status).toBe(200);
    expect(anonymous.headers.getSetCookie()[0]).toStartWith('asena_session=;');
  });

  test('csrf: a cross-site cookie POST is 401 and cannot log out; same-origin, trusted and Bearer POSTs pass', async () => {
    await using app = await boot();
    const { token } = await login(app);
    const cookie = { cookie: `asena_session=${token}` };
    const evil = { origin: 'https://evil.example', 'sec-fetch-site': 'cross-site' };

    expect((await app.fetch('/items', json({ name: 'x' }, { ...cookie, ...evil }))).status).toBe(401);
    expect((await app.fetch('/items', json({ name: 'x' }, { ...cookie, origin: 'https://evil.example' }))).status).toBe(
      401,
    );
    expect((await app.fetch('/items', json({ name: 'x' }, { ...cookie, origin: FAKE_ORIGIN }))).status).toBe(200);
    expect(
      (await app.fetch('/items', json({ name: 'x' }, { ...cookie, 'sec-fetch-site': 'same-origin' }))).status,
    ).toBe(200);
    expect(
      (
        await app.fetch(
          '/items',
          json({ name: 'x' }, { ...cookie, origin: 'https://app.example', 'sec-fetch-site': 'cross-site' }),
        )
      ).status,
    ).toBe(200);
    expect((await app.fetch('/items', json({ name: 'x' }, { ...bearer(token), ...evil }))).status).toBe(200);
    expect((await app.fetch('/me', { headers: { ...cookie, ...evil } })).status).toBe(200);

    await app.fetch('/auth/logout', { method: 'POST', headers: { ...cookie, ...evil } });

    expect((await app.fetch('/me', { headers: cookie })).status).toBe(200);
  });

  test('csrf: a cross-site WebSocket upgrade with only the cookie never opens; a same-origin one does', async () => {
    await using app = await boot();
    const { token } = await login(app);
    const cookie = `asena_session=${token}`;
    const rejected = { opened: false, status: 401 } as const;

    expect(
      await app.connect('/chat', {
        headers: { cookie, origin: 'https://evil.example', 'sec-fetch-site': 'cross-site' },
      }),
    ).toEqual(rejected);
    expect(await app.connect('/chat', { headers: { cookie, origin: 'https://evil.example' } })).toEqual(rejected);

    const sameOrigin = await app.connect('/chat', { headers: { cookie, origin: FAKE_ORIGIN } });

    expect(sameOrigin.opened).toBe(true);

    const viaProtocol = await app.connect('/chat', {
      headers: { cookie, origin: 'https://evil.example' },
      protocols: ['bearer', token],
    });

    expect(viaProtocol.opened).toBe(true);
  });

  test('rotateSession: the old token is 401 at once, the new one works; only a cookie session gets a cookie', async () => {
    await using app = await boot();
    const rotate = async (headers: Record<string, string>) => {
      const res = await app.fetch('/auth/rotate', { method: 'POST', headers });

      expect(res.status).toBe(200);

      return { setCookies: res.headers.getSetCookie(), token: ((await res.json()) as { token: string }).token };
    };

    const viaBearer = (await login(app)).token;
    const fromBearer = await rotate(bearer(viaBearer));

    expect(fromBearer.setCookies).toEqual([]);
    expect((await app.fetch('/me', { headers: bearer(viaBearer) })).status).toBe(401);
    expect((await app.fetch('/me', { headers: bearer(fromBearer.token) })).status).toBe(200);

    const viaCookie = (await login(app)).token;
    const fromCookie = await rotate({ cookie: `asena_session=${viaCookie}` });
    const reissued = Bun.Cookie.parse(fromCookie.setCookies[0] ?? '');

    expect(fromCookie.setCookies).toHaveLength(1);
    expect(reissued.name).toBe('asena_session');
    expect(reissued.value).toBe(fromCookie.token);
    expect(reissued.httpOnly).toBe(true);
    expect((await app.fetch('/me', { headers: { cookie: `asena_session=${viaCookie}` } })).status).toBe(401);
    expect((await app.fetch('/me', { headers: { cookie: `asena_session=${fromCookie.token}` } })).status).toBe(200);
  });

  test('@Roles: 403 without the role, 200 with it; the Better Auth role string passes the default resolver', async () => {
    await using app = await boot();
    const user = (await login(app, ['user'])).token;
    const admin = (await login(app, ['admin'])).token;

    const forbidden = await app.fetch('/me/admin', { headers: bearer(user) });

    expect(forbidden.status).toBe(403);
    expect(forbidden.headers.get('www-authenticate')).toBeNull();
    expect((await app.fetch('/me/admin', { headers: bearer(admin) })).status).toBe(200);
    expect((await app.fetch('/ba/admin', { headers: bearer('ba-token') })).status).toBe(200);
  });

  test('@Public: a method opt-out and a @Public subclass of a @Protected controller', async () => {
    await using app = await boot();

    expect((await app.fetch('/me/public')).status).toBe(200);
    expect((await app.fetch('/users')).status).toBe(401);
    expect((await app.fetch('/open-users')).status).toBe(200);
  });

  test('two providers: a named route takes only its provider, an unnamed one the primary', async () => {
    await using app = await boot();
    const { token } = await login(app);

    expect((await app.fetch('/ba', { headers: bearer('ba-token') })).status).toBe(200);
    expect((await app.fetch('/ba', { headers: bearer(token) })).status).toBe(401);
    expect((await app.fetch('/me', { headers: bearer('ba-token') })).status).toBe(401);
  });

  test('a third-party provider written against @asenajs/asena/auth only is selectable by name', async () => {
    await using app = await boot();

    const res = await app.fetch('/kc', { headers: bearer('kc-token') });

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ user: 'kc1' });
    expect((await app.fetch('/kc')).status).toBe(401);
  });

  test('global AuthSessionMiddleware: public routes see the session, the provider runs once per request', async () => {
    await using app = await boot([SessionConfig]);
    const { token } = await login(app);

    calls.length = 0;

    expect(await (await app.fetch('/me/public')).json()).toEqual({ user: null });
    expect(await (await app.fetch('/me/public', { headers: bearer(token) })).json()).toEqual({ user: 'u1' });
    expect(calls).toEqual(['provider', 'provider']);

    calls.length = 0;

    expect((await app.fetch('/me', { headers: bearer(token) })).status).toBe(200);
    expect(calls).toEqual(['provider']);
  });

  test('global AuthSessionMiddleware does not let a primary-provider session into a named-provider route', async () => {
    await using app = await boot([SessionConfig]);
    const { token } = await login(app);

    expect((await app.fetch('/ba', { headers: bearer(token) })).status).toBe(401);

    const ba = await app.fetch('/ba', { headers: bearer('ba-token') });

    expect(ba.status).toBe(200);
    expect(await ba.json()).toEqual({ user: 'b1' });
  });

  test("WebSocket under the global AuthSessionMiddleware: the subprotocol token wins over the cookie's user", async () => {
    await using app = await boot([SessionConfig]);
    const { token: tokenA } = await login(app);
    const { token: tokenB } = await login(app, [], 'u2');
    const cookie = `asena_session=${tokenA}`;

    const cookieOnly = await app.connect('/chat', { headers: { cookie } });

    expect(cookieOnly.opened).toBe(true);

    if (cookieOnly.opened) {
      expect(cookieOnly.message.authSession.user.id).toBe('u1');
    }

    const swapped = await app.connect('/chat', { headers: { cookie }, protocols: ['bearer', tokenB] });

    expect(swapped.opened).toBe(true);

    if (swapped.opened) {
      expect(swapped.message.authSession.user.id).toBe('u2');
    }

    expect(await app.connect('/chat', { headers: { cookie }, protocols: ['bearer', 'invalid'] })).toEqual({
      opened: false,
      status: 401,
    });
  });

  test("Better Auth's session-refresh Set-Cookie reaches the client on a guarded route, value unchanged", async () => {
    await using app = await boot();

    const plain = await app.fetch('/ba', { headers: bearer('ba-token') });

    expect(plain.status).toBe(200);
    expect(plain.headers.getSetCookie()).toEqual([]);

    const res = await app.fetch('/ba', { headers: { ...bearer('ba-token'), 'x-refresh': '1' } });

    expect(res.status).toBe(200);

    const [cookie] = res.headers.getSetCookie();
    const parsed = Bun.Cookie.parse(cookie ?? '');

    expect(parsed.name).toBe('better-auth.session_token');
    expect(parsed.value).toBe('ba-token.sig%2Bx%3D');
    expect(parsed.maxAge).toBe(604800);
    expect(parsed.httpOnly).toBe(true);
    expect(parsed.path).toBe('/');
  });

  test('BetterAuthController returns the Better Auth handler Response unchanged', async () => {
    await using app = await boot();

    const res = await app.fetch('/api/auth/sign-in/email', json({ email: 'a@b.c' }));

    expect(res.status).toBe(201);
    expect(await res.json()).toEqual({ path: '/api/auth/sign-in/email', method: 'POST' });
  });
});

describe('boot errors', () => {
  @Auth({})
  class First extends AsenaAuthService {}

  @Auth({})
  class Second extends AsenaAuthService {}

  @Protected()
  @Controller('/guarded')
  class Guarded {
    @Get('/')
    get(ctx: any) {
      return ctx.send('x');
    }
  }

  @Protected({ provider: 'First' })
  @Controller('/named')
  class Named {
    @Get('/')
    get(ctx: any) {
      return ctx.send('x');
    }
  }

  const bootError = async (components: any[], imports: readonly any[] = authComponents): Promise<string> => {
    const error: any = await bootFake({ components, imports: [...imports] }).then(
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

    return messages.join(' <- ');
  };

  test('two providers, none primary, only named routes: authComponents fails the boot in the middlewares', async () => {
    const message = await bootError([First, Second, Named]);

    expect(message).toMatch(/Auth(Session|WebSocket)Middleware/);
    expect(message).toContain('primary: true');
    expect(message).toContain('providerName');
    expect(message).toContain('imports: [AuthGuard, AuthGuardMiddleware, AuthProviderRegistry]');
  });

  test('two providers, none primary: the guard components plus a middleware subclass naming its provider boot', async () => {
    @Middleware()
    class FirstSession extends AuthSessionMiddleware {
      protected providerName = 'First';
    }

    await using app = await bootFake({
      components: [First, Second, Named],
      imports: [AuthGuard, AuthGuardMiddleware, AuthProviderRegistry, FirstSession],
    });

    expect((await app.fetch('/named')).status).toBe(401);
  });

  test('two providers, none primary, an unnamed protected route: the boot fails naming the route', async () => {
    expect(await bootError([First, Second, Guarded])).toContain('GET /guarded (Guarded.get)');
  });

  test.each([
    ['class', { access: 'restricted' }, "access 'restricted'"],
    ['method', { access: 'restricted' }, "access 'restricted'"],
    ['class', { access: 'protected', permissions: ['read'] }, "key 'permissions'"],
    ['method', { access: 'protected', permissions: ['read'] }, "key 'permissions'"],
  ] as const)('a %s guard mark %j this version cannot enforce fails the boot', async (level, mark, what) => {
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

    const message = await bootError([First, Forged], [AuthGuard, AuthGuardMiddleware, AuthProviderRegistry]);

    expect(message).toContain(level === 'class' ? 'Forged' : 'Forged.get');
    expect(message).toContain(what);
    expect(message).toContain('upgrade @asenajs/asena-auth');
  });
});

describe.each(contextShapes)('loadUser end to end on the %s context', (shape) => {
  const directory = new Map<string, { id: string; roles: string[] }>();

  @Auth({ loadUser: async (id) => directory.get(id) ?? null })
  class FreshAuth extends AsenaAuthService {}

  @Protected()
  @Controller('/fresh')
  class Fresh {
    @Roles('admin')
    @Get('/admin')
    admin(ctx: any) {
      return ctx.send({ admin: true });
    }
  }

  test('a role demotion applies on the next request; a deleted user is 401 and its row is gone', async () => {
    await using app = await bootFake({
      shape,
      components: [FreshAuth, Fresh],
      imports: [AuthGuard, AuthGuardMiddleware, AuthProviderRegistry],
    });
    const auth = await app.resolve<FreshAuth>('FreshAuth');

    directory.set('u1', { id: 'u1', roles: ['admin'] });

    const { token } = await auth.createSession({ id: 'u1', roles: ['admin'] });

    expect((await app.fetch('/fresh/admin', { headers: bearer(token) })).status).toBe(200);

    directory.set('u1', { id: 'u1', roles: ['user'] });

    expect((await app.fetch('/fresh/admin', { headers: bearer(token) })).status).toBe(403);

    directory.delete('u1');

    expect((await app.fetch('/fresh/admin', { headers: bearer(token) })).status).toBe(401);
    expect(await auth.listUserSessions('u1')).toEqual([]);
  });
});
