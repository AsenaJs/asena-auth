import { afterEach, describe, expect, test } from 'bun:test';
import { AUTH_PROVIDER_KEY, Protected, Public, Roles, getAuthSession } from '@asenajs/asena/auth';
import type { AsenaAuthProvider, AuthSession } from '@asenajs/asena/auth';
import { Config, Controller, Middleware, Service, WebSocket as WebSocketNamespace } from '@asenajs/asena/decorators';
import { Get, Post } from '@asenajs/asena/decorators/http';
import { Implements, Inject } from '@asenajs/asena/decorators/ioc';
import { AsenaMiddlewareService } from '@asenajs/asena/middleware';
import { createTestApp, silentLogger } from '@asenajs/asena/test';
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
  AuthSessionMiddleware,
  AuthWebSocketMiddleware,
  BetterAuth,
  BetterAuthController,
  BetterAuthService,
  applySessionCookie,
  authComponents,
} from '../index';
import type { BetterAuthInstance } from '../index';
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
    getSession: async ({ headers }) =>
      headers.get('authorization') === 'Bearer ba-token'
        ? {
            session: { id: 'bs1', userId: 'b1', createdAt: new Date(), expiresAt: new Date(Date.now() + hour) },
            user: { id: 'b1', role: 'admin,user' },
          }
        : null,
  },
};

@Auth({ primary: true, sessionTtl: 3600 })
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

const bearer = (token: string) => ({ authorization: `Bearer ${token}` });

const json = (body: unknown, headers: Record<string, string> = {}) => ({
  method: 'POST',
  headers: { 'content-type': 'application/json', ...headers },
  body: JSON.stringify(body),
});

describe.each(adapters)('asena-auth end to end on $name', ({ make, routes }) => {
  const boot = (extra: any[] = []) =>
    createTestApp({
      adapter: make(),
      logger: silentLogger,
      components: [
        AppAuth,
        AppBA,
        Keycloak,
        Login,
        Me,
        BaRoutes,
        KcRoutes,
        Users,
        OpenUsers,
        AuthCtrl,
        Chat,
        ...routes,
        ...extra,
      ],
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

  test('@Protected: 401 anonymous, 200 by Bearer and by cookie, 401 once revoked', async () => {
    await using app = await boot();
    const { token } = await login(app);

    expect((await fetch(`${app.baseUrl}/me`)).status).toBe(401);

    const viaBearer = await fetch(`${app.baseUrl}/me`, { headers: bearer(token) });

    expect(viaBearer.status).toBe(200);
    expect(await viaBearer.json()).toEqual({ user: 'u1' });
    expect((await fetch(`${app.baseUrl}/me`, { headers: { cookie: `asena_session=${token}` } })).status).toBe(200);

    await (await app.resolve<AppAuth>('AppAuth')).revokeSession(token);

    expect((await fetch(`${app.baseUrl}/me`, { headers: bearer(token) })).status).toBe(401);
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

  test('@Roles: 403 without the role, 200 with it; the Better Auth role string passes the default resolver', async () => {
    await using app = await boot();
    const user = (await login(app, ['user'])).token;
    const admin = (await login(app, ['admin'])).token;

    expect((await fetch(`${app.baseUrl}/me/admin`, { headers: bearer(user) })).status).toBe(403);
    expect((await fetch(`${app.baseUrl}/me/admin`, { headers: bearer(admin) })).status).toBe(200);
    expect((await fetch(`${app.baseUrl}/ba/admin`, { headers: bearer('ba-token') })).status).toBe(200);
  });

  test('@Public: a method opt-out and a @Public subclass of a @Protected controller', async () => {
    await using app = await boot();

    expect((await fetch(`${app.baseUrl}/me/public`)).status).toBe(200);
    expect((await fetch(`${app.baseUrl}/users`)).status).toBe(401);
    expect((await fetch(`${app.baseUrl}/open-users`)).status).toBe(200);
  });

  test('two providers: a named route takes only its provider, an unnamed one the primary', async () => {
    await using app = await boot();
    const { token } = await login(app);

    expect((await fetch(`${app.baseUrl}/ba`, { headers: bearer('ba-token') })).status).toBe(200);
    expect((await fetch(`${app.baseUrl}/ba`, { headers: bearer(token) })).status).toBe(401);
    expect((await fetch(`${app.baseUrl}/me`, { headers: bearer('ba-token') })).status).toBe(401);
  });

  test('a third-party provider written against @asenajs/asena/auth only is selectable by name', async () => {
    await using app = await boot();

    const res = await fetch(`${app.baseUrl}/kc`, { headers: bearer('kc-token') });

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ user: 'kc1' });
    expect((await fetch(`${app.baseUrl}/kc`)).status).toBe(401);
  });

  test('global AuthSessionMiddleware: public routes see the session, the provider runs once per request', async () => {
    await using app = await boot([SessionConfig]);
    const { token } = await login(app);

    calls.length = 0;

    expect(await (await fetch(`${app.baseUrl}/me/public`)).json()).toEqual({ user: null });
    expect(await (await fetch(`${app.baseUrl}/me/public`, { headers: bearer(token) })).json()).toEqual({ user: 'u1' });
    expect(calls).toEqual(['provider', 'provider']);

    calls.length = 0;

    expect((await fetch(`${app.baseUrl}/me`, { headers: bearer(token) })).status).toBe(200);
    expect(calls).toEqual(['provider']);
  });

  test('global AuthSessionMiddleware does not let a primary-provider session into a named-provider route', async () => {
    await using app = await boot([SessionConfig]);
    const { token } = await login(app);

    expect((await fetch(`${app.baseUrl}/ba`, { headers: bearer(token) })).status).toBe(401);

    const ba = await fetch(`${app.baseUrl}/ba`, { headers: bearer('ba-token') });

    expect(ba.status).toBe(200);
    expect(await ba.json()).toEqual({ user: 'b1' });
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

  test('BetterAuthController returns the Better Auth handler Response unchanged', async () => {
    await using app = await boot();

    const res = await fetch(`${app.baseUrl}/api/auth/sign-in/email`, json({ email: 'a@b.c' }));

    expect(res.status).toBe(201);
    expect(await res.json()).toEqual({ path: '/api/auth/sign-in/email', method: 'POST' });
  });
});

describe('boot errors (adapter-independent, ergenecore)', () => {
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

  test('two providers, none primary, only named routes: authComponents boot', async () => {
    await using app = await createTestApp({
      adapter: createErgenecoreAdapter({ logger: silentLogger }),
      logger: silentLogger,
      components: [First, Second, Named],
      imports: [...authComponents],
    });

    expect((await fetch(`${app.baseUrl}/named`)).status).toBe(401);
  });

  test('two providers, none primary, an unnamed protected route: the boot fails naming the route', async () => {
    const boot = createTestApp({
      adapter: createErgenecoreAdapter({ logger: silentLogger }),
      logger: silentLogger,
      components: [First, Second, Guarded],
      imports: [...authComponents],
    });

    const error: any = await boot.then(
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

    expect(messages.join(' <- ')).toContain('GET /guarded (Guarded.get)');
  });
});
