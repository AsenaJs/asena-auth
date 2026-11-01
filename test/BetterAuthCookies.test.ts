import { describe, expect, test } from 'bun:test';
import { Protected, getAuthSession } from '@asenajs/asena/auth';
import { Controller } from '@asenajs/asena/decorators';
import { Get } from '@asenajs/asena/decorators/http';
import { Inject } from '@asenajs/asena/decorators/ioc';
import { createTestApp, silentLogger } from '@asenajs/asena/test';
import { createErgenecoreAdapter } from '@asenajs/ergenecore';
import { createHonoAdapter } from '@asenajs/hono-adapter';
import { betterAuth } from 'better-auth';
import { memoryAdapter } from 'better-auth/adapters/memory';
import {
  AuthGuard,
  AuthGuardMiddleware,
  AuthProviderRegistry,
  BetterAuth,
  BetterAuthController,
  BetterAuthService,
} from '../index';
import type { BetterAuthInstance } from '../index';

const expires = new Date(Math.floor(Date.now() / 1000) * 1000 + 86_400_000);

const attributeCookie =
  `ba.attrs=v%2Bx%3D; Domain=example.com; Path=/app; Expires=${expires.toUTCString()}; ` +
  'Secure; HttpOnly; SameSite=None; Partitioned';

const attributeAuth: BetterAuthInstance = {
  handler: async () => new Response(null, { status: 404 }),
  api: {
    getSession: async () => ({
      headers: new Headers([['set-cookie', attributeCookie]]),
      response: {
        session: { id: 's1', userId: 'a1', createdAt: new Date(), expiresAt: new Date(Date.now() + 3_600_000) },
        user: { id: 'a1' },
      },
    }),
  },
};

@BetterAuth({ auth: attributeAuth })
class AttrBA extends BetterAuthService {}

@Protected({ provider: 'AttrBA' })
@Controller('/attrs')
class AttrRoutes {
  @Get('/')
  me(ctx: any) {
    return ctx.send({ user: getAuthSession(ctx)?.user.id });
  }
}

const db: Record<string, any[]> = { user: [], session: [], account: [], verification: [] };

const realAuth = (cookieCache: boolean) =>
  betterAuth({
    baseURL: 'http://localhost',
    secret: 'asena-auth-e2e-secret-0123456789abcdef0123456789',
    database: memoryAdapter(db),
    emailAndPassword: { enabled: true },
    session: { expiresIn: 3600, updateAge: 60, cookieCache: { enabled: cookieCache, maxAge: 300 } },
    logger: { disabled: true },
  });

@BetterAuth({ auth: realAuth(false) })
class RealBA extends BetterAuthService {}

@BetterAuth({ auth: realAuth(true) })
class CachedBA extends BetterAuthService {}

@Protected({ provider: 'RealBA' })
@Controller('/real')
class RealRoutes {
  @Get('/')
  me(ctx: any) {
    return ctx.send({ user: getAuthSession(ctx)?.user.id });
  }
}

@Protected({ provider: 'CachedBA' })
@Controller('/cached')
class CachedRoutes {
  @Get('/')
  me(ctx: any) {
    return ctx.send({ user: getAuthSession(ctx)?.user.id });
  }
}

@Controller('/api/auth')
class RealAuthCtrl extends BetterAuthController {
  @Inject(RealBA)
  protected readonly authService!: RealBA;
}

const adapters = [
  { name: 'ergenecore', make: () => createErgenecoreAdapter({ logger: silentLogger }) },
  { name: 'hono', make: () => createHonoAdapter({ logger: silentLogger })[0] },
];

const TOKEN_COOKIE = 'better-auth.session_token';
const DATA_COOKIE = 'better-auth.session_data';

const pair = (setCookie: string) => setCookie.split(';')[0]!;

const byName = (res: Response) =>
  new Map(res.headers.getSetCookie().map((c) => [Bun.Cookie.parse(c).name, c] as const));

/** Pulls the stored session back so `expiresAt - expiresIn + updateAge <= now`: Better Auth's refresh condition. */
const ageSession = (userId: string) => {
  const row = db.session!.find((s) => s.userId === userId);

  row.expiresAt = new Date(Date.now() + 3_600_000 - 120_000);

  return row;
};

describe.each(adapters)('Better Auth cookies on $name', ({ name, make }) => {
  const boot = () =>
    createTestApp({
      adapter: make(),
      logger: silentLogger,
      components: [AttrBA, AttrRoutes, RealBA, CachedBA, RealRoutes, CachedRoutes, RealAuthCtrl],
      imports: [AuthGuard, AuthGuardMiddleware, AuthProviderRegistry],
    });

  type App = Awaited<ReturnType<typeof boot>>;

  const signUp = async (app: App, email: string) => {
    const res = await fetch(`${app.baseUrl}/api/auth/sign-up/email`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email, password: 'correct-horse-battery', name: 'Ada' }),
    });
    const body = (await res.json()) as { user: { id: string } };

    return { res, userId: body.user?.id, cookie: pair(byName(res).get(TOKEN_COOKIE) ?? '') };
  };

  test('a forwarded Set-Cookie keeps Domain, Path, Expires, Secure, HttpOnly, SameSite and Partitioned', async () => {
    await using app = await boot();

    const res = await fetch(`${app.baseUrl}/attrs`);
    const [raw] = res.headers.getSetCookie();
    const cookie = Bun.Cookie.parse(raw ?? '');

    expect(res.status).toBe(200);
    expect(cookie.name).toBe('ba.attrs');
    expect(cookie.value).toBe('v%2Bx%3D');
    expect(cookie.domain).toBe('example.com');
    expect(cookie.path).toBe('/app');
    expect(cookie.expires?.getTime()).toBe(expires.getTime());
    expect(cookie.secure).toBe(true);
    expect(cookie.httpOnly).toBe(true);
    expect(cookie.sameSite).toBe('none');
    expect(cookie.partitioned).toBe(true);
  });

  test('real Better Auth: signing up through the mounted handler opens a guarded route by its cookie', async () => {
    await using app = await boot();
    const { res, userId, cookie } = await signUp(app, `plain-${name}@example.com`);

    expect(res.status).toBe(200);
    expect(cookie.startsWith(`${TOKEN_COOKIE}=`)).toBe(true);
    expect((await fetch(`${app.baseUrl}/real`)).status).toBe(401);

    const me = await fetch(`${app.baseUrl}/real`, { headers: { cookie } });

    expect(me.status).toBe(200);
    expect(await me.json()).toEqual({ user: userId });
    expect(me.headers.getSetCookie()).toEqual([]);
  });

  test("real Better Auth: a session due for refresh answers with Better Auth's refreshed token cookie", async () => {
    await using app = await boot();
    const { userId, cookie } = await signUp(app, `refresh-${name}@example.com`);
    const row = ageSession(userId);
    const aged = row.expiresAt.getTime();

    const res = await fetch(`${app.baseUrl}/real`, { headers: { cookie } });
    const refreshed = byName(res).get(TOKEN_COOKIE);

    expect(res.status).toBe(200);
    expect(refreshed).toBeDefined();
    expect(pair(refreshed!)).toBe(cookie);

    const parsed = Bun.Cookie.parse(refreshed!);

    expect(parsed.maxAge).toBe(3600);
    expect(parsed.httpOnly).toBe(true);
    expect(parsed.path).toBe('/');
    expect(parsed.sameSite).toBe('lax');
    expect(row.expiresAt.getTime()).toBeGreaterThan(aged);
  });

  test('real Better Auth with cookieCache: the session_data cookie passes through, refreshed or not', async () => {
    await using app = await boot();
    const { userId, cookie } = await signUp(app, `cached-${name}@example.com`);

    const plain = await fetch(`${app.baseUrl}/cached`, { headers: { cookie } });

    expect(plain.status).toBe(200);
    expect(await plain.json()).toEqual({ user: userId });
    expect([...byName(plain).keys()]).toEqual([DATA_COOKIE]);

    const cached = await fetch(`${app.baseUrl}/cached`, {
      headers: { cookie: `${cookie}; ${pair(byName(plain).get(DATA_COOKIE)!)}` },
    });

    expect(cached.status).toBe(200);
    expect(await cached.json()).toEqual({ user: userId });

    ageSession(userId);

    const refreshed = await fetch(`${app.baseUrl}/cached`, { headers: { cookie } });
    const cookies = byName(refreshed);

    expect(refreshed.status).toBe(200);
    expect([...cookies.keys()].sort()).toEqual([DATA_COOKIE, TOKEN_COOKIE]);
    expect(pair(cookies.get(TOKEN_COOKIE)!)).toBe(cookie);
    expect(Bun.Cookie.parse(cookies.get(DATA_COOKIE)!).maxAge).toBe(300);
  });
});
