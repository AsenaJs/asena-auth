import { describe, expect, test } from 'bun:test';
import { Protected } from '@asenajs/asena/auth';
import { Controller } from '@asenajs/asena/decorators';
import { Get, Post } from '@asenajs/asena/decorators/http';
import { Inject } from '@asenajs/asena/decorators/ioc';
import { AsenaAuthService, Auth, AuthGuard, AuthGuardMiddleware, AuthProviderRegistry } from '../index';
import { bootFake, contextShapes } from './support/fakeAdapter';

@Auth({})
class LogoutAuth extends AsenaAuthService {}

@Controller('/session')
class SessionRoutes {
  @Inject(LogoutAuth)
  private readonly auth!: LogoutAuth;

  @Post('/logout')
  async logout(ctx: any) {
    await this.auth.logout(ctx);

    return ctx.send({ ok: true });
  }
}

@Protected()
@Controller('/me')
class Me {
  @Get('/')
  me(ctx: any) {
    return ctx.send({ ok: true });
  }
}

describe.each(contextShapes)('logout edge cases on the %s context', (shape) => {
  const boot = () =>
    bootFake({
      shape,
      components: [LogoutAuth, SessionRoutes, Me],
      imports: [AuthGuard, AuthGuardMiddleware, AuthProviderRegistry],
    });

  const status = async (app: Awaited<ReturnType<typeof boot>>, headers: Record<string, string>) =>
    (await app.fetch('/me', { headers })).status;

  const deletion = (res: Response) => {
    const setCookies = res.headers.getSetCookie().map((c) => Bun.Cookie.parse(c));

    expect(setCookies).toHaveLength(1);
    expect(setCookies[0]?.name).toBe('asena_session');
    expect(setCookies[0]?.value).toBe('');
  };

  test('Bearer plus a different cookie: the Bearer session ends, the cookie is cleared, its row is left to expire', async () => {
    await using app = await boot();
    const auth = await app.resolve<LogoutAuth>('LogoutAuth');
    const { token: viaBearer } = await auth.createSession({ id: 'u1' });
    const { token: viaCookie } = await auth.createSession({ id: 'u2' });

    const res = await app.fetch('/session/logout', {
      method: 'POST',
      headers: { authorization: `Bearer ${viaBearer}`, cookie: `asena_session=${viaCookie}` },
    });

    expect(res.status).toBe(200);
    deletion(res);
    expect(await status(app, { authorization: `Bearer ${viaBearer}` })).toBe(401);
    expect(await status(app, { cookie: `asena_session=${viaCookie}` })).toBe(200);
  });

  test('a cross-site logout POST clears the cookie but cannot end the session', async () => {
    await using app = await boot();
    const auth = await app.resolve<LogoutAuth>('LogoutAuth');
    const { token } = await auth.createSession({ id: 'u1' });
    const cookie = `asena_session=${token}`;

    const res = await app.fetch('/session/logout', {
      method: 'POST',
      headers: { cookie, origin: 'https://evil.example', 'sec-fetch-site': 'cross-site' },
    });

    expect(res.status).toBe(200);
    deletion(res);
    expect(await status(app, { cookie })).toBe(200);
  });
});
