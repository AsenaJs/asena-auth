import { describe, expect, mock, test } from 'bun:test';
import { Controller } from '@asenajs/asena/decorators';
import { Post } from '@asenajs/asena/decorators/http';
import { Inject } from '@asenajs/asena/decorators/ioc';
import { createTestApp, silentLogger } from '@asenajs/asena/test';
import { createHonoAdapter } from '@asenajs/hono-adapter';
import { AsenaAuthService } from '../lib/AsenaAuthService';
import { Auth } from '../lib/decorators';
import { applySessionCookie, clearSessionCookie, getRawRequest } from '../lib/helpers';

@Auth({ sessionTtl: 60, cookie: { domain: 'example.com' } })
class RealAuth extends AsenaAuthService {}

const service = {
  cookieName: 'asena_session',
  cookieOptions: {
    httpOnly: true,
    sameSite: 'lax' as const,
    secure: true,
    path: '/',
    domain: 'example.com',
    maxAge: 60,
  },
};

describe('getRawRequest', () => {
  test('ergenecore: ctx.req is the Request', () => {
    const request = new Request('http://localhost/x');

    expect(getRawRequest({ req: request } as any)).toBe(request);
  });

  test('hono: ctx.req wraps it as .raw', () => {
    const request = new Request('http://localhost/x');

    expect(getRawRequest({ req: { raw: request } } as any)).toBe(request);
  });
});

describe('session cookie helpers', () => {
  test('applySessionCookie writes the token with the service cookie config', async () => {
    const setCookie = mock(async () => {});

    await applySessionCookie({ setCookie } as any, service, 'tok');

    expect(setCookie).toHaveBeenCalledWith('asena_session', 'tok', { extraOptions: service.cookieOptions });
  });

  test('clearSessionCookie deletes it with the same path, domain, secure and sameSite', async () => {
    const deleteCookie = mock(async () => {});

    await clearSessionCookie({ deleteCookie } as any, service);

    expect(deleteCookie).toHaveBeenCalledWith('asena_session', {
      extraOptions: { path: '/', domain: 'example.com', secure: true, sameSite: 'lax' },
    });
  });

  test('hono: a __Host- session cookie can be deleted (hono refuses a prefixed cookie without Secure)', async () => {
    @Auth({ cookie: { name: '__Host-session' } })
    class HostAuth extends AsenaAuthService {}

    @Controller('/auth')
    class Logout {
      @Inject(HostAuth)
      private readonly auth!: HostAuth;

      @Post('/logout')
      async logout(ctx: any) {
        await clearSessionCookie(ctx, this.auth);

        return ctx.send({ ok: true });
      }
    }

    await using app = await createTestApp({
      adapter: createHonoAdapter({ logger: silentLogger })[0],
      logger: silentLogger,
      components: [HostAuth, Logout],
    });

    const res = await fetch(`${app.baseUrl}/auth/logout`, { method: 'POST' });

    expect(res.status).toBe(200);
    expect(res.headers.get('set-cookie')).toStartWith('__Host-session=; Max-Age=0; Path=/; Secure');
  });

  test('accept a real AsenaAuthService without a cast', async () => {
    const real: AsenaAuthService = new (RealAuth as any)();
    const setCookie = mock(async () => {});
    const deleteCookie = mock(async () => {});

    await applySessionCookie({ setCookie } as any, real, 'tok');
    await clearSessionCookie({ deleteCookie } as any, real);

    expect(setCookie).toHaveBeenCalledWith('asena_session', 'tok', { extraOptions: real.cookieOptions });
    expect(deleteCookie).toHaveBeenCalledWith('asena_session', {
      extraOptions: { path: '/', domain: 'example.com', secure: true, sameSite: 'lax' },
    });
  });
});
