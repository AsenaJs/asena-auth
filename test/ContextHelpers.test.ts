import { describe, expect, mock, test } from 'bun:test';
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

  test('clearSessionCookie deletes it on the same path and domain', async () => {
    const deleteCookie = mock(async () => {});

    await clearSessionCookie({ deleteCookie } as any, service);

    expect(deleteCookie).toHaveBeenCalledWith('asena_session', {
      extraOptions: { path: '/', domain: 'example.com' },
    });
  });

  test('accept a real AsenaAuthService without a cast', async () => {
    const real: AsenaAuthService = new (RealAuth as any)();
    const setCookie = mock(async () => {});
    const deleteCookie = mock(async () => {});

    await applySessionCookie({ setCookie } as any, real, 'tok');
    await clearSessionCookie({ deleteCookie } as any, real);

    expect(setCookie).toHaveBeenCalledWith('asena_session', 'tok', { extraOptions: real.cookieOptions });
    expect(deleteCookie).toHaveBeenCalledWith('asena_session', {
      extraOptions: { path: '/', domain: 'example.com' },
    });
  });
});
