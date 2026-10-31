import { afterEach, describe, expect, setSystemTime, spyOn, test } from 'bun:test';
import { AUTH_PROVIDER_KEY } from '@asenajs/asena/auth';
import type { AuthSession } from '@asenajs/asena/auth';
import { ComponentConstants } from '@asenajs/asena/ioc/constants';
import { getOwnTypedMetadata, getTypedMetadata } from '@asenajs/asena/utils';
import { AsenaAuthService } from '../lib/AsenaAuthService';
import { Auth } from '../lib/decorators';
import { MemoryAuthStore } from '../lib/store';

const URL_ = 'http://localhost/me';

const bearer = (token: string, scheme = 'Bearer') =>
  new Request(URL_, { headers: { authorization: `${scheme} ${token}` } });

const cookie = (token: string, name = 'asena_session') =>
  new Request(URL_, { headers: { cookie: `${name}=${token}` } });

@Auth({ sessionTtl: 60 })
class AppAuth extends AsenaAuthService {}

const make = <T>(Cls: new () => T): T => new (Cls as any)();

afterEach(() => {
  setSystemTime();
});

describe('@Auth registration', () => {
  test('registers under the class name and keeps it', () => {
    expect(getOwnTypedMetadata<string>(ComponentConstants.NameKey, AppAuth)).toBe('AppAuth');
    expect(AppAuth.name).toBe('AppAuth');
  });

  test('an explicit name wins', () => {
    @Auth({ name: 'Custom' })
    class Named extends AsenaAuthService {}

    expect(getOwnTypedMetadata<string>(ComponentConstants.NameKey, Named)).toBe('Custom');
  });

  test('implements the core provider strategy key', () => {
    expect(getTypedMetadata<string>(ComponentConstants.InterfaceKey, AppAuth)).toBe(AUTH_PROVIDER_KEY);
  });

  test('a thunk registers under the class name and runs at construction, once per instance', () => {
    let calls = 0;

    @Auth(() => {
      calls++;

      return { primary: true };
    })
    class Lazy extends AsenaAuthService {}

    expect(calls).toBe(0);
    expect(getOwnTypedMetadata<string>(ComponentConstants.NameKey, Lazy)).toBe('Lazy');

    const instance = make(Lazy);

    expect(calls).toBe(1);
    expect(instance.primary).toBe(true);
  });

  test('primary reflects the options', () => {
    @Auth({ primary: true })
    class Primary extends AsenaAuthService {}

    expect(make(Primary).primary).toBe(true);
    expect(make(AppAuth).primary).toBe(false);
  });

  test('onStart without options names @Auth', async () => {
    class Bare extends AsenaAuthService {}

    await expect(new Bare().onStart()).rejects.toThrow('@Auth');
  });
});

describe('sessions', () => {
  test('createSession returns a token and the session it maps to', async () => {
    const auth = make(AppAuth);
    const { token, session } = await auth.createSession({ id: 'u1', roles: ['user'] });

    expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(session.user.id).toBe('u1');
    expect(session.session.userId).toBe('u1');
    expect(session.session.expiresAt.getTime() - session.session.createdAt.getTime()).toBe(60_000);
    expect(session.session.id).not.toBe(token);
  });

  test('resolves from a Bearer header and from the session cookie', async () => {
    const auth = make(AppAuth);
    const { token } = await auth.createSession({ id: 'u1' });

    expect((await auth.getSession(bearer(token)))?.user.id).toBe('u1');
    expect((await auth.getSession(cookie(token)))?.user.id).toBe('u1');
  });

  test('the Bearer scheme is case-insensitive', async () => {
    const auth = make(AppAuth);
    const { token } = await auth.createSession({ id: 'u1' });

    expect((await auth.getSession(bearer(token, 'BEARER')))?.user.id).toBe('u1');
    expect((await auth.getSession(bearer(token, 'bearer')))?.user.id).toBe('u1');
  });

  test('Bearer wins over the cookie when both carry different tokens', async () => {
    const auth = make(AppAuth);
    const { token: a } = await auth.createSession({ id: 'alice' });
    const { token: b } = await auth.createSession({ id: 'bob' });
    const request = new Request(URL_, { headers: { authorization: `Bearer ${a}`, cookie: `asena_session=${b}` } });

    expect((await auth.getSession(request))?.user.id).toBe('alice');
  });

  test('the cookie is matched by exact name, not by suffix', async () => {
    const auth = make(AppAuth);
    const { token } = await auth.createSession({ id: 'u1' });

    expect(await auth.getSession(cookie(token, 'xasena_session'))).toBeNull();
    expect(
      (await auth.getSession(new Request(URL_, { headers: { cookie: `a=1; asena_session=${token}` } })))?.user.id,
    ).toBe('u1');
  });

  test('a garbage Authorization header and an unknown token resolve to null', async () => {
    const auth = make(AppAuth);

    expect(await auth.getSession(new Request(URL_, { headers: { authorization: 'Basic dXNlcjpwYXNz' } }))).toBeNull();
    expect(await auth.getSession(new Request(URL_, { headers: { authorization: 'Bearer' } }))).toBeNull();
    expect(await auth.getSession(bearer('not-a-real-token'))).toBeNull();
    expect(await auth.getSession(new Request(URL_))).toBeNull();
  });

  test('header: false ignores Bearer tokens', async () => {
    @Auth({ header: false })
    class CookieOnly extends AsenaAuthService {}

    const auth = make(CookieOnly);
    const { token } = await auth.createSession({ id: 'u1' });

    expect(await auth.getSession(bearer(token))).toBeNull();
    expect((await auth.getSession(cookie(token)))?.user.id).toBe('u1');
  });

  test('a custom cookie name is honoured', async () => {
    @Auth({ cookie: { name: 'sid' } })
    class Sid extends AsenaAuthService {}

    const auth = make(Sid);
    const { token } = await auth.createSession({ id: 'u1' });

    expect(auth.cookieName).toBe('sid');
    expect((await auth.getSession(cookie(token, 'sid')))?.user.id).toBe('u1');
    expect(await auth.getSession(cookie(token))).toBeNull();
  });

  test('an expired session resolves to null', async () => {
    @Auth({ sessionTtl: 1 })
    class Short extends AsenaAuthService {}

    const auth = make(Short);
    const { token } = await auth.createSession({ id: 'u1' });

    setSystemTime(new Date(Date.now() + 1_500));

    expect(await auth.getSession(bearer(token))).toBeNull();
  });

  test('sliding: refreshes only once less than half of the lifetime is left', async () => {
    const store = new MemoryAuthStore();
    const touch = spyOn(store, 'touch');

    @Auth({ sessionTtl: 10, store })
    class Sliding extends AsenaAuthService {}

    const auth = make(Sliding);
    const { token } = await auth.createSession({ id: 'u1' });

    await auth.getSession(bearer(token));
    expect(touch).not.toHaveBeenCalled();

    const later = Date.now() + 6_000;

    setSystemTime(new Date(later));

    const session = (await auth.getSession(bearer(token))) as AuthSession;

    expect(touch).toHaveBeenCalledTimes(1);
    expect(session.session.expiresAt.getTime()).toBe(later + 10_000);
  });

  test('sliding: a cookie-carried slide reports the token so the cookie can be re-issued; Bearer does not', async () => {
    @Auth({ sessionTtl: 10 })
    class Sliding extends AsenaAuthService {}

    const auth = make(Sliding);
    const { token } = await auth.createSession({ id: 'u1' });

    const early = cookie(token);

    await auth.getSession(early);
    expect(auth.slidCookieToken(early)).toBeNull();

    setSystemTime(new Date(Date.now() + 6_000));

    const viaBearer = bearer(token);

    await auth.getSession(viaBearer);
    expect(auth.slidCookieToken(viaBearer)).toBeNull();

    setSystemTime(new Date(Date.now() + 6_000));

    const viaCookie = cookie(token);

    await auth.getSession(viaCookie);
    expect(auth.slidCookieToken(viaCookie)).toBe(token);
  });

  test('sliding: false never refreshes', async () => {
    const store = new MemoryAuthStore();
    const touch = spyOn(store, 'touch');

    @Auth({ sessionTtl: 10, sliding: false, store })
    class Fixed extends AsenaAuthService {}

    const auth = make(Fixed);
    const { token } = await auth.createSession({ id: 'u1' });

    setSystemTime(new Date(Date.now() + 9_000));

    expect(await auth.getSession(bearer(token))).not.toBeNull();
    expect(touch).not.toHaveBeenCalled();
  });

  test('revokeSession kills one token, revokeUserSessions every token of the user', async () => {
    const auth = make(AppAuth);
    const { token: t1 } = await auth.createSession({ id: 'u1' });
    const { token: t2 } = await auth.createSession({ id: 'u1' });
    const { token: other } = await auth.createSession({ id: 'u2' });

    await auth.revokeSession(t1);
    expect(await auth.getSession(bearer(t1))).toBeNull();
    expect(await auth.getSession(bearer(t2))).not.toBeNull();

    await auth.revokeUserSessions('u1');
    expect(await auth.getSession(bearer(t2))).toBeNull();
    expect(await auth.getSession(bearer(other))).not.toBeNull();
  });

  test('passwords use the configured hashing', async () => {
    @Auth({ hashing: { cost: 4 } })
    class Cheap extends AsenaAuthService {}

    const auth = make(Cheap);
    const hash = await auth.hashPassword('pw');

    expect(hash).toContain('$04$');
    expect(await auth.verifyPassword('pw', hash)).toBe(true);
  });

  test('the store lifecycle follows the service', async () => {
    const store = new MemoryAuthStore();
    const start = spyOn(store, 'onStart');
    const stop = spyOn(store, 'onStop');

    @Auth({ store })
    class Lifecycle extends AsenaAuthService {}

    const auth = make(Lifecycle);

    await auth.onStart();
    await auth.onStop();

    expect(start).toHaveBeenCalledTimes(1);
    expect(stop).toHaveBeenCalledTimes(1);
  });
});

describe('cookie options', () => {
  test('secure defaults: httpOnly, lax, secure, path /, maxAge = ttl', () => {
    expect(make(AppAuth).cookieOptions).toEqual({
      httpOnly: true,
      sameSite: 'lax',
      secure: true,
      path: '/',
      maxAge: 60,
    });
  });

  test('overrides apply', () => {
    @Auth({ cookie: { secure: false, sameSite: 'strict', path: '/api', domain: 'example.com' } })
    class Custom extends AsenaAuthService {}

    expect(make(Custom).cookieOptions).toEqual({
      httpOnly: true,
      sameSite: 'strict',
      secure: false,
      path: '/api',
      domain: 'example.com',
      maxAge: 604800,
    });
  });
});

describe('getRoles', () => {
  const session = (user: Record<string, unknown>): AuthSession => ({
    user: { id: 'u1', ...user },
    session: { id: 's', userId: 'u1', createdAt: new Date(), expiresAt: new Date() },
  });

  test('default resolver reads user.roles', () => {
    expect(make(AppAuth).getRoles(session({ roles: ['admin', 'user'] }))).toEqual(['admin', 'user']);
  });

  test('default resolver falls back to a comma-separated user.role', () => {
    expect(make(AppAuth).getRoles(session({ role: 'admin, user' }))).toEqual(['admin', 'user']);
  });

  test('default resolver returns [] when neither is present', () => {
    expect(make(AppAuth).getRoles(session({}))).toEqual([]);
  });

  test('a custom resolver wins', () => {
    @Auth({ roles: (s) => [`tenant:${s.user.id}`] })
    class Custom extends AsenaAuthService {}

    expect(make(Custom).getRoles(session({ roles: ['admin'] }))).toEqual(['tenant:u1']);
  });
});
