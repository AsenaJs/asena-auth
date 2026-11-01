import { afterEach, describe, expect, mock, setSystemTime, spyOn, test } from 'bun:test';
import { AUTH_PROVIDER_KEY } from '@asenajs/asena/auth';
import type { AuthSession } from '@asenajs/asena/auth';
import { ComponentConstants } from '@asenajs/asena/ioc/constants';
import { createTestApp, silentLogger } from '@asenajs/asena/test';
import { getOwnTypedMetadata, getTypedMetadata } from '@asenajs/asena/utils';
import { createErgenecoreAdapter } from '@asenajs/ergenecore';
import { AsenaAuthService } from '../lib/AsenaAuthService';
import { Auth } from '../lib/decorators';
import { withSubprotocolToken } from '../lib/helpers';
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

  test('the stored user is a snapshot: mutating the input or a returned session never reaches later requests', async () => {
    const auth = make(AppAuth);
    const input = { id: 'u1', roles: ['user'] };
    const { token, session } = await auth.createSession(input);

    input.roles.push('admin');
    (session.user as typeof input).roles.push('admin');

    const first = await auth.getSession(bearer(token));

    (first!.user as typeof input).roles.push('admin');

    expect((await auth.getSession(bearer(token)))?.user).toEqual({ id: 'u1', roles: ['user'] });
  });

  test('a user carrying a function cannot be stored: createSession names the cause and stores nothing', async () => {
    const store = new MemoryAuthStore();

    @Auth({ store })
    class Cloning extends AsenaAuthService {}

    const auth = make(Cloning);
    const error = await auth.createSession({ id: 'u1', can: () => true } as any).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(TypeError);
    expect((error as Error).message).toContain('Cloning.createSession');
    expect((error as Error).message).toContain('plain data');
    expect(((error as Error).cause as Error).name).toBe('DataCloneError');
    expect(store.size).toBe(0);
  });

  test('the stored user is data only: a class instance comes back as a plain object, Date and Map survive', async () => {
    class Profile {
      public constructor(public readonly name: string) {}

      public greet(): string {
        return `hi ${this.name}`;
      }
    }

    const auth = make(AppAuth);
    const since = new Date('2026-01-02T03:04:05Z');
    const { token } = await auth.createSession({
      id: 'u1',
      profile: new Profile('Ada'),
      since,
      flags: new Map([['beta', true]]),
    } as any);
    const user = (await auth.getSession(bearer(token)))!.user as any;

    expect(user.profile).not.toBeInstanceOf(Profile);
    expect(Object.getPrototypeOf(user.profile)).toBe(Object.prototype);
    expect(user.profile).toEqual({ name: 'Ada' });
    expect(user.since).toBeInstanceOf(Date);
    expect(user.since.getTime()).toBe(since.getTime());
    expect(user.flags).toBeInstanceOf(Map);
    expect(user.flags.get('beta')).toBe(true);
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

  test('bearer: false ignores Bearer tokens', async () => {
    @Auth({ bearer: false })
    class CookieOnly extends AsenaAuthService {}

    const auth = make(CookieOnly);
    const { token } = await auth.createSession({ id: 'u1' });

    expect(await auth.getSession(bearer(token))).toBeNull();
    expect(
      await auth.getSession(
        withSubprotocolToken(new Request(URL_, { headers: { 'sec-websocket-protocol': `bearer, ${token}` } })),
      ),
    ).toBeNull();
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

  test('absoluteTtl: sliding never moves expiresAt past createdAt + absoluteTtl, and the cap ends the session', async () => {
    @Auth({ sessionTtl: 10, absoluteTtl: 15 })
    class Capped extends AsenaAuthService {}

    const auth = make(Capped);
    const { token, session } = await auth.createSession({ id: 'u1' });
    const createdAt = session.session.createdAt.getTime();

    setSystemTime(new Date(createdAt + 6_000));

    expect((await auth.getSession(bearer(token)))?.session.expiresAt.getTime()).toBe(createdAt + 15_000);

    setSystemTime(new Date(createdAt + 14_000));

    expect(await auth.getSession(bearer(token))).not.toBeNull();

    setSystemTime(new Date(createdAt + 15_000));

    expect(await auth.getSession(bearer(token))).toBeNull();
  });

  test('absoluteTtl: a store row whose expiresAt outlives the cap is still rejected once the cap passed', async () => {
    const store = new MemoryAuthStore();

    @Auth({ sessionTtl: 10, absoluteTtl: 15, store })
    class Capped extends AsenaAuthService {}

    const auth = make(Capped);
    const { token, session } = await auth.createSession({ id: 'u1' });
    const createdAt = session.session.createdAt.getTime();

    await store.touch(session.session.id, createdAt + 60_000);
    setSystemTime(new Date(createdAt + 16_000));

    expect(await auth.getSession(bearer(token))).toBeNull();
    expect(await auth.listUserSessions('u1')).toEqual([]);
  });

  test('absoluteTtl defaults to 30 days: a 7-day session slid on day 29 ends on day 30', async () => {
    const day = 86_400_000;
    const auth = make(
      (() => {
        @Auth({})
        class Defaults extends AsenaAuthService {}

        return Defaults;
      })(),
    );
    const { token, session } = await auth.createSession({ id: 'u1' });
    const createdAt = session.session.createdAt.getTime();

    for (let d = 3; d <= 27; d += 3) {
      setSystemTime(new Date(createdAt + d * day + 1));
      expect(await auth.getSession(bearer(token))).not.toBeNull();
    }

    setSystemTime(new Date(createdAt + 29 * day));

    expect((await auth.getSession(bearer(token)))?.session.expiresAt.getTime()).toBe(createdAt + 30 * day);

    setSystemTime(new Date(createdAt + 30 * day));

    expect(await auth.getSession(bearer(token))).toBeNull();
  });

  test('absoluteTtl: false lets sliding keep a session alive past any cap', async () => {
    @Auth({ sessionTtl: 10, absoluteTtl: false })
    class Uncapped extends AsenaAuthService {}

    const auth = make(Uncapped);
    const { token, session } = await auth.createSession({ id: 'u1' });
    const createdAt = session.session.createdAt.getTime();

    for (let s = 6; s <= 60; s += 6) {
      setSystemTime(new Date(createdAt + s * 1_000));
      expect(await auth.getSession(bearer(token))).not.toBeNull();
    }
  });

  test('absoluteTtl smaller than sessionTtl fails the start, naming both values', async () => {
    @Auth({ sessionTtl: 3600, absoluteTtl: 60 })
    class Inverted extends AsenaAuthService {}

    await expect(make(Inverted).onStart()).rejects.toThrow(/Inverted.*absoluteTtl \(60\).*sessionTtl \(3600\)/);

    @Auth({ sessionTtl: 3_000_000 })
    class LongDefault extends AsenaAuthService {}

    await expect(make(LongDefault).onStart()).rejects.toThrow(/absoluteTtl \(2592000\).*sessionTtl \(3000000\)/);
  });

  test('absoluteTtl smaller than sessionTtl fails a real boot', async () => {
    @Auth({ sessionTtl: 3600, absoluteTtl: 60 })
    class Inverted extends AsenaAuthService {}

    const error = await createTestApp({
      adapter: createErgenecoreAdapter({ logger: silentLogger }),
      logger: silentLogger,
      components: [Inverted],
    }).catch((e: unknown) => e as Error);

    expect(error).toBeInstanceOf(Error);
    expect(String((error as Error).cause)).toContain('absoluteTtl (60) is smaller than sessionTtl (3600)');
  });

  describe('csrf: a cross-site state-changing request does not authenticate by cookie', () => {
    const send = (
      token: string,
      { method = 'POST', headers = {} }: { method?: string; headers?: Record<string, string> } = {},
    ) => new Request(URL_, { method, headers: { cookie: `asena_session=${token}`, ...headers } });

    @Auth({ csrf: { trustedOrigins: ['https://app.example'] } })
    class Guarded extends AsenaAuthService {}

    const login = async (Cls: new () => AsenaAuthService = Guarded) => {
      const auth = make(Cls);

      return { auth, token: (await auth.createSession({ id: 'u1' })).token };
    };

    test('Sec-Fetch-Site decides when present: same-origin and none pass, same-site and cross-site do not', async () => {
      const { auth, token } = await login();

      for (const site of ['same-origin', 'none']) {
        expect(await auth.getSession(send(token, { headers: { 'sec-fetch-site': site } }))).not.toBeNull();
      }

      for (const site of ['same-site', 'cross-site']) {
        expect(await auth.getSession(send(token, { headers: { 'sec-fetch-site': site } }))).toBeNull();
      }

      expect(
        await auth.getSession(
          send(token, { headers: { 'sec-fetch-site': 'same-origin', origin: 'https://evil.example' } }),
        ),
      ).not.toBeNull();
    });

    test("without Sec-Fetch-Site, Origin must be the request URL's origin; no header at all passes", async () => {
      const { auth, token } = await login();

      expect(await auth.getSession(send(token, { headers: { origin: 'http://localhost' } }))).not.toBeNull();
      expect(await auth.getSession(send(token, { headers: { origin: 'https://evil.example' } }))).toBeNull();
      expect(await auth.getSession(send(token, { headers: { origin: 'null' } }))).toBeNull();
      expect(await auth.getSession(send(token, { headers: { origin: 'http://localhost:8080' } }))).toBeNull();
      expect(await auth.getSession(send(token))).not.toBeNull();
    });

    test('trustedOrigins admits a listed Origin, also with Sec-Fetch-Site same-site or cross-site', async () => {
      const { auth, token } = await login();

      expect(await auth.getSession(send(token, { headers: { origin: 'https://app.example' } }))).not.toBeNull();

      for (const site of ['same-site', 'cross-site']) {
        const headers = { 'sec-fetch-site': site, origin: 'https://app.example' };

        expect(await auth.getSession(send(token, { headers }))).not.toBeNull();
      }
    });

    test('safe methods are exempt, every other method is checked', async () => {
      const { auth, token } = await login();
      const headers = { 'sec-fetch-site': 'cross-site', origin: 'https://evil.example' };

      for (const method of ['GET', 'HEAD', 'OPTIONS']) {
        expect(await auth.getSession(send(token, { method, headers }))).not.toBeNull();
      }

      for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) {
        expect(await auth.getSession(send(token, { method, headers }))).toBeNull();
      }
    });

    test('a cross-site WebSocket upgrade (a GET) carrying only the cookie is rejected', async () => {
      const { auth, token } = await login();
      const upgrade = { upgrade: 'websocket', connection: 'Upgrade' };

      expect(
        await auth.getSession(send(token, { method: 'GET', headers: { ...upgrade, origin: 'https://evil.example' } })),
      ).toBeNull();
      expect(
        await auth.getSession(send(token, { method: 'GET', headers: { ...upgrade, origin: 'http://localhost' } })),
      ).not.toBeNull();
    });

    test('Bearer requests are exempt: the check applies only to a token read from the cookie', async () => {
      const { auth, token } = await login();
      const headers = {
        authorization: `Bearer ${token}`,
        'sec-fetch-site': 'cross-site',
        origin: 'https://evil.example',
      };

      expect(await auth.getSession(new Request(URL_, { method: 'POST', headers }))).not.toBeNull();
    });

    test('on by default, and csrf: false disables it', async () => {
      @Auth({ csrf: false })
      class Off extends AsenaAuthService {}

      const headers = { 'sec-fetch-site': 'cross-site', origin: 'https://evil.example' };
      const byDefault = await login(AppAuth as any);
      const off = await login(Off);

      expect(await byDefault.auth.getSession(send(byDefault.token, { headers }))).toBeNull();
      expect(await off.auth.getSession(send(off.token, { headers }))).not.toBeNull();
    });
  });

  describe('loadUser', () => {
    test('the loaded user replaces the stored snapshot on every request, and roles follow it', async () => {
      const directory: Record<string, { id: string; roles: string[] } | null> = { u1: { id: 'u1', roles: ['admin'] } };
      const loadUser = mock(async (id: string) => directory[id] ?? null);

      @Auth({ loadUser })
      class Fresh extends AsenaAuthService {}

      const auth = make(Fresh);
      const { token } = await auth.createSession({ id: 'u1', roles: ['admin'] });

      expect(auth.getRoles((await auth.getSession(bearer(token)))!)).toEqual(['admin']);

      directory.u1 = { id: 'u1', roles: ['user'] };

      const demoted = (await auth.getSession(bearer(token)))!;

      expect(demoted.user).toEqual({ id: 'u1', roles: ['user'] });
      expect(auth.getRoles(demoted)).toEqual(['user']);
      expect(loadUser).toHaveBeenCalledTimes(2);
      expect(loadUser).toHaveBeenLastCalledWith('u1');
    });

    test('a user the loader no longer finds ends the session and deletes its row', async () => {
      const store = new MemoryAuthStore();

      @Auth({ store, loadUser: async () => null })
      class Gone extends AsenaAuthService {}

      const auth = make(Gone);
      const { token, session } = await auth.createSession({ id: 'u1' });

      expect(await auth.getSession(bearer(token))).toBeNull();
      expect(await store.get(session.session.id)).toBeNull();
    });

    test('a loaded user need not be cloneable: it is handed out as loaded', async () => {
      class Row {
        public constructor(public readonly id: string) {}

        public can(): boolean {
          return true;
        }
      }

      @Auth({ loadUser: async (id) => new Row(id) as any })
      class Orm extends AsenaAuthService {}

      const auth = make(Orm);
      const { token } = await auth.createSession({ id: 'u1' });

      expect((await auth.getSession(bearer(token)))?.user).toBeInstanceOf(Row);
    });

    test('an expired session is not loaded', async () => {
      const loadUser = mock(async (id: string) => ({ id }));

      @Auth({ sessionTtl: 1, loadUser })
      class Lazy extends AsenaAuthService {}

      const auth = make(Lazy);
      const { token } = await auth.createSession({ id: 'u1' });

      setSystemTime(new Date(Date.now() + 1_500));

      expect(await auth.getSession(bearer(token))).toBeNull();
      expect(loadUser).not.toHaveBeenCalled();
    });
  });

  describe('rotateSession', () => {
    const ctxFor = (request: Request) => ({ req: request, setCookie: mock(async () => {}) });

    test('replaces the current session: the old token stops working, the new one is a fresh session', async () => {
      @Auth({ sessionTtl: 60, absoluteTtl: 100 })
      class Rotating extends AsenaAuthService {}

      const auth = make(Rotating);
      const { token, session } = await auth.createSession({ id: 'u1', roles: ['user'] });
      const rotatedAt = session.session.createdAt.getTime() + 50_000;

      setSystemTime(new Date(rotatedAt));

      const ctx = ctxFor(bearer(token));
      const next = await auth.rotateSession(ctx as any);

      expect(next).not.toBe(token);
      expect(await auth.getSession(bearer(token))).toBeNull();

      const fresh = (await auth.getSession(bearer(next)))!;

      expect(fresh.user).toEqual({ id: 'u1', roles: ['user'] });
      expect(fresh.session.createdAt.getTime()).toBe(rotatedAt);
      expect(ctx.setCookie).not.toHaveBeenCalled();

      setSystemTime(new Date(rotatedAt + 59_000));

      expect(await auth.getSession(bearer(next))).not.toBeNull();
    });

    test('a given user replaces the session user', async () => {
      const auth = make(AppAuth);
      const { token } = await auth.createSession({ id: 'u1', roles: ['user'] });
      const next = await auth.rotateSession(ctxFor(bearer(token)) as any, { id: 'u1', roles: ['admin'] });

      expect((await auth.getSession(bearer(next)))?.user).toEqual({ id: 'u1', roles: ['admin'] });
    });

    test('a cookie session gets the new token as its cookie', async () => {
      const auth = make(AppAuth);
      const { token } = await auth.createSession({ id: 'u1' });
      const ctx = ctxFor(cookie(token));
      const next = await auth.rotateSession(ctx as any);

      expect(ctx.setCookie).toHaveBeenCalledTimes(1);
      expect(ctx.setCookie).toHaveBeenCalledWith('asena_session', next, { extraOptions: auth.cookieOptions });
      expect(await auth.getSession(cookie(token))).toBeNull();
    });

    test('without a current session it throws and creates nothing', async () => {
      const store = new MemoryAuthStore();

      @Auth({ store })
      class Rotating extends AsenaAuthService {}

      const auth = make(Rotating);

      await expect(auth.rotateSession(ctxFor(new Request(URL_)) as any)).rejects.toThrow(
        'Rotating.rotateSession: the request has no session',
      );
      await expect(auth.rotateSession(ctxFor(bearer('unknown')) as any)).rejects.toThrow('no session');
      expect(store.size).toBe(0);
    });

    test('with loadUser, the new session carries the stored user, so a non-cloneable loaded user does not break it', async () => {
      const store = new MemoryAuthStore();

      @Auth({ store, loadUser: async (id) => ({ id, can: () => true }) as any })
      class Orm extends AsenaAuthService {}

      const auth = make(Orm);
      const { token } = await auth.createSession({ id: 'u1', roles: ['user'] });
      const next = await auth.rotateSession(ctxFor(bearer(token)) as any);
      const fresh = (await auth.getSession(bearer(next)))!;

      expect(typeof (fresh.user as any).can).toBe('function');
      expect((await store.get(fresh.session.id))?.user).toEqual({ id: 'u1', roles: ['user'] });
      expect(await auth.getSession(bearer(token))).toBeNull();
    });

    test('a failed create leaves the current session working', async () => {
      const store = new MemoryAuthStore();

      @Auth({ store })
      class Rotating extends AsenaAuthService {}

      const auth = make(Rotating);
      const { token } = await auth.createSession({ id: 'u1' });

      await expect(
        auth.rotateSession(ctxFor(bearer(token)) as any, { id: 'u1', notify: () => {} } as any),
      ).rejects.toThrow(TypeError);
      expect(await auth.getSession(bearer(token))).not.toBeNull();

      spyOn(store, 'create').mockRejectedValueOnce(new Error('store down'));

      await expect(auth.rotateSession(ctxFor(bearer(token)) as any)).rejects.toThrow('store down');
      expect(await auth.getSession(bearer(token))).not.toBeNull();
      expect(store.size).toBe(1);
    });
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

  test('revokeSessionById ends the session whose AuthSession.session.id it is given, and only that one', async () => {
    const auth = make(AppAuth);
    const { token, session } = await auth.createSession({ id: 'u1' });
    const { token: sameUser } = await auth.createSession({ id: 'u1' });

    await auth.revokeSessionById(session.session.id);

    expect(await auth.getSession(bearer(token))).toBeNull();
    expect(await auth.getSession(bearer(sameUser))).not.toBeNull();
  });

  test("listUserSessions returns the user's live sessions only, each revocable by its id", async () => {
    @Auth({ sessionTtl: 10, sliding: false })
    class Listing extends AsenaAuthService {}

    const auth = make(Listing);
    const { session: early } = await auth.createSession({ id: 'u1', name: 'a' });

    setSystemTime(new Date(Date.now() + 6_000));

    const { token, session: late } = await auth.createSession({ id: 'u1', name: 'a' });

    await auth.createSession({ id: 'u2' });

    const both = await auth.listUserSessions('u1');

    expect(both.map((s) => s.session.id).sort()).toEqual([early.session.id, late.session.id].sort());
    expect(both[0]?.user).toEqual({ id: 'u1', name: 'a' });

    setSystemTime(new Date(Date.now() + 5_000));

    const live = await auth.listUserSessions('u1');

    expect(live.map((s) => s.session.id)).toEqual([late.session.id]);

    await auth.revokeSessionById(live[0]!.session.id);

    expect(await auth.getSession(bearer(token))).toBeNull();
    expect(await auth.listUserSessions('u1')).toEqual([]);
  });

  test('listUserSessions on a store without listByUser names the store', async () => {
    class LegacyStore {
      async create() {}
      async get() {
        return null;
      }
      async delete() {}
      async deleteByUser() {}
      async touch() {}
    }

    @Auth({ store: new LegacyStore() })
    class Legacy extends AsenaAuthService {}

    await expect(make(Legacy).listUserSessions('u1')).rejects.toThrow(/LegacyStore.*listByUser/);
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

  test('sweepInterval is in seconds: the default MemoryAuthStore sweeps every sweepInterval * 1000 ms', async () => {
    @Auth({ sweepInterval: 2 })
    class Sweeping extends AsenaAuthService {}

    const auth = make(Sweeping);
    const interval = spyOn(globalThis, 'setInterval');

    try {
      await auth.onStart();
      expect(interval).toHaveBeenCalledTimes(1);
      expect(interval.mock.calls[0]?.[1]).toBe(2_000);
    } finally {
      interval.mockRestore();
      await auth.onStop();
    }
  });

  test('through the container a supplied store starts and stops once', async () => {
    const store = new MemoryAuthStore();
    const start = spyOn(store, 'onStart');
    const stop = spyOn(store, 'onStop');

    @Auth({ store })
    class Counted extends AsenaAuthService {}

    const app = await createTestApp({
      adapter: createErgenecoreAdapter({ logger: silentLogger }),
      logger: silentLogger,
      components: [Counted],
    });

    try {
      expect(start).toHaveBeenCalledTimes(1);
      expect(stop).not.toHaveBeenCalled();
    } finally {
      await app.stop();
    }

    expect(stop).toHaveBeenCalledTimes(1);
  });

  test('two providers sharing one store: it stops only when the last one stops', async () => {
    const store = new MemoryAuthStore();
    const start = spyOn(store, 'onStart');
    const stop = spyOn(store, 'onStop');

    @Auth({ store })
    class First extends AsenaAuthService {}

    @Auth({ store })
    class Second extends AsenaAuthService {}

    const first = make(First);
    const second = make(Second);

    await first.onStart();
    await second.onStart();
    await first.onStop();

    expect(start).toHaveBeenCalledTimes(1);
    expect(stop).not.toHaveBeenCalled();

    await second.onStop();
    await second.onStop();

    expect(stop).toHaveBeenCalledTimes(1);
  });

  test('two providers starting a shared async store concurrently start it once and both wait for it', async () => {
    const events: string[] = [];
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const store = new MemoryAuthStore();

    store.onStart = async () => {
      events.push('store:start');
      await gate;
      events.push('store:started');
    };
    store.onStop = async () => {
      events.push('store:stop');
    };

    @Auth({ store })
    class First extends AsenaAuthService {}

    @Auth({ store })
    class Second extends AsenaAuthService {}

    const first = make(First);
    const second = make(Second);
    const starting = Promise.all([
      first.onStart().then(() => events.push('first:ready')),
      second.onStart().then(() => events.push('second:ready')),
    ]);

    await Bun.sleep(1);
    release();
    await starting;

    expect(events).toEqual(['store:start', 'store:started', 'first:ready', 'second:ready']);

    await first.onStop();

    expect(events).not.toContain('store:stop');

    await second.onStop();

    expect(events.filter((e) => e === 'store:stop')).toHaveLength(1);
  });

  test('a store whose start failed is started again by the next onStart, and a failed provider never stops it', async () => {
    const store = new MemoryAuthStore();
    const start = spyOn(store, 'onStart').mockImplementationOnce(() => {
      throw new Error('store down');
    });
    const stop = spyOn(store, 'onStop');

    @Auth({ store })
    class Retry extends AsenaAuthService {}

    const auth = make(Retry);

    await expect(auth.onStart()).rejects.toThrow('store down');
    await auth.onStop();

    expect(stop).not.toHaveBeenCalled();

    await auth.onStart();
    await auth.onStop();

    expect(start).toHaveBeenCalledTimes(2);
    expect(stop).toHaveBeenCalledTimes(1);
  });

  test('concurrent stops of two providers stop the shared store once', async () => {
    const store = new MemoryAuthStore();
    const start = spyOn(store, 'onStart');
    const stop = spyOn(store, 'onStop');

    @Auth({ store })
    class First extends AsenaAuthService {}

    @Auth({ store })
    class Second extends AsenaAuthService {}

    const first = make(First);
    const second = make(Second);

    await Promise.all([first.onStart(), second.onStart()]);
    await Promise.all([first.onStop(), second.onStop()]);

    expect(start).toHaveBeenCalledTimes(1);
    expect(stop).toHaveBeenCalledTimes(1);

    await first.onStart();

    expect(start).toHaveBeenCalledTimes(2);

    await first.onStop();

    expect(stop).toHaveBeenCalledTimes(2);
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
