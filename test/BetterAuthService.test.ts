import { describe, expect, mock, test } from 'bun:test';
import { AUTH_PROVIDER_KEY } from '@asenajs/asena/auth';
import { ComponentConstants } from '@asenajs/asena/ioc/constants';
import { getOwnTypedMetadata, getTypedMetadata } from '@asenajs/asena/utils';
import { BetterAuth, BetterAuthService } from '../lib/better-auth';
import type { BetterAuthInstance } from '../lib/types';

const user = { id: 'u1', email: 'a@b.c', role: 'admin,user' };

const mockAuth = (
  result: { session: any; user: any } | null,
  responseHeaders = new Headers(),
): BetterAuthInstance & { api: { getSession: any } } => ({
  handler: async () => new Response(null),
  api: {
    getSession: mock(async (_opts: { headers: Headers; returnHeaders: true }) => ({
      headers: responseHeaders,
      response: result,
    })),
  },
});

const providerFor = (auth: BetterAuthInstance, extra: Record<string, unknown> = {}) => {
  @BetterAuth({ auth, ...extra })
  class AppBA extends BetterAuthService {}

  return new (AppBA as any)() as BetterAuthService;
};

describe('BetterAuthService.getSession', () => {
  test.each([
    ['Date values (in-process)', new Date('2026-01-01T00:00:00Z'), new Date('2026-01-08T00:00:00Z')],
    ['ISO strings (serialized)', '2026-01-01T00:00:00.000Z', '2026-01-08T00:00:00.000Z'],
  ])('maps %s to an AuthSession with Date fields', async (_case, createdAt, expiresAt) => {
    const auth = mockAuth({ session: { id: 's1', userId: 'u1', createdAt, expiresAt, token: 'x' }, user });
    const request = new Request('http://localhost/', { headers: { authorization: 'Bearer ba' } });

    const session = await providerFor(auth).getSession(request);

    expect(session).toEqual({
      user,
      session: {
        id: 's1',
        userId: 'u1',
        createdAt: new Date('2026-01-01T00:00:00Z'),
        expiresAt: new Date('2026-01-08T00:00:00Z'),
      },
    });
    expect(auth.api.getSession).toHaveBeenCalledWith({ headers: request.headers, returnHeaders: true });
  });

  test('null passes through', async () => {
    expect(await providerFor(mockAuth(null)).getSession(new Request('http://localhost/'))).toBeNull();
  });

  test('Set-Cookie headers Better Auth answers with (session refresh) are kept per request', async () => {
    const headers = new Headers();

    headers.append('set-cookie', 'better-auth.session_token=t.sig%3D; Max-Age=604800; Path=/; HttpOnly');
    headers.append('set-cookie', 'better-auth.session_data=; Max-Age=0; Path=/');

    const provider = providerFor(mockAuth(null, headers));
    const request = new Request('http://localhost/');

    await provider.getSession(request);

    expect(provider.responseCookies(request)).toEqual([
      'better-auth.session_token=t.sig%3D; Max-Age=604800; Path=/; HttpOnly',
      'better-auth.session_data=; Max-Age=0; Path=/',
    ]);
    expect(provider.responseCookies(new Request('http://localhost/'))).toEqual([]);
  });

  test.each([
    ['session.id', { userId: 'u1' }],
    ['session.userId', { id: 's1' }],
  ])('a result without %s is treated as no session', async (_case, partial) => {
    const auth = mockAuth({ session: { ...partial, createdAt: new Date(), expiresAt: new Date() }, user });

    expect(await providerFor(auth).getSession(new Request('http://localhost/'))).toBeNull();
  });
});

describe('BetterAuthService.getRoles', () => {
  const session = {
    user,
    session: { id: 's1', userId: 'u1', createdAt: new Date(), expiresAt: new Date() },
  };

  test('default resolver splits the admin plugin role string', () => {
    expect(providerFor(mockAuth(null)).getRoles(session)).toEqual(['admin', 'user']);
  });

  test('a custom resolver replaces it', () => {
    const provider = providerFor(mockAuth(null), { roles: () => ['custom'] });

    expect(provider.getRoles(session)).toEqual(['custom']);
  });
});

describe('BetterAuthService configuration', () => {
  test.each([
    ['an empty object', {}],
    ['no handler', { api: { getSession: async () => ({ headers: new Headers(), response: null }) } }],
    ['no api.getSession', { handler: async () => new Response(null), api: {} }],
  ])('@BetterAuth with %s fails at construction, naming what is missing', (_case, auth) => {
    @BetterAuth({ auth: auth as any })
    class Broken extends BetterAuthService {}

    expect(() => new (Broken as any)()).toThrow(/Better Auth instance/);
  });

  test('instance throws when the class was never decorated', () => {
    class Bare extends BetterAuthService {}

    expect(() => new Bare().instance).toThrow(/@BetterAuth/);
  });

  test('instance returns the configured Better Auth object', () => {
    const auth = mockAuth(null);

    expect(providerFor(auth).instance).toBe(auth);
  });
});

describe('@BetterAuth', () => {
  test('registers a service under the class name, as an auth provider, keeping the name', () => {
    @BetterAuth({ auth: mockAuth(null) })
    class AppBA extends BetterAuthService {}

    expect(AppBA.name).toBe('AppBA');
    expect(getOwnTypedMetadata<string>(ComponentConstants.NameKey, AppBA)).toBe('AppBA');
    expect(getTypedMetadata<string>(ComponentConstants.InterfaceKey, AppBA)).toBe(AUTH_PROVIDER_KEY);
  });

  test('name option overrides the registered name', () => {
    @BetterAuth({ name: 'Social', auth: mockAuth(null) })
    class AppBA extends BetterAuthService {}

    expect(getOwnTypedMetadata<string>(ComponentConstants.NameKey, AppBA)).toBe('Social');
  });

  test('a thunk is evaluated at construction, not at decoration', () => {
    const thunk = mock(() => ({ auth: mockAuth(null), primary: true }));

    @BetterAuth(thunk)
    class AppBA extends BetterAuthService {}

    expect(thunk).not.toHaveBeenCalled();

    const instance = new (AppBA as any)() as BetterAuthService;

    expect(thunk).toHaveBeenCalledTimes(1);
    expect(instance.primary).toBe(true);
  });

  test('primary defaults to false', () => {
    expect(providerFor(mockAuth(null)).primary).toBe(false);
  });
});
