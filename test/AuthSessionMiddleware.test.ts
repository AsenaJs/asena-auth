import { describe, expect, mock, test } from 'bun:test';
import { AUTH_SESSION_CONTEXT_KEY } from '@asenajs/asena/auth';
import { AuthSessionMiddleware } from '../lib/middleware';
import { session, stubContext, stubProvider, stubRegistry } from './middlewareStubs';

const build = (provider = stubProvider()) => {
  const middleware = new AuthSessionMiddleware();
  const registry = stubRegistry(provider);

  (middleware as any).registry = registry;

  return { middleware, registry, provider };
};

describe('AuthSessionMiddleware', () => {
  test('anonymous: stores null and still calls next - it never rejects', async () => {
    const { middleware } = build(stubProvider(null));
    const ctx = stubContext(new Request('http://localhost/'));
    const next = mock(async () => {});

    await middleware.handle(ctx as any, next);

    expect(ctx.getValue(AUTH_SESSION_CONTEXT_KEY)).toBeNull();
    expect(next).toHaveBeenCalledTimes(1);
  });

  test('stores the provider session, resolved from the raw request', async () => {
    const { middleware, provider } = build();
    const request = new Request('http://localhost/');
    const ctx = stubContext(request);

    await middleware.handle(ctx as any, async () => {});

    expect(ctx.getValue(AUTH_SESSION_CONTEXT_KEY)).toBe(session);
    expect(provider.getSession).toHaveBeenCalledWith(request);
  });

  test.each([
    ['a session', session],
    ['resolved-anonymous null', null],
  ])('does not ask the provider again when %s is already in the context', async (_case, value) => {
    const { middleware, provider } = build();
    const ctx = stubContext(new Request('http://localhost/'), { [AUTH_SESSION_CONTEXT_KEY]: value });

    await middleware.handle(ctx as any, async () => {});

    expect(provider.getSession).not.toHaveBeenCalled();
    expect(ctx.getValue(AUTH_SESSION_CONTEXT_KEY)).toBe(value);
  });

  test('selects the provider named by a subclass', async () => {
    class Named extends AuthSessionMiddleware {
      protected providerName = 'Other';
    }

    const middleware = new Named();
    const registry = stubRegistry(stubProvider());

    (middleware as any).registry = registry;
    await middleware.handle(stubContext(new Request('http://localhost/')) as any, async () => {});

    expect(registry.select).toHaveBeenCalledWith('Other');
  });

  test('onStart tolerates several providers without a primary when no provider is named', () => {
    const { middleware, registry } = build();

    (registry as any).providers = new Map([
      ['A', stubProvider()],
      ['B', stubProvider()],
    ]);
    registry.select.mockImplementation(() => {
      throw new Error('none is primary');
    });

    expect(() => middleware.onStart()).not.toThrow();
  });

  test('onStart fails the boot when the registry cannot select a provider', () => {
    const { middleware, registry } = build();

    registry.select.mockImplementation(() => {
      throw new Error('none is primary');
    });

    expect(() => middleware.onStart()).toThrow('none is primary');
  });
});
