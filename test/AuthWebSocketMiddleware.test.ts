import { describe, expect, mock, test } from 'bun:test';
import { AUTH_SESSION_CONTEXT_KEY } from '@asenajs/asena/auth';
import { AuthWebSocketMiddleware } from '../lib/middleware';
import { session, stubContext, stubProvider, stubRegistry } from './middlewareStubs';

const build = (provider = stubProvider()) => {
  const middleware = new AuthWebSocketMiddleware();
  const registry = stubRegistry(provider);

  (middleware as any).registry = registry;

  return { middleware, registry, provider };
};

const upgrade = (headers: Record<string, string> = {}) => new Request('http://localhost/chat', { headers });

describe('AuthWebSocketMiddleware', () => {
  test('no session: a 401 Response before the upgrade, next never runs', async () => {
    const { middleware } = build(stubProvider(null));
    const next = mock(async () => {});

    const result = await middleware.handle(stubContext(upgrade()) as any, next);

    expect(result).toBeInstanceOf(Response);
    expect((result as Response).status).toBe(401);
    expect(next).not.toHaveBeenCalled();
  });

  test('Authorization header: next runs and the socket value carries the session', async () => {
    const { middleware } = build();
    const ctx = stubContext(upgrade({ authorization: 'Bearer abc' }));
    const next = mock(async () => {});

    const result = await middleware.handle(ctx as any, next);

    expect(result).toBeUndefined();
    expect(next).toHaveBeenCalledTimes(1);
    expect(ctx.getWebSocketValue()).toEqual({ [AUTH_SESSION_CONTEXT_KEY]: session });
    expect(ctx.getValue(AUTH_SESSION_CONTEXT_KEY)).toBe(session);
  });

  test('subprotocol only: the provider sees the token as an Authorization header', async () => {
    const { middleware, provider } = build();
    const ctx = stubContext(upgrade({ 'sec-websocket-protocol': 'bearer, abc' }));

    await middleware.handle(ctx as any, async () => {});

    const seen = provider.getSession.mock.calls[0][0];

    expect(seen.headers.get('authorization')).toBe('Bearer abc');
    expect(ctx.getWebSocketValue()).toEqual({ [AUTH_SESSION_CONTEXT_KEY]: session });
  });

  test('keeps what an earlier middleware put in the socket value - adapters replace, not merge', async () => {
    const { middleware } = build();
    const ctx = stubContext(upgrade({ authorization: 'Bearer abc' }));

    ctx.setWebSocketValue({ room: 'lobby' });
    await middleware.handle(ctx as any, async () => {});

    expect(ctx.getWebSocketValue()).toEqual({ room: 'lobby', [AUTH_SESSION_CONTEXT_KEY]: session });
  });

  test('an earlier anonymous null does not hide the subprotocol token', async () => {
    const { middleware, provider } = build();
    const ctx = stubContext(upgrade({ 'sec-websocket-protocol': 'bearer, abc' }), { [AUTH_SESSION_CONTEXT_KEY]: null });

    const result = await middleware.handle(ctx as any, async () => {});

    expect(result).toBeUndefined();
    expect(provider.getSession).toHaveBeenCalledTimes(1);
    expect(ctx.getValue(AUTH_SESSION_CONTEXT_KEY)).toBe(session);
  });

  test('an earlier anonymous null stands when there is no subprotocol token', async () => {
    const { middleware, provider } = build();
    const ctx = stubContext(upgrade(), { [AUTH_SESSION_CONTEXT_KEY]: null });

    const result = await middleware.handle(ctx as any, async () => {});

    expect((result as Response).status).toBe(401);
    expect(provider.getSession).not.toHaveBeenCalled();
  });

  test('a session already in the context is reused', async () => {
    const { middleware, provider } = build();
    const ctx = stubContext(upgrade({ 'sec-websocket-protocol': 'bearer, abc' }), {
      [AUTH_SESSION_CONTEXT_KEY]: session,
    });

    await middleware.handle(ctx as any, async () => {});

    expect(provider.getSession).not.toHaveBeenCalled();
    expect(ctx.getWebSocketValue()).toEqual({ [AUTH_SESSION_CONTEXT_KEY]: session });
  });

  test('onStart fails the boot when the registry cannot select a provider', () => {
    const { middleware, registry } = build();

    registry.select.mockImplementation(() => {
      throw new Error('no provider');
    });

    expect(() => middleware.onStart()).toThrow('no provider');
  });
});
