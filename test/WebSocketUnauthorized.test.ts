import { describe, expect, test } from 'bun:test';
import { WebSocket as WebSocketNamespace } from '@asenajs/asena/decorators';
import { createTestApp, silentLogger } from '@asenajs/asena/test';
import { AsenaWebSocketService } from '@asenajs/asena/web-socket';
import { createErgenecoreAdapter } from '@asenajs/ergenecore';
import { createHonoAdapter } from '@asenajs/hono-adapter';
import { AsenaAuthService, Auth, AuthProviderRegistry, AuthWebSocketMiddleware } from '../index';

@Auth({})
class WsAuth extends AsenaAuthService {}

@WebSocketNamespace({ path: '/ws', name: 'Guarded', middlewares: [AuthWebSocketMiddleware] })
class Guarded extends AsenaWebSocketService {}

const adapters = [
  { name: 'ergenecore', make: () => createErgenecoreAdapter({ logger: silentLogger }) },
  { name: 'hono', make: () => createHonoAdapter({ logger: silentLogger })[0] },
];

describe.each(adapters)('AuthWebSocketMiddleware rejection on $name', ({ make }) => {
  test('an upgrade without a session is answered 401 with WWW-Authenticate: Bearer, like the guard', async () => {
    await using app = await createTestApp({
      adapter: make() as any,
      logger: silentLogger,
      components: [WsAuth, Guarded],
      imports: [AuthProviderRegistry, AuthWebSocketMiddleware],
    });

    const res = await fetch(`${app.baseUrl}/ws`, {
      headers: {
        connection: 'Upgrade',
        upgrade: 'websocket',
        'sec-websocket-version': '13',
        'sec-websocket-key': 'dGhlIHNhbXBsZSBub25jZQ==',
      },
    });

    expect(res.status).toBe(401);
    expect(res.headers.get('www-authenticate')).toBe('Bearer');
  });
});
