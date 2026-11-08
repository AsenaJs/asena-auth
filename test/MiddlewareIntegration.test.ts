import { describe, expect, setSystemTime, test } from 'bun:test';
import { getAuthSession } from '@asenajs/asena/auth';
import { Config, Controller, WebSocket as WebSocketNamespace } from '@asenajs/asena/decorators';
import { Get } from '@asenajs/asena/decorators/http';
import { createTestApp, silentLogger } from '@asenajs/asena/test';
import { AsenaWebSocketService } from '@asenajs/asena/web-socket';
import { createErgenecoreAdapter } from '@asenajs/ergenecore';
import { AsenaAuthService } from '../lib/AsenaAuthService';
import { Auth } from '../lib/decorators';
import { AuthProviderRegistry } from '../lib/guard';
import { AuthSessionMiddleware, AuthWebSocketMiddleware } from '../lib/middleware';
import { bootFake } from './support/fakeAdapter';
import { connect } from './wsClient';

@Auth({ sessionTtl: 3600 })
class AppAuth extends AsenaAuthService {}

@Config()
class AppConfig {
  globalMiddlewares() {
    return [AuthSessionMiddleware];
  }
}

@Controller('/')
class Who {
  @Get('/whoami')
  whoami(ctx: any) {
    return ctx.send({ user: getAuthSession(ctx)?.user.id ?? null });
  }
}

@WebSocketNamespace({ path: '/chat', name: 'Chat', middlewares: [AuthWebSocketMiddleware] })
class Chat extends AsenaWebSocketService {
  protected onOpen(ws: any) {
    ws.send(JSON.stringify(ws.data.values));
  }
}

const components = [AppAuth, AppConfig, Who, Chat];
const imports = [AuthProviderRegistry, AuthSessionMiddleware, AuthWebSocketMiddleware];

const boot = () =>
  createTestApp({
    adapter: createErgenecoreAdapter({ logger: silentLogger }),
    logger: silentLogger,
    components,
    imports,
  });

const tokenFor = async (app: { resolve: <T>(name: string) => Promise<T> }) =>
  (await (await app.resolve<AppAuth>('AppAuth')).createSession({ id: 'u1' })).token;

describe('session and WebSocket middlewares on ergenecore', () => {
  test('browser-style subprotocol token opens the socket, echoes `bearer` and carries the session', async () => {
    await using app = await boot();
    const token = await tokenFor(app);

    const outcome = await connect(app.wsUrl('/chat'), ['bearer', token]);

    expect(outcome.opened).toBe(true);

    if (outcome.opened) {
      expect(outcome.protocol).toBe('bearer');
      expect(outcome.message.authSession.user.id).toBe('u1');
    }
  });
});

describe('session and WebSocket middlewares', () => {
  const bootOnFake = () => bootFake({ components, imports });

  test('global session middleware: null when anonymous, the user with a Bearer token', async () => {
    await using app = await bootOnFake();
    const token = await tokenFor(app);

    expect(await (await app.fetch('/whoami')).json()).toEqual({ user: null });

    const res = await app.fetch('/whoami', { headers: { authorization: `Bearer ${token}` } });

    expect(await res.json()).toEqual({ user: 'u1' });
  });

  test('global session middleware re-issues a slid cookie, also on a public route', async () => {
    await using app = await bootOnFake();
    const token = await tokenFor(app);

    try {
      setSystemTime(new Date(Date.now() + 2_000_000));

      const res = await app.fetch('/whoami', { headers: { cookie: `asena_session=${token}` } });

      expect(await res.json()).toEqual({ user: 'u1' });
      expect(res.headers.get('set-cookie') ?? '').toContain(`asena_session=${token}`);
    } finally {
      setSystemTime();
    }
  });

  test('no token: the upgrade is rejected, the socket never opens', async () => {
    await using app = await bootOnFake();

    expect(await app.connect('/chat')).toEqual({ opened: false, status: 401 });
  });

  test('a token that matches no session is rejected too', async () => {
    await using app = await bootOnFake();

    expect(await app.connect('/chat', { protocols: ['bearer', 'not-a-token'] })).toEqual({
      opened: false,
      status: 401,
    });
  });
});
