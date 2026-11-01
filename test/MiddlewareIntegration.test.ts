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

const boot = () =>
  createTestApp({
    adapter: createErgenecoreAdapter({ logger: silentLogger }),
    logger: silentLogger,
    components: [AppAuth, AppConfig, Who, Chat],
    imports: [AuthProviderRegistry, AuthSessionMiddleware, AuthWebSocketMiddleware],
  });

const tokenFor = async (app: Awaited<ReturnType<typeof boot>>) =>
  (await (await app.resolve<AppAuth>('AppAuth')).createSession({ id: 'u1' })).token;

describe('session and WebSocket middlewares on ergenecore', () => {
  test('global session middleware: null when anonymous, the user with a Bearer token', async () => {
    await using app = await boot();
    const token = await tokenFor(app);

    expect(await (await fetch(`${app.baseUrl}/whoami`)).json()).toEqual({ user: null });

    const res = await fetch(`${app.baseUrl}/whoami`, { headers: { authorization: `Bearer ${token}` } });

    expect(await res.json()).toEqual({ user: 'u1' });
  });

  test('global session middleware re-issues a slid cookie, also on a public route', async () => {
    await using app = await boot();
    const token = await tokenFor(app);

    try {
      setSystemTime(new Date(Date.now() + 2_000_000));

      const res = await fetch(`${app.baseUrl}/whoami`, { headers: { cookie: `asena_session=${token}` } });

      expect(await res.json()).toEqual({ user: 'u1' });
      expect(res.headers.get('set-cookie') ?? '').toContain(`asena_session=${token}`);
    } finally {
      setSystemTime();
    }
  });

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

  test('no token: the upgrade is rejected, the socket never opens', async () => {
    await using app = await boot();

    expect(await connect(app.wsUrl('/chat'))).toEqual({ opened: false });
  });

  test('a token that matches no session is rejected too', async () => {
    await using app = await boot();

    expect(await connect(app.wsUrl('/chat'), ['bearer', 'not-a-token'])).toEqual({ opened: false });
  });
});
