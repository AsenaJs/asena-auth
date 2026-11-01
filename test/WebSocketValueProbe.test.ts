import { describe, expect, test } from 'bun:test';
import { Middleware, WebSocket as WebSocketNamespace } from '@asenajs/asena/decorators';
import { AsenaMiddlewareService } from '@asenajs/asena/middleware';
import { createTestApp, silentLogger } from '@asenajs/asena/test';
import { AsenaWebSocketService } from '@asenajs/asena/web-socket';
import { createErgenecoreAdapter } from '@asenajs/ergenecore';
import { createHonoAdapter } from '@asenajs/hono-adapter';

@Middleware()
class WriterA extends AsenaMiddlewareService {
  async handle(ctx: any, next: () => Promise<void>) {
    ctx.setWebSocketValue({ a: 1 });
    await next();
  }
}

@Middleware()
class WriterB extends AsenaMiddlewareService {
  async handle(ctx: any, next: () => Promise<void>) {
    ctx.setWebSocketValue({ b: 2 });
    await next();
  }
}

@WebSocketNamespace({ path: '/p', name: 'P', middlewares: [WriterA, WriterB] })
class ProbeSocket extends AsenaWebSocketService {
  protected onOpen(ws: any) {
    ws.send(JSON.stringify(ws.data.values));
  }
}

const firstMessage = (url: string) =>
  new Promise<unknown>((resolve, reject) => {
    const ws = new WebSocket(url);

    ws.onmessage = (event) => {
      resolve(JSON.parse(String(event.data)));
      ws.close();
    };
    ws.onerror = () => reject(new Error('socket error'));
  });

const adapters = [
  ['ergenecore', () => createErgenecoreAdapter({ logger: silentLogger })],
  ['hono', () => createHonoAdapter({ logger: silentLogger })[0]],
] as const;

describe.each(adapters)('setWebSocketValue on %s', (_name, adapter) => {
  test('a second write replaces the first - values do not merge', async () => {
    await using app = await createTestApp({
      adapter: adapter(),
      logger: silentLogger,
      components: [WriterA, WriterB, ProbeSocket],
    });

    expect(await firstMessage(app.wsUrl('/p'))).toEqual({ b: 2 });
  });
});
