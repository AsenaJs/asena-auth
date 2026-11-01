import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { Protected, getAuthSession } from '@asenajs/asena/auth';
import { Controller, WebSocket as WebSocketNamespace } from '@asenajs/asena/decorators';
import { Get, Post } from '@asenajs/asena/decorators/http';
import { createTestApp, silentLogger } from '@asenajs/asena/test';
import type { TestApp } from '@asenajs/asena/test';
import { AsenaWebSocketService } from '@asenajs/asena/web-socket';
import { createErgenecoreAdapter } from '@asenajs/ergenecore';
import { createHonoAdapter } from '@asenajs/hono-adapter';
import type { Server, ServerWebSocket } from 'bun';
import { AsenaAuthService, Auth, AuthWebSocketMiddleware, authComponents, getRawRequest } from '../index';
import { connect } from './wsClient';

const PUBLIC_HOST = 'app.example';
const PUBLIC_ORIGIN = `https://${PUBLIC_HOST}`;
const FORWARDED_WS_HEADERS = ['host', 'origin', 'cookie', 'sec-fetch-site', 'sec-websocket-protocol'];

interface Bridge {
  backend: WebSocket;
  pending: string[];
}

function startTlsTerminatingProxy(upstream: string): Server<Bridge> {
  return Bun.serve<Bridge>({
    port: 0,
    async fetch(req, server) {
      const url = new URL(req.url);
      const target = new URL(url.pathname + url.search, upstream);
      const forwarded = {
        'x-forwarded-proto': 'https',
        'x-forwarded-host': PUBLIC_HOST,
        'x-forwarded-for': '127.0.0.1',
      };

      if (req.headers.get('upgrade')?.toLowerCase() !== 'websocket') {
        const headers = new Headers(req.headers);

        for (const [name, value] of Object.entries(forwarded)) {
          headers.set(name, value);
        }

        return fetch(target, { method: req.method, headers, body: req.body, redirect: 'manual' });
      }

      const headers: Record<string, string> = { ...forwarded };

      for (const name of FORWARDED_WS_HEADERS) {
        const value = req.headers.get(name);

        if (value !== null) {
          headers[name] = value;
        }
      }

      target.protocol = 'ws:';

      const backend = new (WebSocket as any)(target.href, { headers }) as WebSocket;
      const pending: string[] = [];

      backend.onmessage = (event) => pending.push(String(event.data));

      const opened = await new Promise<boolean>((resolve) => {
        backend.onopen = () => resolve(true);
        backend.onclose = () => resolve(false);
      });

      if (opened && server.upgrade(req, { data: { backend, pending } })) {
        return undefined;
      }

      backend.close();

      return new Response(null, { status: 502 });
    },
    websocket: {
      open(ws: ServerWebSocket<Bridge>) {
        const { backend, pending } = ws.data;

        for (const message of pending) {
          ws.send(message);
        }

        backend.onmessage = (event) => ws.send(String(event.data));
        backend.onclose = () => ws.close();
      },
      message(ws: ServerWebSocket<Bridge>, message) {
        ws.data.backend.send(message);
      },
      close(ws: ServerWebSocket<Bridge>) {
        ws.data.backend.close();
      },
    },
  });
}

const appBehindProxy = (csrf: { trustedOrigins?: string[] } | undefined) => {
  @Auth({ primary: true, csrf })
  class ProxyAuth extends AsenaAuthService {}

  @Controller('/')
  class Probe {
    @Get('/seen-origin')
    seenOrigin(ctx: any) {
      return ctx.send({ origin: new URL(getRawRequest(ctx).url).origin });
    }
  }

  @Protected()
  @Controller('/items')
  class Items {
    @Post('/')
    create(ctx: any) {
      return ctx.send({ user: getAuthSession(ctx)?.user.id });
    }
  }

  @WebSocketNamespace({ path: '/chat', name: 'ProxyChat', middlewares: [AuthWebSocketMiddleware] })
  class Chat extends AsenaWebSocketService {
    protected onOpen(ws: any) {
      ws.send(JSON.stringify({ open: true }));
    }
  }

  return [ProxyAuth, Probe, Items, Chat];
};

const adapters = [
  { name: 'ergenecore', make: () => createErgenecoreAdapter({ logger: silentLogger }) },
  { name: 'hono', make: () => createHonoAdapter({ logger: silentLogger })[0] },
];

const configs = [
  { name: 'without trustedOrigins', csrf: undefined, legacySameOrigin: 401 },
  {
    name: 'with the public origin in trustedOrigins',
    csrf: { trustedOrigins: [PUBLIC_ORIGIN] },
    legacySameOrigin: 200,
  },
];

const modernSameOrigin = { origin: PUBLIC_ORIGIN, 'sec-fetch-site': 'same-origin' };
const legacySameOrigin = { origin: PUBLIC_ORIGIN };
const modernCrossSite = { origin: 'https://evil.example', 'sec-fetch-site': 'cross-site' };
const legacyCrossSite = { origin: 'https://evil.example' };
const modernSameSite = { origin: `https://admin.${PUBLIC_HOST}`, 'sec-fetch-site': 'same-site' };

describe.each(adapters)('csrf behind a TLS-terminating reverse proxy on $name', ({ make }) => {
  describe.each(configs)('$name', ({ csrf, legacySameOrigin: legacyStatus }) => {
    let app: TestApp;
    let proxy: Server<Bridge>;
    let cookie: string;

    beforeAll(async () => {
      app = await createTestApp({
        adapter: make(),
        logger: silentLogger,
        components: appBehindProxy(csrf),
        imports: [...authComponents],
      });
      proxy = startTlsTerminatingProxy(app.baseUrl);

      const { token } = await (await app.resolve<AsenaAuthService>('ProxyAuth')).createSession({ id: 'u1' });

      cookie = `asena_session=${token}`;
    });

    afterAll(async () => {
      proxy?.stop(true);
      await app?.stop();
    });

    const viaProxy = (path: string, init: RequestInit & { headers?: Record<string, string> } = {}) =>
      fetch(`http://127.0.0.1:${proxy.port}${path}`, {
        ...init,
        headers: { host: PUBLIC_HOST, ...init.headers },
      });

    const post = async (headers: Record<string, string>) =>
      (await viaProxy('/items', { method: 'POST', headers: { cookie, ...headers } })).status;

    const upgrade = async (headers: Record<string, string>) =>
      (await connect(`ws://127.0.0.1:${proxy.port}/chat`, { headers: { host: PUBLIC_HOST, cookie, ...headers } }))
        .opened;

    test("precondition: the app sees the public host over plain http, so request.url's origin is not the browser's", async () => {
      const seen = (await (await viaProxy('/seen-origin')).json()) as { origin: string };

      expect(seen.origin).toBe(`http://${PUBLIC_HOST}`);
      expect(seen.origin).not.toBe(PUBLIC_ORIGIN);
    });

    test('a modern browser same-origin POST (Sec-Fetch-Site: same-origin, https Origin) is authenticated', async () => {
      const res = await viaProxy('/items', { method: 'POST', headers: { cookie, ...modernSameOrigin } });

      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({ user: 'u1' });
    });

    test(`a legacy browser same-origin POST (https Origin, no Sec-Fetch-Site) is ${legacyStatus}; X-Forwarded-Proto is not trusted`, async () => {
      expect(await post(legacySameOrigin)).toBe(legacyStatus);
    });

    test('cross-site POSTs are 401 with and without Sec-Fetch-Site, and a same-site subdomain is not same-origin', async () => {
      expect(await post(modernCrossSite)).toBe(401);
      expect(await post(legacyCrossSite)).toBe(401);
      expect(await post(modernSameSite)).toBe(401);
    });

    test('a cookie POST without Origin or Sec-Fetch-Site (non-browser client) is authenticated', async () => {
      expect(await post({})).toBe(200);
    });

    test('WebSocket upgrade by cookie: modern same-origin opens, cross-site never, legacy same-origin follows trustedOrigins', async () => {
      expect(await upgrade(modernSameOrigin)).toBe(true);
      expect(await upgrade(legacySameOrigin)).toBe(legacyStatus === 200);
      expect(await upgrade(modernCrossSite)).toBe(false);
      expect(await upgrade(legacyCrossSite)).toBe(false);
    });
  });
});
