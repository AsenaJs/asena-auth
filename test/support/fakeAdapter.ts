import { AsenaAdapter, ContractValidationError, isHttpException } from '@asenajs/asena/adapter';
import type {
  AsenaContext,
  BaseMiddleware,
  BaseValidator,
  CookieExtra,
  RequestSchema,
  RouteParams,
  SendOptions,
  WebsocketRouteParams,
} from '@asenajs/asena/adapter';
import { createTestApp, silentLogger } from '@asenajs/asena/test';
import type { TestApp, TestAppOptions } from '@asenajs/asena/test';
import type { Server } from 'bun';

/**
 * The two context shapes the adapter contract allows and asena-auth reads: `ctx.req` is the `Request`
 * itself and `routePattern` is the registered path as is (`/me/`), or `ctx.req` wraps it as `.raw`
 * and `routePattern` is normalized (`/me`).
 */
export type ContextShape = 'plain' | 'wrapped';

export const contextShapes: ContextShape[] = ['plain', 'wrapped'];

export const FAKE_ORIGIN = 'http://localhost';

export type FakeSocketOutcome = { opened: true; message: any } | { opened: false; status: number };

type FakeRouteParams = RouteParams<FakeContext, RequestSchema>;

type FakeRoute = Pick<FakeRouteParams, 'path' | 'middlewares' | 'handler' | 'validator'> & { method: string };

const segments = (path: string) => path.split('/').filter(Boolean);

const normalizePattern = (path: string) => `/${segments(path).join('/')}`;

function matchPath(pattern: string, pathname: string): Record<string, string> | null {
  const expected = segments(pattern);
  const actual = segments(pathname);
  const params: Record<string, string> = {};

  for (const [i, segment] of expected.entries()) {
    if (segment === '*') {
      return actual.length > i ? params : null;
    }

    if (actual[i] === undefined) {
      return null;
    }

    if (segment.startsWith(':')) {
      params[segment.slice(1)] = decodeURIComponent(actual[i]);
    } else if (segment !== actual[i]) {
      return null;
    }
  }

  return actual.length === expected.length ? params : null;
}

function unsupported(what: string): never {
  throw new Error(`The fake adapter does not support ${what}.`);
}

export class FakeContext implements AsenaContext<any, Response> {
  public readonly req: Request | { raw: Request };

  public res!: Response;

  public readonly headers: Record<string, string>;

  /** Every cookie write, in order, as a `Set-Cookie` value. Nothing is merged, so a double write shows. */
  public readonly setCookies: string[] = [];

  public readonly routePattern: string;

  private readonly params: Record<string, string>;

  private readonly values = new Map<string, unknown>();

  private bytes: Promise<ArrayBuffer> | undefined;

  private webSocketValue: unknown;

  public constructor(
    private readonly request: Request,
    shape: ContextShape,
    match: { pattern: string; params: Record<string, string> },
  ) {
    this.req = shape === 'plain' ? request : { raw: request };
    this.routePattern = match.pattern;
    this.params = match.params;
    this.headers = {};
    request.headers.forEach((value, key) => {
      this.headers[key] = value;
    });
  }

  public getArrayBuffer = (): Promise<ArrayBuffer> => {
    this.bytes ??= this.request.clone().arrayBuffer();

    return this.bytes;
  };

  public getBody = async <U>(): Promise<U> => JSON.parse(new TextDecoder().decode(await this.getArrayBuffer()));

  public getParseBody = (): Promise<any> => this.getBody();

  public getBlob = async (): Promise<Blob> => new Blob([await this.getArrayBuffer()]);

  public getFormData = (): Promise<FormData> => this.request.clone().formData();

  public getParam = (name: string): string => this.params[name] ?? '';

  public getQuery = async (name: string): Promise<string | undefined> => this.url.searchParams.get(name) ?? undefined;

  public getQueryAll = async (name: string): Promise<string[]> => this.url.searchParams.getAll(name);

  public getAllQueries = (): Record<string, string | string[]> => {
    const all: Record<string, string | string[]> = {};

    for (const key of new Set(this.url.searchParams.keys())) {
      const values = this.url.searchParams.getAll(key);

      all[key] = values.length === 1 ? values[0]! : values;
    }

    return all;
  };

  public getCookie = async (name: string, secret?: string | BufferSource): Promise<string | false> => {
    if (secret !== undefined) {
      unsupported('signed cookies');
    }

    return new Bun.CookieMap(this.request.headers.get('cookie') ?? '').get(name) ?? false;
  };

  public setCookie = async (name: string, value: string, options?: CookieExtra<any>): Promise<void> => {
    if (options?.secret !== undefined) {
      unsupported('signed cookies');
    }

    this.setCookies.push(new Bun.Cookie(name, value, options?.extraOptions ?? {}).serialize());
  };

  public deleteCookie = async (name: string, options?: CookieExtra<any>): Promise<void> => {
    this.setCookies.push(new Bun.Cookie(name, '', { ...(options?.extraOptions ?? {}), maxAge: 0 }).serialize());
  };

  public getValue(key: string): any {
    return this.values.get(key);
  }

  public setValue(key: string, value: any): void {
    this.values.set(key, value);
  }

  public setWebSocketValue = (value: unknown): void => {
    this.webSocketValue = value;
  };

  public getWebSocketValue = <T>(): T => this.webSocketValue as T;

  public send = (data: unknown, status?: SendOptions | number): Response => {
    const init = typeof status === 'number' ? { status } : { status: status?.status ?? 200, headers: status?.headers };

    return typeof data === 'string' ? new Response(data, init) : Response.json(data, init);
  };

  public html = (data: string): Response => new Response(data, { headers: { 'content-type': 'text/html' } });

  public redirect = (): void => unsupported('redirect');

  public stream = (): Response => unsupported('streaming');

  public streamSSE = (): Response => unsupported('streaming');

  public streamText = (): Response => unsupported('streaming');

  private get url(): URL {
    return new URL(this.request.url);
  }
}

class FakeSocket {
  public readonly sent: string[] = [];

  public readonly data: { values: unknown; id: string; path: string };

  public constructor(
    public readonly id: string,
    path: string,
    values: unknown,
  ) {
    this.data = { values, id, path };
  }

  public send(message: string): void {
    this.sent.push(message);
  }

  public subscribe(): void {}

  public unsubscribe(): void {}

  public close(): void {}
}

/**
 * An adapter built from `@asenajs/asena/adapter` only and driven in process: {@link FakeAdapter.fetch} answers
 * a `Request` without a server, {@link FakeAdapter.connect} runs a WebSocket upgrade and the namespace's `onOpen`
 * against a socket that records what it is sent. Global middlewares, then route middlewares, then a `json()`
 * validator, then the handler; every cookie written is on the response, an error response included. Anything
 * else the contract allows throws, so no test passes on a feature the fake only pretends to have.
 */
export class FakeAdapter extends AsenaAdapter<FakeContext, RequestSchema> {
  public readonly name = 'fake';

  private readonly globalMiddlewares: BaseMiddleware[] = [];

  private readonly routes: FakeRoute[] = [];

  private readonly sockets: WebsocketRouteParams<FakeContext>[] = [];

  private socketCount = 0;

  public constructor(private readonly shape: ContextShape = 'plain') {
    super(silentLogger);
  }

  public setPort(port: number): void {
    this.port = port;
  }

  public use(middleware: BaseMiddleware<FakeContext>, config?: unknown): void {
    if (config !== undefined) {
      unsupported('route patterns on global middlewares');
    }

    this.globalMiddlewares.push(middleware);
  }

  public registerRoute({ method, path, middlewares, handler, validator, contextClass }: FakeRouteParams): void {
    if (contextClass) {
      unsupported('context contracts');
    }

    this.routes.push({ method: method.toUpperCase(), path, middlewares, handler, validator });
  }

  public registerHTMLRoute(): void {
    unsupported('HTML routes');
  }

  public registerWebsocketRoute(params: WebsocketRouteParams<FakeContext>): void {
    this.sockets.push(params);
  }

  public start(): Server<any> {
    return { port: 0, stop: async () => {} } as unknown as Server<any>;
  }

  public onError(): void {
    unsupported('onError handlers');
  }

  public serveOptions(): void {}

  public async stop(): Promise<void> {}

  public fetch = async (path: string, init?: RequestInit): Promise<Response> => {
    const request = new Request(new URL(path, FAKE_ORIGIN), init);
    const { pathname } = new URL(request.url);
    const found = this.findRoute(request.method, pathname);

    if (!found) {
      return new Response('Not Found', { status: 404 });
    }

    const { route, params } = found;
    const ctx = this.context(request, route.path, params);
    let response: Response;

    try {
      response = (await this.runChain(ctx, [...this.globalMiddlewares, ...route.middlewares], async () => {
        await this.validate(ctx, route.validator);

        const result = await route.handler(ctx);

        if (!(result instanceof Response)) {
          throw new Error(`${request.method} ${route.path}: the handler returned no Response.`);
        }

        return result;
      }))!;
    } catch (error) {
      response = this.errorResponse(error);
    }

    const headers = new Headers(response.headers);

    for (const cookie of ctx.setCookies) {
      headers.append('set-cookie', cookie);
    }

    return new Response(request.method === 'HEAD' ? null : response.body, { status: response.status, headers });
  };

  public connect = async (
    path: string,
    { headers, protocols }: { headers?: Record<string, string>; protocols?: string[] } = {},
  ): Promise<FakeSocketOutcome> => {
    const upgrade = new Headers(headers);

    upgrade.set('upgrade', 'websocket');
    upgrade.set('connection', 'Upgrade');

    if (protocols) {
      upgrade.set('sec-websocket-protocol', protocols.join(', '));
    }

    const request = new Request(new URL(path, FAKE_ORIGIN), { headers: upgrade });
    const { pathname } = new URL(request.url);
    const route = this.sockets.find((socket) => matchPath(socket.path, pathname));

    if (!route) {
      return { opened: false, status: 404 };
    }

    const ctx = this.context(request, route.path, {});
    let rejection: Response | undefined;

    try {
      rejection = await this.runChain(ctx, [...this.globalMiddlewares, ...route.middlewares], async () => undefined);
    } catch (error) {
      rejection = this.errorResponse(error);
    }

    if (rejection) {
      return { opened: false, status: rejection.status };
    }

    const socket = new FakeSocket(`fake-${++this.socketCount}`, normalizePattern(route.path), ctx.getWebSocketValue());

    await (route.websocketService as any).onOpenInternal(socket);

    return { opened: true, message: socket.sent[0] === undefined ? undefined : JSON.parse(socket.sent[0]) };
  };

  private context(request: Request, registered: string, params: Record<string, string>): FakeContext {
    const pattern = this.shape === 'plain' ? registered : normalizePattern(registered);

    return new FakeContext(request, this.shape, { pattern, params });
  }

  private findRoute(method: string, pathname: string): { route: FakeRoute; params: Record<string, string> } | null {
    const methods = method === 'HEAD' ? ['HEAD', 'GET', 'ALL'] : [method, 'ALL'];

    for (const candidate of methods) {
      for (const route of this.routes) {
        const params = route.method === candidate ? matchPath(route.path, pathname) : null;

        if (params) {
          return { route, params };
        }
      }
    }

    return null;
  }

  private async runChain<T extends Response | undefined>(
    ctx: FakeContext,
    middlewares: BaseMiddleware[],
    last: () => Promise<T>,
  ): Promise<Response | T> {
    let outcome: Response | T | undefined;

    const dispatch = async (index: number): Promise<void> => {
      const middleware = middlewares[index];

      if (!middleware) {
        outcome = await last();

        return;
      }

      if (middleware.override) {
        unsupported('override middlewares');
      }

      let nextCalled = false;
      const result = await middleware.handle(ctx, async () => {
        nextCalled = true;
        await dispatch(index + 1);
      });

      if (result instanceof Response) {
        outcome = result;
      } else if (!nextCalled) {
        throw new Error(`Middleware ${index} neither called next() nor returned a Response.`);
      }
    };

    await dispatch(0);

    return outcome as Response | T;
  }

  private async validate(ctx: FakeContext, validator: BaseValidator<RequestSchema> | undefined): Promise<void> {
    const { json, ...others } = validator ?? {};

    if (Object.keys(others).length > 0) {
      unsupported('validators other than json()');
    }

    if (json) {
      const schema = await json.handle();
      const result = await schema['~standard'].validate(await ctx.getBody().catch(() => undefined));

      if (result.issues) {
        throw new ContractValidationError('body', result.issues);
      }
    }
  }

  private errorResponse(error: unknown): Response {
    return isHttpException(error)
      ? (error.getResponse?.() ?? new Response(error.message, { status: error.status }))
      : new Response('Internal Server Error', { status: 500 });
  }
}

export type FakeApp = TestApp & Pick<FakeAdapter, 'fetch' | 'connect'>;

/** `createTestApp` on a {@link FakeAdapter}, with the adapter's in-process `fetch` and `connect` on the app. */
export async function bootFake({
  shape = 'plain',
  ...options
}: Omit<TestAppOptions, 'adapter'> & { shape?: ContextShape }): Promise<FakeApp> {
  const adapter = new FakeAdapter(shape);
  const app = await createTestApp({ logger: silentLogger, ...options, adapter });

  return Object.assign(app, { fetch: adapter.fetch, connect: adapter.connect });
}
