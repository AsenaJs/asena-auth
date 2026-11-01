import { expect, test } from 'bun:test';
import { Controller, Middleware, Service } from '@asenajs/asena/decorators';
import { Get } from '@asenajs/asena/decorators/http';
import { Inject, OnStart } from '@asenajs/asena/decorators/ioc';
import { AsenaMiddlewareService } from '@asenajs/asena/middleware';
import { createTestApp, silentLogger } from '@asenajs/asena/test';
import { createErgenecoreAdapter } from '@asenajs/ergenecore';

const started: string[] = [];

@Service('R')
class R {
  @OnStart()
  start() {
    started.push('R');
  }
}

@Middleware()
class M extends AsenaMiddlewareService {
  @Inject('R')
  r!: R;

  @OnStart()
  start() {
    started.push('M');
  }

  async handle(_ctx: any, next: () => Promise<void>) {
    await next();
  }
}

@Controller('/probe')
class SomeController {
  @Get({ path: '/', middlewares: [M] })
  get(ctx: any) {
    return ctx.send('ok');
  }
}

test('a dependency starts before its dependent, whatever the listing order', async () => {
  await using _app = await createTestApp({
    adapter: createErgenecoreAdapter({ logger: silentLogger }),
    logger: silentLogger,
    components: [M, R, SomeController],
  });

  expect(started).toEqual(['R', 'M']);
});
