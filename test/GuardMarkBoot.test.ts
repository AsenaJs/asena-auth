import { describe, expect, test } from 'bun:test';
import { Protected } from '@asenajs/asena/auth';
import { Controller } from '@asenajs/asena/decorators';
import { Get } from '@asenajs/asena/decorators/http';
import { AsenaAuthService, Auth, AuthGuard, AuthGuardMiddleware, AuthProviderRegistry } from '../index';
import { bootFake, contextShapes } from './support/fakeAdapter';

@Auth({})
class MarkAuth extends AsenaAuthService {}

describe.each(contextShapes)('guard marks at boot on the %s context', (shape) => {
  test('@Protected({ provider: undefined }) boots and guards like @Protected()', async () => {
    @Protected({ provider: undefined })
    @Controller('/plain')
    class Plain {
      @Get('/')
      get(ctx: any) {
        return ctx.send('ok');
      }
    }

    await using app = await bootFake({
      shape,
      components: [MarkAuth, Plain],
      imports: [AuthGuard, AuthGuardMiddleware, AuthProviderRegistry],
    });
    const auth = await app.resolve<MarkAuth>('MarkAuth');
    const { token } = await auth.createSession({ id: 'u1' });

    expect((await app.fetch('/plain')).status).toBe(401);
    expect((await app.fetch('/plain', { headers: { authorization: `Bearer ${token}` } })).status).toBe(200);
  });
});
