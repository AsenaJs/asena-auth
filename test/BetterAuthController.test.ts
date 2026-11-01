import { describe, expect, test } from 'bun:test';
import { Controller } from '@asenajs/asena/decorators';
import { Inject } from '@asenajs/asena/decorators/ioc';
import { createTestApp, silentLogger } from '@asenajs/asena/test';
import { createErgenecoreAdapter } from '@asenajs/ergenecore';
import { createHonoAdapter } from '@asenajs/hono-adapter';
import { BetterAuth, BetterAuthController, BetterAuthService } from '../lib/better-auth';

const seen: unknown[] = [];

@BetterAuth({
  auth: {
    handler: async (req: Request) => {
      seen.push(req);

      return new Response(JSON.stringify({ path: new URL(req.url).pathname, method: req.method }), { status: 201 });
    },
    api: { getSession: async () => ({ headers: new Headers(), response: null }) },
  },
})
class AppBA extends BetterAuthService {}

@Controller('/api/auth')
class AuthCtrl extends BetterAuthController {
  @Inject(AppBA)
  protected readonly authService!: AppBA;
}

describe.each([
  ['ergenecore', () => createErgenecoreAdapter({ logger: silentLogger })],
  ['hono', () => createHonoAdapter({ logger: silentLogger })[0]],
] as const)('BetterAuthController on %s', (_name, adapter) => {
  const boot = () => createTestApp({ adapter: adapter(), logger: silentLogger, components: [AppBA, AuthCtrl] });

  test.each([
    ['POST', '/api/auth/sign-in/email'],
    ['GET', '/api/auth/session'],
  ])(
    '%s %s reaches the Better Auth handler with the raw Request, its Response returned as is',
    async (method, path) => {
      await using app = await boot();
      seen.length = 0;

      const res = await fetch(`${app.baseUrl}${path}`, { method });

      expect(res.status).toBe(201);
      expect(await res.json()).toEqual({ path, method });
      expect(seen[0]).toBeInstanceOf(Request);
    },
  );
});
