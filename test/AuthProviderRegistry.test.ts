import { describe, expect, test } from 'bun:test';
import { Protected } from '@asenajs/asena/auth';
import type { AsenaAuthProvider } from '@asenajs/asena/auth';
import { Controller } from '@asenajs/asena/decorators';
import { Get } from '@asenajs/asena/decorators/http';
import { createCapturingLogger, createTestApp, silentLogger } from '@asenajs/asena/test';
import { createErgenecoreAdapter } from '@asenajs/ergenecore';
import { AsenaAuthService } from '../lib/AsenaAuthService';
import { Auth } from '../lib/decorators';
import { AuthGuard, AuthGuardMiddleware, AuthProviderRegistry } from '../lib/guard';
import { AUTH_REGISTRY_NAME } from '../lib/types';

@Auth({})
class Native extends AsenaAuthService {}

@Auth({ primary: true })
class PrimaryNative extends AsenaAuthService {}

@Auth({ name: 'Second' })
class SecondProvider extends AsenaAuthService {}

@Auth({ name: 'AlsoPrimary', primary: true })
class AlsoPrimary extends AsenaAuthService {}

@Controller('/users')
class Users {
  @Protected()
  @Get('/')
  create(ctx: any) {
    return ctx.send('ok');
  }
}

@Controller('/named')
class Named {
  @Protected({ provider: 'Second' })
  @Get('/')
  list(ctx: any) {
    return ctx.send('ok');
  }
}

@Controller('/nope')
class UnknownProvider {
  @Protected({ provider: 'Nope' })
  @Get('/')
  list(ctx: any) {
    return ctx.send('ok');
  }
}

const guardComponents = [AuthGuard, AuthGuardMiddleware, AuthProviderRegistry];

const boot = (components: any[], imports: any[] = guardComponents, logger: any = silentLogger) =>
  createTestApp({ adapter: createErgenecoreAdapter({ logger: silentLogger }), logger, components, imports });

const bootError = async (components: any[], imports?: any[]): Promise<string> => {
  try {
    const app = await boot(components, imports);

    await app.stop();
  } catch (error) {
    const messages: string[] = [];

    for (let e: any = error; e; e = e.cause) {
      messages.push(String(e.message));
    }

    return messages.join(' <- ');
  }

  throw new Error('boot did not fail');
};

describe('AuthProviderRegistry', () => {
  test('a single provider is selected for unnamed routes', async () => {
    await using app = await boot([Native, Users]);
    const registry = await app.resolve<AuthProviderRegistry>(AUTH_REGISTRY_NAME);

    expect([...registry.providers.keys()]).toEqual(['Native']);
    expect(registry.select()).toBe(await app.resolve<AsenaAuthProvider>('Native'));
  });

  test('two providers + primary: unnamed routes use the primary, a named route its own', async () => {
    await using app = await boot([PrimaryNative, SecondProvider, Users, Named]);
    const registry = await app.resolve<AuthProviderRegistry>(AUTH_REGISTRY_NAME);

    expect(registry.select()).toBe(await app.resolve<AsenaAuthProvider>('PrimaryNative'));
    expect(registry.select('Second')).toBe(await app.resolve<AsenaAuthProvider>('Second'));
  });

  test('providers are keyed by registered name, not class name', async () => {
    await using app = await boot([SecondProvider, Named]);
    const registry = await app.resolve<AuthProviderRegistry>(AUTH_REGISTRY_NAME);

    expect([...registry.providers.keys()]).toEqual(['Second']);
  });

  test('two providers, no primary, unnamed protected route: boot fails naming the route and both candidates', async () => {
    const message = await bootError([Native, SecondProvider, Users]);

    expect(message).toContain('Users.create');
    expect(message).toContain('Native');
    expect(message).toContain('Second');
    expect(message).toContain('primary: true');
  });

  test('two primaries: boot fails naming both', async () => {
    const message = await bootError([PrimaryNative, AlsoPrimary, Users]);

    expect(message).toContain('PrimaryNative');
    expect(message).toContain('AlsoPrimary');
  });

  test('an unknown provider name: boot fails listing the candidates', async () => {
    const message = await bootError([Native, UnknownProvider]);

    expect(message).toContain("'Nope'");
    expect(message).toContain('UnknownProvider.list');
    expect(message).toContain('Native');
  });

  test('guard imported, protected route, zero providers: boot fails', async () => {
    const message = await bootError([Users]);

    expect(message).toContain('Users.create');
    expect(message).toContain('@Auth');
  });

  test('the error is logged in full before the boot fails', async () => {
    const { logger, entries } = createCapturingLogger();

    await expect(boot([Users], guardComponents, logger)).rejects.toThrow();

    expect(entries.some((e: any) => e.level === 'error' && String(e.message).includes('Users.create'))).toBe(true);
  });

  test('registry without the guard warns and boots', async () => {
    const { logger, entries } = createCapturingLogger();

    await using app = await boot([Native], [AuthProviderRegistry], logger);
    const registry = await app.resolve<AuthProviderRegistry>(AUTH_REGISTRY_NAME);

    expect(registry.select()).toBeDefined();
    expect(entries.some((e: any) => e.level === 'warn' && String(e.message).includes('AuthGuard'))).toBe(true);
  });

  test('select() fails descriptively when nothing fits', async () => {
    await using app = await boot([Native, SecondProvider], [AuthProviderRegistry]);
    const registry = await app.resolve<AuthProviderRegistry>(AUTH_REGISTRY_NAME);

    expect(() => registry.select()).toThrow('primary: true');
    expect(() => registry.select('Missing')).toThrow('Native, Second');
  });
});
