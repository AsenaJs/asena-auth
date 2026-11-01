import { describe, expect, test } from 'bun:test';
import { ComponentConstants } from '@asenajs/asena/ioc/constants';
import { getOwnTypedMetadata } from '@asenajs/asena/utils';
import { AsenaAuthService } from '../lib/AsenaAuthService';
import { BetterAuth, BetterAuthService } from '../lib/better-auth';
import { Auth } from '../lib/decorators';

abstract class AuthBase extends AsenaAuthService {
  public static readonly kind = 'auth-base';

  public extra(): string {
    return 'from base';
  }
}

@Auth({ name: 'AppAuth' })
class AppAuth extends AuthBase {}

describe('@Auth inheritance', () => {
  test('keeps methods and statics declared on an intermediate base class', () => {
    const instance: any = new (AppAuth as any)();

    expect(instance.extra()).toBe('from base');
    expect((AppAuth as any).kind).toBe('auth-base');
  });

  test('instances stay instanceof every declared base', () => {
    const instance: any = new (AppAuth as any)();

    expect(instance instanceof AuthBase).toBe(true);
    expect(instance instanceof AsenaAuthService).toBe(true);
  });

  test('@BetterAuth keeps methods declared on an intermediate base class', () => {
    abstract class BetterAuthBase extends BetterAuthService {
      public extra(): string {
        return 'from better-auth base';
      }
    }

    @BetterAuth({
      auth: {
        handler: async () => new Response(null),
        api: { getSession: async () => ({ headers: new Headers(), response: null }) },
      },
    })
    class AppBA extends BetterAuthBase {}

    const instance: any = new (AppBA as any)();

    expect(instance.extra()).toBe('from better-auth base');
    expect(instance instanceof BetterAuthBase).toBe(true);
    expect(instance instanceof BetterAuthService).toBe(true);
  });

  test('a decorated class extending another decorated class registers under its own name', () => {
    @Auth({})
    class PrimaryAuth extends AsenaAuthService {}

    @Auth({})
    class SecondaryAuth extends PrimaryAuth {}

    expect(getOwnTypedMetadata<string>(ComponentConstants.NameKey, PrimaryAuth)).toBe('PrimaryAuth');
    expect(getOwnTypedMetadata<string>(ComponentConstants.NameKey, SecondaryAuth)).toBe('SecondaryAuth');
  });
});
