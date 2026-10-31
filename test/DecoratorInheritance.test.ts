import { describe, expect, test } from 'bun:test';
import { ComponentConstants } from '@asenajs/asena/ioc/constants';
import { getOwnTypedMetadata } from '@asenajs/asena/utils';
import { AsenaAuthService } from '../lib/AsenaAuthService';
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

  test('a decorated class extending another decorated class registers under its own name', () => {
    @Auth({})
    class PrimaryAuth extends AsenaAuthService {}

    @Auth({})
    class SecondaryAuth extends PrimaryAuth {}

    expect(getOwnTypedMetadata<string>(ComponentConstants.NameKey, PrimaryAuth)).toBe('PrimaryAuth');
    expect(getOwnTypedMetadata<string>(ComponentConstants.NameKey, SecondaryAuth)).toBe('SecondaryAuth');
  });
});
