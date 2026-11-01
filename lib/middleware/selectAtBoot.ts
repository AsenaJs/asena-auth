import type { AuthProviderRegistryLike } from '../types';

export function selectAtBoot(registry: AuthProviderRegistryLike, middleware: string, providerName?: string): void {
  try {
    registry.select(providerName);
  } catch (cause) {
    if (providerName !== undefined || registry.providers.size < 2) {
      throw cause;
    }

    const names = [...registry.providers.keys()];

    throw new Error(
      `[asena-auth] ${middleware} is registered, but ${names.length} auth providers are (${names.join(', ')}) ` +
        'and none is primary, so it cannot pick one. Mark one provider primary: true ' +
        '(@Auth({ primary: true }) or @BetterAuth({ primary: true })), or import only what the app uses instead of ' +
        'authComponents, e.g. imports: [AuthGuard, AuthGuardMiddleware, AuthProviderRegistry], and when the app uses ' +
        `${middleware}, add a subclass that names its provider: ` +
        `@Middleware() class My${middleware} extends ${middleware} { protected providerName = '${names[0]}'; }.`,
      { cause },
    );
  }
}
