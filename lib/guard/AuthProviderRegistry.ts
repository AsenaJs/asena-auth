import { AUTH_PROVIDER_KEY } from '@asenajs/asena/auth';
import type { AsenaAuthProvider } from '@asenajs/asena/auth';
import type { Container } from '@asenajs/asena/container';
import { Service } from '@asenajs/asena/decorators';
import { Inject, OnStart } from '@asenajs/asena/decorators/ioc';
import { ComponentConstants } from '@asenajs/asena/ioc/constants';
import { ICoreServiceNames } from '@asenajs/asena/ioc/types';
import type { ServerLogger } from '@asenajs/asena/logger';
import { getTypedMetadata } from '@asenajs/asena/utils';
import { AUTH_GUARD_NAME, AUTH_REGISTRY_NAME } from '../types';
import type { AuthProviderRegistryLike } from '../types';
import type { AuthGuard, GuardRouteMark } from './AuthGuard';

/**
 * Maps registered provider names to providers, picks the primary and, at boot, checks that every
 * route `AuthGuard` protected can be served. A misconfiguration fails the boot, not a request.
 */
@Service(AUTH_REGISTRY_NAME)
export class AuthProviderRegistry implements AuthProviderRegistryLike {
  @Inject(ICoreServiceNames.CONTAINER)
  protected container!: Container;

  @Inject(ICoreServiceNames.SERVER_LOGGER)
  protected logger!: ServerLogger;

  private byName = new Map<string, AsenaAuthProvider>();

  private primary: AsenaAuthProvider | undefined;

  public get providers(): ReadonlyMap<string, AsenaAuthProvider> {
    return this.byName;
  }

  @OnStart()
  public async onStart(): Promise<void> {
    const discovered = await this.container.resolveStrategy<AsenaAuthProvider>(AUTH_PROVIDER_KEY);
    const named = discovered
      .map(
        (provider) => [getTypedMetadata<string>(ComponentConstants.NameKey, provider.constructor), provider] as const,
      )
      .filter((entry): entry is readonly [string, AsenaAuthProvider] => typeof entry[0] === 'string')
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));

    this.byName = new Map(named);

    const primaries = [...this.byName].filter(([, provider]) => (provider as { primary?: boolean }).primary === true);

    if (primaries.length > 1) {
      this.fail(
        `More than one auth provider is primary (${primaries.map(([name]) => name).join(', ')}). Keep primary: true on exactly one.`,
      );
    }

    this.primary = primaries[0]?.[1];

    if (!this.container.services[AUTH_GUARD_NAME]) {
      this.logger.warn(
        '[asena-auth] AuthGuard is not imported: @Protected/@Roles routes are not enforced and not validated. ' +
          'Add it to imports (or import authComponents).',
      );

      return;
    }

    const guard = (await this.container.resolve<Pick<AuthGuard, 'marks'>>(AUTH_GUARD_NAME)) as Pick<AuthGuard, 'marks'>;

    for (const [key, mark] of guard.marks) {
      this.validate(key, mark);
    }
  }

  public select(name?: string): AsenaAuthProvider {
    if (name !== undefined) {
      const provider = this.byName.get(name);

      if (!provider) {
        throw new Error(`[asena-auth] No auth provider registered as '${name}'. Registered: ${this.candidates()}.`);
      }

      return provider;
    }

    if (this.primary) {
      return this.primary;
    }

    if (this.byName.size === 1) {
      return this.byName.values().next().value as AsenaAuthProvider;
    }

    throw new Error(
      this.byName.size === 0
        ? '[asena-auth] No auth provider is registered. Add an @Auth or @BetterAuth service.'
        : `[asena-auth] ${this.byName.size} auth providers are registered (${this.candidates()}) and none is primary. ` +
            'Add primary: true to one of them or name one explicitly.',
    );
  }

  private validate(key: string, mark: GuardRouteMark): void {
    const route = `${key} (${mark.controller}.${mark.method})`;

    if (this.byName.size === 0) {
      this.fail(`Route ${route} is protected but no auth provider is registered. Add an @Auth or @BetterAuth service.`);
    }

    if (mark.provider !== undefined) {
      if (!this.byName.has(mark.provider)) {
        this.fail(
          `Route ${route} asks for auth provider '${mark.provider}', which is not registered. Registered: ${this.candidates()}.`,
        );
      }

      return;
    }

    if (!this.primary && this.byName.size > 1) {
      this.fail(
        `Route ${route} is protected without a provider name, but ${this.byName.size} auth providers are registered ` +
          `(${this.candidates()}) and none is primary. Add primary: true to one of them or use @Protected({ provider }).`,
      );
    }
  }

  private candidates(): string {
    return [...this.byName.keys()].join(', ') || 'none';
  }

  private fail(message: string): never {
    const full = `[asena-auth] ${message}`;

    this.logger.error(full);

    throw new Error(full);
  }
}
