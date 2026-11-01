import { mock } from 'bun:test';
import type { AsenaAuthProvider, AuthSession } from '@asenajs/asena/auth';
import type { AuthProviderRegistryLike } from '../lib/types';

export const session: AuthSession = {
  user: { id: 'u1' },
  session: { id: 's1', userId: 'u1', createdAt: new Date(0), expiresAt: new Date(60_000) },
};

export function stubProvider(result: AuthSession | null = session) {
  return {
    getSession: mock(async (_request: Request) => result),
    getRoles: () => [],
  } satisfies AsenaAuthProvider;
}

export function stubRegistry(
  provider: AsenaAuthProvider,
): AuthProviderRegistryLike & { select: ReturnType<typeof mock> } {
  return {
    providers: new Map([['P', provider]]),
    select: mock((_name?: string) => provider),
  };
}

export function stubContext(request: Request, initial: Record<string, unknown> = {}) {
  const values = new Map(Object.entries(initial));
  let wsValue: unknown;

  return {
    req: request,
    getValue: (key: string) => values.get(key),
    setValue: (key: string, value: unknown) => values.set(key, value),
    setWebSocketValue: (value: unknown) => {
      wsValue = value;
    },
    getWebSocketValue: () => wsValue,
  };
}
