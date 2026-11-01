import { AuthGuard, AuthGuardMiddleware, AuthProviderRegistry } from './guard';
import { AuthSessionMiddleware, AuthWebSocketMiddleware } from './middleware';

/** Everything the package ships decorated, for `imports: [...authComponents]`. */
export const authComponents = [
  AuthGuard,
  AuthGuardMiddleware,
  AuthProviderRegistry,
  AuthSessionMiddleware,
  AuthWebSocketMiddleware,
] as const;
