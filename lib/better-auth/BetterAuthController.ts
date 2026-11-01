import type { AsenaContext } from '@asenajs/asena/adapter';
import { All } from '@asenajs/asena/decorators/http';
import { getRawRequest } from '../helpers/context';
import type { BetterAuthService } from './BetterAuthService';

/**
 * Mounts Better Auth's handler under the subclass's `@Controller` prefix, which must equal
 * Better Auth's `basePath` (default `/api/auth`). Satisfy `authService` with
 * `@Inject(AppBetterAuth) protected readonly authService!: AppBetterAuth`.
 */
export abstract class BetterAuthController {
  protected abstract readonly authService: BetterAuthService<any>;

  @All('/*')
  public async handleAuth(context: AsenaContext<any, any>): Promise<Response> {
    return this.authService.instance.handler(getRawRequest(context));
  }
}
