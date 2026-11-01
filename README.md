# @asenajs/asena-auth

Authentication for [AsenaJS](https://asena.sh): a native opaque-session provider and a Better Auth provider behind the `@asenajs/asena/auth` contract, with `@Protected` / `@Roles` guards enforced before validators.

## Requirements

- Bun 1.4 or higher
- `@asenajs/asena` 0.12.2 or higher
- `better-auth` 1.2 or higher (below 2), only for the Better Auth provider

## Installation

```bash
bun add @asenajs/asena-auth
```

## Quick Start

```typescript
import { Protected, getAuthSession } from '@asenajs/asena/auth';
import { Controller } from '@asenajs/asena/decorators';
import { Get } from '@asenajs/asena/decorators/http';
import { AsenaAuthService, Auth, authComponents } from '@asenajs/asena-auth';

@Auth({ sessionTtl: 3600 })
export class AppAuth extends AsenaAuthService {}

@Protected()
@Controller('/me')
export class MeController {
  @Get('/')
  me(ctx: Context) {
    return ctx.send(getAuthSession(ctx)?.user);
  }
}

await AsenaServerFactory.create({ adapter, logger, imports: [...authComponents] });
```

`AppAuth.createSession(user)` issues the token; send it as `Authorization: Bearer <token>` or the `asena_session` cookie. `AppAuth.logout(ctx)` ends the current session and clears the cookie.

## Documentation

Full documentation: [asena.sh/docs/packages/auth](https://asena.sh/docs/packages/auth)

## License

MIT
