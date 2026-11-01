import type { AuthSession } from '@asenajs/asena/auth';

/** `user.roles` when it is an array, else `user.role` split on commas (Better Auth admin plugin shape), else `[]`. */
export function defaultRolesResolver(session: AuthSession<any>): string[] {
  const { roles, role } = session.user;

  if (Array.isArray(roles)) {
    return roles;
  }

  if (typeof role === 'string') {
    return role
      .split(',')
      .map((r) => r.trim())
      .filter(Boolean);
  }

  return [];
}
