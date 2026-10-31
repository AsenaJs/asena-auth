import type { HashingOptions } from '../types';

export async function hashPassword(password: string, options: HashingOptions = {}): Promise<string> {
  const { algorithm = 'bcrypt', cost = 12 } = options;

  if (algorithm === 'bcrypt') {
    return Bun.password.hash(password, { algorithm, cost });
  }

  return Bun.password.hash(password, { algorithm });
}

/** The algorithm is read from the hash itself. */
export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return Bun.password.verify(password, hash);
}
