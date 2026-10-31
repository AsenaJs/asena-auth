import { describe, expect, test } from 'bun:test';
import { generateToken, hashPassword, hashToken, verifyPassword } from '../lib/crypto';

describe('generateToken', () => {
  test('is unpadded base64url, so it is a valid Sec-WebSocket-Protocol token and a cookie value', () => {
    for (let i = 0; i < 50; i++) {
      const token = generateToken();

      expect(token).toMatch(/^[A-Za-z0-9_-]+$/);
      expect(token).not.toContain('=');
      expect(token).not.toContain('+');
      expect(token).not.toContain('/');
    }
  });

  test('32 bytes encode to 43 characters (256 bits of entropy)', () => {
    expect(generateToken()).toHaveLength(43);
    expect(generateToken(16)).toHaveLength(22);
  });

  test('two tokens differ', () => {
    expect(generateToken()).not.toBe(generateToken());
  });
});

describe('hashToken', () => {
  test('is a stable 64-char hex SHA-256', () => {
    const token = generateToken();

    expect(hashToken(token)).toBe(hashToken(token));
    expect(hashToken(token)).toMatch(/^[0-9a-f]{64}$/);
    expect(hashToken('abc')).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  });

  test('different tokens hash differently', () => {
    expect(hashToken('a')).not.toBe(hashToken('b'));
  });
});

describe('password hashing', () => {
  test('bcrypt round-trips and is the default', async () => {
    const hash = await hashPassword('correct horse', { cost: 4 });

    expect(hash.startsWith('$2')).toBe(true);
    expect(await verifyPassword('correct horse', hash)).toBe(true);
  });

  test('a wrong password does not verify', async () => {
    const hash = await hashPassword('correct horse', { cost: 4 });

    expect(await verifyPassword('wrong horse', hash)).toBe(false);
  });

  test('passwords that diverge after byte 72 do not cross-verify (bcrypt truncation regression guard)', async () => {
    const prefix = 'x'.repeat(72);
    const hash = await hashPassword(`${prefix}AAAA`, { cost: 4 });

    expect(await verifyPassword(`${prefix}AAAA`, hash)).toBe(true);
    expect(await verifyPassword(`${prefix}BBBB`, hash)).toBe(false);
  });

  test('argon2id is passed through and round-trips', async () => {
    const hash = await hashPassword('secret', { algorithm: 'argon2id' });

    expect(hash.startsWith('$argon2id$')).toBe(true);
    expect(await verifyPassword('secret', hash)).toBe(true);
    expect(await verifyPassword('other', hash)).toBe(false);
  });
});
