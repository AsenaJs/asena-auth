/** Unpadded base64url: `=` is not a valid `Sec-WebSocket-Protocol` token character. */
export function generateToken(bytes = 32): string {
  const buffer = new Uint8Array(bytes);

  crypto.getRandomValues(buffer);

  return Buffer.from(buffer).toString('base64url');
}

/** SHA-256 hex. Stores key sessions by this, so a leaked store yields no usable token. */
export function hashToken(token: string): string {
  return new Bun.CryptoHasher('sha256').update(token).digest('hex');
}
