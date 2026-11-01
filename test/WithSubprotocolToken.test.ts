import { describe, expect, test } from 'bun:test';
import { withSubprotocolToken } from '../lib/helpers';

const ws = (headers: Record<string, string>) => new Request('http://localhost/chat', { headers });

describe('withSubprotocolToken', () => {
  test('moves the token of `bearer, <token>` into an Authorization header', () => {
    const result = withSubprotocolToken(ws({ 'sec-websocket-protocol': 'bearer, abc' }));

    expect(result.headers.get('authorization')).toBe('Bearer abc');
    expect(result.url).toBe('http://localhost/chat');
  });

  test('scheme is case-insensitive and whitespace is optional', () => {
    const result = withSubprotocolToken(ws({ 'sec-websocket-protocol': 'Bearer,abc' }));

    expect(result.headers.get('authorization')).toBe('Bearer abc');
  });

  test('an existing Authorization header wins over the subprotocol token', () => {
    const request = ws({ 'sec-websocket-protocol': 'bearer, abc', authorization: 'Bearer header-token' });
    const result = withSubprotocolToken(request);

    expect(result).toBe(request);
    expect(result.headers.get('authorization')).toBe('Bearer header-token');
  });

  test.each([
    ['no subprotocol header', {}],
    ['bearer without a token', { 'sec-websocket-protocol': 'bearer' }],
    ['bearer with an empty token', { 'sec-websocket-protocol': 'bearer, ' }],
    ['another protocol first', { 'sec-websocket-protocol': 'graphql-ws, abc' }],
  ])('%s: the request is returned unchanged', (_case, headers) => {
    const request = ws(headers);
    const result = withSubprotocolToken(request);

    expect(result).toBe(request);
    expect(result.headers.get('authorization')).toBeNull();
  });

  test('never mutates the original request', () => {
    const request = ws({ 'sec-websocket-protocol': 'bearer, abc' });

    withSubprotocolToken(request);

    expect(request.headers.get('authorization')).toBeNull();
  });
});
