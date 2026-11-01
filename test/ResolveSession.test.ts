import { describe, expect, test } from 'bun:test';
import { AUTH_SESSION_CONTEXT_KEY } from '@asenajs/asena/auth';
import { resolveSession } from '../lib/middleware';
import { session, stubContext, stubProvider } from './middlewareStubs';

describe('resolveSession', () => {
  test('the same provider is asked once per request', async () => {
    const provider = stubProvider();
    const ctx = stubContext(new Request('http://localhost/'));

    await resolveSession(ctx as any, provider, ctx.req);
    await resolveSession(ctx as any, provider, ctx.req);

    expect(provider.getSession).toHaveBeenCalledTimes(1);
  });

  test("a session another provider resolved is not accepted for this one - that provider's verdict is", async () => {
    const primary = stubProvider(session);
    const named = stubProvider(null);
    const ctx = stubContext(new Request('http://localhost/'));

    await resolveSession(ctx as any, primary, ctx.req);

    expect(await resolveSession(ctx as any, named, ctx.req)).toBeNull();
    expect(named.getSession).toHaveBeenCalledTimes(1);
    expect(ctx.getValue(AUTH_SESSION_CONTEXT_KEY)).toBeNull();
  });

  test('a value put into the context by application code is reused as is', async () => {
    const provider = stubProvider(null);
    const ctx = stubContext(new Request('http://localhost/'), { [AUTH_SESSION_CONTEXT_KEY]: session });

    expect(await resolveSession(ctx as any, provider, ctx.req)).toBe(session);
    expect(provider.getSession).not.toHaveBeenCalled();
  });
});
