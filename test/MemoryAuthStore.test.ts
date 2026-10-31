import { describe, expect, test } from 'bun:test';
import { MemoryAuthStore } from '../lib/store';
import type { StoredSession } from '../lib/store';

const row = (id: string, userId: string, ttlMs = 60_000): StoredSession => ({
  id,
  userId,
  user: { id: userId },
  createdAt: Date.now(),
  expiresAt: Date.now() + ttlMs,
});

describe('MemoryAuthStore', () => {
  test('create, get, delete', async () => {
    const store = new MemoryAuthStore();

    await store.create(row('s1', 'u1'));
    expect((await store.get('s1'))?.userId).toBe('u1');

    await store.delete('s1');
    expect(await store.get('s1')).toBeNull();
  });

  test('get of an unknown id is null', async () => {
    expect(await new MemoryAuthStore().get('nope')).toBeNull();
  });

  test('deleteByUser removes every session of that user and nothing else', async () => {
    const store = new MemoryAuthStore();

    await store.create(row('a1', 'alice'));
    await store.create(row('a2', 'alice'));
    await store.create(row('b1', 'bob'));

    await store.deleteByUser('alice');

    expect(await store.get('a1')).toBeNull();
    expect(await store.get('a2')).toBeNull();
    expect((await store.get('b1'))?.userId).toBe('bob');
    expect(store.size).toBe(1);
  });

  test('an expired row reads as null and is removed', async () => {
    const store = new MemoryAuthStore();

    await store.create(row('old', 'u1', -1));

    expect(store.size).toBe(1);
    expect(await store.get('old')).toBeNull();
    expect(store.size).toBe(0);
  });

  test('touch extends the expiry', async () => {
    const store = new MemoryAuthStore();

    await store.create(row('s1', 'u1', 10));
    await store.touch('s1', Date.now() + 60_000);
    await Bun.sleep(30);

    expect(await store.get('s1')).not.toBeNull();
  });

  test('the sweep removes an expired row without anyone calling get', async () => {
    const store = new MemoryAuthStore(20);

    store.onStart();

    try {
      await store.create(row('short', 'u1', 5));
      await store.create(row('long', 'u2'));
      await Bun.sleep(60);

      expect(store.size).toBe(1);
    } finally {
      store.onStop();
    }
  });

  test('no sweep runs before onStart or after onStop', async () => {
    const store = new MemoryAuthStore(10);

    await store.create(row('short', 'u1', 1));
    await Bun.sleep(40);
    expect(store.size).toBe(1);

    store.onStart();
    store.onStop();
    await store.create(row('short2', 'u2', 1));
    await Bun.sleep(40);
    expect(store.size).toBe(2);
  });
});
