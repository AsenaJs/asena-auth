import type { AuthUser } from '@asenajs/asena/auth';
import type { AuthSessionStore, StoredSession } from './AuthSessionStore';

/** In-process session store. Sessions die with the process and are not shared between instances. */
export class MemoryAuthStore<TUser = AuthUser> implements AuthSessionStore<TUser> {
  private readonly sessions = new Map<string, StoredSession<TUser>>();

  private readonly byUser = new Map<string, Set<string>>();

  private timer: ReturnType<typeof setInterval> | undefined;

  /** @param sweepInterval seconds between sweeps of expired rows. */
  public constructor(private readonly sweepInterval = 60) {}

  public get size(): number {
    return this.sessions.size;
  }

  public async create(session: StoredSession<TUser>): Promise<void> {
    this.sessions.set(session.id, session);

    let ids = this.byUser.get(session.userId);

    if (!ids) {
      ids = new Set();
      this.byUser.set(session.userId, ids);
    }

    ids.add(session.id);
  }

  public async get(id: string): Promise<StoredSession<TUser> | null> {
    const session = this.sessions.get(id);

    if (!session) {
      return null;
    }

    if (session.expiresAt <= Date.now()) {
      this.remove(session);

      return null;
    }

    return session;
  }

  public async delete(id: string): Promise<void> {
    const session = this.sessions.get(id);

    if (session) {
      this.remove(session);
    }
  }

  public async deleteByUser(userId: string): Promise<void> {
    const ids = this.byUser.get(userId);

    if (!ids) {
      return;
    }

    for (const id of ids) {
      this.sessions.delete(id);
    }

    this.byUser.delete(userId);
  }

  public async listByUser(userId: string): Promise<StoredSession<TUser>[]> {
    return [...(this.byUser.get(userId) ?? [])].flatMap((id) => this.sessions.get(id) ?? []);
  }

  public async touch(id: string, expiresAt: number): Promise<void> {
    const session = this.sessions.get(id);

    if (session) {
      session.expiresAt = expiresAt;
    }
  }

  public onStart(): void {
    if (this.timer) {
      return;
    }

    this.timer = setInterval(() => this.sweep(), this.sweepInterval * 1000);
    this.timer.unref();
  }

  public onStop(): void {
    clearInterval(this.timer);
    this.timer = undefined;
  }

  private sweep(): void {
    const now = Date.now();

    for (const session of this.sessions.values()) {
      if (session.expiresAt <= now) {
        this.remove(session);
      }
    }
  }

  private remove(session: StoredSession<TUser>): void {
    this.sessions.delete(session.id);

    const ids = this.byUser.get(session.userId);

    ids?.delete(session.id);

    if (ids?.size === 0) {
      this.byUser.delete(session.userId);
    }
  }
}
