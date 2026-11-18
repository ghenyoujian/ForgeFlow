/** Shared read cache. Keys contain an auth generation, never a credential. */
export type QuerySnapshot<T> = { data?: T; error?: Error; loading: boolean; updatedAt?: string };
type Entry<T> = {
  snapshot: QuerySnapshot<T>; listeners: Set<() => void>; controller?: AbortController;
  promise?: Promise<void>; accessed: number; settled: number; stale: boolean;
};
export class QueryCache<T> {
  private entries = new Map<string, Entry<T>>();
  constructor(private fetcher: (key: string, signal: AbortSignal) => Promise<T>, private ttl = 20_000, private budget = 120) {}
  private entry(key: string) {
    let entry = this.entries.get(key);
    if (!entry) {
      entry = { snapshot: { loading: true }, listeners: new Set(), accessed: Date.now(), settled: 0, stale: true };
      this.entries.set(key, entry);
    }
    entry.accessed = Date.now();
    return entry;
  }
  get(key: string): QuerySnapshot<T> { return this.entry(key).snapshot; }
  ensure(key: string) { const entry = this.entry(key); if (entry.stale || Date.now() - entry.settled > this.ttl) void this.fetch(key); }
  subscribe(key: string, listener: () => void) {
    const entry = this.entry(key);
    entry.listeners.add(listener);
    this.ensure(key);
    this.prune();
    return () => {
      entry.listeners.delete(listener);
      queueMicrotask(() => {
        // Let StrictMode remount or another consumer take over the shared read.
        if (!entry.listeners.size && entry.controller) {
          entry.controller.abort(); entry.controller = undefined; entry.promise = undefined; entry.stale = true;
          entry.snapshot = { ...entry.snapshot, loading: false };
        }
        this.prune();
      });
    };
  }
  private publish(entry: Entry<T>, snapshot: QuerySnapshot<T>) {
    entry.snapshot = snapshot;
    for (const notify of entry.listeners) notify();
  }
  async fetch(key: string): Promise<void> {
    const entry = this.entry(key);
    if (entry.promise) return entry.promise;
    const controller = new AbortController(); entry.controller = controller; entry.stale = false;
    this.publish(entry, { ...entry.snapshot, loading: true, error: undefined });
    const pending = Promise.resolve().then(() => this.fetcher(key, controller.signal)).then(data => {
      if (controller.signal.aborted || this.entries.get(key) !== entry) return;
      entry.settled = Date.now();
      this.publish(entry, { data, loading: false, updatedAt: new Date().toISOString() });
    }).catch(cause => {
      if (!controller.signal.aborted && this.entries.get(key) === entry) {
        entry.settled = Date.now();
        this.publish(entry, { ...entry.snapshot, loading: false, error: cause instanceof Error ? cause : new Error(String(cause)) });
      }
    }).finally(() => {
      if (entry.controller !== controller) return;
      entry.controller = undefined; entry.promise = undefined;
      if (entry.stale && entry.listeners.size) void this.fetch(key);
    });
    entry.promise = pending;
    return pending;
  }
  invalidate(matches: (key: string) => boolean) {
    for (const [key, entry] of this.entries) if (matches(key)) {
      entry.stale = true;
      if (entry.listeners.size && !entry.promise) void this.fetch(key);
    }
  }
  clear() {
    const old = [...this.entries.values()]; this.entries.clear();
    for (const entry of old) entry.controller?.abort();
    for (const entry of old) for (const notify of entry.listeners) notify();
  }
  private prune() {
    const unused = [...this.entries].filter(([, e]) => !e.listeners.size).sort((a, b) => a[1].accessed - b[1].accessed);
    while (this.entries.size > this.budget && unused.length) {
      const [key, entry] = unused.shift()!; entry.controller?.abort(); this.entries.delete(key);
    }
  }
}
