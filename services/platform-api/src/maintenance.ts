import type { Container } from './container.ts';

export interface MaintenanceHandle {
  stop(): void;
  /** Runs one pass now (also used by tests). */
  runOnce(): Promise<{ challenges: number; leases: number } | undefined>;
}

/**
 * Background retention, deliberately off the request path (found necessary by load testing).
 * Failures are counted and logged but never crash the server; the next tick retries.
 * Safe with several instances: the deletes are idempotent and batch-bounded.
 */
export function startMaintenance(
  c: Container,
  opts: { everyMs?: number; onError?: (e: unknown) => void } = {},
): MaintenanceHandle {
  let running = false;
  const runOnce = async () => {
    if (running) return undefined; // never overlap passes in one process
    running = true;
    const t0 = performance.now();
    try {
      const r = await c.licensing.runMaintenance();
      const auth = await c.auth.runMaintenance();
      const windows = (await c.rateBackend?.purgeExpired()) ?? 0;
      const sharing = await c.sharing?.runRetention();
      if (sharing)
        for (const [table, n] of Object.entries(sharing))
          c.metrics.inc('maintenance_deleted_total', { table: `sharing_${table}` }, n);
      c.metrics.inc('maintenance_deleted_total', { table: 'login_failures' }, auth.loginFailures);
      c.metrics.inc(
        'maintenance_deleted_total',
        { table: 'webauthn_challenges' },
        auth.webauthnChallenges,
      );
      c.metrics.inc('maintenance_deleted_total', { table: 'rate_limits' }, windows);
      const operationEvents = await c.operationsEvents.retain();
      c.metrics.inc('maintenance_deleted_total', { table: 'operations_events' }, operationEvents);
      c.metrics.inc('maintenance_runs_total', { outcome: 'ok' });
      c.metrics.inc('maintenance_deleted_total', { table: 'challenges' }, r.challenges);
      c.metrics.inc('maintenance_deleted_total', { table: 'leases' }, r.leases);
      c.metrics.inc('maintenance_deleted_total', { table: 'device_signals' }, r.deviceSignals);
      c.metrics.observe('maintenance_duration_ms', performance.now() - t0);
      return r;
    } catch (e) {
      c.metrics.inc('maintenance_runs_total', { outcome: 'error' });
      opts.onError?.(e);
      return undefined;
    } finally {
      running = false;
    }
  };
  const timer = setInterval(() => void runOnce(), opts.everyMs ?? 60_000);
  timer.unref();
  return { stop: () => clearInterval(timer), runOnce };
}
