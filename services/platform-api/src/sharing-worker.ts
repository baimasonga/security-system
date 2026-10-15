import type { Container } from './container.ts';

/**
 * Runs sharing jobs (quarantine checks, object deletion, opt-in notification mail) off the request path. Safe
 * with several instances: jobs are claimed with fenced leases, and an expired lease returns work to the queue.
 */
export function startSharingWorker(
  c: Container,
  opts: { everyMs?: number; onError?: (e: unknown) => void } = {},
) {
  let running: Promise<void> | undefined;
  let stopped = false;
  const runOnce = (): Promise<void> => {
    if (stopped || !c.sharing) return Promise.resolve();
    if (running) return running;
    running = (async () => {
      try {
        // Drain in bounded rounds so a backlog is worked through without starving the event loop.
        for (let round = 0; round < 10; round++) {
          const r = await c.sharing!.processJobs({ limit: 20 });
          c.metrics.inc('sharing_jobs_total', { outcome: 'done' }, r.done);
          c.metrics.inc('sharing_jobs_total', { outcome: 'failed' }, r.failed);
          if (r.done + r.failed < 20) break;
        }
      } catch (e) {
        c.metrics.inc('sharing_worker_errors_total');
        opts.onError?.(e);
      }
    })().finally(() => {
      running = undefined;
    });
    return running;
  };
  const timer = setInterval(() => void runOnce(), opts.everyMs ?? 5000);
  timer.unref();
  void runOnce();
  return {
    runOnce,
    stop: () => {
      stopped = true;
      clearInterval(timer);
    },
  };
}
