import type { Container } from './container.ts';

/** Recovery links expire in 15 minutes; mail delivery must not inherit a long retention cadence. */
export function startIdentityMailWorker(
  c: Container,
  opts: { everyMs?: number; onError?: () => void } = {},
) {
  let running: Promise<void> | undefined;
  let stopped = false;
  const runOnce = (): Promise<void> => {
    if (stopped) return Promise.resolve();
    if (running) return running;
    running = (async () => {
      try {
        await c.auth.processIdentityMail();
      } catch {
        opts.onError?.();
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
