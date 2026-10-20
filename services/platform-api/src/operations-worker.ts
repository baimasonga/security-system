import type { Container } from './container.ts';
export function startOperationsWorker(
  c: Container,
  opts: { everyMs?: number; onError?: () => void } = {},
) {
  let running: Promise<void> | undefined,
    stopped = false;
  const runOnce = () => {
    if (stopped) return Promise.resolve();
    if (running) return running;
    running = c.operationsAutomation
      .tick()
      .catch(() => opts.onError?.())
      .finally(() => {
        running = undefined;
      });
    return running;
  };
  const timer = setInterval(() => void runOnce(), opts.everyMs ?? 15000);
  timer.unref();
  void runOnce();
  return {
    runOnce,
    async stop() {
      stopped = true;
      clearInterval(timer);
      await running;
    },
  };
}
