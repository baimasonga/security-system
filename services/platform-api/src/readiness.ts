/** Fixed internal persistence check; no request-controlled destinations or raw diagnostics. */
export function persistenceReadiness(query: () => Promise<unknown>, timeoutMs = 1000) {
  let active: Promise<boolean> | undefined;
  let last = { at: -Infinity, ready: false };
  return async () => {
    if (performance.now() - last.at < 1000) return last.ready;
    if (active) return active;
    let deliver!: (ready: boolean) => void;
    // Keep this same settled result while a timed-out query is still pending. Later callers
    // must not add more queries, timers or handlers to a wedged persistence connection.
    active = new Promise<boolean>((resolve) => {
      deliver = resolve;
    });
    const result = active;
    const timer = setTimeout(() => {
      last = { at: performance.now(), ready: false };
      deliver(false);
    }, timeoutMs);
    void Promise.resolve()
      .then(query)
      .then(
        () => finish(true),
        () => finish(false),
      );
    function finish(ready: boolean) {
      clearTimeout(timer);
      last = { at: performance.now(), ready };
      active = undefined;
      deliver(ready);
    }
    return result;
  };
}
