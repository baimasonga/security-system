/** Fixed internal persistence check; no request-controlled destinations or raw diagnostics. */
export function persistenceReadiness(query: () => Promise<unknown>, timeoutMs = 1000) {
  let pending: Promise<boolean> | undefined;
  let last = { at: -Infinity, ready: false };
  return async () => {
    if (Date.now() - last.at < 1000) return last.ready;
    // One query at a time even if the pool is wedged. Timed-out callers cannot fan out.
    pending ??= query()
      .then(
        () => true,
        () => false,
      )
      .finally(() => {
        pending = undefined;
      });
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      const ready = await Promise.race([
        pending,
        new Promise<false>((resolve) => {
          timer = setTimeout(() => resolve(false), timeoutMs);
        }),
      ]);
      last = { at: Date.now(), ready };
      return ready;
    } finally {
      if (timer) clearTimeout(timer);
    }
  };
}
