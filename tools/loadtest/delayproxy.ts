import net from 'node:net';

/**
 * TCP proxy that delays every chunk by `oneWayMs` in each direction (round-trip ≈ 2 × oneWayMs), to
 * emulate network distance between the API and PostgreSQL. Order within a direction is preserved
 * (equal-duration timers fire FIFO). Node timers have ~1 ms granularity, so use whole milliseconds.
 */
export async function startDelayProxy(
  targetPort: number,
  oneWayMs: number,
): Promise<{ port: number; close(): Promise<void> }> {
  const sockets = new Set<net.Socket>();
  const pump = (from: net.Socket, to: net.Socket) => {
    from.on('data', (chunk) => {
      if (oneWayMs <= 0) to.write(chunk);
      else setTimeout(() => !to.destroyed && to.write(chunk), oneWayMs);
    });
    from.on('end', () => setTimeout(() => to.end(), oneWayMs));
    from.on('error', () => to.destroy());
  };
  const server = net.createServer((client) => {
    const upstream = net.connect(targetPort, '127.0.0.1');
    for (const s of [client, upstream]) {
      sockets.add(s);
      s.setNoDelay(true);
      s.on('close', () => sockets.delete(s));
    }
    pump(client, upstream);
    pump(upstream, client);
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  return {
    port: (server.address() as net.AddressInfo).port,
    async close() {
      for (const s of sockets) s.destroy();
      await new Promise<void>((r) => server.close(() => r()));
    },
  };
}
