import { isIP } from 'node:net';
import type { Clock } from '@trust/shared-types';
import type { InventoryStore } from '@trust/operations';
import type { ProbeCheck } from './integrations/probe-http.ts';

/** One operator-configured outside-in check, bound to an existing inventory component. */
export interface ProbeTarget extends ProbeCheck {
  orgId: string;
  applicationId: string;
  environmentId: string;
  componentId: string;
}

const KEYS = [
  'org_id',
  'application_id',
  'environment_id',
  'component_id',
  'url',
  'content_type',
  'contains',
] as const;
const IDS = {
  org_id: /^org_[a-f0-9]{24}$/,
  application_id: /^opa_[a-f0-9]{24}$/,
  environment_id: /^ope_[a-f0-9]{24}$/,
  component_id: /^opm_[a-f0-9]{24}$/,
} as const;
export const MAX_PROBE_TARGETS = 10;
/** A public-looking DNS name: at least two labels, letters/digits/hyphens, alphabetic TLD. */
function dnsName(host: string) {
  const labels = host.split('.');
  return (
    host.length <= 253 &&
    labels.length >= 2 &&
    labels.every((l) => /^[a-z0-9-]{1,63}$/.test(l) && !l.startsWith('-') && !l.endsWith('-')) &&
    /^[a-z]{2,63}$/.test(labels.at(-1)!)
  );
}

/**
 * Parses OPERATIONS_PROBE_TARGETS (a JSON array). Fails closed on anything unexpected; error
 * messages name the field, never the value. Only public DNS names on HTTPS port 443 are allowed.
 */
export function parseProbeTargets(raw: string): ProbeTarget[] {
  let list: unknown;
  try {
    list = JSON.parse(raw);
  } catch {
    throw new Error('OPERATIONS_PROBE_TARGETS must be a JSON array');
  }
  if (!Array.isArray(list) || list.length < 1 || list.length > MAX_PROBE_TARGETS)
    throw new Error(`OPERATIONS_PROBE_TARGETS must list 1–${MAX_PROBE_TARGETS} targets`);
  const seen = new Set<string>();
  return list.map((item, i) => {
    const bad = (field: string) => new Error(`OPERATIONS_PROBE_TARGETS[${i}].${field} is invalid`);
    if (!item || typeof item !== 'object' || Array.isArray(item)) throw bad('target');
    const t = item as Record<string, unknown>;
    for (const k of Object.keys(t)) if (!(KEYS as readonly string[]).includes(k)) throw bad(k);
    for (const [k, re] of Object.entries(IDS))
      if (typeof t[k] !== 'string' || !re.test(t[k] as string)) throw bad(k);
    if (typeof t['url'] !== 'string' || t['url'].length > 500) throw bad('url');
    let url: URL;
    try {
      url = new URL(t['url']);
    } catch {
      throw bad('url');
    }
    const host = url.hostname;
    if (
      url.protocol !== 'https:' ||
      url.port !== '' ||
      url.username ||
      url.password ||
      url.hash ||
      isIP(host.replace(/^\[|\]$/g, '')) !== 0 ||
      !dnsName(host) ||
      /(?:^|\.)(?:localhost|local|internal|localdomain|home\.arpa|arpa)$/.test(host)
    )
      throw bad('url');
    if (t['content_type'] !== 'json' && t['content_type'] !== 'html') throw bad('content_type');
    if (
      typeof t['contains'] !== 'string' ||
      t['contains'].length < 1 ||
      t['contains'].length > 200 ||
      [...t['contains']].some((ch) => ch.charCodeAt(0) < 32 || ch.charCodeAt(0) === 127)
    )
      throw bad('contains');
    if (seen.has(t['component_id'] as string)) throw bad('component_id');
    seen.add(t['component_id'] as string);
    return {
      orgId: t['org_id'] as string,
      applicationId: t['application_id'] as string,
      environmentId: t['environment_id'] as string,
      componentId: t['component_id'] as string,
      url,
      contentType: t['content_type'],
      contains: t['contains'],
    };
  });
}

/**
 * Runs every target once and records the outcome as the component's latest probe result.
 * A target whose component is missing or in another scope is not recorded; the run reports it.
 */
export async function runProbes(d: {
  targets: readonly ProbeTarget[];
  store: InventoryStore;
  clock: Clock;
  check(target: ProbeCheck): Promise<boolean>;
}): Promise<{ recorded: number; unrecorded: number }> {
  const outcomes = await Promise.all(
    d.targets.map(async (t) => {
      const started = d.clock.now();
      let ok = false;
      try {
        ok = await d.check(t);
      } catch {
        ok = false;
      }
      try {
        // Re-runnable: reads and one idempotent upsert ordered by occurrence.
        await d.store.transaction(t.orgId, async (tx) => {
          const c = await tx.find('component', t.orgId, t.componentId);
          if (!c || c.applicationId !== t.applicationId || c.environmentId !== t.environmentId)
            throw new Error('probe target unavailable');
          const receivedAt = await tx.observeHealthTime(t.orgId, d.clock.now());
          await tx.recordProbeResult({
            orgId: t.orgId,
            applicationId: t.applicationId,
            environmentId: t.environmentId,
            componentId: t.componentId,
            status: ok ? 'healthy' : 'unavailable',
            occurredAt: started < receivedAt ? started : receivedAt,
            receivedAt,
            expiresAt: new Date(+receivedAt + 30 * 86400000),
          });
        });
        return true;
      } catch {
        return false;
      }
    }),
  );
  const recorded = outcomes.filter(Boolean).length;
  return { recorded, unrecorded: outcomes.length - recorded };
}

export function startProbeWorker(
  run: () => Promise<{ unrecorded: number }>,
  opts: { everyMs?: number; onUnrecorded?: (count: number) => void } = {},
) {
  let running: Promise<void> | undefined,
    stopped = false;
  const runOnce = () => {
    if (stopped) return Promise.resolve();
    if (running) return running;
    running = run()
      .then((r) => {
        if (r.unrecorded) opts.onUnrecorded?.(r.unrecorded);
      })
      .catch(() => opts.onUnrecorded?.(-1))
      .finally(() => {
        running = undefined;
      });
    return running;
  };
  const timer = setInterval(() => void runOnce(), opts.everyMs ?? 60000);
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
