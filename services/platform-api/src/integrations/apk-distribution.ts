import { z } from 'zod';

const url = 'https://api.github.com/repos/baimasonga/Rokelapdf-online/releases/tags/android';
const assetUrl =
  'https://github.com/baimasonga/Rokelapdf-online/releases/download/android/rokela-pdf.apk';
const schema = z.object({
  tag_name: z.literal('android'),
  draft: z.literal(false),
  assets: z
    .array(
      z.object({
        id: z.number().int().positive().safe(),
        name: z.string().max(255),
        state: z.string().max(32),
        download_count: z.number().int().nonnegative().safe(),
        size: z.number().int().positive().safe(),
        created_at: z.string().datetime(),
        updated_at: z.string().datetime(),
        browser_download_url: z.string().max(500),
      }),
    )
    .max(100),
});

/** Fixed public integration. No user destinations, provider credentials or raw response output. */
export function createApkDistributionReader(request: typeof fetch = fetch, now = Date.now) {
  let cached: { until: number; value: Record<string, unknown> } | undefined;
  let pending: Promise<Record<string, unknown>> | undefined;
  async function collect(): Promise<Record<string, unknown>> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5000);
    let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
    let value: Record<string, unknown>;
    try {
      const response = await request(url, {
        redirect: 'error',
        credentials: 'omit',
        signal: controller.signal,
        headers: {
          Accept: 'application/vnd.github+json',
          'User-Agent': 'Warrior-APK-monitor',
          'X-GitHub-Api-Version': '2022-11-28',
        },
      });
      if (
        !response.ok ||
        response.redirected ||
        !/^application\/json(?:\s*;|$)/i.test(response.headers.get('content-type') ?? '')
      )
        throw new Error('unavailable');
      reader = response.body?.getReader();
      if (!reader) throw new Error('unavailable');
      const chunks: Uint8Array[] = [];
      let length = 0;
      for (;;) {
        const part = await reader.read();
        if (part.done) break;
        length += part.value.byteLength;
        if (length > 262144) throw new Error('oversized');
        chunks.push(part.value);
      }
      const bytes = new Uint8Array(length);
      let offset = 0;
      for (const chunk of chunks) {
        bytes.set(chunk, offset);
        offset += chunk.byteLength;
      }
      const release = schema.parse(
        JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)),
      );
      const matches = release.assets.filter((asset) => asset.name === 'rokela-pdf.apk');
      const asset = matches[0];
      if (
        matches.length !== 1 ||
        !asset ||
        asset.state !== 'uploaded' ||
        asset.browser_download_url !== assetUrl
      )
        throw new Error('unavailable');
      value = {
        status: 'available',
        checked_at: new Date(now()).toISOString(),
        source: 'github_release_asset',
        asset_id: asset.id,
        downloads: asset.download_count,
        size_bytes: asset.size,
        created_at: asset.created_at,
        updated_at: asset.updated_at,
      };
    } catch {
      value = {
        status: 'unavailable',
        checked_at: new Date(now()).toISOString(),
        source: 'github_release_asset',
      };
    } finally {
      clearTimeout(timer);
      controller.abort();
      await reader?.cancel().catch(() => {});
    }
    cached = { until: now() + (value.status === 'available' ? 300000 : 30000), value };
    return value;
  }
  return () => {
    if (cached && now() < cached.until) return Promise.resolve(cached.value);
    if (!pending)
      pending = collect().finally(() => {
        pending = undefined;
      });
    return pending;
  };
}
