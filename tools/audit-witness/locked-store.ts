import { createHash } from 'node:crypto';

export interface ObjectFacts {
  version: string;
  digest: string;
  mode: string;
  retainUntil: Date;
}
export interface LockedObjectPort {
  head(key: string, version?: string): Promise<ObjectFacts | undefined>;
  /** Conditional create only; undefined means another writer won, never unconditional overwrite. */
  put(key: string, body: string, digest: string, until: Date): Promise<string | undefined>;
}
export function createLockedStore(port: LockedObjectPort, days: number, now = () => new Date()) {
  if (!Number.isInteger(days) || days < 1 || days > 3650) throw new Error('invalid retention');
  return {
    async retain(body: string) {
      const digest = createHash('sha256').update(body).digest('hex');
      const key = `anchors/${digest}.json`;
      const at = now();
      const until = new Date(Math.floor(at.getTime() / 1000) * 1000 + days * 86400000);
      // Create first: HEAD on a missing key needs ListBucket to distinguish 404 from 403.
      // Conditional PUT avoids granting bucket-list access and converges concurrent retries.
      const written = await port.put(key, body, digest, until);
      const facts = await port.head(key, written);
      if (
        !facts ||
        !/^[\x21-\x7e]{1,120}$/.test(facts.version) ||
        facts.version === 'null' ||
        (written !== undefined && facts.version !== written) ||
        facts.digest !== digest ||
        facts.mode !== 'COMPLIANCE' ||
        !Number.isFinite(facts.retainUntil.getTime()) ||
        facts.retainUntil <= at ||
        (written !== undefined && facts.retainUntil < until)
      )
        throw new Error('retention not established');
      return `v1:${digest}:${Buffer.from(facts.version).toString('base64url')}`;
    },
  };
}
