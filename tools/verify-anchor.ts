// Checks the live audit log against audit anchors that an external witness holds (ADR-010).
//
//   DATABASE_URL=postgres://… node tools/verify-anchor.ts <file>
//
// <file> is a single manifest (JSON) or a witness log (JSON Lines, one manifest or {"manifest": …} per line, as
// written by tools/anchor-witness.ts). EVERY manifest in it is checked, so one run proves that nothing the
// witness ever saw has been rewritten, truncated or removed. The chains themselves are verified first: the
// witness only adds value on top of an internally consistent log.
// Exit status: 0 = consistent, 1 = tampering or inconsistency found, 2 = usage / input error.
import { readFileSync } from 'node:fs';
import pg from 'pg';
import type { AnchorManifest } from '@trust/audit';
import { PgAuditLog } from '../services/platform-api/src/db/pg-audit-log.ts';
import { auditVerifierPoolSettings } from './audit-verifier-connection.ts';

const [file] = process.argv.slice(2);
const url = process.env['DATABASE_URL'];
if (!file || !url) {
  console.error(
    'usage: DATABASE_URL=… node tools/verify-anchor.ts <manifest.json | witness.jsonl>',
  );
  process.exit(2);
}

function load(path: string): AnchorManifest[] {
  const text = readFileSync(path, 'utf8').trim();
  if (!text) throw new Error('empty input');
  const pick = (v: unknown): AnchorManifest => {
    const m = (
      v && typeof v === 'object' && 'manifest' in v ? (v as { manifest: unknown }).manifest : v
    ) as AnchorManifest;
    if (!m || typeof m !== 'object' || m.v !== 1) throw new Error('not an anchor manifest');
    return m;
  };
  if (text.startsWith('{') && !text.includes('\n')) return [pick(JSON.parse(text))];
  try {
    return [pick(JSON.parse(text))]; // pretty-printed single manifest
  } catch {
    return text
      .split('\n')
      .filter(Boolean)
      .map((l) => pick(JSON.parse(l)));
  }
}

let manifests: AnchorManifest[];
try {
  manifests = load(file);
} catch (e) {
  console.error(`cannot read ${file}: ${(e as Error).message}`);
  process.exit(2);
}

let settings;
try {
  settings = auditVerifierPoolSettings(process.env, (path) => readFileSync(path, 'utf8'));
} catch {
  console.error(
    'invalid database TLS configuration: check DATABASE_URL and DATABASE_CA_PEM or DATABASE_CA_FILE',
  );
  process.exit(2);
}
const pool = new pg.Pool(settings);
const log = new PgAuditLog(pool, { now: () => new Date() });
try {
  const v = await log.verifyChain();
  if (!v.ok) {
    console.error(`FAIL log: chain ${v.chain} broken at seq ${v.brokenAtSeq}: ${v.reason}`);
    process.exitCode = 1;
  } else {
    let bad = 0;
    for (const [i, m] of manifests.entries()) {
      const r = await log.checkAnchor(m);
      if (!r.ok) {
        bad++;
        console.error(
          `FAIL anchor #${i + 1} (${m.created_at}): ${r.chain ?? '-'}@${r.seq ?? '-'}: ${r.reason}`,
        );
      }
    }
    if (bad) process.exitCode = 1;
    else
      console.log(
        `OK: ${v.chains} chains / ${v.count} events verified; ${manifests.length} witnessed anchor(s) still hold`,
      );
  }
} finally {
  await pool.end();
}
