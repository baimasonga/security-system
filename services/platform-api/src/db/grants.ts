import type { Client } from 'pg';
import { assertSchemaName } from './connection.ts';

// Least-privilege grants for the application's database role (ADR-012).
//
// The application connects as a role that OWNS NOTHING. Only the owner can disable a trigger or drop a table, so
// even a fully compromised application (SQL injection, stolen credentials) cannot switch off the audit log's
// append-only triggers, rewrite events, or truncate evidence. Every table must be listed here: an unlisted table
// makes `applyAppGrants` fail, so adding a table forces a decision about who may touch it (a drift test enforces it).

type Priv = 'SELECT' | 'INSERT' | 'UPDATE' | 'DELETE';
const R: Priv[] = ['SELECT'];
const RI: Priv[] = ['SELECT', 'INSERT'];
const RIU: Priv[] = ['SELECT', 'INSERT', 'UPDATE'];
const ALL: Priv[] = ['SELECT', 'INSERT', 'UPDATE', 'DELETE'];

export const TABLE_PRIVILEGES: Record<string, Priv[]> = {
  schema_migrations: R, // read by the startup guard; only the owner migrates
  users: RIU,
  identity_tokens: ALL, // expiring single-use reset/verification hashes
  identity_mail_outbox: ALL, // encrypted short-lived recovery messages and fenced worker leases
  organizations: RI,
  memberships: RI,
  sessions: RIU,
  passkeys: ALL, // users remove their own credentials (ADR-023)
  webauthn_challenges: ALL, // single-use consumption + retention
  login_failures: ALL, // lockout counters; purged by maintenance
  products: RI,
  plans: RIU,
  subscriptions: RIU,
  licenses: RIU,
  quota_charges: RI,
  license_seats: ALL, // admins unassign seats
  device_signals: ['SELECT', 'INSERT', 'DELETE'], // server-observed evidence: never rewritten, purged after retention
  device_posture: RIU, // derived, recomputed from signals
  billing_checkouts: RIU,
  billing_events: RI, // immutable accounting receipts; no rewrite or deletion by the app
  trial_claims: RI,
  devices: RI,
  activations: RIU,
  leases: ['SELECT', 'INSERT', 'DELETE'], // retention deletes expired lease records
  challenges: ALL, // single-use consumption + retention
  signing_keys: RIU,
  audit_events: RI, // append-only: no UPDATE, DELETE or TRUNCATE for the application, ever
  audit_chains: RIU, // chain heads advance; the database guard also forbids rewinding or deleting them
  audit_anchors: RI,
  security_events: RI,
  telemetry_events: RI,
  rate_limits: ALL, // disposable counters
  // File sharing and short links (ADR-021). Immutable history (versions' blobs, destination history, comments)
  // cannot be rewritten or deleted by the application; only disposable state is deletable.
  // Privileged operations (ADR-022): requests are an accountability record (no DELETE); a freeze is lifted by
  // deleting its row (the audit log keeps the history).
  privileged_requests: RIU,
  privileged_freezes: ALL,
  share_accounts: RIU, // lock anchor for per-organization quota checks (row locks need UPDATE; no mutable data)
  share_blobs: RIU, // object metadata; deletion is a status change, the row stays as a tombstone
  share_documents: RIU,
  share_versions: RIU, // publication timestamps only; blob and number never change (no DELETE)
  share_transfers: RIU,
  share_transfer_files: RIU,
  share_links: RIU,
  share_comments: RI,
  share_reviews: RIU,
  short_links: RIU,
  short_link_destinations: RI, // destination history is append-only
  upload_requests: RIU,
  upload_submissions: RIU,
  upload_submission_files: RIU,
  share_events: ['SELECT', 'INSERT', 'DELETE'], // receipts; retention deletes expired rows, never edits them
  share_stats: ALL, // aggregates: upsert + retention
  share_notifications: ALL, // read markers + retention
  share_jobs: ALL, // fenced work queue; finished jobs are deleted
  share_domains: ALL, // a tenant may remove an unused custom domain
  share_brands: RIU,
  abuse_reports: RIU,
  share_usage: RIU,
  share_attempts: ALL, // password-attempt counters; purged by maintenance
};

/** Roles that a managed platform's auto-generated API uses. They must have no access to the platform's data. */
export const API_ROLES = ['anon', 'authenticated', 'service_role'] as const;

export interface GrantOptions {
  schema: string;
  role: string;
  /** Extra roles to lock out (the well-known API roles are always handled when they exist). */
  lockedOutRoles?: string[];
}

/** The statements `applyAppGrants` would run, in order. Pure given the schema's table list and existing roles. */
export function planGrants(
  o: GrantOptions & { tables: string[]; existingRoles: string[] },
): string[] {
  const s = `"${assertSchemaName(o.schema)}"`;
  const role = `"${assertSchemaName(o.role)}"`;
  const unknown = o.tables.filter((t) => !(t in TABLE_PRIVILEGES));
  if (unknown.length)
    throw new Error(
      `no grant policy for table(s): ${unknown.join(', ')} — add them to TABLE_PRIVILEGES (db/grants.ts) deliberately`,
    );
  const out: string[] = [
    `REVOKE ALL ON ALL TABLES IN SCHEMA ${s} FROM ${role}`,
    `REVOKE ALL ON ALL SEQUENCES IN SCHEMA ${s} FROM ${role}`,
    `REVOKE ALL ON SCHEMA ${s} FROM PUBLIC`,
    `REVOKE ALL ON SCHEMA ${s} FROM ${role}`,
    `GRANT USAGE ON SCHEMA ${s} TO ${role}`, // usage only: no CREATE
  ];
  for (const t of [...o.tables].sort()) {
    out.push(`GRANT ${TABLE_PRIVILEGES[t]!.join(', ')} ON TABLE ${s}."${t}" TO ${role}`);
  }
  // Identity/serial columns need USAGE on their sequences for inserts to work.
  out.push(`GRANT USAGE ON ALL SEQUENCES IN SCHEMA ${s} TO ${role}`);
  // Tables created later must not be reachable until someone decides (and re-runs this).
  out.push(`ALTER DEFAULT PRIVILEGES IN SCHEMA ${s} REVOKE ALL ON TABLES FROM ${role}`);

  const locked = new Set([...API_ROLES, ...(o.lockedOutRoles ?? [])]);
  for (const r of [...locked].sort()) {
    if (!o.existingRoles.includes(r)) continue;
    const q = `"${assertSchemaName(r)}"`;
    out.push(
      `REVOKE ALL ON ALL TABLES IN SCHEMA ${s} FROM ${q}`,
      `REVOKE ALL ON ALL SEQUENCES IN SCHEMA ${s} FROM ${q}`,
      `REVOKE ALL ON ALL FUNCTIONS IN SCHEMA ${s} FROM ${q}`,
      `REVOKE ALL ON SCHEMA ${s} FROM ${q}`,
      `ALTER DEFAULT PRIVILEGES IN SCHEMA ${s} REVOKE ALL ON TABLES FROM ${q}`,
      `ALTER DEFAULT PRIVILEGES IN SCHEMA ${s} REVOKE ALL ON SEQUENCES FROM ${q}`,
      `ALTER DEFAULT PRIVILEGES IN SCHEMA ${s} REVOKE ALL ON FUNCTIONS FROM ${q}`,
    );
  }
  return out;
}

/**
 * Applies the grants in one transaction using the schema OWNER's connection. Idempotent: run it after every
 * migration. Refuses a role that is a superuser or the connecting (owner) role itself.
 */
export async function applyAppGrants(client: Client, o: GrantOptions): Promise<string[]> {
  const schema = assertSchemaName(o.schema);
  assertSchemaName(o.role);
  const me = (await client.query('SELECT current_user AS u')).rows[0]!.u as string;
  if (me === o.role)
    throw new Error('the application role must differ from the role that owns the schema');
  const role = (await client.query('SELECT rolsuper FROM pg_roles WHERE rolname = $1', [o.role]))
    .rows[0];
  if (!role)
    throw new Error(
      `role "${o.role}" does not exist (create it first; see docs/deploy/supabase.md)`,
    );
  if (role.rolsuper)
    throw new Error(`role "${o.role}" is a superuser; use a dedicated least-privilege role`);

  const tables = (
    await client.query('SELECT tablename FROM pg_tables WHERE schemaname = $1', [schema])
  ).rows.map((r) => r.tablename as string);
  const existingRoles = (await client.query('SELECT rolname FROM pg_roles')).rows.map(
    (r) => r.rolname as string,
  );
  const statements = planGrants({ ...o, tables, existingRoles });
  await client.query('BEGIN');
  try {
    for (const s of statements) await client.query(s);
    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw e;
  }
  return statements;
}
