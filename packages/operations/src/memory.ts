import { AuditBuffer, type AuditLog, type AuditEventInput } from '@trust/audit';
import type {
  InventoryEntities,
  InventoryRepo,
  InventoryScope,
  InventoryStore,
  InventoryTx,
  InventoryType,
} from './model.ts';

class Repo implements InventoryRepo {
  rows: { [K in InventoryType]: Map<string, InventoryEntities[K]> } = {
    application: new Map(),
    environment: new Map(),
    component: new Map(),
  };
  async find<K extends InventoryType>(
    type: K,
    orgId: string,
    id: string,
  ): Promise<InventoryEntities[K] | undefined> {
    const row = this.rows[type].get(id);
    return row?.orgId === orgId ? structuredClone(row) : undefined;
  }
  async list<K extends InventoryType>(
    type: K,
    scope: InventoryScope,
  ): Promise<InventoryEntities[K][]> {
    return [...this.rows[type].values()]
      .filter(
        (row) =>
          row.orgId === scope.orgId &&
          (!scope.applicationId ||
            ('applicationId' in row && row.applicationId === scope.applicationId)) &&
          (!scope.environmentId ||
            ('environmentId' in row && row.environmentId === scope.environmentId)),
      )
      .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
      .map((row) => structuredClone(row));
  }
  async insert<K extends InventoryType>(type: K, row: InventoryEntities[K]) {
    const scope = {
      orgId: row.orgId,
      ...('applicationId' in row ? { applicationId: row.applicationId } : {}),
      ...('environmentId' in row ? { environmentId: row.environmentId } : {}),
    };
    if (
      this.rows[type].has(row.id) ||
      (await this.list(type, scope)).some((r) => r.code === row.code)
    )
      throw new Error('duplicate_inventory');
    if ('applicationId' in row && !(await this.find('application', row.orgId, row.applicationId)))
      throw new Error('inventory_parent');
    if ('environmentId' in row) {
      const parent = await this.find('environment', row.orgId, row.environmentId);
      if (!parent || parent.applicationId !== row.applicationId)
        throw new Error('inventory_parent');
    }
    this.rows[type].set(row.id, structuredClone(row));
  }
  async update<K extends InventoryType>(
    type: K,
    row: InventoryEntities[K],
    expectedVersion: number,
  ) {
    const old = await this.find(type, row.orgId, row.id);
    if (!old || old.version !== expectedVersion || row.version !== old.version + 1)
      throw new Error('inventory_version');
    if (
      old.code !== row.code ||
      ('applicationId' in old && old.applicationId !== (row as typeof old).applicationId) ||
      ('environmentId' in old && old.environmentId !== (row as typeof old).environmentId)
    )
      throw new Error('inventory_immutable');
    if (old.state === 'archived') throw new Error('inventory_archived');
    this.rows[type].set(row.id, structuredClone(row));
  }
}
export class InMemoryInventoryStore extends Repo implements InventoryStore {
  #tail: Promise<unknown> = Promise.resolve();
  readonly committedAudit: AuditEventInput[] = [];
  readonly #audit?: AuditLog;
  constructor(options?: { audit?: AuditLog }) {
    super();
    this.#audit = options?.audit;
  }
  transaction<T>(_orgId: string, fn: (tx: InventoryTx) => Promise<T>): Promise<T> {
    const run = async () => {
      // Work against an isolated snapshot: readers cannot see uncommitted rows.
      const repo = new Repo();
      repo.rows = structuredClone(this.rows);
      const buffer = new AuditBuffer();
      const out = await fn(Object.assign(repo, { audit: buffer }));
      const events = buffer.drain();
      if (this.#audit) await this.#audit.appendMany(events);
      else this.committedAudit.push(...events);
      this.rows = repo.rows;
      return out;
    };
    const result = this.#tail.then(run, run);
    this.#tail = result.catch(() => undefined);
    return result;
  }
}
