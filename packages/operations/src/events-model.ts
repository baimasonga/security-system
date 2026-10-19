import type { HealthRepo } from './health.ts';
import type { CredentialScope } from './model.ts';
export interface EventInput {
  id: string;
  component_id: string;
  occurred_at: string;
  type: string;
  attributes: Record<string, string | number>;
}
export interface OperationEvent extends CredentialScope {
  id: string;
  componentId: string;
  credentialId: string;
  source: 'backend_report';
  type: string;
  attributes: Record<string, string | number>;
  occurredAt: string;
  receivedAt: Date;
  expiresAt: Date;
  contentHash: string;
  sizeBytes: number;
}
export interface EventCounter {
  orgId: string;
  key: string;
  count: number;
  bytes: number;
  /** At most sixty server receipt timestamps: an exact sliding request window. */
  requestTimes: number[];
  expiresAt: Date | null;
}
export interface EventAggregate extends CredentialScope {
  outcome: string;
  componentId: string;
  type: string;
  hour: Date;
  count: number;
  expiresAt: Date;
}
export interface EventRepo extends HealthRepo {
  findEvent(scope: CredentialScope, id: string): Promise<OperationEvent | undefined>;
  insertEvent(row: OperationEvent): Promise<void>;
  getEventCounter(orgId: string, key: string): Promise<EventCounter | undefined>;
  putEventCounter(row: EventCounter): Promise<void>;
  addEventAggregate(row: EventAggregate): Promise<void>;
  getEventAggregate(
    scope: CredentialScope,
    componentId: string,
    type: string,
    hour: Date,
    outcome: string,
  ): Promise<EventAggregate | undefined>;
  /** Delete at most limit expired rows, returning immutable accounting material. */
  pruneEventRows(orgId: string, now: Date, limit: number): Promise<OperationEvent[]>;
  pruneEventMetadata(orgId: string, now: Date, limit: number): Promise<void>;
  expiredEventOrganizations(now: Date, limit: number): Promise<string[]>;
}
