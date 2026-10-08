import { InMemoryAuditLog } from '../src/index.ts';
import { auditLogContract } from './log-contract.ts';

auditLogContract('in-memory', (clock) => new InMemoryAuditLog(clock));
