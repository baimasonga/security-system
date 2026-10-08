import { InMemoryAuditLog } from '../src/index.ts';
import { auditLogContract } from './log-contract.ts';

auditLogContract('in-memory', (clock, opts) => new InMemoryAuditLog(clock, opts));
