import { expect, it } from 'vitest';
import {
  incidentEmailReadiness,
  type RecipientEvidence,
} from '../../../tools/incident-email-readiness.ts';

const config = {
  operationsAutomationEnabled: true,
  operationsEmailNotificationsEnabled: true,
  emailDelivery: {
    provider: 'cloudflare' as const,
    accountId: 'SECRET_ACCOUNT',
    apiToken: 'SECRET_TOKEN',
    from: 'PRIVATE_ADDRESS',
    publicOrigin: 'PRIVATE_ORIGIN',
  },
};
const evidence: RecipientEvidence = {
  accountExists: true,
  emailVerified: true,
  enabledRules: 1,
  pending: 0,
  claimed: 0,
  delivered: 2,
  failed: 0,
};

it('reports prerequisites without asserting inbox delivery or exposing configuration', () => {
  const report = incidentEmailReadiness(config, evidence);
  expect(report.ready_for_controlled_test).toBe(true);
  expect(report.inbox_delivery).toBe('not_verified');
  expect(report.historical_delivery_transport).toBe('not_recorded');
  expect(JSON.stringify(report)).not.toMatch(/SECRET|PRIVATE/);
});
it.each(['operationsAutomationEnabled', 'operationsEmailNotificationsEnabled'] as const)(
  'refuses readiness when %s is off even with delivered notifications',
  (key) => {
    expect(
      incidentEmailReadiness({ ...config, [key]: false }, evidence).ready_for_controlled_test,
    ).toBe(false);
  },
);
it('requires a configured provider', () => {
  expect(
    incidentEmailReadiness({ ...config, emailDelivery: undefined }, evidence)
      .ready_for_controlled_test,
  ).toBe(false);
});
it.each([{ accountExists: false }, { emailVerified: false }, { enabledRules: 0 }])(
  'refuses missing recipient prerequisites %j',
  (change) => {
    expect(
      incidentEmailReadiness(config, { ...evidence, ...change }).ready_for_controlled_test,
    ).toBe(false);
  },
);
