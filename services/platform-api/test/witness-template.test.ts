import { expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { parse } from 'yaml';

const template = parse(readFileSync('infrastructure/audit-witness/template.yaml', 'utf8'));
it('requires an explicit retention period and preserves locked evidence on stack deletion', () => {
  expect(template.Parameters.RetentionDays.Default).toBeUndefined();
  const bucket = template.Resources.Evidence;
  expect(bucket.DeletionPolicy).toBe('Retain');
  expect(bucket.UpdateReplacePolicy).toBe('Retain');
  expect(bucket.Properties.ObjectLockEnabled).toBe(true);
  expect(bucket.Properties.VersioningConfiguration.Status).toBe('Enabled');
  expect(bucket.Properties.ObjectLockConfiguration.Rule.DefaultRetention).toEqual({
    Mode: 'COMPLIANCE',
    Days: { Ref: 'RetentionDays' },
  });
  expect(Object.values(bucket.Properties.PublicAccessBlockConfiguration)).toEqual([
    true,
    true,
    true,
    true,
  ]);
});
it('grants the receiver only create and inspection actions; bucket policy forbids replacement and deletion', () => {
  const policy = template.Resources.ReceiverRole.Properties.Policies[0].PolicyDocument.Statement;
  expect(policy).toHaveLength(1);
  expect(policy[0].Action).toEqual([
    's3:PutObject',
    's3:GetObject',
    's3:GetObjectVersion',
    's3:GetObjectRetention',
  ]);
  expect(policy[0].Resource).toEqual({ 'Fn::Sub': '${Evidence.Arn}/anchors/*' });
  const denies = template.Resources.EvidencePolicy.Properties.PolicyDocument.Statement;
  expect(denies).toContainEqual(
    expect.objectContaining({
      Effect: 'Deny',
      Action: 's3:PutObject',
      Condition: { StringNotEquals: { 's3:if-none-match': '*' } },
    }),
  );
  expect(denies).toContainEqual(
    expect.objectContaining({
      Effect: 'Deny',
      Action: ['s3:DeleteObject', 's3:DeleteObjectVersion'],
    }),
  );
});
it('bounds execution and exposes only the anchor route with no body logging', () => {
  expect(template.Resources.Receiver.Properties.Timeout).toBe(10);
  expect(template.Resources.Receiver.Properties.ReservedConcurrentExecutions).toBe(2);
  expect(template.Resources.Route.Properties.RouteKey).toBe('POST /anchors');
  expect(template.Resources.Stage.Properties.AccessLogSettings).toBeUndefined();
  expect(template.Resources.Stage.Properties.DefaultRouteSettings.ThrottlingRateLimit).toBe(2);
});
