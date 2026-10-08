import { describe, expect, it } from 'vitest';
import {
  EntitlementValidationError,
  hasCapability,
  resolveEntitlements,
  validateCapabilities,
  validateEntitlementMap,
  type PlanDefinition,
} from '../src/index.ts';

const plan: PlanDefinition = {
  id: 'pln_1',
  productId: 'prd_1',
  code: 'professional',
  tier: 'professional',
  version: 3,
  entitlements: { pdf_editing: true, ocr_pages_monthly: 5000, cloud_workspace: true },
  capabilities: ['OCR_ADVANCED', 'CLOUD_SYNC'],
  deviceLimit: 3,
};

describe('resolveEntitlements', () => {
  it('resolves plan facts with its version', () => {
    const r = resolveEntitlements(plan);
    expect(r).toMatchObject({ planVersion: 3, tier: 'professional', deviceLimit: 3 });
    expect(r.capabilities).toEqual(['CLOUD_SYNC', 'OCR_ADVANCED']);
    expect(hasCapability(r, 'OCR_ADVANCED')).toBe(true);
    expect(hasCapability(r, 'AI_DOCUMENT_ASSISTANT')).toBe(false);
  });

  it('applies per-license overrides without mutating the plan', () => {
    const snapshot = structuredClone(plan);
    const r = resolveEntitlements(plan, {
      entitlements: { ocr_pages_monthly: 20000, cloud_workspace: null, beta_flag: true },
      capabilities: { add: ['AI_DOCUMENT_ASSISTANT'], remove: ['CLOUD_SYNC'] },
      deviceLimit: 10,
    });
    expect(r.entitlements).toEqual({
      beta_flag: true,
      ocr_pages_monthly: 20000,
      pdf_editing: true,
    });
    expect(r.capabilities).toEqual(['AI_DOCUMENT_ASSISTANT', 'OCR_ADVANCED']);
    expect(r.deviceLimit).toBe(10);
    expect(plan).toEqual(snapshot);
  });

  it('a new plan version changes the result with no other input change', () => {
    const v4 = {
      ...plan,
      version: 4,
      capabilities: [...plan.capabilities, 'AI_DOCUMENT_ASSISTANT'],
    };
    expect(resolveEntitlements(v4).capabilities).toContain('AI_DOCUMENT_ASSISTANT');
    expect(resolveEntitlements(v4).planVersion).toBe(4);
  });

  it('rejects malformed keys, values and limits (negative paths)', () => {
    expect(() => validateEntitlementMap({ 'Bad Key': true })).toThrow(EntitlementValidationError);
    expect(() => validateEntitlementMap({ a: -1 })).toThrow(EntitlementValidationError);
    expect(() => validateEntitlementMap({ a: 1.5 })).toThrow(EntitlementValidationError);
    expect(() => validateEntitlementMap({ a: 'yes' })).toThrow(EntitlementValidationError);
    expect(() => validateCapabilities(['lowercase'])).toThrow(EntitlementValidationError);
    expect(() => resolveEntitlements(plan, { deviceLimit: 0 })).toThrow(EntitlementValidationError);
    expect(() => resolveEntitlements(plan, { deviceLimit: 1e9 })).toThrow(
      EntitlementValidationError,
    );
    expect(() =>
      validateEntitlementMap(
        Object.fromEntries(Array.from({ length: 101 }, (_, i) => [`k${i}`, true])),
      ),
    ).toThrow();
  });
});
