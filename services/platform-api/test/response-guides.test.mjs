import { expect, it } from 'vitest';
import { responseGuide } from '../src/web/operations.mjs';
import { RUNBOOKS } from '../../../packages/operations/src/automation-model.ts';

it.each(RUNBOOKS)('provides bounded response and recovery guidance for %s', (code) => {
  const guide = responseGuide(code);
  expect(guide.title).toBeTruthy();
  expect(guide.steps.length).toBeGreaterThanOrEqual(3);
  expect(guide.steps.length).toBeLessThanOrEqual(5);
  expect(guide.recovery).toContain('fresh');
  expect(guide.escalation).toContain('application owner');
});
it.each(['unknown', '__proto__', 'constructor', 'https://example.invalid', null])(
  'never treats an unrecognized value as an executable or inherited guide: %s',
  (code) => {
    expect(responseGuide(code)).toBeNull();
  },
);
it('scanner guidance preserves malware refusal and requires a clean synthetic check', () => {
  const guide = responseGuide('check_scanner');
  expect(guide.steps.join(' ')).toContain('Never disable scanning');
  expect(guide.recovery).toContain('clean synthetic file');
  expect(guide.recovery).toContain('malware refusal');
});
it('storage guidance preserves original objects and email guidance preserves confirmation', () => {
  expect(responseGuide('check_storage').steps.join(' ')).toContain('Do not delete');
  expect(responseGuide('check_email').steps.join(' ')).toContain('Keep email confirmation enabled');
});
