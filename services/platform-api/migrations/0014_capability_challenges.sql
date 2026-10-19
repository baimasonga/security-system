-- Capability tokens (ADR-024): devices answer a challenge with the new 'capability' proof purpose.
ALTER TABLE challenges DROP CONSTRAINT challenges_purpose_check;
ALTER TABLE challenges ADD CONSTRAINT challenges_purpose_check
  CHECK (purpose IN ('activate','validate','refresh','deactivate','capability'));
